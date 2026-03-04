import os
import time
import json
import hashlib
import pathlib
import base64
from typing import Dict, Any, Tuple, Optional, List

from flask import Flask, request, jsonify, make_response
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

app = Flask(__name__)

# ============================================================
# Config (env)
# ============================================================
ENV = os.getenv("SCP_ENV", "production").strip()
API_VERSION = os.getenv("SCP_API_VERSION", "0.5.0").strip()

PARTNER_ID = os.getenv("SCP_PARTNER_ID", "hashkey").strip()

SCP_API_KEYS_RAW = os.getenv("SCP_API_KEYS", "").strip()
SCP_API_KEYS = {k.strip() for k in SCP_API_KEYS_RAW.split(",") if k.strip()}

RATE_LIMIT_PER_MIN = int(os.getenv("SCP_RATE_LIMIT_PER_MIN", "60"))

# Ed25519 signing keys (base64 raw 32 bytes)
SCP_SIGNING_PRIVATE_KEY_B64 = os.getenv("SCP_SIGNING_PRIVATE_KEY_B64", "").strip()
SCP_SIGNING_PUBLIC_KEY_B64 = os.getenv("SCP_SIGNING_PUBLIC_KEY_B64", "").strip()
SCP_SIGNING_KID = os.getenv("SCP_SIGNING_KID", "k1").strip()

# Optional ops metadata
SCP_GIT_SHA = os.getenv("SCP_GIT_SHA", "").strip()

# Server-side evidence log
ENABLE_COMMITMENT_LOG = os.getenv("SCP_ENABLE_COMMITMENT_LOG", "1").strip() == "1"
COMMITMENT_LOG_PATH = os.getenv("SCP_COMMITMENT_LOG_PATH", "commitment_log.jsonl").strip()

# ============================================================
# Partner pack paths
# ============================================================
BASE_DIR = pathlib.Path(__file__).resolve().parent
PARTNER_DIR = BASE_DIR / "config" / "partners" / PARTNER_ID

ALLOWLIST_PATH = str(PARTNER_DIR / "allowlist.json")
POLICY_CONFIG_PATH = str(PARTNER_DIR / "policy_config.json")
MAPPING_CONFIG_PATH = str(PARTNER_DIR / "mapping_config.json")
PARTNER_META_PATH = str(PARTNER_DIR / "partner_meta.json")

# ============================================================
# In-memory rate limit
# ============================================================
_rate_state: Dict[str, Tuple[int, int]] = {}

def _rate_limit_ok(api_key: str) -> bool:
    now_min = int(time.time() // 60)
    window, count = _rate_state.get(api_key, (now_min, 0))
    if window != now_min:
        window, count = now_min, 0
    if count >= RATE_LIMIT_PER_MIN:
        _rate_state[api_key] = (window, count)
        return False
    _rate_state[api_key] = (window, count + 1)
    return True

# ============================================================
# Utils: deterministic canonicalization
# ============================================================
def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _file_sha256(path_str: str) -> str:
    p = pathlib.Path(path_str)
    if not p.exists():
        return ""
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except Exception:
        return ""

# ============================================================
# Standard error response
# ============================================================
def _error(status: int, msg: str, hint: str = "", meta: Optional[Dict[str, Any]] = None):
    payload: Dict[str, Any] = {"error": msg}
    if hint:
        payload["hint"] = hint
    if meta:
        payload["meta"] = meta
    return make_response(jsonify(payload), status)

# ============================================================
# Auth
# ============================================================
def _extract_api_key() -> str:
    api_key = request.headers.get("X-SCP-API-KEY", "") or request.headers.get("X-API-KEY", "")
    return (api_key or "").strip()

def _auth_ok() -> Tuple[bool, str]:
    api_key = _extract_api_key()
    if not api_key:
        return False, ""
    if SCP_API_KEYS and api_key not in SCP_API_KEYS:
        return False, api_key
    return True, api_key

# ============================================================
# Cached JSON loaders (per-partner pack)
# ============================================================
_cache: Dict[str, Dict[str, Any]] = {}
_cache_mtime: Dict[str, float] = {}

def _load_json_dict_cached(path_str: str) -> Dict[str, Any]:
    path = pathlib.Path(path_str)
    if not path.exists():
        return {}
    try:
        mtime = path.stat().st_mtime
    except Exception:
        return {}

    if path_str in _cache and _cache_mtime.get(path_str, 0.0) == mtime:
        return _cache[path_str]

    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}

    if not isinstance(data, dict):
        return {}

    _cache[path_str] = data
    _cache_mtime[path_str] = mtime
    return data

def _partner_meta() -> Dict[str, Any]:
    return _load_json_dict_cached(PARTNER_META_PATH)

def _allowlist() -> Dict[str, Any]:
    return _load_json_dict_cached(ALLOWLIST_PATH)

def _policy_cfg() -> Dict[str, Any]:
    return _load_json_dict_cached(POLICY_CONFIG_PATH)

def _mapping_cfg() -> Dict[str, Any]:
    return _load_json_dict_cached(MAPPING_CONFIG_PATH)

# ============================================================
# Authority model (key-scoped allowlist)
# ============================================================
def _enforce_key_scope(api_key: str, body_norm: Dict[str, Any]) -> Tuple[bool, str]:
    allow = _allowlist()
    if not allow:
        return False, f"allowlist not loaded (missing/invalid): {ALLOWLIST_PATH}"

    entry = allow.get(api_key)
    if not entry:
        return False, "api_key not found in allowlist"

    status = str(entry.get("status", "active")).strip().lower()
    if status != "active":
        return False, f"api_key status is '{status}'"

    allowed_owners = entry.get("allowed_owners", [])
    allowed_types = entry.get("allowed_decision_types", [])

    owner = body_norm.get("decision_owner", "")
    dt = body_norm.get("decision_type", "")

    if allowed_owners and owner not in allowed_owners:
        return False, f"decision_owner '{owner}' not allowed for this api_key"

    if allowed_types and dt not in allowed_types:
        return False, f"decision_type '{dt}' not allowed for this api_key"

    return True, ""

# ============================================================
# Mapping: partner payload -> canonical SCP fields (config-driven)
# ============================================================
CANON_FIELDS = [
    "decision_type",
    "decision_owner",
    "decision_size_usd",
    "request_id",
    "idempotency_key",
    "parent_commitment_id",
]

def _get_first(body: Dict[str, Any], keys: List[str]) -> Any:
    for k in keys:
        if k in body and body.get(k) is not None:
            return body.get(k)
    return None

def normalize_payload(body: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(body, dict):
        return {}

    cfg = _mapping_cfg() or {}

    keys_dt = cfg.get("decision_type_keys", ["decision_type", "type"])
    keys_owner = cfg.get("decision_owner_keys", ["decision_owner", "requested_by", "owner"])
    keys_size = cfg.get("decision_size_usd_keys", ["decision_size_usd", "limit_usd", "size_usd"])
    keys_req = cfg.get("request_id_keys", ["request_id", "incident_id", "ticket_id"])
    keys_idem = cfg.get("idempotency_key_keys", ["idempotency_key", "event_id", "incident_id"])
    keys_parent = cfg.get("parent_commitment_id_keys", ["parent_commitment_id", "parent_id"])

    dt = _get_first(body, keys_dt)
    owner = _get_first(body, keys_owner)
    size_raw = _get_first(body, keys_size)
    request_id = _get_first(body, keys_req)
    idem = _get_first(body, keys_idem)
    parent = _get_first(body, keys_parent)

    # If they send action, map action -> decision_type
    if not dt:
        action_key = cfg.get("action_key", "action")
        action = str(body.get(action_key, "")).strip()
        action_map = cfg.get("action_map", {})
        if action and isinstance(action_map, dict) and action in action_map:
            dt = action_map[action]
        elif action:
            dt = cfg.get("default_decision_type", "break_glass")

    if not owner:
        owner = cfg.get("default_decision_owner", "")

    try:
        size = int(size_raw) if size_raw is not None else 0
    except Exception:
        size = 0

    out = {
        "decision_type": str(dt or "").strip(),
        "decision_owner": str(owner or "").strip(),
        "decision_size_usd": size,
        "request_id": str(request_id or "").strip(),
        "idempotency_key": str(idem or "").strip(),
        "parent_commitment_id": str(parent or "").strip(),
    }

    # remove empty optional fields
    for k in ["request_id", "idempotency_key", "parent_commitment_id"]:
        if not out.get(k):
            out.pop(k, None)

    return out

def _normalize_body(body: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k in CANON_FIELDS:
        if k in body:
            out[k] = body[k]

    out["decision_type"] = str(out.get("decision_type", "")).strip()
    out["decision_owner"] = str(out.get("decision_owner", "")).strip()

    try:
        out["decision_size_usd"] = int(out.get("decision_size_usd", 0))
    except Exception:
        out["decision_size_usd"] = 0

    for opt in ["request_id", "idempotency_key", "parent_commitment_id"]:
        if opt in out:
            out[opt] = str(out.get(opt, "")).strip()
            if not out[opt]:
                out.pop(opt, None)

    return out

# ============================================================
# Policy (config-driven)
# ============================================================
def run_policy(body_norm: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _policy_cfg() or {}
    size = int(body_norm.get("decision_size_usd", 0))

    reject_threshold = int(cfg.get("reject_threshold_usd", 10_000_000))
    constrain_threshold = int(cfg.get("constrain_threshold_usd", 1_000_000))

    constrain_text = str(cfg.get("constrain_constraints", "Require escalation to risk committee / break-glass approval."))
    constrain_reason = str(cfg.get("constrain_reason", "Constrained: size >= 1M threshold."))
    reject_reason = str(cfg.get("reject_reason", "Rejected: size >= 10M threshold."))
    allow_reason = str(cfg.get("allow_reason", "Within policy."))

    meta = _partner_meta() or {}
    policy_pack_id = str(cfg.get("policy_pack_id", meta.get("policy_pack_id", "pilot_pack_v1")))

    if size >= reject_threshold:
        return {
            "verdict": "REJECT",
            "constraints": "",
            "policy_pack": policy_pack_id,
            "policy_reason": reject_reason,
        }

    if size >= constrain_threshold:
        return {
            "verdict": "CONSTRAIN",
            "constraints": constrain_text,
            "policy_pack": policy_pack_id,
            "policy_reason": constrain_reason,
        }

    return {
        "verdict": "ALLOW",
        "constraints": "",
        "policy_pack": policy_pack_id,
        "policy_reason": allow_reason,
    }

# ============================================================
# Signing: Ed25519 (signature over commitment_id)
# ============================================================
def _b64_decode(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def _load_private_key() -> Optional[Ed25519PrivateKey]:
    if not SCP_SIGNING_PRIVATE_KEY_B64:
        return None
    try:
        raw = _b64_decode(SCP_SIGNING_PRIVATE_KEY_B64)
        if len(raw) != 32:
            return None
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        return None

def _load_public_key_bytes() -> Optional[bytes]:
    if not SCP_SIGNING_PUBLIC_KEY_B64:
        return None
    try:
        raw = _b64_decode(SCP_SIGNING_PUBLIC_KEY_B64)
        if len(raw) != 32:
            return None
        return raw
    except Exception:
        return None

def _ed25519_sign_hex(commitment_id_hex: str) -> str:
    sk = _load_private_key()
    if not sk:
        raise ValueError("missing_or_invalid_private_key")
    sig = sk.sign(commitment_id_hex.encode("utf-8"))
    return sig.hex()

# ============================================================
# Receipt builder (deterministic)
# ============================================================
REQUIRED_FIELDS = ["decision_type", "decision_owner", "decision_size_usd"]

def build_receipt(body_norm: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    policy = run_policy(body_norm)
    meta = _partner_meta() or {}
    gate_id = str(meta.get("gate_id", f"{PARTNER_ID}_gate_v1")).strip()

    boundary_snapshot: Dict[str, Any] = {
        "gate_id": gate_id,
        "decision": {
            "decision_type": body_norm.get("decision_type", ""),
            "decision_owner": body_norm.get("decision_owner", ""),
            "decision_size_usd": body_norm.get("decision_size_usd", 0),
        },
        "verdict": policy["verdict"],
        "policy_pack": policy["policy_pack"],
        "policy_reason": policy["policy_reason"],
        "constraints": policy["constraints"],
        "api_version": API_VERSION,
        "env": ENV,
        "partner_id": PARTNER_ID,
        "sig_alg": "ed25519",
        "kid": SCP_SIGNING_KID,
        # Config hashes for “which config produced this receipt”
        "allowlist_sha256": _file_sha256(ALLOWLIST_PATH),
        "policy_config_sha256": _file_sha256(POLICY_CONFIG_PATH),
        "mapping_config_sha256": _file_sha256(MAPPING_CONFIG_PATH),
    }

    # Optional signed fields (for chain / de-dup / tracing)
    for opt in ["request_id", "idempotency_key", "parent_commitment_id"]:
        if opt in body_norm:
            boundary_snapshot[opt] = body_norm[opt]

    # Commitment id is deterministic hash of the canonical boundary snapshot
    commitment_id = _sha256_hex(_canonical_json(boundary_snapshot))

    # Signature is Ed25519(private_key, commitment_id)
    signature = _ed25519_sign_hex(commitment_id)

    receipt = {
        "commitment_id": commitment_id,
        "signature": signature,
        "sig_alg": "ed25519",
        "kid": SCP_SIGNING_KID,
        "boundary_snapshot": boundary_snapshot,
        # non-sensitive operational metadata
        "server_meta": {
            "git_sha": SCP_GIT_SHA,
            "api_key_fingerprint": _sha256_hex(api_key)[:16],
        },
    }
    return receipt

# ============================================================
# Append-only evidence log WITH hash chaining (optional)
# ============================================================
def _read_last_log_hash() -> str:
    p = pathlib.Path(COMMITMENT_LOG_PATH)
    if not p.exists():
        return ""
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            if line.strip():
                obj = json.loads(line)
                return str(obj.get("log_hash", "")).strip()
    except Exception:
        return ""
    return ""

def _append_commitment_log(receipt: Dict[str, Any]) -> None:
    if not ENABLE_COMMITMENT_LOG:
        return
    try:
        p = pathlib.Path(COMMITMENT_LOG_PATH)
        prev_hash = _read_last_log_hash()

        entry = {
            "ts_epoch": int(time.time()),
            "commitment_id": receipt.get("commitment_id", ""),
            "gate_id": receipt.get("boundary_snapshot", {}).get("gate_id", ""),
            "verdict": receipt.get("boundary_snapshot", {}).get("verdict", ""),
            "policy_pack": receipt.get("boundary_snapshot", {}).get("policy_pack", ""),
            "decision": receipt.get("boundary_snapshot", {}).get("decision", {}),
            "prev_log_hash": prev_hash,
        }

        entry["log_hash"] = _sha256_hex(_canonical_json(entry))
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # logging failure must not break /evaluate
        return

# ============================================================
# Server config validation
# ============================================================
def _validate_server_config() -> Optional[str]:
    if not _load_public_key_bytes():
        return "Missing/invalid SCP_SIGNING_PUBLIC_KEY_B64 (must decode to 32 bytes)."
    if not _load_private_key():
        return "Missing/invalid SCP_SIGNING_PRIVATE_KEY_B64 (must decode to 32 bytes)."
    if not pathlib.Path(PARTNER_DIR).exists():
        return f"Partner pack not found: {PARTNER_DIR}"
    for p in [ALLOWLIST_PATH, POLICY_CONFIG_PATH, MAPPING_CONFIG_PATH, PARTNER_META_PATH]:
        if not pathlib.Path(p).exists():
            return f"Missing partner pack file: {p}"
    return None

# ============================================================
# Routes
# ============================================================
@app.get("/")
def root():
    return jsonify(
        {
            "env": ENV,
            "status": "SCP Pilot Gateway running",
            "version": API_VERSION,
            "partner_id": PARTNER_ID,
        }
    )

@app.get("/healthz")
def healthz():
    err = _validate_server_config()
    return jsonify(
        {
            "env": ENV,
            "ok": err is None,
            "version": API_VERSION,
            "partner_id": PARTNER_ID,
            "error": err or "",
        }
    )

@app.get("/meta")
def meta():
    return jsonify(
        {
            "env": ENV,
            "version": API_VERSION,
            "partner_id": PARTNER_ID,
            "partner_dir": str(PARTNER_DIR),
            "gate_id": str((_partner_meta() or {}).get("gate_id", "")),
            "policy_pack_id": str((_policy_cfg() or {}).get("policy_pack_id", "")),
            "allowlist_sha256": _file_sha256(ALLOWLIST_PATH),
            "policy_config_sha256": _file_sha256(POLICY_CONFIG_PATH),
            "mapping_config_sha256": _file_sha256(MAPPING_CONFIG_PATH),
            "rate_limit_per_min": RATE_LIMIT_PER_MIN,
            "sig_alg": "ed25519",
            "kid": SCP_SIGNING_KID,
            "has_private_key": bool(_load_private_key()),
            "has_public_key": bool(_load_public_key_bytes()),
            "git_sha": SCP_GIT_SHA,
            "commitment_log_enabled": ENABLE_COMMITMENT_LOG,
        }
    )

@app.get("/config/validate")
def config_validate():
    problems = []
    if not _allowlist():
        problems.append(f"allowlist invalid/missing: {ALLOWLIST_PATH}")
    if not _policy_cfg():
        problems.append(f"policy_config invalid/missing: {POLICY_CONFIG_PATH}")
    if not _mapping_cfg():
        problems.append(f"mapping_config invalid/missing: {MAPPING_CONFIG_PATH}")
    if not _partner_meta():
        problems.append(f"partner_meta invalid/missing: {PARTNER_META_PATH}")

    key_err = _validate_server_config()
    if key_err:
        problems.append(f"signing/config error: {key_err}")

    return jsonify(
        {
            "ok": len(problems) == 0,
            "partner_id": PARTNER_ID,
            "problems": problems,
            "allowlist_sha256": _file_sha256(ALLOWLIST_PATH),
            "policy_config_sha256": _file_sha256(POLICY_CONFIG_PATH),
            "mapping_config_sha256": _file_sha256(MAPPING_CONFIG_PATH),
        }
    )

@app.post("/evaluate")
def evaluate():
    # 0) server config validation
    err = _validate_server_config()
    if err:
        return _error(500, "server_misconfigured", err)

    # 1) auth
    ok, api_key = _auth_ok()
    if not ok:
        return _error(401, "unauthorized", "Send header X-SCP-API-KEY with a valid key.")

    # 2) rate limit
    if not _rate_limit_ok(api_key):
        return _error(429, "rate_limited", f"Too many requests. Limit={RATE_LIMIT_PER_MIN}/min per key.")

    # 3) json
    if not request.is_json:
        return _error(400, "bad_request", "Content-Type must be application/json")

    # 4) parse
    body = request.get_json(silent=True) or {}

    # 5) normalize partner payload -> canonical fields
    body = normalize_payload(body)

    # 6) required fields
    missing = [f for f in REQUIRED_FIELDS if f not in body]
    if missing:
        return _error(400, "bad_request", f"Missing field: {missing[0]}")

    body_norm = _normalize_body(body)

    # 7) strict validation
    if not body_norm["decision_type"] or not body_norm["decision_owner"]:
        return _error(400, "bad_request", "decision_type and decision_owner must be non-empty strings.")
    if body_norm["decision_size_usd"] <= 0:
        return _error(400, "bad_request", "decision_size_usd must be a positive integer.")

    # 8) enforce authority model (key-scoped role model)
    ok_scope, reason = _enforce_key_scope(api_key, body_norm)
    if not ok_scope:
        return _error(403, "forbidden", reason)

    # 9) build receipt
    receipt = build_receipt(body_norm, api_key)

    # 10) append evidence log (optional)
    _append_commitment_log(receipt)

    resp = jsonify(receipt)
    resp.headers["X-SCP-Env"] = ENV
    resp.headers["X-SCP-Version"] = API_VERSION
    resp.headers["X-SCP-Partner"] = PARTNER_ID
    resp.headers["X-SCP-Sig-Alg"] = "ed25519"
    resp.headers["X-SCP-Kid"] = SCP_SIGNING_KID
    return resp

