import os
import time
import json
import hashlib
import pathlib
from typing import Dict, Any, Tuple, Optional

from flask import Flask, request, jsonify, make_response

# crypto (Ed25519)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64

app = Flask(__name__)

# ============================================================
# Config (env)
# ============================================================
ENV = os.getenv("SCP_ENV", "production").strip()
API_VERSION = os.getenv("SCP_API_VERSION", "0.6.1").strip()

# Multi-tenant identifiers (partner + gate)
PARTNER_ID = os.getenv("SCP_PARTNER_ID", "default").strip()
GATE_ID = os.getenv("SCP_GATE_ID", "default_gate_v1").strip()

# API key allow-list (optional)
SCP_API_KEYS_RAW = os.getenv("SCP_API_KEYS", "").strip()
SCP_API_KEYS = {k.strip() for k in SCP_API_KEYS_RAW.split(",") if k.strip()}

RATE_LIMIT_PER_MIN = int(os.getenv("SCP_RATE_LIMIT_PER_MIN", "60"))

# Human readable “policy pack id” (shows up in receipt)
POLICY_PACK_ID = os.getenv("SCP_POLICY_PACK_ID", "pilot_pack_v1").strip()

# ---- Partner config directory layout (no code change per partner) ----
# repo layout:
#   config/partners/<partner_id>/
#       allowlist.json
#       mapping_config.json
#       policy_config.json
#       partner_meta.json
BASE_PARTNERS_DIR = os.getenv("SCP_PARTNERS_DIR", "config/partners").strip()
PARTNER_DIR = os.getenv("SCP_PARTNER_DIR", "").strip()
if not PARTNER_DIR:
    PARTNER_DIR = str(pathlib.Path(BASE_PARTNERS_DIR) / PARTNER_ID)

ALLOWLIST_PATH = os.getenv("SCP_ALLOWLIST_PATH", str(pathlib.Path(PARTNER_DIR) / "allowlist.json"))
MAPPING_CONFIG_PATH = os.getenv("SCP_MAPPING_CONFIG_PATH", str(pathlib.Path(PARTNER_DIR) / "mapping_config.json"))
POLICY_CONFIG_PATH = os.getenv("SCP_POLICY_CONFIG_PATH", str(pathlib.Path(PARTNER_DIR) / "policy_config.json"))
PARTNER_META_PATH = os.getenv("SCP_PARTNER_META_PATH", str(pathlib.Path(PARTNER_DIR) / "partner_meta.json"))

# ---- Signing (Ed25519) ----
# Railway env:
#   SCP_SIGNING_PRIVATE_KEY_B64 = base64(32 bytes seed)  [server only]
# Optional env (NOT required): SCP_SIGNING_PUBLIC_KEY_B64 (for debugging only)
KEYS_DIR = os.getenv("SCP_KEYS_DIR", "config/keys").strip()
PUBLIC_KEYS_JSON_PATH = os.getenv("SCP_PUBLIC_KEYS_JSON_PATH", str(pathlib.Path(KEYS_DIR) / "public_keys.json"))
ACTIVE_KID_PATH = os.getenv("SCP_ACTIVE_KID_PATH", str(pathlib.Path(KEYS_DIR) / "active_kid.txt"))

# ---- Append-only commitment log ----
DATA_DIR = os.getenv("SCP_DATA_DIR", "data").strip()
COMMITMENT_LOG_PATH = os.getenv("SCP_COMMITMENT_LOG_PATH", str(pathlib.Path(DATA_DIR) / "commitment_log.jsonl"))
ENABLE_COMMITMENT_LOG = os.getenv("SCP_ENABLE_COMMITMENT_LOG", "1").strip() == "1"

# ============================================================
# Utilities
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

def _error(status: int, msg: str, hint: str = "", meta: Optional[Dict[str, Any]] = None):
    payload: Dict[str, Any] = {"error": msg}
    if hint:
        payload["hint"] = hint
    if meta:
        payload["meta"] = meta
    return make_response(jsonify(payload), status)

def _read_text(path: pathlib.Path, encoding: str = "utf-8-sig") -> str:
    # utf-8-sig handles BOM (Windows Notepad often writes BOM)
    return path.read_text(encoding=encoding)

def _b64_to_bytes(s: str) -> bytes:
    s = (s or "").strip().strip('"').strip("'")
    # tolerate missing padding
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)

# ============================================================
# Rate limit (simple in-memory)
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
# Auth
# ============================================================
def _auth_ok() -> Tuple[bool, str]:
    api_key = request.headers.get("X-SCP-API-KEY", "") or request.headers.get("X-API-KEY", "")
    api_key = (api_key or "").strip()
    if not api_key:
        return False, ""
    if SCP_API_KEYS and api_key not in SCP_API_KEYS:
        return False, api_key
    return True, api_key

# ============================================================
# Cached JSON loader (partner configs)
# ============================================================
_cache: Dict[str, Dict[str, Any]] = {}
_mtime: Dict[str, float] = {}

def _load_json_dict_cached(path_str: str) -> Dict[str, Any]:
    p = pathlib.Path(path_str)
    if not p.exists():
        return {}
    try:
        mt = p.stat().st_mtime
    except Exception:
        return {}

    key = str(p.resolve())
    if key in _cache and _mtime.get(key) == mt:
        return _cache[key]

    try:
        raw = _read_text(p, encoding="utf-8-sig")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {}
        _cache[key] = data
        _mtime[key] = mt
        return data
    except Exception:
        return {}

# ============================================================
# Allowlist (key-scoped role/authority model)
# ============================================================
def _enforce_key_scope(api_key: str, body_norm: Dict[str, Any]) -> Tuple[bool, str]:
    allowlist = _load_json_dict_cached(ALLOWLIST_PATH)
    if not allowlist:
        return False, f"allowlist not loaded (missing/invalid): {ALLOWLIST_PATH}"

    entry = allowlist.get(api_key)
    if not entry:
        return False, "api_key not found in allowlist"

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
# Mapping (partner -> canonical) driven by mapping_config.json
# ============================================================
REQUIRED_FIELDS = ["decision_type", "decision_owner", "decision_size_usd"]

def normalize_payload(body: Any) -> Dict[str, Any]:
    if not isinstance(body, dict):
        return {}

    cfg = _load_json_dict_cached(MAPPING_CONFIG_PATH) or {}

    dt_keys = cfg.get("decision_type_keys", ["decision_type", "type"])
    owner_keys = cfg.get("decision_owner_keys", ["decision_owner", "requested_by", "owner"])
    size_keys = cfg.get("decision_size_usd_keys", ["decision_size_usd", "limit_usd", "size_usd"])

    action_key = cfg.get("action_key", "action")
    action_map = cfg.get("action_map", {}) or {}
    default_dt = cfg.get("default_decision_type", "break_glass")
    default_owner = cfg.get("default_decision_owner", "")

    # decision_type
    dt = ""
    for k in dt_keys:
        v = body.get(k)
        if v is not None and str(v).strip():
            dt = str(v).strip()
            break
    if not dt:
        action = str(body.get(action_key, "")).strip()
        if action and action in action_map:
            dt = str(action_map[action]).strip()
        elif action:
            dt = str(default_dt).strip()
        else:
            dt = ""

    # decision_owner
    owner = ""
    for k in owner_keys:
        v = body.get(k)
        if v is not None and str(v).strip():
            owner = str(v).strip()
            break
    if not owner:
        owner = str(default_owner).strip()

    # decision_size_usd
    size_raw = None
    for k in size_keys:
        if k in body:
            size_raw = body.get(k)
            break
    try:
        size = int(size_raw) if size_raw is not None else 0
    except Exception:
        size = 0

    return {
        "decision_type": dt,
        "decision_owner": owner,
        "decision_size_usd": size,
    }

def _normalize_body(body: Dict[str, Any]) -> Dict[str, Any]:
    dt = str(body.get("decision_type", "")).strip()
    owner = str(body.get("decision_owner", "")).strip()
    try:
        size = int(body.get("decision_size_usd", 0))
    except Exception:
        size = 0
    return {"decision_type": dt, "decision_owner": owner, "decision_size_usd": size}

# ============================================================
# Policy (thresholds from policy_config.json)
# ============================================================
def run_policy(body_norm: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _load_json_dict_cached(POLICY_CONFIG_PATH) or {}

    reject_threshold = int(cfg.get("reject_threshold_usd", 10_000_000))
    constrain_threshold = int(cfg.get("constrain_threshold_usd", 1_000_000))

    constrain_text = str(cfg.get("constrain_constraints", "Require escalation to risk committee / break-glass approval."))
    constrain_reason = str(cfg.get("constrain_reason", "Constrained: size >= 1M threshold."))
    reject_reason = str(cfg.get("reject_reason", "Rejected: size >= 10M threshold."))
    allow_reason = str(cfg.get("allow_reason", "Within policy."))

    size = int(body_norm.get("decision_size_usd", 0))

    if size >= reject_threshold:
        return {"verdict": "REJECT", "constraints": "", "policy_pack": POLICY_PACK_ID, "policy_reason": reject_reason}

    if size >= constrain_threshold:
        return {
            "verdict": "CONSTRAIN",
            "constraints": constrain_text,
            "policy_pack": POLICY_PACK_ID,
            "policy_reason": constrain_reason,
        }

    return {"verdict": "ALLOW", "constraints": "", "policy_pack": POLICY_PACK_ID, "policy_reason": allow_reason}

# ============================================================
# Signing (Ed25519) + key rotation (kid)
# ============================================================
def _load_active_kid() -> str:
    p = pathlib.Path(ACTIVE_KID_PATH)
    if not p.exists():
        return "k1"
    try:
        return _read_text(p, encoding="utf-8-sig").strip() or "k1"
    except Exception:
        return "k1"

def _load_public_keys() -> Dict[str, str]:
    data = _load_json_dict_cached(PUBLIC_KEYS_JSON_PATH)
    if not data:
        return {}
    out: Dict[str, str] = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, str):
            out[k] = v.strip()
    return out

def _load_private_key() -> Optional[Ed25519PrivateKey]:
    sk_b64 = os.getenv("SCP_SIGNING_PRIVATE_KEY_B64", "").strip()
    if not sk_b64:
        return None
    try:
        seed = _b64_to_bytes(sk_b64)
        if len(seed) != 32:
            return None
        return Ed25519PrivateKey.from_private_bytes(seed)
    except Exception:
        return None

def _sign_commitment_id(commitment_id: str) -> Tuple[str, str, str]:
    """
    v0.6.1 rule:
      signature = Ed25519.Sign( commitment_id.encode("utf-8") )
      signature returned as hex string (64 bytes -> 128 hex chars)
    returns: (sig_hex, sig_alg, kid)
    """
    kid = _load_active_kid()
    sk = _load_private_key()
    if sk is None:
        raise RuntimeError("missing/invalid SCP_SIGNING_PRIVATE_KEY_B64 (must be base64 of 32 bytes)")

    msg = commitment_id.encode("utf-8")
    sig = sk.sign(msg)
    return sig.hex(), "ed25519", kid

# ============================================================
# Receipt (deterministic)
# ============================================================
def build_receipt(body_norm: Dict[str, Any]) -> Dict[str, Any]:
    policy = run_policy(body_norm)

    boundary_snapshot = {
        "decision": body_norm,
        "verdict": policy["verdict"],
        "policy_pack": policy["policy_pack"],
        "policy_reason": policy["policy_reason"],
        "constraints": policy["constraints"],
        "api_version": API_VERSION,
        "env": ENV,
        "partner_id": PARTNER_ID,
        "gate_id": GATE_ID,
        "allowlist_sha256": _file_sha256(ALLOWLIST_PATH),
        "mapping_config_sha256": _file_sha256(MAPPING_CONFIG_PATH),
        "policy_config_sha256": _file_sha256(POLICY_CONFIG_PATH),
    }

    canonical = _canonical_json(boundary_snapshot)
    commitment_id = _sha256_hex(canonical)

    sig_hex, sig_alg, kid = _sign_commitment_id(commitment_id)

    return {
        "commitment_id": commitment_id,
        "signature": sig_hex,
        "sig_alg": sig_alg,
        "kid": kid,
        "boundary_snapshot": boundary_snapshot,
    }

# ============================================================
# Append-only log (server-side evidence)
# ============================================================
def _append_commitment_log(receipt: Dict[str, Any]) -> None:
    if not ENABLE_COMMITMENT_LOG:
        return
    try:
        pathlib.Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
        p = pathlib.Path(COMMITMENT_LOG_PATH)
        line = {
            "ts_epoch": int(time.time()),
            "partner_id": PARTNER_ID,
            "gate_id": GATE_ID,
            "commitment_id": receipt.get("commitment_id", ""),
            "verdict": receipt.get("boundary_snapshot", {}).get("verdict", ""),
            "policy_pack": receipt.get("boundary_snapshot", {}).get("policy_pack", ""),
            "decision": receipt.get("boundary_snapshot", {}).get("decision", {}),
            "kid": receipt.get("kid", ""),
            "sig_alg": receipt.get("sig_alg", ""),
        }
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
    except Exception:
        return

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
            "gate_id": GATE_ID,
        }
    )

@app.get("/healthz")
def healthz():
    return jsonify(
        {"env": ENV, "ok": True, "version": API_VERSION, "partner_id": PARTNER_ID, "gate_id": GATE_ID}
    )

@app.get("/meta")
def meta():
    pub_keys = _load_public_keys()
    kid = _load_active_kid()

    public_key_b64_active = (pub_keys.get(kid, "") or "").strip()
    public_key_b64_env = os.getenv("SCP_SIGNING_PUBLIC_KEY_B64", "").strip()

    return jsonify(
        {
            "env": ENV,
            "version": API_VERSION,
            "partner_id": PARTNER_ID,
            "gate_id": GATE_ID,
            "policy_pack_id": POLICY_PACK_ID,
            "rate_limit_per_min": RATE_LIMIT_PER_MIN,
            "commitment_log_enabled": ENABLE_COMMITMENT_LOG,

            "sig_alg": "ed25519",
            "kid": kid,

            # server key state
            "has_private_key": bool(os.getenv("SCP_SIGNING_PRIVATE_KEY_B64", "").strip()),
            "has_public_keys_file": bool(pub_keys),

            # ⭐⭐⭐ the only strings you should copy for offline verify
            "public_key_b64_active": public_key_b64_active,
            "public_key_b64_env": public_key_b64_env,

            # paths + hashes for debugging
            "partner_dir": str(pathlib.Path(PARTNER_DIR).as_posix()),
            "allowlist_path": str(pathlib.Path(ALLOWLIST_PATH).as_posix()),
            "mapping_config_path": str(pathlib.Path(MAPPING_CONFIG_PATH).as_posix()),
            "policy_config_path": str(pathlib.Path(POLICY_CONFIG_PATH).as_posix()),
            "allowlist_sha256": _file_sha256(ALLOWLIST_PATH),
            "mapping_config_sha256": _file_sha256(MAPPING_CONFIG_PATH),
            "policy_config_sha256": _file_sha256(POLICY_CONFIG_PATH),
            "git_sha": os.getenv("SCP_GIT_SHA", "").strip(),
        }
    )

@app.post("/evaluate")
def evaluate():
    # 1) auth
    ok, api_key = _auth_ok()
    if not ok:
        return _error(401, "unauthorized", "Send header X-SCP-API-KEY (or X-API-KEY).")

    # 2) rate limit
    if not _rate_limit_ok(api_key):
        return _error(429, "rate_limited", f"Too many requests. Limit={RATE_LIMIT_PER_MIN}/min per key.")

    # 3) json
    if not request.is_json:
        return _error(400, "bad_request", "Content-Type must be application/json")

    # 4) parse
    body = request.get_json(silent=True) or {}

    # 5) normalize partner payload -> canonical
    body = normalize_payload(body)

    # 6) required fields exist
    missing = [f for f in REQUIRED_FIELDS if f not in body]
    if missing:
        return _error(400, "bad_request", f"Missing field: {missing[0]}")

    body_norm = _normalize_body(body)

    # 7) strict validation
    if not body_norm["decision_type"] or not body_norm["decision_owner"]:
        return _error(400, "bad_request", "decision_type and decision_owner must be non-empty strings.")
    if body_norm["decision_size_usd"] <= 0:
        return _error(400, "bad_request", "decision_size_usd must be a positive integer.")

    # 8) enforce key-scoped authority model
    ok_scope, reason = _enforce_key_scope(api_key, body_norm)
    if not ok_scope:
        return _error(403, "forbidden", reason)

    # 9) build receipt (must have server private key)
    try:
        receipt = build_receipt(body_norm)
    except Exception as e:
        return _error(500, "server_misconfigured", str(e))

    # 10) append-only evidence log
    _append_commitment_log(receipt)

    resp = jsonify(receipt)
    resp.headers["X-SCP-Env"] = ENV
    resp.headers["X-SCP-Version"] = API_VERSION
    resp.headers["X-SCP-Policy-Pack"] = POLICY_PACK_ID
    resp.headers["X-SCP-Partner"] = PARTNER_ID
    resp.headers["X-SCP-Gate"] = GATE_ID
    resp.headers["X-SCP-Sig-Alg"] = receipt.get("sig_alg", "ed25519")
    resp.headers["X-SCP-Kid"] = receipt.get("kid", "")
    return resp