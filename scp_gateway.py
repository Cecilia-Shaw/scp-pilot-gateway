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
API_VERSION = os.getenv("SCP_API_VERSION", "0.6.3").strip()

# Multi-tenant identifiers (partner + gate)
PARTNER_ID = os.getenv("SCP_PARTNER_ID", "default").strip()
GATE_ID = os.getenv("SCP_GATE_ID", "default_gate_v1").strip()

# API key allow-list (optional)
SCP_API_KEYS_RAW = os.getenv("SCP_API_KEYS", "").strip()
SCP_API_KEYS = {k.strip() for k in SCP_API_KEYS_RAW.split(",") if k.strip()}

RATE_LIMIT_PER_MIN = int(os.getenv("SCP_RATE_LIMIT_PER_MIN", "60"))

# Human readable “policy pack id” (shows up in receipt)
POLICY_PACK_ID = os.getenv("SCP_POLICY_PACK_ID", "pilot_pack_v1").strip()

# A+ NEW: Partner pack path (single-file config)
SCP_PARTNER_PACK_PATH = os.getenv("SCP_PARTNER_PACK_PATH", "").strip()

# A+ NEW: Admin key for reload endpoint (server only)
SCP_ADMIN_API_KEY = os.getenv("SCP_ADMIN_API_KEY", "").strip()

# ---- Partner legacy config directory layout (fallback) ----
BASE_PARTNERS_DIR = os.getenv("SCP_PARTNERS_DIR", "config/partners").strip()
PARTNER_DIR = os.getenv("SCP_PARTNER_DIR", "").strip()
if not PARTNER_DIR:
    PARTNER_DIR = str(pathlib.Path(BASE_PARTNERS_DIR) / PARTNER_ID)

ALLOWLIST_PATH = os.getenv("SCP_ALLOWLIST_PATH", str(pathlib.Path(PARTNER_DIR) / "allowlist.json"))
MAPPING_CONFIG_PATH = os.getenv("SCP_MAPPING_CONFIG_PATH", str(pathlib.Path(PARTNER_DIR) / "mapping_config.json"))
POLICY_CONFIG_PATH = os.getenv("SCP_POLICY_CONFIG_PATH", str(pathlib.Path(PARTNER_DIR) / "policy_config.json"))
PARTNER_META_PATH = os.getenv("SCP_PARTNER_META_PATH", str(pathlib.Path(PARTNER_DIR) / "partner_meta.json"))

# ---- Signing (Ed25519) + key rotation (kid) ----
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
    if not path_str:
        return ""
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
    return path.read_text(encoding=encoding)

def _b64_to_bytes(s: str) -> bytes:
    s = (s or "").strip().strip('"').strip("'")
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
# Cached JSON loader (generic)
# ============================================================
_cache: Dict[str, Dict[str, Any]] = {}
_mtime: Dict[str, float] = {}

def _load_json_dict_cached(path_str: str) -> Dict[str, Any]:
    if not path_str:
        return {}
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

def _clear_cache_for_path(path_str: str) -> None:
    if not path_str:
        return
    try:
        p = pathlib.Path(path_str)
        key = str(p.resolve())
        if key in _cache:
            _cache.pop(key, None)
        if key in _mtime:
            _mtime.pop(key, None)
    except Exception:
        return

# ============================================================
# A+ Partner pack loader (single-file)
# ============================================================
def _default_pack_path() -> str:
    # If SCP_PARTNER_PACK_PATH not set, try default location based on PARTNER_ID
    if SCP_PARTNER_PACK_PATH:
        return SCP_PARTNER_PACK_PATH
    return str(pathlib.Path(BASE_PARTNERS_DIR) / PARTNER_ID / "partner_pack.json")

def _load_partner_pack() -> Dict[str, Any]:
    return _load_json_dict_cached(_default_pack_path())

def _partner_pack_sha256() -> str:
    return _file_sha256(_default_pack_path())

def _pack_get_section(pack: Dict[str, Any], key: str) -> Dict[str, Any]:
    v = pack.get(key, {})
    return v if isinstance(v, dict) else {}

def _get_pack_schema_version(pack: Dict[str, Any]) -> str:
    return str(pack.get("schema_version", "")).strip()

def _get_portable_anchor(pack: Dict[str, Any]) -> Dict[str, Any]:
    v = pack.get("portable_anchor", {})
    return v if isinstance(v, dict) else {}

def _get_extensible_metadata(pack: Dict[str, Any]) -> Dict[str, Any]:
    v = pack.get("extensible_metadata", {})
    return v if isinstance(v, dict) else {}

def _extract_portable_metadata(raw_body: Dict[str, Any], pack: Dict[str, Any]) -> Dict[str, Any]:
    """
    Optional future-facing metadata for portability / cross-system references.
    These fields are NOT required for V4 pilot.
    They are included only if present and non-empty.
    """
    if not isinstance(raw_body, dict):
        return {}

    ext_cfg = _get_extensible_metadata(pack)

    field_map = {
        "source_system": "supports_source_system",
        "target_system": "supports_target_system",
        "case_id": "supports_case_id",
        "incident_id": "supports_incident_id",
        "external_reference": "supports_external_reference",
        "operator_reference": "supports_operator_reference",
        "shift_reference": "supports_shift_reference",
    }

    out: Dict[str, Any] = {}

    for field_name, flag_name in field_map.items():
        if ext_cfg and not ext_cfg.get(flag_name, False):
            continue

        val = raw_body.get(field_name, None)
        if val is None:
            continue

        if isinstance(val, str):
            val = val.strip()
            if not val:
                continue

        out[field_name] = val

    return out

# ============================================================
# Allowlist (key-scoped role/authority model)
#   A+ rule: prefer pack.allowlist, else fallback to allowlist.json
# ============================================================
def _get_allowlist(pack: Dict[str, Any]) -> Dict[str, Any]:
    allowlist = _pack_get_section(pack, "allowlist")
    if allowlist:
        return allowlist
    return _load_json_dict_cached(ALLOWLIST_PATH)

def _enforce_key_scope(api_key: str, body_norm: Dict[str, Any], pack: Dict[str, Any]) -> Tuple[bool, str]:
    allowlist = _get_allowlist(pack)
    if not allowlist:
        return False, "allowlist not loaded (missing/invalid allowlist)"

    entry = allowlist.get(api_key)
    if not entry or not isinstance(entry, dict):
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
# Mapping (partner -> canonical)
#   A+ rule: prefer pack.mapping, else fallback to mapping_config.json
# ============================================================
REQUIRED_FIELDS = ["decision_type", "decision_owner", "decision_size_usd"]

def _get_mapping_cfg(pack: Dict[str, Any]) -> Dict[str, Any]:
    m = _pack_get_section(pack, "mapping")
    if m:
        return m
    return _load_json_dict_cached(MAPPING_CONFIG_PATH) or {}

def normalize_payload(body: Any, pack: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(body, dict):
        return {}

    cfg = _get_mapping_cfg(pack) or {}

    # A+ simple mapping keys:
    action_key = str(cfg.get("action_key", "action")).strip()
    owner_key = str(cfg.get("owner_key", cfg.get("decision_owner_key", "requested_by"))).strip()
    size_key = str(cfg.get("size_key", cfg.get("decision_size_usd_key", "limit_usd"))).strip()

    action_map = cfg.get("action_map", {}) or {}
    default_dt = str(cfg.get("default_decision_type", "break_glass")).strip()
    default_owner = str(cfg.get("default_decision_owner", "")).strip()

    # decision_type
    dt = str(body.get("decision_type", "")).strip()
    if not dt:
        action_val = str(body.get(action_key, "")).strip()
        if action_val and action_val in action_map:
            dt = str(action_map[action_val]).strip()
        elif action_val:
            dt = default_dt
        else:
            dt = ""

    # decision_owner
    owner = str(body.get("decision_owner", "")).strip()
    if not owner:
        owner = str(body.get(owner_key, "")).strip()
    if not owner:
        owner = default_owner

    # decision_size_usd
    size_raw = body.get("decision_size_usd", None)
    if size_raw is None:
        size_raw = body.get(size_key, None)

    try:
        size = int(size_raw) if size_raw is not None else 0
    except Exception:
        size = 0

    return {"decision_type": dt, "decision_owner": owner, "decision_size_usd": size}

def _normalize_body(body: Dict[str, Any]) -> Dict[str, Any]:
    dt = str(body.get("decision_type", "")).strip()
    owner = str(body.get("decision_owner", "")).strip()
    try:
        size = int(body.get("decision_size_usd", 0))
    except Exception:
        size = 0
    return {"decision_type": dt, "decision_owner": owner, "decision_size_usd": size}
# ============================================================
# Policy (thresholds)
#   A+ rule: prefer pack.policy, else fallback to policy_config.json
# ============================================================
def _get_policy_cfg(pack: Dict[str, Any]) -> Dict[str, Any]:
    p = _pack_get_section(pack, "policy")
    if p:
        return p
    return _load_json_dict_cached(POLICY_CONFIG_PATH) or {}

def run_policy(body_norm: Dict[str, Any], pack: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _get_policy_cfg(pack) or {}

    reject_threshold = int(cfg.get("reject_threshold_usd", 10_000_000))
    constrain_threshold = int(cfg.get("constrain_threshold_usd", 1_000_000))

    constrain_text = str(cfg.get("constrain_constraints", "Require escalation to risk committee / break-glass approval."))
    constrain_reason = str(cfg.get("constrain_reason", "Constrained: threshold hit."))
    reject_reason = str(cfg.get("reject_reason", "Rejected: threshold hit."))
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
    rule:
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
def build_receipt(body_norm: Dict[str, Any], pack: Dict[str, Any], portable_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    policy = run_policy(body_norm, pack)

    pack_sha = _partner_pack_sha256()

    # legacy hashes for fallback/debug only
    allow_sha = _file_sha256(ALLOWLIST_PATH)
    map_sha = _file_sha256(MAPPING_CONFIG_PATH)
    pol_sha = _file_sha256(POLICY_CONFIG_PATH)

    pack_schema_version = _get_pack_schema_version(pack)
    portable_anchor = _get_portable_anchor(pack)

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

        # portability-prep
        "receipt_schema_version": pack_schema_version or API_VERSION,
        "portable_anchor": {
            "primary_id": str(portable_anchor.get("primary_id", "commitment_id")).strip() or "commitment_id",
            "description": str(portable_anchor.get("description", "portable boundary identity anchor")).strip()
        },

        # A+ self-proof
        "partner_pack_sha256": pack_sha,

        # legacy (kept for debugging; OK if empty)
        "allowlist_sha256": allow_sha,
        "mapping_config_sha256": map_sha,
        "policy_config_sha256": pol_sha,
    }

    if portable_meta:
        boundary_snapshot["portable_metadata"] = portable_meta

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
            "portable_metadata": receipt.get("boundary_snapshot", {}).get("portable_metadata", {}),
            "kid": receipt.get("kid", ""),
            "sig_alg": receipt.get("sig_alg", ""),
            "partner_pack_sha256": receipt.get("boundary_snapshot", {}).get("partner_pack_sha256", ""),
        }
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
    except Exception:
        return

# ============================================================
# A+ endpoints
# ============================================================
def _require_admin() -> Optional[Any]:
    # simple admin auth for /reload (server only)
    if not SCP_ADMIN_API_KEY:
        return _error(500, "server_misconfigured", "Missing SCP_ADMIN_API_KEY env var.")
    key = (request.headers.get("X-SCP-ADMIN-KEY", "") or "").strip()
    if key != SCP_ADMIN_API_KEY:
        return _error(401, "unauthorized", "Missing/invalid X-SCP-ADMIN-KEY.")
    return None

def _reload_partner_pack() -> None:
    # clear cache for partner pack + legacy configs
    _clear_cache_for_path(_default_pack_path())
    _clear_cache_for_path(ALLOWLIST_PATH)
    _clear_cache_for_path(MAPPING_CONFIG_PATH)
    _clear_cache_for_path(POLICY_CONFIG_PATH)
    _clear_cache_for_path(PUBLIC_KEYS_JSON_PATH)
    _clear_cache_for_path(ACTIVE_KID_PATH)

# ============================================================
# Routes
# ============================================================
@app.get("/")
def root():
    return jsonify(
        {"env": ENV, "status": "SCP Pilot Gateway running", "version": API_VERSION, "partner_id": PARTNER_ID, "gate_id": GATE_ID}
    )

@app.get("/healthz")
def healthz():
    return jsonify({"env": ENV, "ok": True, "version": API_VERSION, "partner_id": PARTNER_ID, "gate_id": GATE_ID})

@app.get("/meta")
def meta():
    pub_keys = _load_public_keys()
    kid = _load_active_kid()

    public_key_b64_active = (pub_keys.get(kid, "") or "").strip()
    public_key_b64_env = os.getenv("SCP_SIGNING_PUBLIC_KEY_B64", "").strip()

    pack_path = _default_pack_path()
    pack = _load_partner_pack()
    pack_sha = _partner_pack_sha256()

    # If pack includes ids / schema / portability info, show them for debugging
    pack_partner_id = ""
    pack_gate_id = ""
    pack_schema_version = ""
    portable_anchor = {}
    extensible_metadata = {}

    if pack:
        pack_partner_id = str(pack.get("partner_id", "")).strip()
        pack_gate_id = str(pack.get("gate_id", "")).strip()
        pack_schema_version = _get_pack_schema_version(pack)
        portable_anchor = _get_portable_anchor(pack)
        extensible_metadata = _get_extensible_metadata(pack)

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

            "has_private_key": bool(os.getenv("SCP_SIGNING_PRIVATE_KEY_B64", "").strip()),
            "has_public_keys_file": bool(pub_keys),

            # verifier convenience
            "public_key_b64_active": public_key_b64_active,
            "public_key_b64_env": public_key_b64_env,

            # A+ pack self-proof
            "partner_pack_path": str(pathlib.Path(pack_path).as_posix()),
            "partner_pack_loaded": bool(pack),
            "partner_pack_sha256": pack_sha,
            "pack_partner_id": pack_partner_id,
            "pack_gate_id": pack_gate_id,
            "pack_schema_version": pack_schema_version,
            "portable_anchor": portable_anchor,
            "extensible_metadata": extensible_metadata,

            # legacy paths + hashes for debugging (ok if empty)
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

@app.get("/config_digest")
def config_digest():
    """
    Enterprise self-proof: returns only hashes + identifiers (no config plaintext)
    """
    kid = _load_active_kid()
    pack_sha = _partner_pack_sha256()
    pack = _load_partner_pack()
    pack_schema_version = _get_pack_schema_version(pack)
    portable_anchor = _get_portable_anchor(pack)

    return jsonify(
        {
            "env": ENV,
            "version": API_VERSION,
            "partner_id": PARTNER_ID,
            "gate_id": GATE_ID,
            "policy_pack_id": POLICY_PACK_ID,
            "kid": kid,
            "sig_alg": "ed25519",
            "partner_pack_sha256": pack_sha,
            "pack_schema_version": pack_schema_version,
            "portable_anchor": portable_anchor,
        }
    )

@app.post("/reload")
def reload_config():
    err = _require_admin()
    if err is not None:
        return err
    _reload_partner_pack()
    return jsonify(
        {
            "ok": True,
            "reloaded": True,
            "partner_id": PARTNER_ID,
            "gate_id": GATE_ID,
            "partner_pack_sha256": _partner_pack_sha256(),
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
    raw_body = request.get_json(silent=True) or {}

    # 5) A+ load pack (single-file config)
    pack = _load_partner_pack()

    # 6) normalize partner payload -> canonical
    body = normalize_payload(raw_body, pack)
    portable_meta = _extract_portable_metadata(raw_body, pack)

    # 7) required fields exist
    missing = [f for f in REQUIRED_FIELDS if f not in body]
    if missing:
        return _error(400, "bad_request", f"Missing field: {missing[0]}")

    body_norm = _normalize_body(body)

    # 8) strict validation
    if not body_norm["decision_type"] or not body_norm["decision_owner"]:
        return _error(400, "bad_request", "decision_type and decision_owner must be non-empty strings.")
    if body_norm["decision_size_usd"] <= 0:
        return _error(400, "bad_request", "decision_size_usd must be a positive integer.")

    # 9) enforce key-scoped authority model
    ok_scope, reason = _enforce_key_scope(api_key, body_norm, pack)
    if not ok_scope:
        return _error(403, "forbidden", reason)

    # 10) build receipt (must have server private key)
    try:
        receipt = build_receipt(body_norm, pack, portable_meta=portable_meta)
    except Exception as e:
        return _error(500, "server_misconfigured", str(e))

    # 11) append-only evidence log
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