import os
import time
import hmac
import hashlib
import json
import pathlib
from typing import Dict, Any, Tuple, Optional

from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# ============================================================
# Config (env)
# ============================================================
ENV = os.getenv("SCP_ENV", "production")
API_VERSION = os.getenv("SCP_API_VERSION", "0.3.1")

SCP_API_KEYS_RAW = os.getenv("SCP_API_KEYS", "")
SCP_API_KEYS = {k.strip() for k in SCP_API_KEYS_RAW.split(",") if k.strip()}

SCP_SIGNING_SECRET = os.getenv("SCP_SIGNING_SECRET", "").strip()  # required: 64 hex chars
RATE_LIMIT_PER_MIN = int(os.getenv("SCP_RATE_LIMIT_PER_MIN", "60"))  # per api key

# NEW: policy pack id (human-readable, shows up in receipt)
POLICY_PACK_ID = os.getenv("SCP_POLICY_PACK_ID", "pilot_pack_v1")

# NEW: repo config files
ALLOWLIST_PATH = os.getenv("SCP_ALLOWLIST_PATH", "allowlist.json")
POLICY_CONFIG_PATH = os.getenv("SCP_POLICY_CONFIG_PATH", "policy_config.json")

# NEW: append-only audit log (server-side optional)
COMMITMENT_LOG_PATH = os.getenv("SCP_COMMITMENT_LOG_PATH", "commitment_log.jsonl")
ENABLE_COMMITMENT_LOG = os.getenv("SCP_ENABLE_COMMITMENT_LOG", "1").strip() == "1"

# ============================================================
# Simple in-memory rate limit
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
# Deterministic canonicalization + signing
# ============================================================
def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _is_hex_64(s: str) -> bool:
    if len(s) != 64:
        return False
    try:
        bytes.fromhex(s)
        return True
    except Exception:
        return False


def _hmac_sha256_hex(secret_hex: str, message: str) -> str:
    secret_bytes = bytes.fromhex(secret_hex)
    return hmac.new(secret_bytes, message.encode("utf-8"), hashlib.sha256).hexdigest()


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
# Auth + API key extraction
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
# NEW: Allowlist role/authority model (key-scoped)
# ============================================================
_allowlist_cache: Dict[str, Any] = {}
_allowlist_mtime: float = 0.0


def _load_json_file_cached(path_str: str, cache: Dict[str, Any], mtime_holder_name: str) -> Tuple[Dict[str, Any], float]:
    """
    Generic loader: reads a JSON dict file with mtime cache.
    Returns (data_dict, mtime).
    """
    path = pathlib.Path(path_str)
    if not path.exists():
        return {}, 0.0

    try:
        mtime = path.stat().st_mtime
    except Exception:
        return {}, 0.0

    # use global mtime variable by name
    current_mtime = globals().get(mtime_holder_name, 0.0)
    if cache and mtime == current_mtime:
        return cache, mtime

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}, 0.0

    if not isinstance(data, dict):
        return {}, 0.0

    return data, mtime


def _load_allowlist() -> Dict[str, Any]:
    global _allowlist_cache, _allowlist_mtime
    data, mtime = _load_json_file_cached(ALLOWLIST_PATH, _allowlist_cache, "_allowlist_mtime")
    if data:
        _allowlist_cache = data
        _allowlist_mtime = mtime
    return _allowlist_cache


def _enforce_key_scope(api_key: str, body_norm: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Enforce:
      api_key -> allowed_owners
      api_key -> allowed_decision_types (optional)
    """
    allowlist = _load_allowlist()
    if not allowlist:
        return False, "allowlist not loaded (missing/invalid allowlist.json)"

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


def _file_sha256(path_str: str) -> str:
    p = pathlib.Path(path_str)
    if not p.exists():
        return ""
    try:
        b = p.read_bytes()
        return hashlib.sha256(b).hexdigest()
    except Exception:
        return ""


# ============================================================
# NEW: Policy config (thresholds not in code)
# ============================================================
_policy_cache: Dict[str, Any] = {}
_policy_mtime: float = 0.0


def _load_policy_config() -> Dict[str, Any]:
    global _policy_cache, _policy_mtime
    data, mtime = _load_json_file_cached(POLICY_CONFIG_PATH, _policy_cache, "_policy_mtime")
    if data:
        _policy_cache = data
        _policy_mtime = mtime
    return _policy_cache


# ============================================================
# Mapping (partner -> canonical)
# ============================================================
REQUIRED_FIELDS = ["decision_type", "decision_owner", "decision_size_usd"]


def normalize_payload(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts either:
      A) canonical SCP fields: decision_type / decision_owner / decision_size_usd
      B) partner fields (example): action / severity / requested_by / limit_usd / scope ...
    Returns canonical SCP fields only (for determinism + policy evaluation).
    """
    if not isinstance(body, dict):
        return {}

    # --- decision_type ---
    dt = body.get("decision_type")
    if not dt:
        action = str(body.get("action", "")).strip()
        # default mapping: any partner action => break_glass
        dt = "break_glass" if action else ""

    # --- decision_owner ---
    owner = body.get("decision_owner")
    if not owner:
        owner = str(body.get("requested_by", "")).strip() or str(body.get("owner", "")).strip()

    # --- decision_size_usd ---
    size_raw = body.get("decision_size_usd")
    if size_raw is None:
        size_raw = body.get("limit_usd", 0)

    try:
        size = int(size_raw)
    except Exception:
        size = 0

    return {
        "decision_type": str(dt).strip(),
        "decision_owner": str(owner).strip(),
        "decision_size_usd": size,
    }


def _normalize_body(body: Dict[str, Any]) -> Dict[str, Any]:
    dt = str(body.get("decision_type", "")).strip()
    owner = str(body.get("decision_owner", "")).strip()
    try:
        size = int(body.get("decision_size_usd", 0))
    except Exception:
        size = 0
    return {
        "decision_type": dt,
        "decision_owner": owner,
        "decision_size_usd": size,
    }


# ============================================================
# Policy (pilot_pack_v1) - thresholds from policy_config.json
# ============================================================
def run_policy(body_norm: Dict[str, Any]) -> Dict[str, Any]:
    size = int(body_norm.get("decision_size_usd", 0))

    cfg = _load_policy_config() or {}
    reject_threshold = int(cfg.get("reject_threshold_usd", 10_000_000))
    constrain_threshold = int(cfg.get("constrain_threshold_usd", 1_000_000))

    constrain_text = str(cfg.get("constrain_constraints", "Require escalation to risk committee / break-glass approval."))
    constrain_reason = str(cfg.get("constrain_reason", "Constrained: size >= 1M threshold."))
    reject_reason = str(cfg.get("reject_reason", "Rejected: size >= 10M threshold."))
    allow_reason = str(cfg.get("allow_reason", "Within policy."))

    if size >= reject_threshold:
        return {
            "verdict": "REJECT",
            "constraints": "",
            "policy_pack": POLICY_PACK_ID,
            "policy_reason": reject_reason,
        }

    if size >= constrain_threshold:
        return {
            "verdict": "CONSTRAIN",
            "constraints": constrain_text,
            "policy_pack": POLICY_PACK_ID,
            "policy_reason": constrain_reason,
        }

    return {
        "verdict": "ALLOW",
        "constraints": "",
        "policy_pack": POLICY_PACK_ID,
        "policy_reason": allow_reason,
    }


# ============================================================
# Receipt (deterministic)
# ============================================================
def build_receipt(body_norm: Dict[str, Any]) -> Dict[str, Any]:
    policy = run_policy(body_norm)

    # IMPORTANT: what is signed must be deterministic (no runtime timestamps)
    boundary_snapshot = {
        "decision": body_norm,
        "verdict": policy["verdict"],
        "policy_pack": policy["policy_pack"],
        "policy_reason": policy["policy_reason"],
        "constraints": policy["constraints"],
        "api_version": API_VERSION,
        "env": ENV,
        # NEW: include config hashes (still deterministic, and helps partner see what config was used)
        "allowlist_sha256": _file_sha256(ALLOWLIST_PATH),
        "policy_config_sha256": _file_sha256(POLICY_CONFIG_PATH),
    }

    canonical = _canonical_json(boundary_snapshot)
    commitment_id = _sha256_hex(canonical)
    signature = _hmac_sha256_hex(SCP_SIGNING_SECRET, commitment_id)

    return {
        "commitment_id": commitment_id,
        "signature": signature,
        "boundary_snapshot": boundary_snapshot,
    }


# ============================================================
# NEW: Append-only audit log (server-side evidence)
# ============================================================
def _append_commitment_log(receipt: Dict[str, Any]) -> None:
    if not ENABLE_COMMITMENT_LOG:
        return
    try:
        p = pathlib.Path(COMMITMENT_LOG_PATH)
        line = {
            "ts_epoch": int(time.time()),
            "commitment_id": receipt.get("commitment_id", ""),
            "verdict": receipt.get("boundary_snapshot", {}).get("verdict", ""),
            "decision": receipt.get("boundary_snapshot", {}).get("decision", {}),
            "policy_pack": receipt.get("boundary_snapshot", {}).get("policy_pack", ""),
        }
        p.write_text("", encoding="utf-8") if (not p.exists()) else None
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
    except Exception:
        # logging failure should not break evaluate
        return


# ============================================================
# Routes
# ============================================================
@app.get("/")
def root():
    return jsonify({"env": ENV, "status": "SCP Pilot Gateway running", "version": API_VERSION})


@app.get("/healthz")
def healthz():
    return jsonify({"env": ENV, "ok": True, "version": API_VERSION})


# NEW: meta endpoint for debugging / partner integration
@app.get("/meta")
def meta():
    return jsonify(
        {
            "env": ENV,
            "version": API_VERSION,
            "policy_pack_id": POLICY_PACK_ID,
            "allowlist_path": ALLOWLIST_PATH,
            "policy_config_path": POLICY_CONFIG_PATH,
            "allowlist_sha256": _file_sha256(ALLOWLIST_PATH),
            "policy_config_sha256": _file_sha256(POLICY_CONFIG_PATH),
            "rate_limit_per_min": RATE_LIMIT_PER_MIN,
            "has_signing_secret": bool(SCP_SIGNING_SECRET),
        }
    )


@app.post("/evaluate")
def evaluate():
    # 0) server config validation
    if not SCP_SIGNING_SECRET:
        return _error(500, "server_misconfigured", "Missing SCP_SIGNING_SECRET env var.")
    if not _is_hex_64(SCP_SIGNING_SECRET):
        return _error(500, "server_misconfigured", "SCP_SIGNING_SECRET must be 64 hex chars (32 bytes).")

    # 1) auth
    ok, api_key = _auth_ok()
    if not ok:
        return _error(
            401,
            "unauthorized",
            "Send header X-SCP-API-KEY (or X-API-KEY) with a valid key in SCP_API_KEYS.",
        )

    # 2) rate limit
    if not _rate_limit_ok(api_key):
        return _error(429, "rate_limited", f"Too many requests. Limit={RATE_LIMIT_PER_MIN}/min per key.")

    # 3) json
    if not request.is_json:
        return _error(400, "bad_request", "Content-Type must be application/json")

    # 4) parse
    body = request.get_json(silent=True) or {}

    # 5) NEW: normalize partner payload -> canonical fields
    body = normalize_payload(body)

    # 6) required fields (after normalize)
    missing = [f for f in REQUIRED_FIELDS if f not in body]
    if missing:
        return _error(400, "bad_request", f"Missing field: {missing[0]}")

    body_norm = _normalize_body(body)

    # 7) strict validation
    if not body_norm["decision_type"] or not body_norm["decision_owner"]:
        return _error(400, "bad_request", "decision_type and decision_owner must be non-empty strings.")
    if body_norm["decision_size_usd"] <= 0:
        return _error(400, "bad_request", "decision_size_usd must be a positive integer.")

    # 8) NEW: enforce key-scoped authority model (role model)
    ok_scope, reason = _enforce_key_scope(api_key, body_norm)
    if not ok_scope:
        return _error(403, "forbidden", reason)

    # 9) build receipt
    receipt = build_receipt(body_norm)

    # 10) NEW: append-only audit log (server side)
    _append_commitment_log(receipt)

    resp = jsonify(receipt)
    resp.headers["X-SCP-Env"] = ENV
    resp.headers["X-SCP-Version"] = API_VERSION
    resp.headers["X-SCP-Policy-Pack"] = POLICY_PACK_ID
    return resp