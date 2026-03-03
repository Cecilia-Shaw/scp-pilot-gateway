import os
import time
import hmac
import hashlib
import json
from typing import Dict, Any, Tuple

from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# =========================
# Config (env)
# =========================
ENV = os.getenv("SCP_ENV", "production")
API_VERSION = os.getenv("SCP_API_VERSION", "0.3.1")

SCP_API_KEYS_RAW = os.getenv("SCP_API_KEYS", "")
SCP_API_KEYS = {k.strip() for k in SCP_API_KEYS_RAW.split(",") if k.strip()}

SCP_SIGNING_SECRET = os.getenv("SCP_SIGNING_SECRET", "")  # required
RATE_LIMIT_PER_MIN = int(os.getenv("SCP_RATE_LIMIT_PER_MIN", "60"))  # per api key

# =========================
# Simple in-memory rate limit
# =========================
# key -> (window_start_epoch_minute, count)
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
        action = body.get("action", "")
        # pilot default: treat any partner 'action' as break-glass category
        dt = "break_glass" if action else ""

    # --- decision_owner ---
    owner = body.get("decision_owner")
    if not owner:
        owner = body.get("requested_by", "") or body.get("owner", "")

    # --- decision_size_usd ---
    size_raw = body.get("decision_size_usd")
    if size_raw is None:
        size_raw = body.get("limit_usd", 0)  # partner payload often uses limit_usd
    try:
        size = int(size_raw)
    except Exception:
        size = 0

    return {
        "decision_type": str(dt).strip(),
        "decision_owner": str(owner).strip(),
        "decision_size_usd": size,
    }


# =========================
# Deterministic canonicalization
# =========================
def _canonical_json(obj: Any) -> str:
    # Deterministic JSON string
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _hmac_sha256_hex(secret_hex: str, message: str) -> str:
    # secret expected as hex string (64 hex chars for 32 bytes)
    secret_bytes = bytes.fromhex(secret_hex)
    return hmac.new(secret_bytes, message.encode("utf-8"), hashlib.sha256).hexdigest()


# =========================
# Validation
# =========================
REQUIRED_FIELDS = ["decision_type", "decision_owner", "decision_size_usd"]


def _error(status: int, msg: str, hint: str = ""):
    payload = {"error": msg}
    if hint:
        payload["hint"] = hint
    return make_response(jsonify(payload), status)


def _auth_ok() -> Tuple[bool, str]:
    api_key = request.headers.get("X-SCP-API-KEY", "") or request.headers.get("X-API-KEY", "")
    if not api_key:
        return False, ""
    if SCP_API_KEYS and api_key not in SCP_API_KEYS:
        return False, api_key
    return True, api_key


def _normalize_body(body: Dict[str, Any]) -> Dict[str, Any]:
    # Keep only supported fields for now; anything extra can be added later but must be deterministic
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


# =========================
# Policy (pilot_pack_v1)
# =========================
def run_policy(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns:
      verdict: ALLOW | CONSTRAIN | REJECT
      constraints: "" or human-readable constraint
      policy_pack: pilot_pack_v1
      policy_reason: short reason
    """
    size = int(body.get("decision_size_usd", 0))

    # --- thresholds (可按 pilot partner 调整) ---
    if size >= 10_000_000:
        return {
            "verdict": "REJECT",
            "constraints": "",
            "policy_pack": "pilot_pack_v1",
            "policy_reason": "Rejected: size >= 10M threshold.",
        }

    if size >= 1_000_000:
        return {
            "verdict": "CONSTRAIN",
            "constraints": "Require escalation to risk committee / break-glass approval.",
            "policy_pack": "pilot_pack_v1",
            "policy_reason": "Constrained: size >= 1M threshold.",
        }

    return {
        "verdict": "ALLOW",
        "constraints": "",
        "policy_pack": "pilot_pack_v1",
        "policy_reason": "Within policy.",
    }


# =========================
# Receipt
# =========================
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
    }

    canonical = _canonical_json(boundary_snapshot)
    commitment_id = _sha256_hex(canonical)

    # Signature is HMAC(secret, commitment_id)
    signature = _hmac_sha256_hex(SCP_SIGNING_SECRET, commitment_id)

    receipt = {
        "commitment_id": commitment_id,
        "signature": signature,
        "boundary_snapshot": boundary_snapshot,
    }
    return receipt


# =========================
# Routes
# =========================
@app.get("/")
def root():
    return jsonify({"env": ENV, "status": "SCP Pilot Gateway running", "version": API_VERSION})


@app.get("/healthz")
def healthz():
    return jsonify({"env": ENV, "ok": True, "version": API_VERSION})


@app.post("/evaluate")
def evaluate():
    if not SCP_SIGNING_SECRET:
        return _error(500, "server_misconfigured", "Missing SCP_SIGNING_SECRET env var.")

    ok, api_key = _auth_ok()
    if not ok:
        return _error(
            401,
            "unauthorized",
            "Send header X-SCP-API-KEY (or X-API-KEY) with a valid key in SCP_API_KEYS.",
        )

    if not _rate_limit_ok(api_key):
        return _error(429, "rate_limited", f"Too many requests. Limit={RATE_LIMIT_PER_MIN}/min per key.")

    if not request.is_json:
        return _error(400, "bad_request", "Content-Type must be application/json")

    # 1) parse
    body = request.get_json(silent=True) or {}
    # 2) IMPORTANT: normalize partner payload -> canonical fields
    body = normalize_payload(body)

    # 3) required fields check (after normalize)
    missing = [f for f in REQUIRED_FIELDS if f not in body]
    if missing:
        return _error(400, "bad_request", f"Missing field: {missing[0]}")

    body_norm = _normalize_body(body)

    if not body_norm["decision_type"] or not body_norm["decision_owner"]:
        return _error(400, "bad_request", "decision_type and decision_owner must be non-empty strings.")
    if body_norm["decision_size_usd"] <= 0:
        return _error(400, "bad_request", "decision_size_usd must be a positive integer.")

    receipt = build_receipt(body_norm)

    resp = jsonify(receipt)
    resp.headers["X-SCP-Env"] = ENV
    resp.headers["X-SCP-Version"] = API_VERSION
    return resp