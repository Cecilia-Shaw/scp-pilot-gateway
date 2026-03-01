import os
import json
import time
import hmac
import hashlib
import uuid
from typing import Dict, Tuple

from flask import Flask, request, jsonify, g

app = Flask(__name__)

# ---------------- Version / Env ----------------
API_VERSION = "0.3.1"
ENV = os.getenv("SCP_ENV", "production")

# ---------------- Helpers ----------------
def _now_ts() -> int:
    return int(time.time())

def _now_ms() -> int:
    return int(time.time() * 1000)

def _json_log(event: dict):
    # one-line JSON log for Railway
    print(json.dumps(event, ensure_ascii=False, separators=(",", ":")))

def _canonical_json(obj) -> str:
    # stable canonicalization for deterministic hashing
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _hmac_sha256(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def _get_api_keys() -> set:
    # "key1,key2"
    raw = os.getenv("SCP_API_KEYS", "")
    return set(k.strip() for k in raw.split(",") if k.strip())

def _get_signing_secret() -> str:
    return os.getenv("SCP_SIGNING_SECRET", "")

def _extract_api_key() -> str:
    # recommended: X-SCP-API-KEY
    # compat: X-API-KEY (PowerShell habit)
    return (
        request.headers.get("X-SCP-API-KEY", "")
        or request.headers.get("X-API-KEY", "")
        or ""
    )

def _bad_request(msg: str, rid: str):
    return jsonify({"error": "bad_request", "message": msg, "request_id": rid}), 400

# ---------------- Minimal Rate Limiting (single-instance) ----------------
# Fixed window limiter: per api_key, per window_seconds
# NOTE: This is NOT distributed; good enough for pilot phase.
_RL_STATE: Dict[str, Tuple[int, int]] = {}  # key -> (window_start_ts, count)

def _rate_limit_check(api_key: str, rid: str):
    enabled = os.getenv("SCP_RATE_LIMIT_ENABLED", "1").strip().lower() not in ("0", "false", "no")
    if not enabled:
        return None

    try:
        limit = int(os.getenv("SCP_RATE_LIMIT_PER_MIN", "60"))
    except Exception:
        limit = 60

    window_seconds = 60
    now = _now_ts()

    window_start, count = _RL_STATE.get(api_key, (now, 0))
    if now - window_start >= window_seconds:
        window_start, count = now, 0

    count += 1
    _RL_STATE[api_key] = (window_start, count)

    if count > limit:
        # 429 Too Many Requests
        retry_after = max(1, window_seconds - (now - window_start))
        resp = jsonify({
            "error": "rate_limited",
            "message": f"rate limit exceeded ({limit}/min)",
            "request_id": rid
        })
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    return None

# ---------------- Middleware: request id + auth + timing ----------------
@app.before_request
def _before():
    g.t0_ms = _now_ms()
    rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    g.request_id = rid

    # allow CORS preflight / health
    if request.method == "OPTIONS":
        return None
    if request.path in ("/", "/healthz"):
        return None

    api_keys = _get_api_keys()
    if not api_keys:
        return jsonify({"error": "SCP_API_KEYS not configured", "request_id": rid}), 500

    key = _extract_api_key()
    if key not in api_keys:
        return jsonify({
            "error": "unauthorized",
            "hint": "Send header X-SCP-API-KEY (or X-API-KEY) with a value included in SCP_API_KEYS",
            "request_id": rid
        }), 401

    rl = _rate_limit_check(key, rid)
    if rl is not None:
        return rl

@app.after_request
def _after(resp):
    resp.headers["X-Request-Id"] = getattr(g, "request_id", "")
    resp.headers["X-SCP-Env"] = ENV
    resp.headers["X-SCP-API-Version"] = API_VERSION
    return resp

# ---------------- Core policy evaluation ----------------
def run_policy(body: dict) -> dict:
    """
    Return:
      {
        "verdict": "ALLOW" | "CONSTRAIN" | "REJECT",
        "constraints": "...",          # "" if none
        "policy_pack": "pilot_pack_v1",
        "policy_reason": "..."
      }
    """
    # TODO: paste your existing policy logic here
    return {
        "verdict": "ALLOW",
        "constraints": "",
        "policy_pack": "pilot_pack_v1",
        "policy_reason": "Within policy."
    }

# ---------------- Deterministic Commitment ----------------
def _commitment_payload(decision_type: str, decision_owner: str, decision_size_usd: int, result: dict) -> dict:
    # STRICT DETERMINISM:
    # - NO request_id
    # - NO timestamp
    # - Only canonical decision boundary + verdict snapshot inputs
    return {
        "decision_type": decision_type,
        "decision_owner": decision_owner,
        "decision_size_usd": decision_size_usd,
        "policy_pack": result.get("policy_pack", ""),
        "verdict": result.get("verdict", ""),
        "constraints": result.get("constraints", "") or "",
        "policy_reason": result.get("policy_reason", "") or "",
    }

def _commitment_id_from_payload(payload: dict) -> str:
    # 32-hex short id (still derived from full sha256)
    return _sha256_hex(_canonical_json(payload))[:32]

def _signature_from_commitment(signing_secret: str, commitment_id: str) -> str:
    return _hmac_sha256(signing_secret, commitment_id)

# ---------------- Routes ----------------
@app.get("/")
def health():
    return jsonify({"status": "SCP Gateway Running", "env": ENV, "version": API_VERSION})

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "env": ENV, "version": API_VERSION})

@app.post("/evaluate")
def evaluate():
    rid = g.request_id
    ts = _now_ts()

    body = request.get_json(silent=True) or {}

    # ---- Input validation (hard fail with 400, no crashes) ----
    decision_type = body.get("decision_type")
    decision_owner = body.get("decision_owner")
    decision_size_usd = body.get("decision_size_usd")

    if not isinstance(decision_type, str) or not decision_type.strip():
        return _bad_request("decision_type must be a non-empty string", rid)

    if not isinstance(decision_owner, str) or not decision_owner.strip():
        return _bad_request("decision_owner must be a non-empty string", rid)

    # allow number or numeric string
    try:
        decision_size_usd = int(decision_size_usd)
    except Exception:
        return _bad_request("decision_size_usd must be an integer", rid)

    if decision_size_usd <= 0:
        return _bad_request("decision_size_usd must be > 0", rid)

    # optional sanity cap for pilot (avoid insane payloads)
    cap = int(os.getenv("SCP_SIZE_USD_CAP", "1000000000"))  # default 1B
    if decision_size_usd > cap:
        return _bad_request(f"decision_size_usd too large (cap={cap})", rid)

    # ---- Policy evaluation ----
    result = run_policy(body)

    # ---- Signing secret check ----
    signing_secret = _get_signing_secret()
    if not signing_secret:
        return jsonify({"error": "SCP_SIGNING_SECRET not configured", "request_id": rid}), 500

    # ---- Deterministic commitment + signature ----
    commitment_payload = _commitment_payload(decision_type, decision_owner, decision_size_usd, result)
    commitment_id = _commitment_id_from_payload(commitment_payload)
    signature = _signature_from_commitment(signing_secret, commitment_id)

    latency_ms = max(0, _now_ms() - getattr(g, "t0_ms", _now_ms()))

    resp = {
        "commitment_id": commitment_id,
        "signature": signature,
        "timestamp": ts,      # allowed, but NOT part of commitment
        "request_id": rid,    # allowed, but NOT part of commitment
        "boundary_snapshot": result,
    }

    _json_log({
        "event": "scp.evaluate",
        "version": API_VERSION,
        "env": ENV,
        "request_id": rid,
        "timestamp": ts,
        "latency_ms": latency_ms,
        "commitment_id": commitment_id,
        "decision_type": decision_type,
        "decision_owner": decision_owner,
        "decision_size_usd": decision_size_usd,
        "verdict": result.get("verdict"),
        "policy_pack": result.get("policy_pack"),
    })

    return jsonify(resp)