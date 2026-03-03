 import os, json, time, hmac, hashlib, uuid
from flask import Flask, request, jsonify, g

app = Flask(__name__)

# =========================
# v0.3.1 Config
# =========================
API_VERSION = "0.3.1"
ENV = os.getenv("SCP_ENV", "production")

# Security / keys
def _get_api_keys() -> set:
    raw = os.getenv("SCP_API_KEYS", "")  # "key1,key2"
    return set(k.strip() for k in raw.split(",") if k.strip())

def _get_signing_secret() -> str:
    return os.getenv("SCP_SIGNING_SECRET", "")

def _extract_api_key() -> str:
    # 推荐：X-SCP-API-KEY
    # 兼容：X-API-KEY（方便 PowerShell）
    return (
        request.headers.get("X-SCP-API-KEY", "")
        or request.headers.get("X-API-KEY", "")
        or ""
    )

# Rate limit (simple in-memory window)
# 默认：每个 API key 每分钟 60 次（可用 env 改）
RATE_LIMIT_RPM = int(os.getenv("SCP_RATE_LIMIT_RPM", "60"))
_rl_state = {}  # key -> (window_start_ts, count)

# Request size guard (optional)
MAX_BODY_BYTES = int(os.getenv("SCP_MAX_BODY_BYTES", "65536"))  # 64KB default

# =========================
# Utils
# =========================
def _now_ts() -> int:
    return int(time.time())

def _json_log(event: dict):
    print(json.dumps(event, ensure_ascii=False))

def _hmac_sha256(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def _canonical_json(obj) -> str:
    # strict deterministic canonical form
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _commitment_id_from_payload(payload: dict) -> str:
    # deterministic boundary hash (32 hex chars for compact id)
    return _sha256_hex(_canonical_json(payload))[:32]

def _signature_from_commitment(signing_secret: str, commitment_id: str) -> str:
    # HMAC over commitment_id only (offline verifiable)
    return _hmac_sha256(signing_secret, commitment_id)

def _rate_limit_check(api_key: str):
    if RATE_LIMIT_RPM <= 0:
        return None  # disabled

    now = _now_ts()
    window = now // 60
    win_start, cnt = _rl_state.get(api_key, (window, 0))
    if win_start != window:
        win_start, cnt = window, 0

    cnt += 1
    _rl_state[api_key] = (win_start, cnt)

    if cnt > RATE_LIMIT_RPM:
        return jsonify({
            "error": "rate_limited",
            "hint": f"Rate limit exceeded: {RATE_LIMIT_RPM} requests/min per api key",
        }), 429
    return None

def _validate_body(body: dict):
    # strict input validation
    if not isinstance(body, dict):
        return "Body must be a JSON object."

    required = ["decision_type", "decision_owner", "decision_size_usd"]
    for k in required:
        if k not in body:
            return f"Missing field: {k}"

    if not isinstance(body.get("decision_type"), str) or not body["decision_type"].strip():
        return "decision_type must be a non-empty string."
    if not isinstance(body.get("decision_owner"), str) or not body["decision_owner"].strip():
        return "decision_owner must be a non-empty string."

    # allow int/float/string-number, but normalize deterministically later
    v = body.get("decision_size_usd")
    try:
        float(v)
    except Exception:
        return "decision_size_usd must be a number (or numeric string)."

    return None

def _normalize_decision_size(v):
    # deterministic normalization: keep as integer if it is an integer value
    # otherwise keep as float with minimal representation
    f = float(v)
    if f.is_integer():
        return int(f)
    return float(f)

# =========================
# Middleware: request id + auth + rate limit
# =========================
@app.before_request
def _before():
    # request id
    rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    g.request_id = rid

    # allow OPTIONS
    if request.method == "OPTIONS":
        return None

    # size guard
    cl = request.content_length
    if cl is not None and cl > MAX_BODY_BYTES:
        return jsonify({"error": "payload_too_large", "max_bytes": MAX_BODY_BYTES}), 413

    # allow health endpoints without auth
    if request.path in ("/", "/healthz"):
        return None

    api_keys = _get_api_keys()
    if not api_keys:
        return jsonify({"error": "SCP_API_KEYS not configured"}), 500

    key = _extract_api_key()
    if key not in api_keys:
        return jsonify({
            "error": "unauthorized",
            "hint": "Send header X-SCP-API-KEY (or X-API-KEY) with a value included in SCP_API_KEYS",
            "request_id": rid
        }), 401

    # rate limit per api key
    rl = _rate_limit_check(key)
    if rl is not None:
        return rl

@app.after_request
def _after(resp):
    resp.headers["X-Request-Id"] = getattr(g, "request_id", "")
    resp.headers["X-SCP-Env"] = ENV
    resp.headers["X-SCP-Version"] = API_VERSION
    return resp

# =========================
# Core policy evaluation (placeholder)
# =========================
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
   size = int(body.get("decision_size_usd", 0))

if size >= 10_000_000:
    return {
        "verdict": "REJECT",
        "constraints": "",
        "policy_pack": "pilot_pack_v1",
        "policy_reason": "Rejected: size >= 10M threshold."
    }

if size >= 1_000_000:
    return {
        "verdict": "CONSTRAIN",
        "constraints": "Require escalation to risk committee / break-glass approval.",
        "policy_pack": "pilot_pack_v1",
        "policy_reason": "Constrained: size >= 1M threshold."
    }

return {
    "verdict": "ALLOW",
    "constraints": "",
    "policy_pack": "pilot_pack_v1",
    "policy_reason": "Within policy."
}

# =========================
# Routes
# =========================
@app.get("/")
def root():
    return jsonify({"env": ENV, "status": "SCP Gateway Running", "version": API_VERSION})

@app.get("/healthz")
def healthz():
    return jsonify({"env": ENV, "ok": True, "version": API_VERSION})

@app.post("/evaluate")
def evaluate():
    rid = g.request_id
    ts = _now_ts()

    signing_secret = _get_signing_secret()
    if not signing_secret:
        return jsonify({"error": "SCP_SIGNING_SECRET not configured", "request_id": rid}), 500

    body = request.get_json(silent=True) or {}
    err = _validate_body(body)
    if err:
        return jsonify({"error": "invalid_request", "detail": err, "request_id": rid}), 400

    # normalize input deterministically
    decision_type = body.get("decision_type").strip()
    decision_owner = body.get("decision_owner").strip()
    decision_size_usd = _normalize_decision_size(body.get("decision_size_usd"))

    # evaluate boundary policy
    result = run_policy({
        "decision_type": decision_type,
        "decision_owner": decision_owner,
        "decision_size_usd": decision_size_usd,
        # pass through optional context if present
        "policy_context": body.get("policy_context", None),
    })

    # ✅ deterministic commitment payload (NO request_id / NO timestamp)
    commitment_payload = {
        "decision_type": decision_type,
        "decision_owner": decision_owner,
        "decision_size_usd": decision_size_usd,
        "policy_pack": result.get("policy_pack"),
        "verdict": result.get("verdict"),
        "constraints": result.get("constraints", ""),
        "policy_reason": result.get("policy_reason", ""),
    }

    commitment_id = _commitment_id_from_payload(commitment_payload)
    signature = _signature_from_commitment(signing_secret, commitment_id)

    resp = {
        "commitment_id": commitment_id,
        "signature": signature,
        "timestamp": ts,     # allowed, but NOT part of commitment
        "request_id": rid,   # allowed, but NOT part of commitment
        "boundary_snapshot": result,
        "api_version": API_VERSION
    }

    _json_log({
        "event": "scp.evaluate",
        "version": API_VERSION,
        "request_id": rid,
        "timestamp": ts,
        "commitment_id": commitment_id,
        "decision_type": decision_type,
        "decision_owner": decision_owner,
        "decision_size_usd": decision_size_usd,
        "verdict": result.get("verdict"),
        "policy_pack": result.get("policy_pack"),
    })

    return jsonify(resp)

@app.post("/validate")
def validate():
    """
    Optional helper endpoint (server-side verification).
    Still keep offline verification as the primary story.
    """
    rid = g.request_id
    signing_secret = _get_signing_secret()
    if not signing_secret:
        return jsonify({"error": "SCP_SIGNING_SECRET not configured", "request_id": rid}), 500

    body = request.get_json(silent=True) or {}
    commitment_id = (body.get("commitment_id") or "").strip()
    signature = (body.get("signature") or "").strip()

    if not commitment_id or not signature:
        return jsonify({"error": "invalid_request", "detail": "commitment_id and signature are required", "request_id": rid}), 400

    expected = _signature_from_commitment(signing_secret, commitment_id)
    ok = (hmac.compare_digest(expected, signature))

    return jsonify({
        "ok": ok,
        "commitment_id": commitment_id,
        "request_id": rid,
        "api_version": API_VERSION
    })