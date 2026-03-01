import os, json, time, hmac, hashlib, uuid
from collections import defaultdict, deque
from flask import Flask, request, jsonify, g

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64KB

# ---------------- Versions ----------------
GATEWAY_VERSION = os.getenv("SCP_GATEWAY_VERSION", "v0.3")
SCHEMA_VERSION = os.getenv("SCP_SCHEMA_VERSION", "scp.receipt.v1")
ENV = os.getenv("SCP_ENV", "production")

# ---------------- Keys / Secrets ----------------
def _get_api_keys() -> set:
    raw = os.getenv("SCP_API_KEYS", "")  # "key1,key2"
    return set(k.strip() for k in raw.split(",") if k.strip())

def _get_signing_secret() -> str:
    return os.getenv("SCP_SIGNING_SECRET", "")

def _extract_api_key() -> str:
    # recommended: X-SCP-API-KEY
    # compatibility: X-API-KEY
    return (
        request.headers.get("X-SCP-API-KEY", "")
        or request.headers.get("X-API-KEY", "")
        or ""
    )

# ---------------- Utils ----------------
def _now_ts() -> int:
    return int(time.time())

def _json_dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _hmac_sha256(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def _log(event: dict):
    print(_json_dumps(event))

# ---------------- Pilot-grade rate limit (in-memory) ----------------
# default 60 req/min per key
RATE_LIMIT_PER_MIN = int(os.getenv("SCP_RATE_LIMIT_PER_MIN", "60"))
_buckets = defaultdict(deque)  # api_key -> timestamps

def _rate_limit_ok(api_key: str) -> bool:
    if RATE_LIMIT_PER_MIN <= 0:
        return True
    now = time.time()
    q = _buckets[api_key]
    while q and (now - q[0]) > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MIN:
        return False
    q.append(now)
    return True

# ---------------- Errors (uniform) ----------------
def _err(status_code: int, code: str, message: str):
    ts = _now_ts()
    rid = getattr(g, "request_id", str(uuid.uuid4()))
    body = {
        "error": code,
        "message": message,
        "request_id": rid,
        "timestamp": ts,
        "schema_version": SCHEMA_VERSION,
        "gateway_version": GATEWAY_VERSION,
    }
    return jsonify(body), status_code

# ---------------- Middleware ----------------
@app.before_request
def _before():
    rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    g.request_id = rid
    g.start = time.time()

    # allow health
    if request.path in ("/", "/healthz"):
        return None

    # allow preflight
    if request.method == "OPTIONS":
        return None

    # strict JSON for POST-like
    if request.method in ("POST", "PUT", "PATCH"):
        ctype = request.headers.get("Content-Type", "")
        if "application/json" not in ctype:
            return _err(415, "unsupported_media_type", "Content-Type must be application/json")

    api_keys = _get_api_keys()
    if not api_keys:
        return _err(500, "server_misconfig", "SCP_API_KEYS not configured")

    key = _extract_api_key()
    if not key:
        return _err(401, "unauthorized", "missing API key")
    if key not in api_keys:
        return _err(401, "unauthorized", "invalid API key")

    if not _rate_limit_ok(key):
        return _err(429, "rate_limited", "too many requests")

@app.after_request
def _after(resp):
    resp.headers["X-Request-Id"] = getattr(g, "request_id", "")
    resp.headers["X-SCP-Env"] = ENV
    resp.headers["X-SCP-Gateway-Version"] = GATEWAY_VERSION
    return resp

# ---------------- Policy (your logic goes here) ----------------
def run_policy(body: dict) -> dict:
    """
    Return:
      {
        "verdict": "ALLOW" | "CONSTRAIN" | "REJECT",
        "constraints": {},             # {} if none
        "policy_pack": "pilot_pack_v1",
        "policy_reason": "..."
      }
    """
    # TODO: paste your real policy logic here
    return {
        "verdict": "ALLOW",
        "constraints": {},
        "policy_pack": "pilot_pack_v1",
        "policy_reason": "Within policy."
    }

# ---------------- Deterministic commitment (STRICT) ----------------
def canonical_decision_boundary(body: dict) -> dict:
    # Only boundary-defining fields; do NOT include request_id / timestamp
    return {
        "decision_type": body.get("decision_type"),
        "decision_owner": body.get("decision_owner"),
        "decision_size_usd": body.get("decision_size_usd"),
        "policy_context": body.get("policy_context"),
    }

def make_commitment_id(boundary: dict, snapshot: dict) -> str:
    # Deterministic: depends only on canonical boundary + policy outcome + schema version
    material = {
        "schema_version": SCHEMA_VERSION,
        "boundary": boundary,
        "verdict": snapshot.get("verdict"),
        "policy_pack": snapshot.get("policy_pack"),
        "constraints": snapshot.get("constraints", {}),
    }
    return _sha256_hex(_json_dumps(material))[:32]

# ---------------- Routes ----------------
@app.get("/")
def root():
    return jsonify({"status": "SCP Gateway Running", "env": ENV, "version": GATEWAY_VERSION})

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "env": ENV, "version": GATEWAY_VERSION})

@app.post("/evaluate")
@app.post("/v1/evaluate")
def evaluate():
    rid = g.request_id
    ts = _now_ts()

    body = request.get_json(silent=True)
    if body is None:
        return _err(400, "bad_request", "invalid JSON body")

    signing_secret = _get_signing_secret()
    if not signing_secret:
        return _err(500, "server_misconfig", "SCP_SIGNING_SECRET not configured")

    snapshot = run_policy(body)
    boundary = canonical_decision_boundary(body)

    commitment_id = make_commitment_id(boundary, snapshot)
    signature = _hmac_sha256(signing_secret, commitment_id)

    resp = {
        "schema_version": SCHEMA_VERSION,
        "gateway_version": GATEWAY_VERSION,
        "request_id": rid,
        "timestamp": ts,
        "commitment_id": commitment_id,
        "signature": signature,
        "boundary_snapshot": snapshot,
        # If you want less disclosure, delete the next line:
        "boundary": boundary,
    }

    latency_ms = int((time.time() - g.start) * 1000)
    _log({
        "event": "scp.evaluate",
        "request_id": rid,
        "timestamp": ts,
        "latency_ms": latency_ms,
        "commitment_id": commitment_id,
        "verdict": snapshot.get("verdict"),
        "policy_pack": snapshot.get("policy_pack"),
    })

    return jsonify(resp), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)