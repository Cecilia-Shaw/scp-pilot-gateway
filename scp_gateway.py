import os, json, time, hmac, hashlib, uuid
from flask import Flask, request, jsonify, g

app = Flask(__name__)

# ---------------- Config ----------------
def _get_api_keys():
    """
    Reads from env: SCP_API_KEYS="key1,key2"
    Returns a set of keys.
    """
    raw = os.getenv("SCP_API_KEYS", "")  # "key1,key2"
    return set([k.strip() for k in raw.split(",") if k.strip()])

def _get_signing_secret():
    return os.getenv("SCP_SIGNING_SECRET", "")

ENV = os.getenv("SCP_ENV", "production")

def _now_ts():
    return int(time.time())

def _json_log(event: dict):
    print(json.dumps(event, ensure_ascii=False))

def _hmac_sha256(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def _stable_hash(obj) -> str:
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# ---------------- Middleware: request id + auth ----------------
@app.before_request
def _before():
    rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    g.request_id = rid

    # health endpoint does not require auth
    if request.path == "/":
        return None

    # IMPORTANT: load keys dynamically (avoid "stuck" config)
    api_keys = _get_api_keys()
    if not api_keys:
        return jsonify({"error": "SCP_API_KEYS not configured", "request_id": rid}), 500

    # Accept either header name to reduce mistakes
    key = request.headers.get("X-SCP-API-KEY", "") or request.headers.get("X-API-Key", "")
    if key not in api_keys:
        return jsonify({"error": "unauthorized", "request_id": rid}), 401

@app.after_request
def _after(resp):
    resp.headers["X-Request-Id"] = getattr(g, "request_id", "")
    resp.headers["X-SCP-Env"] = ENV
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
    # -------------------------------------------------
    # 下面只是占位，防止你没贴逻辑时程序报错
    return {
        "verdict": "ALLOW",
        "constraints": "",
        "policy_pack": "pilot_pack_v1",
        "policy_reason": "Within policy."
    }

# ---------------- Routes ----------------
@app.get("/")
def health():
    return jsonify({"status": "SCP Gateway Running", "env": ENV})

@app.post("/evaluate")
def evaluate():
    rid = g.request_id
    ts = _now_ts()

    body = request.get_json(silent=True) or {}
    decision_type = body.get("decision_type")
    decision_owner = body.get("decision_owner")
    decision_size_usd = body.get("decision_size_usd")

    result = run_policy(body)

    payload = {
        "request_id": rid,
        "timestamp": ts,
        "input": {
            "decision_type": decision_type,
            "decision_owner": decision_owner,
            "decision_size_usd": decision_size_usd,
        },
        "output": result,
    }

    commitment_id = _stable_hash(payload)[:32]

    signing_secret = _get_signing_secret()
    if not signing_secret:
        return jsonify({"error": "SCP_SIGNING_SECRET not configured", "request_id": rid}), 500

    signature = _hmac_sha256(signing_secret, commitment_id)

    resp = {
        "commitment_id": commitment_id,
        "signature": signature,
        "timestamp": ts,
        "request_id": rid,
        "boundary_snapshot": result,
    }

    _json_log({
        "event": "scp.evaluate",
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