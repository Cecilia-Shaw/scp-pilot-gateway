import os, json, time, hmac, hashlib, uuid
from flask import Flask, request, jsonify, g

app = Flask(__name__)

# ---------------- Config ----------------
ENV = os.getenv("SCP_ENV", "production")

def _now_ts():
    return int(time.time())

def _json_log(event: dict):
    print(json.dumps(event, ensure_ascii=False))

def _hmac_sha256(secret: str, msg: str) -> str:
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def _canonical_json(obj) -> str:
    # deterministic canonical json
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _commitment_id_from_payload(payload: dict) -> str:
    canonical = _canonical_json(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def _signature_from_commitment(signing_secret: str, commitment_id: str) -> str:
    return _hmac_sha256(signing_secret, commitment_id)

def _get_api_keys() -> set:
    raw = os.getenv("SCP_API_KEYS", "")  # "key1,key2"
    return set(k.strip() for k in raw.split(",") if k.strip())

def _get_signing_secret() -> str:
    return os.getenv("SCP_SIGNING_SECRET", "")

def _extract_api_key() -> str:
    # recommend X-SCP-API-KEY, but keep X-API-KEY compatible
    return (
        request.headers.get("X-SCP-API-KEY", "")
        or request.headers.get("X-API-KEY", "")
        or ""
    )

# ---------------- Middleware: request id + auth ----------------
@app.before_request
def _before():
    rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    g.request_id = rid

    # allow preflight + health
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
    # TODO: replace with your real policy logic
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

@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "env": ENV})

@app.post("/evaluate")
def evaluate():
    rid = g.request_id
    ts = _now_ts()

    body = request.get_json(silent=True) or {}
    decision_type = body.get("decision_type")
    decision_owner = body.get("decision_owner")
    decision_size_usd = body.get("decision_size_usd")

    result = run_policy(body)

    signing_secret = _get_signing_secret()
    if not signing_secret:
        return jsonify({"error": "SCP_SIGNING_SECRET not configured", "request_id": rid}), 500

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

    commitment_id = _commitment_id_from_payload(commitment_payload)[:32]
    signature = _signature_from_commitment(signing_secret, commitment_id)

    resp = {
        "commitment_id": commitment_id,
        "signature": signature,
        "timestamp": ts,      # allowed, but NOT part of commitment
        "request_id": rid,    # allowed, but NOT part of commitment
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