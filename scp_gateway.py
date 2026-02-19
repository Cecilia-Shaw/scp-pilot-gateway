from flask import Flask, request, jsonify
import hashlib, json, time

app = Flask(__name__)

def evaluate_policy(decision_obj: dict) -> dict:
    size = float(decision_obj.get("decision_size_usd", 0))
    authority = decision_obj.get("decision_owner", "UNKNOWN")
    decision_type = decision_obj.get("decision_type", "unknown")

    # Rule 1: size threshold -> constrain
    if size >= 1_000_000:
        return {
            "status": "constrain",
            "reason": "Size exceeds threshold; escalation required.",
            "constraints": {"requires_escalation_to": "RISK_COMMITTEE"}
        }

    # Rule 2: authority cannot approve liquidation -> reject
    if decision_type == "liquidation" and authority == "TRADING_TEAM":
        return {
            "status": "reject-by-policy",
            "reason": "Trading team cannot authorize liquidation decisions.",
            "constraints": {}
        }

    # Rule 3: default allow
    return {
        "status": "allow",
        "reason": "Within policy envelope.",
        "constraints": {}
    }

def make_commitment_id(decision_obj: dict) -> str:
    payload = {
        "decision_obj": decision_obj,
        "ts_bucket": int(time.time()) // 10
    }
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

@app.route("/scp_gateway/evaluate", methods=["POST"])
@app.route("/evaluate", methods=["POST"])
def evaluate():
    decision_obj = request.get_json(force=True)

    verdict = evaluate_policy(decision_obj)
    commitment_id = make_commitment_id(decision_obj)

    boundary_snapshot = {
        "decision_type": decision_obj.get("decision_type"),
        "authority_object": decision_obj.get("decision_owner"),
        "size_usd": decision_obj.get("decision_size_usd"),
        "policy_reason": verdict["reason"],
        "constraints": verdict.get("constraints", {}),
        "schema_version": "scp.schema.v1",
        "policy_pack": "pilot_pack_v1"
    }

    return jsonify({
        "status": verdict["status"],
        "commitment_id": commitment_id,
        "boundary_snapshot": boundary_snapshot
    })

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", "5055"))
    app.run(host="0.0.0.0", port=port, debug=False)