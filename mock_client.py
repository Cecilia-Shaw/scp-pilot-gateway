import os
import json
import requests

URL = os.getenv("SCP_URL", "https://scp-pilot-gateway-production-42c7.up.railway.app/evaluate")
API_KEY = os.getenv("SCP_API_KEY", "pilot_key_123")

payload = {
    "decision_type": "trade",
    "decision_owner": "risk_team",
    "decision_size_usd": 100000
}

r = requests.post(
    URL,
    headers={"X-SCP-API-KEY": API_KEY, "Content-Type": "application/json"},
    data=json.dumps(payload)
)

print("status:", r.status_code)
print(r.text)