import requests
import json

# 模拟 decision object（现实世界客户系统会构造这个）
decision_object = {
    "decision_proposal": "Delay liquidation for stressed account",
    "decision_owner": "Risk Committee",
    "decision_size_usd": 250000,
    "decision_type": "liquidation"
}

try:
    response = requests.post("http://127.0.0.1:5055/scp_gateway/evaluate", json=decision_object)

    print("=== SCP Response ===")
    print("HTTP status:", response.status_code)
    print("Raw text:", response.text)
    print(json.dumps(response.json(), indent=2))

    # 模拟客户系统写日志
    with open("customer_log.txt", "a") as f:
        f.write(response.text + "\n")

    print("\nCommitment recorded in customer_log.txt")

except Exception as e:
    print("Error calling SCP:", e)