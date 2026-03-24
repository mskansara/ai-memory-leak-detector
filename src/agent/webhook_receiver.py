from flask import Flask, request, jsonify
import os
import sys


src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(src_path)

from analysis.ai_diagnosis import diagnosis_leak


app = Flask(__name__)


@app.route("/webhook", methods=["POST"])
def alert_webhook():
    data = request.get_json()

    for alert in data.get("alerts", []):
        if alert["status"] == "firing":
            labels = alert["labels"]
            leak_info = {
                "pid": labels.get("pid"),
                "process_name": labels.get("process_name"),
                "symbol_path": labels.get("symbol_path"),
                "confidence": 0.95,
                "velocity": float(alert["annotations"].get("value", 0)),
            }

            print(
                f"ALERT RECEIVED: Memory leak in {leak_info['process_name']} (PID: {leak_info['pid']})"
            )

            print("AI Agent is analyzing source code...")
            report = diagnosis_leak(leak_info)

            if report:
                print(f"AI Diagnosis complete! Report saved for PID {leak_info['pid']}")
            else:
                print("AI Diagnosis failed.")

    return jsonify({"status": "received"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
