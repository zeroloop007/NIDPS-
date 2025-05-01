import requests
import pandas as pd
import time
from collect_log import extract_system_logs, preprocess_logs
from datetime import datetime

API_ENDPOINT = "http://127.0.0.1:5000/analyze-file"
LOG_INTERVAL = 60  # seconds
SYSTEM_LOG_PATH = "system_logs_abnormal.csv"
PREVENTION_LOG = "prevention_alerts.log"


def analyze_log_file(file_path):
    """Send log CSV to API and return result JSON."""
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f, 'text/csv')}
            response = requests.post(API_ENDPOINT, files=files)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def prevention_logic(results):
    """Trigger prevention if first 2 rows are abnormal."""
    if not results or "results" not in results:
        print("[x] No valid results from model.")
        return

    preds = results["results"]
    if len(preds) < 2:
        print("[!] Not enough data for analysis.")
        return

    abnormal_rows = [p for p in preds if p["classification"] == "abnormal"]

    if abnormal_rows:
        print(f"{len(abnormal_rows)} abnormal rows detected! Triggering prevention ")
        with open(PREVENTION_LOG, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] PREVENTION TRIGGERED:\n")
            for row in abnormal_rows:
                f.write(str(row) + "\n")
    else:
        print("[✓] Traffic looks safe, no prevention triggered.")

if __name__ == "__main__":
    print("[*] Checking system logs for potential threats...")
    result = analyze_log_file(SYSTEM_LOG_PATH)
    prevention_logic(result)