# simulate_stream.py - sends synthetic traffic to the local server
import time
import random
import requests

BASE = "http://127.0.0.1:5000"

LABELS = ["safe", "safe", "safe", "suspicious", "malicious"]  # skew towards safe
RPS = 6  # requests per second

def main():
    print("Streaming mixed traffic... Ctrl+C to stop.")
    backoff = 1
    ok_once = False
    while True:
        try:
            if not ok_once:
                r = requests.get(f"{BASE}/api/stats", timeout=3)
                r.raise_for_status()
                print("[OK] Connected to http://127.0.0.1:5000")
                ok_once = True
            for _ in range(RPS):
                label = random.choice(LABELS)
                requests.post(f"{BASE}/api/inject", json={"label": label}, timeout=3)
            time.sleep(1.0)
            backoff = 1
        except KeyboardInterrupt:
            print("Stopped stream")
            break
        except Exception:
            if ok_once:
                print("[WARN] Lost connection, retrying...")
            else:
                print("[INFO] Waiting for server...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 5)

if __name__ == "__main__":
    main()
