import subprocess

ROUTER_IP = "192.168.1.1"
FALLBACK_INTERFACE = "eth0"
DEV_MARKER = "dev"

def active_interface(target_ip):
    try:
        output = subprocess.check_output(["ip", "route", "get", target_ip], text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return FALLBACK_INTERFACE
    words = output.split()
    index = 0
    while index < len(words):
        if words[index] == DEV_MARKER and index + 1 < len(words):
            return words[index + 1]
        index = index + 1
    return FALLBACK_INTERFACE

if __name__ == "__main__":
    print(active_interface(ROUTER_IP))