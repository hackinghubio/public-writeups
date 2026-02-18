from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad

# Load ciphertext
with open("cipher.bin", "rb") as f:
    ciphertext = f.read()

# Load wordlist
with open("wordlist.txt", "r", errors="ignore") as f:
    passwords = f.readlines()

for pwd in passwords:
    pwd = pwd.strip()
    if not pwd:
        continue

    try:
        # Derive AES key from password
        key = MD5.new(pwd.encode()).digest()

        # Attempt decryption
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(ciphertext), 16)

        # Check for flag
        if b"flag{" in plaintext:
            print("[+] Password found:", pwd)
            print("[+] Decrypted:", plaintext.decode())
            break

    except (ValueError, UnicodeDecodeError):
        # Wrong key / padding
        continue
