import json
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad

# =========================
# Load challenge files
# =========================
with open("data.json", "r") as f:
    data = json.load(f)

with open("cipher.bin", "rb") as f:
    ciphertext = f.read()

# =========================
# Curve parameters
# =========================
p = data["curve"]["p"]
a = data["curve"]["a"]
b = data["curve"]["b"]

G = (data["generator"]["x"], data["generator"]["y"])
public_keys = data["public_keys"]

# =========================
# EC math
# =========================
def inv_mod(k, p):
    return pow(k, -1, p)

def ec_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P == Q:
        m = (3 * x1 * x1 + a) * inv_mod(2 * y1, p)
    else:
        m = (y2 - y1) * inv_mod(x2 - x1, p)

    m %= p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def ec_mul(k, P):
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = ec_add(R, Q)
        Q = ec_add(Q, Q)
        k >>= 1
    return R

# =========================
# Point decompression
# =========================
def decompress_point(x, y_parity):
    """
    Given x and parity of y, recover y.
    """
    rhs = (x**3 + a*x + b) % p
    y = pow(rhs, (p + 1) // 4, p)  # since p % 4 == 3
    if y % 2 != y_parity:
        y = (-y) % p
    return (x, y)

# =========================
# Try each public key
# =========================
print("[*] Starting ECC solve...")

for idx, pk in enumerate(public_keys):
    print(f"[*] Trying public key {idx+1}/{len(public_keys)}")

    Q = decompress_point(pk["x"], pk["y_parity"])

    # Solve discrete log: find d such that dG = Q
    R = None
    for d in range(1, p):
        R = ec_add(R, G) if R else G
        if R == Q:
            print(f"[+] Found private key d = {d}")

            # =========================
            # Derive AES key from y-coordinate
            # =========================
            shared_secret = Q[1]
            aes_key = MD5.new(str(shared_secret).encode()).digest()

            # =========================
            # Attempt decryption
            # =========================
            try:
                cipher = AES.new(aes_key, AES.MODE_ECB)
                plaintext = unpad(cipher.decrypt(ciphertext), 16)

                if b"flag{" in plaintext:
                    print("[+] Flag found!")
                    print(plaintext.decode())
                    exit(0)
            except Exception:
                pass

print("[-] Flag not found")
