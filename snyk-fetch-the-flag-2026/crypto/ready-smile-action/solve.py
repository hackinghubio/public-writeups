import json
from Crypto.Util.number import long_to_bytes

def iroot(k, n):
    """
    Integer k-th root of n.
    Returns (root, exact)
    """
    low = 0
    high = n
    while low < high:
        mid = (low + high) // 2
        if mid**k < n:
            low = mid + 1
        else:
            high = mid
    return low, low**k == n

with open("data.json", "r") as f:
    data = json.load(f)

payload = data["payload"]

# Extract values (hex to int)
n = int(payload["x"], 16)
e = int(payload["y"], 16)
c = int(payload["z"], 16)

print(f"[+] Parsed values")
print(f"    e = {e}")

# Low exponent attack
print("[*] Attempting integer root attack...")

m, exact = iroot(e, c)

if not exact:
    print("[-] Exact root not found — attack failed")
    exit(1)

# Convert back to bytes
plaintext = long_to_bytes(m)

# Output result
try:
    decoded = plaintext.decode()
    print("[+] Decrypted message:", decoded)
except UnicodeDecodeError:
    print("[+] Raw plaintext bytes:", plaintext)
