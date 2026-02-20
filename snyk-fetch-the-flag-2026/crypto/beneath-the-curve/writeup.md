# Beneath the Curve — Writeup

**Category:** Cryptography  
**Difficulty:** Hard  
**Author:** @nicl4ssic  
**Tags:** #elliptic #curve #crypto

## Challenge description

> A custom implementation was found in use within a closed system.  
> Several parameters and outputs were recovered.  
> Assess the security of the implementation.

We are given two files:

- **`data.json`** — curve parameters, a generator point, and several **compressed** public keys
- **`cipher.bin`** — AES-encrypted ciphertext (the flag is inside)

The goal is to break the custom elliptic-curve crypto and recover the flag.

---

## Understanding the setup

The implementation is based on **elliptic curve cryptography (ECC)** over a prime field \(\mathbb{F}_p\):

- Curve equation: \(y^2 = x^3 + ax + b \pmod{p}\)
- Public data: \(p, a, b\), generator \(G\), and several public keys \(Q_1, Q_2, \ldots\)

Each public key is stored in **compressed form**: only the \(x\)-coordinate and the **parity of \(y\)** (0 or 1). So we must **decompress** each key to get the full point \((x, y)\) before doing any curve operations.

The encryption is likely **ECDH-style**: two parties agree on a shared secret (a point on the curve), and the key for AES is derived from that secret (e.g. from the \(y\)-coordinate). One of the given public keys corresponds to the party that encrypted the flag; if we recover that party’s **private key** \(d\) (such that \(Q = dG\)), we can recompute the same shared secret and thus the AES key, then decrypt `cipher.bin`.

So the attack plan is:

1. Parse curve parameters and generator from `data.json`.
2. Decompress each public key to a full point \(Q\).
3. For each \(Q\), solve the **elliptic curve discrete logarithm**: find \(d\) such that \(Q = dG\).
4. From \(d\) (and \(Q\)), derive the AES key (same way the “custom implementation” does).
5. Decrypt `cipher.bin` and look for `flag{...}`.

The **vulnerability** is that the curve is **extremely small**: \(p = 9739\). By Hasse’s theorem, the curve order is close to \(p\), so the discrete log can be solved by **brute force** (trying \(d = 1, 2, 3, \ldots\) until \(dG = Q\)).

---

## Step 1: Load data and curve parameters

From `data.json` we get:

- **Curve:** \(p = 9739\), \(a = 497\), \(b = 1768\)
- **Generator:** \(G = (1804, 5368)\)
- **Public keys (compressed):** five entries, each with `"x"` and `"y_parity"` (0 or 1)

The solve script loads these and the ciphertext:

```python
with open("data.json", "r") as f:
    data = json.load(f)
with open("cipher.bin", "rb") as f:
    ciphertext = f.read()

p = data["curve"]["p"]
a = data["curve"]["a"]
b = data["curve"]["b"]
G = (data["generator"]["x"], data["generator"]["y"])
public_keys = data["public_keys"]
```

*(When running the solver, ensure `data.json` and `cipher.bin` are in the same directory as `solve.py`, or adjust paths; the challenge folder has them under `challenge/`.)*

---

## Step 2: Elliptic curve arithmetic

We need:

- **Modular inverse** (for slope in point addition):  
  `inv_mod(k, p) = k^(-1) mod p` → implemented as `pow(k, -1, p)`.
- **Point addition** \(P + Q\) (and doubling \(P + P\)) using the usual chord-and-tangent formulas in \(\mathbb{F}_p\).
- **Scalar multiplication** \(k \cdot P\) (e.g. for \(dG\)) via double-and-add.

The solve implements these in `ec_add` and `ec_mul`. No existing crypto library is required for the curve math; it keeps the writeup self-contained.

---

## Step 3: Point decompression

A compressed point is \((x, y\_parity)\). On the curve we have \(y^2 = x^3 + ax + b \pmod{p}\). So:

1. Compute \(r = x^3 + ax + b \pmod{p}\).
2. Find \(y\) such that \(y^2 \equiv r \pmod{p}\).

Because **\(p \equiv 3 \pmod{4}\)**, a square root of \(r\) is given by:

\[
y = r^{(p+1)/4} \bmod p.
\]

There are two square roots, \(\pm y\). We pick the one whose parity (0 or 1 for \(y \bmod 2\)) matches `y_parity`:

```python
def decompress_point(x, y_parity):
    rhs = (x**3 + a*x + b) % p
    y = pow(rhs, (p + 1) // 4, p)
    if y % 2 != y_parity:
        y = (-y) % p
    return (x, y)
```

So we recover the full point \(Q = (x, y)\) for each compressed public key.

---

## Step 4: Solving the discrete logarithm

For each decompressed public key \(Q\), we need \(d \in \mathbb{Z}\) such that \(Q = dG\).

Because the curve order is small (on the order of \(p\)), we can brute force:

- Start with \(R = G\) and \(d = 1\).
- While \(R \neq Q\), set \(R \leftarrow R + G\) and \(d \leftarrow d + 1\).
- When \(R = Q\), we have \(d\).

The solve does exactly this (incrementally adding \(G\) in a loop). Alternatively one could use `ec_mul(d, G)` for each \(d\); the incremental approach avoids repeated full scalar muls and is fine for such a small order.

---

## Step 5: Key derivation and decryption

Once we have the correct private key \(d\) and public key \(Q = dG\), we assume the “custom implementation” derives the shared secret from the **\(y\)-coordinate of the shared point**. In the scenario where we are “the other party,” the shared point is exactly \(Q\), so:

- `shared_secret = Q[1]` (the \(y\)-coordinate).
- AES key = `MD5(str(shared_secret).encode()).digest()` (16 bytes for AES-128).

Then we decrypt `cipher.bin` with **AES-ECB** (no IV) and PKCS7 unpad. If the result contains `flag{`, we have the flag.

The script tries every public key until one yields a valid decryption:

```python
shared_secret = Q[1]
aes_key = MD5.new(str(shared_secret).encode()).digest()
cipher = AES.new(aes_key, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(ciphertext), 16)
if b"flag{" in plaintext:
    print(plaintext.decode())
```

---

## Running the solve

1. Put `solve.py` in a folder that has `data.json` and `cipher.bin`.  
   In this repo the challenge files are in `challenge/`. Either run from the challenge directory (`cd challenge` then `python ../solve.py`) after copying `solve.py`, or change the first two `open(...)` paths in `solve.py` to `"challenge/data.json"` and `"challenge/cipher.bin"` and run from the repo root.

2. Install PyCryptodome if needed:
   ```bash
   pip install pycryptodome
   ```

3. Run:
   ```bash
   python solve.py
   ```

Example output:

```
[*] Starting ECC solve...
[*] Trying public key 1/5
[*] Trying public key 2/5
[+] Found private key d = 1820
[+] Flag found!
flag{2feb83a4383775b2b9b375b646355409}
```

---

## Summary

| Step | What we did |
|------|------------------|
| 1 | Loaded curve parameters, generator, compressed public keys, and ciphertext |
| 2 | Implemented EC addition and scalar multiplication over \(\mathbb{F}_p\) |
| 3 | Decompressed each public key using \(y^2 = x^3+ax+b\) and \(p \equiv 3 \pmod{4}\) |
| 4 | Brute-forced the discrete log \(Q = dG\) (feasible because \(p\) is tiny) |
| 5 | Derived AES key from the \(y\)-coordinate of the shared point and decrypted with AES-ECB |

**Takeaway:** The system is insecure because it uses a **custom curve with a very small prime**. In practice, curves must use large primes (e.g. 256+ bits) so that the elliptic curve discrete logarithm problem is computationally hard. “Beneath the curve” refers to this weak, small curve hiding beneath the otherwise standard ECC design.
