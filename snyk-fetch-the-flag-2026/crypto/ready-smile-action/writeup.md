# Ready, Smile, Action — Writeup

**Category:** Cryptography  
**Difficulty:** Medium  
**Tags:** #rsa #crypto

## Challenge Overview

We are given a configuration export (`data.json`) from a “secure service.” The description says the values look unrelated but may hide something valuable, and we need to reconstruct the original message.

## Given Files

- **data.json** — JSON with a `payload` object containing three hex-encoded values: `x`, `y`, and `z`.

Example structure:

```json
{
  "meta": { "v": "2.0", "fmt": "export" },
  "payload": {
    "x": "0xb0412986...",
    "y": "0x3",
    "z": "0x10652cdf..."
  }
}
```

## Recon: What Are x, y, z?

The format suggests RSA-like data:

- **x** — large integer → treat as RSA modulus **n**
- **y** — small integer (`0x3` = 3) → treat as public exponent **e**
- **z** — large integer → treat as ciphertext **c**

So we have: **n**, **e** = 3, and **c**, with the goal of recovering the plaintext **m** where  
`c ≡ m^e (mod n)` (standard RSA encryption).

## Vulnerability: Low Public Exponent (e = 3)

In textbook RSA:

- Plaintext **m** is turned into an integer (e.g. by padding).
- Ciphertext: **c = m^e mod n**.

If **m** is small enough that **m^e < n**, then no modular reduction happens:

- **c = m^e** (as integers, not mod n).

Then we can recover **m** by taking the **e-th root** of **c** over the integers:

- **m = c^(1/e)** (integer e-th root).

So the attack is:

1. Interpret **x, y, z** as **n, e, c**.
2. Check that **e** is small (here **e = 3**).
3. Compute the integer **e-th root** of **c** (e.g. via binary search).
4. If that root is exact, it is **m**; convert **m** back to bytes to get the message/flag.

This is the classic **“small exponent” / “low public exponent”** attack when **m^e < n**.

## Solve Script Walkthrough

### 1. Load data and map to n, e, c

```python
payload = data["payload"]
n = int(payload["x"], 16)
e = int(payload["y"], 16)
c = int(payload["z"], 16)
```

- **n**, **e**, and **c** are parsed from the hex strings in `payload`.

### 2. Integer k-th root

The script uses a binary search to compute the **e-th root** of **c** (here **e = 3**):

```python
def iroot(k, n):
    low, high = 0, n
    while low < high:
        mid = (low + high) // 2
        if mid**k < n:
            low = mid + 1
        else:
            high = mid
    return low, low**k == n
```

- Returns the integer **root** and a boolean **exact** indicating whether **root^k == n**.
- For the attack to work we need **exact == True** (i.e. **c** is a perfect **e**-th power).

### 3. Recover plaintext

```python
m, exact = iroot(e, c)
if not exact:
    print("[-] Exact root not found — attack failed")
    exit(1)
plaintext = long_to_bytes(m)
```

- **m** is the integer plaintext; **long_to_bytes** converts it to the original byte string (the message/flag).

### 4. Output

The script prints the decrypted message (or raw bytes if it’s not valid UTF-8).

## How to Run the Solve

Requirements: Python 3 with `pycryptodome` (for `long_to_bytes`):

```bash
pip install pycryptodome
```

Run from the challenge directory (where `data.json` and `solve.py` are):

```bash
python solve.py
```

Expected type of output:

```text
[+] Parsed values
    e = 3
[*] Attempting integer root attack...
[+] Decrypted message: flag{...}
```

## Summary

| Step | What we do |
|------|------------|
| 1 | Treat `payload.x` → **n**, `payload.y` → **e**, `payload.z` → **c** (RSA parameters and ciphertext). |
| 2 | Use the fact that **e = 3** and **m^e < n**, so **c = m^e** in integers. |
| 3 | Compute **m = c^(1/3)** via integer cube root (e.g. binary search). |
| 4 | Convert **m** to bytes to get the original message and the flag. |

**Flag:** `flag{ebfa978db8859d177a6c4fe16de06778}`
