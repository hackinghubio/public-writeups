# Old Habits — Writeup

**Category:** Cryptography  
**Difficulty:** Easy  
**Author:** @nicl4ssic  
**Tags:** #aes #crypto

## Challenge description

> A secure file was encrypted using a shared secret.  
> The developers used a legacy approach to derive encryption keys.  
> Can you recover the original message?

**Files provided:** `cipher.bin`, `wordlist.txt`

---

## Idea

The wording “shared secret” and “legacy approach to derive encryption keys” suggests:

1. The ciphertext was encrypted with a **password-based** key (the “shared secret”).
2. The key is derived from that password with an **old, weak** method—here, **MD5** used directly as the key-derivation step for AES.

So the attack is: **try each candidate password from the wordlist**, derive an AES key with MD5, decrypt, and see which one yields a plaintext that looks like the flag.

---

## Crypto details

- **Cipher:** AES.
- **Mode:** ECB (symmetric, no IV; same block always encrypts to the same ciphertext block).
- **Key derivation:** `key = MD5(password)`.
  - MD5 output is 16 bytes → fits AES-128.
  - Using raw MD5 as a key is the “legacy” (insecure) habit; modern practice is a proper KDF (e.g. PBKDF2, Argon2) with salt and iteration count.

Given a wordlist of possible passwords, we:

1. For each candidate password, compute `key = MD5(password)`.
2. Decrypt `cipher.bin` with AES-ECB using that key.
3. Remove PKCS7 padding and check if the result contains `flag{`.
4. The first candidate that produces valid padding and a `flag{` substring is the correct password; the decrypted message is the flag.

---

## Solve script walkthrough

The solution is a small Python script that brute-forces the wordlist with the above logic.

### 1. Load the ciphertext and wordlist

```python
with open("cipher.bin", "rb") as f:
    ciphertext = f.read()

with open("wordlist.txt", "r", errors="ignore") as f:
    passwords = f.readlines()
```

- `cipher.bin` is the AES-ECB ciphertext (e.g. 48 bytes = 3 × 16-byte blocks).
- `wordlist.txt` is a list of candidate passwords (one per line); `errors="ignore"` avoids crashes on odd characters.

### 2. Try each password

```python
for pwd in passwords:
    pwd = pwd.strip()
    if not pwd:
        continue
```

Each line is trimmed and empty lines are skipped.

### 3. Derive key and decrypt (legacy style)

```python
key = MD5.new(pwd.encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(ciphertext), 16)
```

- **Key:** 16-byte MD5 hash of the password — this is the “legacy” key derivation.
- **Decrypt:** AES in ECB mode, then PKCS7 unpad with block size 16.

### 4. Detect success

```python
if b"flag{" in plaintext:
    print("[+] Password found:", pwd)
    print("[+] Decrypted:", plaintext.decode())
    break
```

If decryption succeeds (valid padding) and the plaintext contains `flag{`, we treat this as the right password and print it and the decrypted message (the flag).

### 5. Ignore wrong candidates

```python
except (ValueError, UnicodeDecodeError):
    continue
```

Wrong key or bad padding causes `unpad` or decoding to raise; we skip and try the next password.

---

## How to run

1. Install PyCryptodome if needed:
   ```bash
   pip install pycryptodome
   ```

2. Run the script from the directory that contains `cipher.bin` and `wordlist.txt` (e.g. the `challenge/` folder):
   ```bash
   cd challenge
   python ../solve.py
   ```
   Or copy `solve.py` into `challenge/` and run:
   ```bash
   cd challenge
   python solve.py
   ```

3. Expected output (password and flag will match your challenge build):
   ```text
   [+] Password found: <the shared secret>
   [+] Decrypted: flag{...}
   ```

---

## Takeaway

- **Weak key derivation:** Using MD5(password) directly as an AES key is a “legacy” anti-pattern; it’s fast to brute-force with a wordlist and has no salt or cost factor.
- **Defense:** Use a proper KDF (e.g. PBKDF2, scrypt, or Argon2) with a random salt and high work factor when deriving encryption keys from passwords.

---

## Flag

```text
flag{bf3eb75ca3235cce13fb98a5860e6db2}
```

*(Exact value may vary per instance; your run will print the actual decrypted flag.)*
