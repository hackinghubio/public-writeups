# Despicable Me


**Category:** Crypto  
**Difficulty:** Medium  

## Description
I found this file, but I’m not sure what to do with it. I’ve heard solving this challenge requires two phases.

## Write-Up
The challenge is split into two phases.

The first phase involves a ZIP archive encrypted with ZipCrypto (Classic PKZIP). This encryption is vulnerable to known-plaintext attacks. With at least 12 bytes of known plaintext, the internal keys can be recovered, allowing the correct ZIP password to be obtained and the archive to be extracted.

Once extracted, the archive file is a PDF file. opening the PDF file contain an RSA challenge. The same plaintext is encrypted using a small public exponent (e = 3) across three different RSA moduli, making it vulnerable to Håstad’s Broadcast Attack. Using the Chinese Remainder Theorem, the original plaintext can be recovered.

## Exploitation
First, let’s take a look at the files inside the ZIP archive.
```bash
zipinfo EchoChamber.zip
Archive:  EchoChamber.zip
Zip file size: 31865 bytes, number of entries: 1
-rw-r--r--  3.0 unx    31639 BX stor 26-Jan-23 03:58 Encryption_Nightmare.pdf
1 file, 31639 bytes uncompressed, 31639 bytes compressed:  0.0%
````
From the archive contents, we can see that it contains a PDF file. Using 7z will reveal the encryption method used.
```bash
7z l EchoChamber.zip -slt

7-Zip 24.08 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-08-11
 64-bit locale=en_US.UTF-8 Threads:8 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 31865 bytes (32 KiB)

Listing archive: EchoChamber.zip

--
Path = EchoChamber.zip
Type = zip
Physical Size = 31865

----------
Path = Encryption_Nightmare.pdf
Folder = -
Size = 31639
Packed Size = 31651
Modified = 2026-01-23 03:58:02
Created =
Accessed =
Attributes =  -rw-r--r--
Encrypted = +
Comment =
CRC = A9139F5B
Method = ZipCrypto Store
Characteristics = UT:MA:1 ux : Encrypt Descriptor
Host OS = Unix
Version = 10
Volume Index = 0
Offset = 0
```
Now that it is clear the archive uses ZipCrypto encryption, which is vulnerable to known-plaintext attacks, we can proceed. Since the file inside the archive is a PDF, its structure is known, the standard PDF-1.4 header which is the default pdf header till date.

A known-plaintext attack against ZipCrypto requires at least 12 bytes of known plaintext. Tools commonly used for this attack include pkcrack and bkcrack. In my case, bkcrack is used and can be obtained from [here](https://github.com/kimci86/bkcrack).

This are the step took to recover the password.
```
echo -ne '\x25\x50\x44\x46\x2D\x31\x2E\x34\0x0A\x25\xD3\xEB' > attack.bin
----
cat attack.bin
%PDF-1.4
%��
```
The 12bytes of the default pdf header, the more the bytes the more to be able to crack the password quickly. For the attack to succeed, bkcrack must be used with the exact filename of the file inside the archive, matching the name as it appears in the ZIP.
```bash
bkcrack -C EchoChamber.zip -c Encryption_Nightmare.pdf -p attack.bin
bkcrack 1.8.0 - 2025-08-18
[04:15:12] Z reduction using 5 bytes of known plaintext
100.0 % (5 / 5)
[04:15:13] Attack on 1074875 Z values at index 6
Keys: 24393531 7b8cf6ba 7b22a1a9
72.8 % (782584 / 1074875)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 782584
[04:39:01] Keys
24393531 7b8cf6ba 7b22a1a9
```
The recovered key in hexadecimal format, they can be used directly to extract the contents of the ZIP archive or we can use this command to convert the keys to it's orginal self.
```bash
bkcrack -k 24393531 7b8cf6ba 7b22a1a9 -r 12 ?p
bkcrack 1.8.0 - 2025-08-18
[04:42:30] Recovering password
length 0-6...
length 7...
length 8...
length 9...
length 10...
length 11...
length 12...
Password: 3N@5g&m#9P6l
20.5 % (1851 / 9025)
Found a solution. Stopping.
You may resume the password recovery with the option: --continue-recovery 334e43202020
[04:43:15] Password
as bytes: 33 4e 40 35 67 26 6d 23 39 50 36 6c
as text: 3N@5g&m#9P6l
```
Using the recovered hexadecimal keys, the ZIP archive can be decrypted, allowing the PDF file inside to be extracted and opened.
```bash
bkcrack -C EchoChamber.zip -c Encryption_Nightmare.pdf -k 24393531 7b8cf6ba 7b22a1a9 -d Rsa_decrypted.pdf
bkcrack 1.8.0 - 2025-08-18
[06:31:51] Writing deciphered data Rsa_decrypted.pdf
Wrote deciphered data (not compressed)
```

<img width="1518" height="907" alt="image" src="https://github.com/user-attachments/assets/32ebb9d9-0569-44d5-ac35-89a87e61645b" />

This is where the second phase started and by the look and message should already give a clue to hastad broadcast attack.

In this challenge, 512-bit primes are used to generate 1024-bit RSA moduli. The PDF provides the values n₁, c₁, n₂, c₂, and n₃, c₃.

Since the same plaintext is encrypted with a small public exponent (e = 3) across these different moduli, Håstad’s Broadcast Attack applies.

Using the Chinese Remainder Theorem (CRT), the ciphertexts are combined to compute m³. Because the exponent is known, taking the integer cube root recovers the original message m. Finally, this integer is converted to bytes to reveal the flag.

My solve Script
```bash
from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot

# Given values
e = 3
n1 = 84099308805923547835177090789576441717312302281668410687402490238839853848980735103271146133103703457196904144971444159406713139285959779170659247775683702636695706946398560542942703363514061244119652487997620496816472939589071397067922911793967358937846640952783308427842909414996648552547523837780377474267
ct1 = 2217344750798650463174992433838508829419089276588455948988985852417659712042056237854732147728306878966725116586322322539405062237215227262583989045885953684476168025961343026635623913424457503260409304957226910401353760266427067998037068425265777333909929743050096686338917
n2 = 86300567393365200391685121670794292534686052905683995655246289459299064218165801765067784581223929302994182129912379860073883921322948367364737049852798009254868127919603127634113956680368719930572421775168544429069971642629778215629007084373844654606663308487411250209886848165124701458027876743465850985543
ct2 = 2217344750798650463174992433838508829419089276588455948988985852417659712042056237854732147728306878966725116586322322539405062237215227262583989045885953684476168025961343026635623913424457503260409304957226910401353760266427067998037068425265777333909929743050096686338917
n3 = 132539693279926105875287493060493220504232083057871467899553030033375790910815874261553832165589754277892443542534474565734090536544420659585699056007316728094423650678011680660686625519632461198791950691188692674473534534764002636699243992139172306321011037696602951070761240999457924839576024547064513716643
ct3 = 2217344750798650463174992433838508829419089276588455948988985852417659712042056237854732147728306878966725116586322322539405062237215227262583989045885953684476168025961343026635623913424457503260409304957226910401353760266427067998037068425265777333909929743050096686338917

Cs = [ct1, ct2, ct3]
Ns = [n1, n2, n3]

# Function to compute the extended GCD
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

# Function to compute modular inverse
def mod_inverse(a, m):
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

# Chinese Remainder Theorem implementation
def crt(remainders, moduli):
    if len(remainders) != len(moduli):
        raise ValueError("Remainder and moduli lists must have the same length")

    # Compute product of all moduli
    N = 1
    for mod in moduli:
        N *= mod

    result = 0
    for i in range(len(remainders)):
        Ni = N // moduli[i]
        inv = mod_inverse(Ni, moduli[i])
        result += remainders[i] * Ni * inv

    return result % N

# Compute m^e using CRT
m_e = crt(Cs, Ns)

# Compute m by taking the e-th root
m, exact = iroot(m_e, e)
if not exact:
    raise ValueError("e-th root is not an integer")

# Convert m to bytes and print
print(long_to_bytes(int(m)))
--------------------------------------------------------

python3 solve.py
b'flag{859e0b8f3b794b487a445ff0e911bfb2}'
```

## Flag
flag{859e0b8f3b794b487a445ff0e911bfb2}







