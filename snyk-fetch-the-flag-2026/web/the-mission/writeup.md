# 🐶 The Mission – Writeup

Created By: BuildHackSecure

## Challenge Overview

NahamSec has lost his dog, Patch. Fortunately, Patch wears a GPS tracking collar powered by **Pet Track 247**. Unfortunately, NahamSec has forgotten his login credentials — and there’s no customer support available.

Your mission: hack your way into the system and reunite Patch with his owner.

This challenge requires:

- Basic content discovery
- Git repository extraction
- Mass assignment exploitation
- IDOR enumeration
- Credential brute forcing
- Client-Side Path Traversal (CSPT)
- Privilege escalation via headless browser interaction

---

## Initial Recon

When launching the lab, we are presented with the **Pet Track 247** marketing site. The homepage contains promotional material and a “How It Works” page with imagery of the GPS collar.

Clicking **Portal** redirects us to:

```
https://app-{hash}.ctfhub.io
```

This immediately redirects to:

```
https://auth-{hash}.ctfhub.io
```

The separation between `app` and `auth` subdomains suggests an authentication service architecture.

Since we do not have credentials, we create a new account.

After registration, we are redirected back to the `app` subdomain — but receive the message:

> “Your account is currently in review and will be authorised within 24 hours.”

This tells us:

- Account approval is required
- There is likely an authorisation flag stored server-side
- Our account currently lacks the required privileges

---

## Content Discovery – Exposed Git Repository

Returning to the `auth` subdomain and performing content discovery (e.g. using `ffuf`, `dirsearch`, etc.), we discover:

```
/.git/
```

An exposed `.git` directory is a critical misconfiguration. It allows attackers to reconstruct the full source code of the application.

Using tools such as:

- `GitDumper`
- `GitExtractor`

We download the entire repository.

---

## 🚩 Flag 1 – Source Code Disclosure

Inside `index.php`, we find the first flag.

More importantly, reviewing the application logic reveals how user accounts are created.

---

## Vulnerability 1 – Mass Assignment

In `code/user.php`, the account creation logic contains a **mass assignment vulnerability**.

The `create()` method allows arbitrary POST parameters to be bound directly to the user model without strict whitelisting.

Specifically:

If the `pre_auth_user` field exists in the POST body, the account is automatically marked as pre-authorised.

This occurs because:

- The same model logic is reused for internal functionality
- Sensitive attributes are not restricted
- Input fields are not properly validated

This is a textbook example of improper model binding.

### Exploitation

Intercept the registration request and add:

```
pre_auth_user=1
```

Now the account is automatically approved.

After logging in, we gain full application access.

---

## 🚩 Flag 2 – Application Access

With an authorised account, we can now view the second flag.

However, we still do not have any GPS trackers associated with our account, limiting functionality.

Time to dig deeper.

---

## JavaScript Analysis – Hidden API Endpoints

Inspecting the page source reveals a JavaScript file:

```
/assets/js/DZ7eA3bN.js
```

Reviewing it exposes several API endpoints:

```
/api/trackers
/api/trackers/{tracker}
/api/trackers/{tracker}/members
/api/trackers/{tracker}/location
/api/admin/upgrade-to-admin/{username}
```

The admin endpoint is particularly interesting:

```
/api/admin/upgrade-to-admin/{username}
```

However, direct access results in proper server-side authorisation checks.

We need another way.

---

## Discovering a Tracker ID

Returning to the marketing site, the “How It Works” page displays an image of a collar showing:

```
SN-967G83712F
```

This appears to be a valid serial number.

---

## Vulnerability 2 – IDOR (Insecure Direct Object Reference)

Testing:

```
/api/trackers/SN-967G83712F/members
```

Returns a list of users who have access to that tracker.

This endpoint lacks proper authorisation checks — a classic **IDOR vulnerability**.

Discovered usernames:

```
brianhooper
testdesk3738
sarah3729
sturner
```

---

## Brute Forcing Credentials

Returning to the authentication subdomain, we attempt to brute force these accounts.

Only one account succeeds:

```
Username: sarah3729
Password: welcome
```

We now have access to a legitimate user account with a tracker assigned.

---

## 🚩 Flag 3 – Tracker Access

Viewing the tracker loads:

```
/pets/view?tracker=SN-967G83712F
```

When this page loads, the frontend calls:

```
/api/trackers/SN-967G83712F
```

This frontend behaviour will become important.

---

## Support Ticket Functionality – A Clue

The application allows users to create support tickets.

The form includes:

- Support Team
- Tracker (dropdown)
- Message

Applications that allow user-generated content viewed by admins often involve headless browser interaction.

This suggests a potential stored client-side exploit vector.

---

## Weak Regex Validation

Tampering with the ticket request reveals validation:

```
Serial Number does not match the pattern /SN-[A-Z0-9]{10}/
```

This regex only checks that the pattern appears *somewhere* in the string.

Because it lacks anchors:

- `^` (start of string)
- `$` (end of string)

It allows payloads like:

```
ADAM_SN-967G83712F_TEST
```

to pass validation.

The secure version should have been:

```
^SN-[A-Z0-9]{10}$
```

Without anchors, substring matches are accepted — enabling injection into the tracker parameter.

---

## Vulnerability 3 – Client-Side Path Traversal (CSPT)

When a support ticket is created, the tracker value is reflected into a link:

```
/pets/view?tracker=<value>
```

When that page loads, it calls:

```
/api/trackers/<value>
```

Because the frontend concatenates the value directly into the API path, we can inject path traversal sequences.

Example payload:

```
SN-967G83712F/../../test
```

This causes the frontend to request:

```
/api/test
```

This is **Client-Side Path Traversal (CSPT)** — manipulating frontend routing logic to access unintended API endpoints.

---

## Privilege Escalation via Headless Browser

Now we chain the vulnerabilities.

From the JavaScript file we know:

```
/api/admin/upgrade-to-admin/{username}
```

If we craft the tracker value as:

```
SN-967G83712F/../../admin/upgrade-to-admin/sarah3729
```

The support ticket link becomes:

```
/pets/view?tracker=SN-967G83712F/../../admin/upgrade-to-admin/sarah3729
```

When the support team’s headless browser reviews the ticket:

1. It loads `/pets/view`
2. The frontend JavaScript makes an API request
3. That request resolves to:
   ```
   /api/admin/upgrade-to-admin/sarah3729
   ```
4. The admin session performs the privileged action

Our user is now upgraded to admin.

---

## 🏁 Final Flag – Reuniting Patch

After logging back in as `sarah3729`, we now have admin privileges.

Viewing available trackers reveals a new one:

```
Patch
```

Accessing Patch’s tracker reveals the final flag.

Mission complete. 🐾

---

# Vulnerability Summary

| Step | Vulnerability | Impact |
|------|--------------|--------|
| 1 | Exposed `.git` directory | Source code disclosure |
| 2 | Mass Assignment | Privilege bypass |
| 3 | IDOR | User enumeration |
| 4 | Weak password | Account compromise |
| 5 | Weak regex validation | Input validation bypass |
| 6 | Client-Side Path Traversal | Arbitrary API endpoint access |
| 7 | Stored exploit via headless browser | Privilege escalation |

---

# Key Learning Points

- Never expose `.git` directories
- Always whitelist assignable model fields
- Protect direct object references with proper authorisation checks
- Anchor regex patterns when validating full inputs
- Never trust client-side path construction
- Treat admin bot functionality as high-risk  
