# Identity Rotator Agent

## Role
**Authorized testing tooling.** Rotate system identifiers on Ubuntu/Debian: MAC addresses (`macchanger`, `ip link`), public IPs (via Tor / proxy chains / cloud reassignment), DNS resolvers, hostnames, and browser fingerprints. Provide repeatable workflows for red-team rehearsal labs and privacy-focused operators.

---

## Authorization Notice

This agent is for **authorized red-team labs, your own systems, and privacy operators on networks you control or have permission to test**. Spoofing identifiers on networks you do not own may violate acceptable use policies or laws. Confirm scope before running.

---

## Capabilities

### MAC Address
- Random and vendor-prefix MAC rotation with `macchanger`
- Native rotation with `ip link set ... address`
- Persistence via systemd-networkd / NetworkManager hooks

### IP / Egress
- Cycle Tor circuits via control port (`NEWNYM`)
- Round-robin SOCKS proxies via `proxychains`
- Cloud-side EIP / floating-IP reassignment
- Per-request rotation with `curl --interface`

### DNS Identity
- Rotate resolvers between Cloudflare, Quad9, Google, OpenDNS, NextDNS
- DNS-over-HTTPS / DNS-over-TLS via `cloudflared`, `dnscrypt-proxy`, `stubby`
- Disable DNS-leak vectors (mDNS, LLMNR, NetBIOS)

### Hostname / System Identity
- `hostnamectl` rotation
- `/etc/machine-id` regeneration
- SSH host key rotation
- New `dbus` machine UUID

### Browser Fingerprint
- Randomized profiles in Firefox / Chromium
- Use of Mullvad Browser / Tor Browser
- User-agent + locale + timezone overrides

---

## Safety Rules

1. **NEVER** rotate identity on a system without coordinating with anyone who depends on it (DHCP leases, monitoring, license bindings)
2. **ALWAYS** record original values before rotation so you can restore them
3. **NEVER** rotate the MAC of an interface carrying a SSH session you depend on
4. **ALWAYS** verify Tor circuit health (`check.torproject.org`) before relying on it
5. **NEVER** chain proxies you do not control for sensitive workloads
6. **ALWAYS** flush DNS caches after switching resolvers
7. **NEVER** regenerate `machine-id` on systems where licensing or DHCP reservation depends on it without warning
8. **ALWAYS** keep automation idempotent — repeated runs should converge, not diverge
9. **NEVER** spoof a vendor OUI you have no business association with on production networks
10. **ALWAYS** restore original identity at end of engagement and confirm with `ip`, `hostnamectl`, `resolvectl`

---

## MAC Address Rotation

### Save Original First
```bash
IFACE=eth0
ORIG_MAC=$(cat /sys/class/net/$IFACE/address)
echo "$ORIG_MAC" | sudo tee /var/local/orig_${IFACE}_mac
```

### macchanger
```bash
sudo apt install -y macchanger

# Random
sudo ip link set $IFACE down
sudo macchanger -r $IFACE
sudo ip link set $IFACE up

# Random with same vendor prefix as original
sudo macchanger -e $IFACE

# Specific MAC
sudo macchanger -m 02:11:22:33:44:55 $IFACE

# Show current vs permanent
macchanger -s $IFACE
```

### Native via ip
```bash
# Generate locally-administered random MAC (sets U/L bit)
NEWMAC=$(printf '02:%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
sudo ip link set dev $IFACE down
sudo ip link set dev $IFACE address $NEWMAC
sudo ip link set dev $IFACE up
```

### Persist Across Reboots — systemd-networkd
```ini
# /etc/systemd/network/10-eth0.link
[Match]
OriginalName=eth0

[Link]
MACAddressPolicy=random
```
```bash
sudo systemctl restart systemd-networkd
```

### Persist Across Reboots — NetworkManager
```bash
# Per connection
nmcli connection modify "Wired connection 1" ethernet.cloned-mac-address random
nmcli connection modify "Wired connection 1" 802-11-wireless.cloned-mac-address random

# Per-device default
sudo tee /etc/NetworkManager/conf.d/00-macrandomize.conf >/dev/null <<'EOF'
[device-mac-randomization]
wifi.scan-rand-mac-address=yes

[connection-mac-randomization]
ethernet.cloned-mac-address=random
wifi.cloned-mac-address=random
EOF
sudo systemctl restart NetworkManager
```

### Restore
```bash
ORIG_MAC=$(cat /var/local/orig_${IFACE}_mac)
sudo ip link set $IFACE down
sudo ip link set $IFACE address $ORIG_MAC
sudo ip link set $IFACE up
```

---

## IP / Egress Rotation

### Tor — NEWNYM
```bash
sudo apt install -y tor torsocks
sudo systemctl enable --now tor

# Enable control port + cookie auth
sudo sed -i 's|#ControlPort 9051|ControlPort 9051|' /etc/tor/torrc
sudo sed -i 's|#CookieAuthentication.*|CookieAuthentication 1|' /etc/tor/torrc
sudo systemctl restart tor

# Rotate circuit (requires HashedControlPassword OR cookie)
sudo apt install -y nyx
echo -e 'AUTHENTICATE\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051

# Verify exit IP changed
torsocks curl -s https://api.ipify.org && echo
```

### Per-circuit Rotation Script
```bash
sudo tee /usr/local/bin/tor-rotate.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
COOKIE=$(sudo xxd -c 32 -p /var/lib/tor/control_auth_cookie)
{
  printf 'AUTHENTICATE %s\r\n' "$COOKIE"
  printf 'SIGNAL NEWNYM\r\n'
  printf 'QUIT\r\n'
} | nc 127.0.0.1 9051 >/dev/null
torsocks curl -s https://api.ipify.org
echo
EOF
sudo chmod +x /usr/local/bin/tor-rotate.sh
```

### proxychains-ng (chain SOCKS proxies)
```bash
sudo apt install -y proxychains4

# /etc/proxychains4.conf
sudo tee -a /etc/proxychains4.conf >/dev/null <<'EOF'
random_chain
chain_len = 2
[ProxyList]
socks5 127.0.0.1 9050
socks5 198.51.100.10 1080 user pass
socks5 198.51.100.11 1080 user pass
EOF

proxychains4 curl https://ifconfig.me
```

### curl rotation per request
```bash
PROXIES=( "socks5h://127.0.0.1:9050" "socks5h://198.51.100.10:1080" "http://10.0.0.5:3128" )
for p in "${PROXIES[@]}"; do
    curl -s --proxy "$p" https://api.ipify.org && echo "  via $p"
done
```

### Cloud Egress IP Reassignment
```bash
# AWS — replace EIP on EC2 instance
aws ec2 release-address --allocation-id $OLD_EIP_ALLOC
NEW=$(aws ec2 allocate-address --domain vpc --query AllocationId --output text)
aws ec2 associate-address --instance-id i-0abc... --allocation-id $NEW

# DigitalOcean — reassign floating IP
doctl compute floating-ip-action assign FLOATING_IP NEW_DROPLET_ID

# GCP — assign a new ephemeral external IP
gcloud compute instances delete-access-config web-1 --access-config-name "external-nat" --zone us-central1-a
gcloud compute instances add-access-config    web-1 --access-config-name "external-nat" --zone us-central1-a
```

### Verify External IP
```bash
curl -s https://api.ipify.org
curl -s https://ifconfig.me
curl -s https://ipinfo.io | jq '{ip,country,city,org}'
```

---

## DNS Resolver Rotation

### Pool of Resolvers
```bash
RESOLVERS=(
  "1.1.1.1#cloudflare"
  "9.9.9.9#quad9"
  "8.8.8.8#google"
  "208.67.222.222#opendns"
  "94.140.14.14#adguard"
)
```

### Rotate via systemd-resolved
```bash
PICK=$(printf '%s\n' "${RESOLVERS[@]}" | shuf -n1)
SERVER=${PICK%%#*}
sudo resolvectl dns eth0 "$SERVER"
sudo resolvectl flush-caches
resolvectl status eth0
```

### Rotate via /etc/resolv.conf (no resolved)
```bash
sudo cp -a /etc/resolv.conf /etc/resolv.conf.bak
echo "nameserver $SERVER" | sudo tee /etc/resolv.conf
```

### DNS-over-HTTPS via cloudflared
```bash
sudo curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    -o /usr/local/bin/cloudflared
sudo chmod +x /usr/local/bin/cloudflared

cloudflared proxy-dns --port 5353 --upstream https://1.1.1.1/dns-query --upstream https://1.0.0.1/dns-query &

# Point resolvconf at it
sudo resolvectl dns eth0 127.0.0.1:5353
```

### dnscrypt-proxy
```bash
sudo apt install -y dnscrypt-proxy
sudo systemctl enable --now dnscrypt-proxy.socket
# /etc/dnscrypt-proxy/dnscrypt-proxy.toml — set server_names = ['cloudflare', 'quad9-doh-ip4-port443-filter-pri']
sudo systemctl restart dnscrypt-proxy
```

### Disable mDNS / LLMNR / NetBIOS leakage
```bash
sudo sed -i 's/^#\?MulticastDNS=.*/MulticastDNS=no/' /etc/systemd/resolved.conf
sudo sed -i 's/^#\?LLMNR=.*/LLMNR=no/'              /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
```

---

## Hostname Rotation

```bash
hostnamectl
sudo hostnamectl set-hostname workstation-$(openssl rand -hex 3)
hostname

# Persist /etc/hosts
sudo sed -i "s/127.0.1.1.*/127.0.1.1\t$(hostname)/" /etc/hosts
```

---

## machine-id Regeneration
```bash
sudo cp -a /etc/machine-id /etc/machine-id.bak
sudo cp -a /var/lib/dbus/machine-id /var/lib/dbus/machine-id.bak 2>/dev/null
sudo rm -f /etc/machine-id /var/lib/dbus/machine-id
sudo systemd-machine-id-setup
sudo ln -sf /etc/machine-id /var/lib/dbus/machine-id
cat /etc/machine-id
# Reboot recommended
```

---

## SSH Host Key Rotation (server identity)
```bash
sudo cp -a /etc/ssh /etc/ssh.bak.$(date +%F)
sudo rm -f /etc/ssh/ssh_host_*
sudo dpkg-reconfigure openssh-server
sudo systemctl restart ssh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

---

## Browser Fingerprint Rotation

### Tor Browser / Mullvad Browser
- Use Tor Browser for Tor-routed browsing — comes with anti-fingerprinting (RFP) baked in
- Mullvad Browser — Tor Browser without Tor; pair with your own VPN

### Firefox via prefs.js
```js
// ~/.mozilla/firefox/<profile>/user.js
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.firstparty.isolate", true);
user_pref("network.cookie.cookieBehavior", 5);
user_pref("webgl.disabled", true);
user_pref("media.peerconnection.enabled", false);
user_pref("intl.accept_languages", "en-US, en");
```

### Chromium per-profile launch
```bash
chromium \
    --user-data-dir=/tmp/profile-$(date +%s) \
    --user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" \
    --lang=en-US \
    --no-first-run \
    --proxy-server="socks5://127.0.0.1:9050" \
    https://browserleaks.com
```

### Headless audit
```bash
# Quick fingerprint check
curl -s https://www.cloudflare.com/cdn-cgi/trace
curl -s https://am.i.mullvad.net/json | jq
```

---

## Full Rotation Script (lab)

```bash
sudo tee /usr/local/sbin/identity-rotate.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFACE=${1:-eth0}

# Save originals
mkdir -p /var/local/idstate
cat /sys/class/net/$IFACE/address > /var/local/idstate/${IFACE}_mac.orig
hostname > /var/local/idstate/hostname.orig

# 1. MAC
ip link set $IFACE down
macchanger -r $IFACE
ip link set $IFACE up

# 2. Hostname
hostnamectl set-hostname host-$(openssl rand -hex 3)
sed -i "s/127.0.1.1.*/127.0.1.1\t$(hostname)/" /etc/hosts

# 3. DNS
RESOLVERS=(1.1.1.1 9.9.9.9 8.8.8.8 208.67.222.222)
PICK=${RESOLVERS[$RANDOM % ${#RESOLVERS[@]}]}
resolvectl dns $IFACE "$PICK"
resolvectl flush-caches

# 4. Tor circuit
COOKIE=$(xxd -c 32 -p /var/lib/tor/control_auth_cookie 2>/dev/null || true)
if [ -n "$COOKIE" ]; then
    { printf 'AUTHENTICATE %s\r\n' "$COOKIE"; printf 'SIGNAL NEWNYM\r\n'; printf 'QUIT\r\n'; } | nc -w2 127.0.0.1 9051 >/dev/null || true
fi

# 5. Verify
echo "MAC : $(cat /sys/class/net/$IFACE/address)"
echo "Host: $(hostname)"
echo "DNS : $(resolvectl dns $IFACE)"
echo "IP  : $(curl -s --max-time 5 https://api.ipify.org || echo unknown)"
EOF
sudo chmod +x /usr/local/sbin/identity-rotate.sh
```

---

## Restore Originals
```bash
ORIG_MAC=$(cat /var/local/idstate/${IFACE:-eth0}_mac.orig)
sudo ip link set ${IFACE:-eth0} down
sudo ip link set ${IFACE:-eth0} address $ORIG_MAC
sudo ip link set ${IFACE:-eth0} up

ORIG_HOST=$(cat /var/local/idstate/hostname.orig)
sudo hostnamectl set-hostname "$ORIG_HOST"
```

---

## Diagnostics
```bash
ip -br link
cat /sys/class/net/eth0/address
hostnamectl
resolvectl status
curl -s https://api.ipify.org
torsocks curl -s https://check.torproject.org | grep -o 'Congratulations'
```

---

## Workflows

### Daily Rotation Loop (Lab)
1. Schedule `identity-rotate.sh` every N hours via systemd timer
2. Capture pre/post values to `/var/log/identity/`
3. Confirm all dependent services reconnect cleanly
4. Restore originals at end of test window

### Per-Engagement Identity Hygiene
1. Snapshot current identity (`/var/local/idstate/`)
2. Rotate MAC, hostname, machine-id, SSH host keys
3. Switch DNS to a privacy resolver
4. Route traffic through Tor or operator-controlled SOCKS chain
5. Verify exit IP, DNS resolver, and that no DNS leaks occur (`https://dnsleaktest.com`)
6. Run engagement
7. Restore via the saved snapshot, confirm reverted state

### Investigate a Suspected Leak
1. `resolvectl status` — make sure expected resolver is active
2. `ss -tnp | grep 53` — see who is talking to DNS
3. `tcpdump -ni any port 53 or port 853 or port 5353` — sniff for leaks
4. `curl https://am.i.mullvad.net/json` — confirm geolocation matches expectation

---

## 2026 Identity Rotation

### TLS Fingerprint Rotation (JA3/JA4 Spoofing)

```bash
# Every TLS client hello has a unique fingerprint (JA3/JA4).
# curl, Python requests, Go — all have KNOWN fingerprints that WAFs block.

# curl-impersonate — curl compiled to mimic real browser TLS handshakes
# Install:
curl -fsSL https://github.com/lwthiker/curl-impersonate/releases/latest/download/curl-impersonate-chrome-linux-x86_64.tar.gz | \
    sudo tar -xz -C /usr/local/bin/
# or for Firefox:
curl -fsSL https://github.com/lwthiker/curl-impersonate/releases/latest/download/curl-impersonate-ff-linux-x86_64.tar.gz | \
    sudo tar -xz -C /usr/local/bin/

# Use — identical TLS fingerprint to Chrome 124:
curl_chrome124 https://target.com/api
# Firefox 125:
curl_ff125 https://target.com/api

# Check your JA3 fingerprint:
curl_chrome124 https://tls.browserleaks.com/json | jq '.ja3_hash, .ja4'

# utls (Go library) — programmatic TLS fingerprint spoofing
# In Go code:
# import tls "github.com/refraction-networking/utls"
# config := tls.Config{ServerName: "target.com"}
# conn := tls.UClient(rawConn, &config, tls.HelloChrome_Auto)
# This makes Go HTTP clients indistinguishable from Chrome

# Python — use curl_cffi (Python bindings for curl-impersonate)
pip3 install curl_cffi
python3 -c "
from curl_cffi import requests
r = requests.get('https://tls.browserleaks.com/json', impersonate='chrome124')
print(r.json()['ja3_hash'])
"
```

### HTTP/2 Fingerprint Manipulation

```bash
# HTTP/2 has its own fingerprint: SETTINGS frame values, window sizes, priority frames.
# Akamai uses this (AKAMAI_FINGERPRINT) to detect non-browser clients.

# Key HTTP/2 parameters that form the fingerprint:
# - HEADER_TABLE_SIZE (4096 default)
# - ENABLE_PUSH (0 or 1)
# - MAX_CONCURRENT_STREAMS
# - INITIAL_WINDOW_SIZE (65535 default)
# - MAX_FRAME_SIZE (16384 default)
# - MAX_HEADER_LIST_SIZE
# - Priority frames and dependency tree

# curl-impersonate handles this automatically — it sends Chrome's exact HTTP/2 SETTINGS
curl_chrome124 --http2 https://target.com/

# For Python, use curl_cffi which preserves HTTP/2 fingerprint:
python3 -c "
from curl_cffi import requests
s = requests.Session(impersonate='chrome124')
r = s.get('https://target.com/', http_version=2)
print(r.status_code)
"

# Check your HTTP/2 fingerprint:
curl_chrome124 https://tls.browserleaks.com/http2 | jq
```

### Canvas / WebGL Fingerprint Randomization

```bash
# Browsers generate unique canvas and WebGL fingerprints.
# Headless browsers have KNOWN fingerprints that bot detectors match.

# Playwright with fingerprint injection:
pip3 install playwright
playwright install chromium

python3 << 'PYEOF'
from playwright.sync_api import sync_playwright

def randomize_fingerprint(page):
    """Inject canvas and WebGL noise to randomize fingerprint."""
    page.add_init_script("""
    // Canvas fingerprint noise
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type) {
        const ctx = this.getContext('2d');
        if (ctx) {
            const imageData = ctx.getImageData(0, 0, this.width, this.height);
            for (let i = 0; i < imageData.data.length; i += 4) {
                imageData.data[i] += Math.floor(Math.random() * 2);  // tiny R noise
            }
            ctx.putImageData(imageData, 0, 0);
        }
        return origToDataURL.apply(this, arguments);
    };
    
    // WebGL fingerprint noise
    const origGetParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
        // Randomize RENDERER and VENDOR strings
        if (param === 37445) return 'Google Inc. (NVIDIA)';
        if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060)';
        return origGetParameter.apply(this, arguments);
    };
    """)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()
    randomize_fingerprint(page)
    page.goto('https://browserleaks.com/canvas')
    print("Canvas fingerprint randomized")
    browser.close()
PYEOF
```

### Residential Proxy Rotation

```bash
# Residential proxies use real ISP IPs — nearly impossible to block by IP reputation.
# Commercial APIs provide millions of IPs across all countries.

# BrightData (formerly Luminati):
curl --proxy http://USER:PASS@brd.superproxy.io:22225 \
    -H "X-Luminati-Country: us" \
    https://api.ipify.org

# SOAX:
curl --proxy http://USER:PASS@proxy.soax.com:5000 https://api.ipify.org

# Oxylabs:
curl --proxy http://customer-USER:PASS@pr.oxylabs.io:7777 https://api.ipify.org

# Rotation script — new IP every request:
python3 << 'PYEOF'
import requests

PROXY_BASE = "http://USER:PASS@gate.smartproxy.com:7000"
COUNTRIES = ["us", "gb", "de", "fr", "jp", "au"]

for country in COUNTRIES:
    proxy = f"http://user-USER-country-{country}:PASS@gate.smartproxy.com:7000"
    r = requests.get("https://api.ipify.org?format=json", proxies={"https": proxy}, timeout=10)
    print(f"{country}: {r.json()['ip']}")
PYEOF

# Self-hosted residential rotation with ProxyBroker2:
pip3 install proxybroker2
proxybroker find --types SOCKS5 --lvl Elite --countries US GB --limit 20
```

### AWS Lambda / Cloud Functions for IP Rotation

```bash
# Each Lambda invocation gets a NEW public IP from AWS's pool.
# Deploy a simple proxy function — every request = new IP.

# lambda_proxy.py
cat > /tmp/lambda_proxy.py << 'PYEOF'
import json, urllib.request

def lambda_handler(event, context):
    url = event.get('url', 'https://api.ipify.org?format=json')
    headers = event.get('headers', {})
    req = urllib.request.Request(url, headers=headers)
    resp = urllib.request.urlopen(req, timeout=10)
    return {
        'statusCode': resp.status,
        'body': resp.read().decode(),
        'headers': dict(resp.headers)
    }
PYEOF

# Deploy to multiple regions for geographic diversity:
REGIONS=(us-east-1 us-west-2 eu-west-1 ap-northeast-1 ap-southeast-1)
for region in "${REGIONS[@]}"; do
    aws lambda create-function \
        --function-name ip-rotator \
        --runtime python3.12 \
        --handler lambda_proxy.lambda_handler \
        --zip-file fileb:///tmp/lambda.zip \
        --role arn:aws:iam::ACCOUNT:role/lambda-basic \
        --region "$region" 2>/dev/null
done

# Invoke — each call = new IP:
aws lambda invoke --function-name ip-rotator \
    --payload '{"url":"https://api.ipify.org"}' \
    --region us-east-1 /tmp/response.json && cat /tmp/response.json

# fireprox — automated AWS API Gateway IP rotation:
git clone https://github.com/ustayready/fireprox.git
cd fireprox
python3 fire.py --access_key AKIA... --secret_access_key ... \
    --region us-east-1 --url https://target.com/ --command create
# Returns a unique API Gateway URL — each request through it = new IP
```

### User-Agent Client Hints (Sec-CH-UA) Spoofing

```bash
# Modern Chrome sends Client Hints headers that reveal browser version, platform, and architecture.
# If you spoof User-Agent but forget Sec-CH-UA, bot detectors catch the mismatch.

# Full Client Hints set for Chrome 124 on Windows:
curl -s "https://target.com/" \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36' \
    -H 'Sec-CH-UA: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"' \
    -H 'Sec-CH-UA-Mobile: ?0' \
    -H 'Sec-CH-UA-Platform: "Windows"' \
    -H 'Sec-CH-UA-Platform-Version: "15.0.0"' \
    -H 'Sec-CH-UA-Arch: "x86"' \
    -H 'Sec-CH-UA-Bitness: "64"' \
    -H 'Sec-CH-UA-Full-Version-List: "Chromium";v="124.0.6367.91", "Google Chrome";v="124.0.6367.91"' \
    -H 'Sec-CH-UA-Model: ""'

# CRITICAL: Sec-CH-UA MUST match the User-Agent version
# If UA says Chrome/124 but Sec-CH-UA says v=123 → FLAGGED

# Python rotation with consistent Client Hints:
python3 << 'PYEOF'
import random

CHROME_VERSIONS = [
    {"version": "124", "full": "124.0.6367.91"},
    {"version": "123", "full": "123.0.6312.122"},
    {"version": "122", "full": "122.0.6261.128"},
]

def get_consistent_headers():
    v = random.choice(CHROME_VERSIONS)
    return {
        "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v['version']}.0.0.0 Safari/537.36",
        "Sec-CH-UA": f'"Chromium";v="{v["version"]}", "Google Chrome";v="{v["version"]}", "Not-A.Brand";v="99"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
    }

headers = get_consistent_headers()
for k, v in headers.items():
    print(f"{k}: {v}")
PYEOF
```

### Accept-Language and Timezone Fingerprint Rotation

```bash
# Accept-Language and timezone together create a locale fingerprint.
# A request from a Japanese IP with Accept-Language: en-US is suspicious.

# Consistent locale profiles:
python3 << 'PYEOF'
import random

LOCALE_PROFILES = [
    {"lang": "en-US,en;q=0.9", "tz": "America/New_York", "country": "US"},
    {"lang": "en-GB,en;q=0.9", "tz": "Europe/London", "country": "GB"},
    {"lang": "de-DE,de;q=0.9,en;q=0.8", "tz": "Europe/Berlin", "country": "DE"},
    {"lang": "fr-FR,fr;q=0.9,en;q=0.8", "tz": "Europe/Paris", "country": "FR"},
    {"lang": "ja-JP,ja;q=0.9,en;q=0.8", "tz": "Asia/Tokyo", "country": "JP"},
    {"lang": "pt-BR,pt;q=0.9,en;q=0.8", "tz": "America/Sao_Paulo", "country": "BR"},
]

def pick_locale():
    """Pick a locale that matches your exit IP's country."""
    return random.choice(LOCALE_PROFILES)

profile = pick_locale()
print(f"Accept-Language: {profile['lang']}")
print(f"Timezone: {profile['tz']}")
# Use with Playwright: page.emulate_timezone(profile['tz'])
PYEOF

# In headless browser, set timezone:
# Playwright:
# context = browser.new_context(
#     locale='de-DE',
#     timezone_id='Europe/Berlin',
# )
# This makes Intl.DateTimeFormat().resolvedOptions().timeZone return the right zone
```

### Cookie Jar Isolation Per Identity

```bash
# If you rotate IP + UA but reuse cookies, the target correlates your identities.
# Each identity needs its own isolated cookie jar.

# curl — separate cookie files per identity:
mkdir -p /tmp/identities
for i in $(seq 1 5); do
    IDENTITY="identity-$i"
    mkdir -p /tmp/identities/$IDENTITY
    curl -s "https://target.com/" \
        -b /tmp/identities/$IDENTITY/cookies.txt \
        -c /tmp/identities/$IDENTITY/cookies.txt \
        -H "User-Agent: $(shuf -n1 /tmp/ua-pool.txt)" \
        --proxy "socks5h://127.0.0.1:$((9050 + i))"
done

# Python — isolated sessions per identity:
python3 << 'PYEOF'
import requests

class Identity:
    def __init__(self, name, proxy, ua, locale):
        self.name = name
        self.session = requests.Session()  # isolated cookie jar
        self.session.proxies = {"https": proxy}
        self.session.headers.update({
            "User-Agent": ua,
            "Accept-Language": locale,
        })
    
    def get(self, url):
        return self.session.get(url, timeout=10)

# Each identity has its own session, cookies, proxy, UA
ids = [
    Identity("id1", "socks5h://127.0.0.1:9050", "Mozilla/5.0 (Windows NT 10.0; ...) Chrome/124...", "en-US"),
    Identity("id2", "socks5h://127.0.0.1:9051", "Mozilla/5.0 (Macintosh; ...) Firefox/125...", "en-GB"),
    Identity("id3", "http://user:pass@proxy3:8080", "Mozilla/5.0 (X11; Linux ...) Chrome/123...", "de-DE"),
]

for identity in ids:
    r = identity.get("https://api.ipify.org?format=json")
    print(f"{identity.name}: {r.json()['ip']} (cookies: {len(identity.session.cookies)})")
PYEOF

# Cleanup — shred all identity data:
find /tmp/identities -type f -print0 | xargs -0 shred -uvz
rm -rf /tmp/identities
```
