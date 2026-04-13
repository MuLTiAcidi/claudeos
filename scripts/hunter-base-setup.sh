#!/bin/bash
# ClaudeOS Hunter Base — Full VPS Setup
# Installs ALL tools that the 318 agents need to operate
# Run: bash hunter-base-setup.sh

set -e

echo "============================================"
echo "  ClaudeOS Hunter Base — Setting Up"
echo "  Installing tools for 318 agents"
echo "============================================"
echo ""

export DEBIAN_FRONTEND=noninteractive
export PATH=$PATH:/root/go/bin:/usr/local/go/bin:/opt/jadx/bin

# === SYSTEM BASICS ===
echo "[1/10] System packages..."
apt-get update -qq
apt-get install -y -qq \
  python3 python3-pip python3-venv \
  nodejs npm \
  default-jdk \
  git curl wget unzip jq \
  nmap masscan \
  tcpdump tshark \
  whois dnsutils \
  tmux screen \
  build-essential \
  libssl-dev libffi-dev \
  chromium-browser \
  2>/dev/null

echo "  Done."

# === GO (if not installed) ===
echo "[2/10] Go language..."
if ! command -v go &>/dev/null; then
  wget -q "https://go.dev/dl/go1.22.2.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> /root/.bashrc
  export PATH=$PATH:/usr/local/go/bin:/root/go/bin
fi
echo "  Go: $(go version 2>/dev/null | head -1)"

# === SECURITY SCANNING TOOLS ===
echo "[3/10] Security scanning tools..."
# ProjectDiscovery suite
for tool in nuclei subfinder httpx dnsx katana; do
  if ! command -v $tool &>/dev/null; then
    echo "  Installing $tool..."
    go install -v github.com/projectdiscovery/$tool/cmd/$tool@latest 2>/dev/null
  fi
done

# ffuf
if ! command -v ffuf &>/dev/null; then
  go install github.com/ffuf/ffuf/v2@latest 2>/dev/null
fi

# Update nuclei templates
echo "  Updating nuclei templates..."
/root/go/bin/nuclei -update-templates -silent 2>/dev/null || true

echo "  Done."

# === PLAYWRIGHT (Headless Browser — THE CLOUDFLARE KILLER) ===
echo "[4/10] Playwright (headless browser + stealth)..."
pip3 install playwright 2>/dev/null | tail -1
python3 -m playwright install chromium 2>/dev/null | tail -1
python3 -m playwright install-deps 2>/dev/null | tail -3

# Create stealth browser script
cat > /opt/claudeos-stealth-browser.py << 'STEALTH_EOF'
#!/usr/bin/env python3
"""ClaudeOS Stealth Browser — Solve Cloudflare challenges, render SPAs, intercept APIs."""
import asyncio, json, sys, os

async def stealth_browse(url, output_dir="/tmp/stealth-output"):
    from playwright.async_api import async_playwright

    os.makedirs(output_dir, exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
            ]
        )

        context = await browser.new_context(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            viewport={'width': 1920, 'height': 1080},
            locale='en-US',
        )

        # Intercept and log ALL network requests
        api_calls = []

        page = await context.new_page()

        # Remove webdriver flag
        await page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            window.chrome = {runtime: {}};
        """)

        def on_response(response):
            url = response.url
            if any(skip in url for skip in ['.png', '.jpg', '.gif', '.css', '.woff', '.svg', 'google', 'facebook', 'analytics']):
                return
            api_calls.append({
                'url': url,
                'status': response.status,
                'method': response.request.method,
                'content_type': response.headers.get('content-type', ''),
            })

        page.on('response', on_response)

        print(f"Navigating to {url}...")
        await page.goto(url, wait_until='networkidle', timeout=30000)

        # Wait for Cloudflare challenge to resolve
        await page.wait_for_timeout(5000)

        # Get cookies (including cf_clearance)
        cookies = await context.cookies()

        # Get rendered HTML
        html = await page.content()

        # Get all cookies
        cookie_dict = {c['name']: c['value'] for c in cookies}

        # Screenshot
        await page.screenshot(path=f"{output_dir}/screenshot.png")

        # Save results
        with open(f"{output_dir}/cookies.json", 'w') as f:
            json.dump(cookies, f, indent=2)

        with open(f"{output_dir}/api_calls.json", 'w') as f:
            json.dump(api_calls, f, indent=2)

        with open(f"{output_dir}/page.html", 'w') as f:
            f.write(html)

        # Print summary
        print(f"\nCookies: {len(cookies)}")
        cf = cookie_dict.get('cf_clearance', '')
        if cf:
            print(f"cf_clearance: {cf[:50]}...")

        print(f"\nAPI calls intercepted: {len(api_calls)}")
        for call in api_calls:
            if 'api' in call['url'].lower() or call['content_type'].startswith('application/json'):
                print(f"  [{call['method']}] {call['url'][:100]}")

        print(f"\nSaved to {output_dir}/")
        print(f"  cookies.json, api_calls.json, page.html, screenshot.png")

        # Output cookie string for curl
        cookie_str = '; '.join(f"{c['name']}={c['value']}" for c in cookies)
        print(f"\nCookie string for curl:")
        print(f"  -H 'Cookie: {cookie_str[:200]}...'")

        await browser.close()

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    output = sys.argv[2] if len(sys.argv) > 2 else '/tmp/stealth-output'
    asyncio.run(stealth_browse(url, output))
STEALTH_EOF

chmod +x /opt/claudeos-stealth-browser.py
echo "  Done."

# === JADX (APK Decompilation) ===
echo "[5/10] jadx (APK decompilation)..."
if [ ! -f /opt/jadx/bin/jadx ]; then
  wget -q "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip" -O /tmp/jadx.zip
  mkdir -p /opt/jadx
  unzip -o /tmp/jadx.zip -d /opt/jadx/ 2>/dev/null
  chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui
fi
echo "  jadx: $(/opt/jadx/bin/jadx --version 2>/dev/null || echo 'installed')"

# === MITMPROXY (Intercepting Proxy) ===
echo "[6/10] mitmproxy (intercepting proxy)..."
pip3 install mitmproxy 2>/dev/null | tail -1
echo "  mitmproxy: $(mitmproxy --version 2>/dev/null | head -1 || echo 'installed')"

# === INTERACTSH (Blind Testing Callback Server) ===
echo "[7/10] interactsh (callback server)..."
if ! command -v interactsh-server &>/dev/null; then
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest 2>/dev/null
  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null
fi
echo "  Done."

# === PYTHON TOOLS ===
echo "[8/10] Python security tools..."
pip3 install -q \
  requests \
  pyjwt \
  cryptography \
  beautifulsoup4 \
  lxml \
  pyyaml \
  sqlmap \
  2>/dev/null | tail -1
echo "  Done."

# === DIRECTORY STRUCTURE ===
echo "[9/10] Creating directory structure..."
mkdir -p /opt/claudeos/{scans,pocs,callbacks,apks,wordlists}
mkdir -p /opt/claudeos/scans/{recon,vulns,screenshots}

# Download essential wordlists
if [ ! -f /opt/claudeos/wordlists/subdomains-top1million-5000.txt ]; then
  wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
    -O /opt/claudeos/wordlists/subdomains-top1million-5000.txt 2>/dev/null
fi
echo "  Done."

# === VERIFICATION ===
echo "[10/10] Verifying installation..."
echo ""
echo "  Tool Status:"

for tool in nuclei subfinder httpx dnsx katana ffuf nmap python3 mitmproxy node; do
  if command -v $tool &>/dev/null || [ -f /root/go/bin/$tool ]; then
    echo "    [OK] $tool"
  else
    echo "    [!!] $tool — NOT FOUND"
  fi
done

# Check jadx
if [ -f /opt/jadx/bin/jadx ]; then
  echo "    [OK] jadx"
else
  echo "    [!!] jadx — NOT FOUND"
fi

# Check playwright
python3 -c "from playwright.sync_api import sync_playwright; print('    [OK] playwright')" 2>/dev/null || echo "    [!!] playwright — NOT FOUND"

echo ""
echo "============================================"
echo "  ClaudeOS Hunter Base — READY"
echo "  All tools installed. The team has weapons."
echo "============================================"
