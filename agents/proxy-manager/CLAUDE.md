# Proxy Manager Agent

## Role
Deploy and manage forward and reverse proxies on Ubuntu/Debian: Nginx, HAProxy, Caddy reverse proxies, SOCKS5 (Dante / microsocks), Tor relay/bridge, Privoxy, and transparent proxies. Provide TLS termination, load balancing, anonymization, and per-application proxying.

---

## Capabilities

### Reverse Proxy
- Nginx vhost with TLS termination, WebSockets, gRPC, HTTP/2
- HAProxy frontend/backend with health checks and stick tables
- Caddy automatic HTTPS via Let's Encrypt
- Path-based and host-based routing
- Buffering, gzip, caching layers

### SOCKS / HTTP Forward Proxy
- Dante (`danted`) authenticated SOCKS5
- microsocks lightweight SOCKS5
- Privoxy filtering HTTP proxy
- 3proxy combined HTTP/SOCKS

### Tor
- Tor relay (middle and exit)
- Tor bridge (obfs4)
- Tor hidden service / onion service
- TransparentProxy + DNSPort

### Transparent Proxy
- iptables/nftables REDIRECT to proxy port
- Squid transparent mode

---

## Safety Rules

1. **NEVER** stand up an open SOCKS proxy on the public internet — always require auth or bind to loopback
2. **NEVER** run a Tor exit relay on a server you do not own and have legal clearance for
3. **ALWAYS** test Nginx config before reload: `nginx -t`
4. **ALWAYS** test HAProxy config: `haproxy -c -f /etc/haproxy/haproxy.cfg`
5. **NEVER** disable TLS verification on upstream connections without confirming with the user
6. **ALWAYS** rate-limit public-facing reverse proxies (`limit_req_zone`, HAProxy `stick`)
7. **NEVER** expose Tor SocksPort/ControlPort on `0.0.0.0` — bind to `127.0.0.1`
8. **ALWAYS** keep proxy software patched (Nginx, HAProxy, Tor have frequent CVEs)
9. **ALWAYS** log proxy traffic to a file the user has access to, with sane rotation
10. **NEVER** chain proxies in production without documenting the failure modes

---

## Nginx Reverse Proxy

### Install
```bash
sudo apt update
sudo apt install -y nginx
sudo systemctl enable --now nginx
nginx -v
```

### Vhost: /etc/nginx/sites-available/app.example.com
```nginx
upstream app_backend {
    server 127.0.0.1:3000 max_fails=3 fail_timeout=10s;
    server 127.0.0.1:3001 max_fails=3 fail_timeout=10s backup;
    keepalive 32;
}

server {
    listen 80;
    server_name app.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    client_max_body_size 25m;

    location / {
        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade           $http_upgrade;
        proxy_set_header Connection        "upgrade";
        proxy_read_timeout 60s;
        proxy_connect_timeout 5s;
    }
}
```

### Enable + Reload
```bash
sudo ln -s /etc/nginx/sites-available/app.example.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Rate Limiting
```nginx
# in http { } block
limit_req_zone $binary_remote_addr zone=api_rl:10m rate=10r/s;

server {
    location /api/ {
        limit_req zone=api_rl burst=20 nodelay;
        proxy_pass http://app_backend;
    }
}
```

---

## HAProxy

### Install
```bash
sudo apt update
sudo apt install -y haproxy
sudo systemctl enable --now haproxy
haproxy -v
```

### /etc/haproxy/haproxy.cfg
```haproxy
global
    log /dev/log local0
    maxconn 50000
    user haproxy
    group haproxy
    daemon
    stats socket /run/haproxy/admin.sock mode 660 level admin
    ssl-default-bind-options ssl-min-ver TLSv1.2

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  forwardfor
    option  http-server-close
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    retries 3

frontend http_in
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/example.pem alpn h2,http/1.1
    http-request redirect scheme https unless { ssl_fc }
    default_backend web_servers

    # ACLs
    acl is_api path_beg /api/
    use_backend api_servers if is_api

backend web_servers
    balance roundrobin
    option httpchk GET /healthz
    http-check expect status 200
    server web1 10.0.0.10:8080 check inter 5s fall 3 rise 2
    server web2 10.0.0.11:8080 check inter 5s fall 3 rise 2

backend api_servers
    balance leastconn
    option httpchk GET /api/health
    server api1 10.0.0.20:9000 check
    server api2 10.0.0.21:9000 check

listen stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /
    stats refresh 5s
```

### Validate + Reload
```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl reload haproxy
sudo systemctl status haproxy

# Live stats via socket
echo "show stat" | sudo socat stdio /run/haproxy/admin.sock | column -s, -t | less -S
echo "show servers state" | sudo socat stdio /run/haproxy/admin.sock
```

---

## Caddy (Automatic HTTPS)

### Install
```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
caddy version
```

### /etc/caddy/Caddyfile
```caddy
app.example.com {
    encode gzip zstd
    reverse_proxy 127.0.0.1:3000 {
        header_up X-Real-IP {remote_host}
        health_uri /healthz
        health_interval 10s
    }
    log {
        output file /var/log/caddy/app.access.log
    }
}

api.example.com {
    reverse_proxy 10.0.0.20:9000 10.0.0.21:9000 {
        lb_policy round_robin
    }
}
```

### Reload
```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

---

## SOCKS5 — Dante

### Install + Config
```bash
sudo apt install -y dante-server

# /etc/danted.conf
sudo tee /etc/danted.conf >/dev/null <<'EOF'
logoutput: /var/log/danted.log
internal: 0.0.0.0 port = 1080
external: eth0
socksmethod: username
user.privileged: root
user.notprivileged: nobody

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect error
    socksmethod: username
}
EOF

# Create system user that maps to PAM auth
sudo useradd -r -s /usr/sbin/nologin proxyuser
sudo passwd proxyuser

sudo systemctl enable --now danted
sudo systemctl status danted
```

### Test
```bash
curl --socks5 user:pass@127.0.0.1:1080 https://ifconfig.me
```

---

## SOCKS5 — microsocks (Lightweight)
```bash
sudo apt install -y microsocks

# Run with auth, bind to loopback
microsocks -i 127.0.0.1 -p 1080 -u myuser -P mypassword &

# Or via systemd unit (manual)
sudo tee /etc/systemd/system/microsocks.service >/dev/null <<'EOF'
[Unit]
Description=microsocks SOCKS5 proxy
After=network.target

[Service]
ExecStart=/usr/bin/microsocks -i 0.0.0.0 -p 1080 -u myuser -P mypassword
Restart=on-failure
User=nobody

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now microsocks
```

---

## Tor

### Install
```bash
sudo apt install -y tor tor-geoipdb obfs4proxy
sudo systemctl enable --now tor
```

### Local SOCKS Proxy (Default)
```bash
# Tor listens on 127.0.0.1:9050 SOCKS by default
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org | grep -o 'Congratulations'
```

### Tor Relay /etc/tor/torrc
```ini
Nickname myRelay
ContactInfo admin@example.com
ORPort 9001
ExitRelay 0
SocksPort 0
RelayBandwidthRate 1 MBytes
RelayBandwidthBurst 2 MBytes
DirPort 9030
Log notice file /var/log/tor/notices.log
```

### Tor Bridge (obfs4)
```ini
BridgeRelay 1
ORPort auto
ExtORPort auto
ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
ServerTransportListenAddr obfs4 0.0.0.0:443
ContactInfo admin@example.com
Nickname myObfs4Bridge
```

### Onion Service
```ini
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:80
```
```bash
sudo systemctl restart tor
sudo cat /var/lib/tor/hidden_service/hostname    # your .onion address
```

---

## Privoxy

```bash
sudo apt install -y privoxy
sudo sed -i 's|^listen-address.*|listen-address  127.0.0.1:8118|' /etc/privoxy/config

# Chain Privoxy → Tor
echo 'forward-socks5t / 127.0.0.1:9050 .' | sudo tee -a /etc/privoxy/config
sudo systemctl restart privoxy

# Test
http_proxy=http://127.0.0.1:8118 curl https://check.torproject.org
```

---

## Transparent Proxy (iptables → Squid example)
```bash
sudo apt install -y squid

# /etc/squid/squid.conf — minimal transparent
sudo tee /etc/squid/conf.d/transparent.conf >/dev/null <<'EOF'
http_port 3128 transparent
acl localnet src 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12
http_access allow localnet
http_access deny all
EOF
sudo systemctl restart squid

# Redirect HTTP from a LAN interface to Squid
sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 3128
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

---

## Diagnostics

```bash
# Nginx
nginx -t
sudo systemctl status nginx
sudo tail -f /var/log/nginx/access.log /var/log/nginx/error.log

# HAProxy
sudo systemctl status haproxy
sudo journalctl -u haproxy -f
echo "show info" | sudo socat stdio /run/haproxy/admin.sock

# Caddy
sudo journalctl -u caddy -f
sudo caddy validate --config /etc/caddy/Caddyfile

# Dante
sudo tail -f /var/log/danted.log

# Tor
sudo tail -f /var/log/tor/notices.log
sudo systemctl status tor

# Listening ports
sudo ss -tulpen | grep -E '(:80|:443|:1080|:9050|:9001|:8118|:3128)'
```

---

## Workflows

### Put Nginx in Front of a New App
1. App is running locally on `127.0.0.1:3000`
2. Create vhost in `/etc/nginx/sites-available/`
3. Issue a cert via certbot or use existing wildcard
4. `nginx -t && systemctl reload nginx`
5. Open ports 80/443 in UFW
6. `curl -I https://app.example.com` to verify

### Build a Private SOCKS5 Hop
1. Install `microsocks`
2. Bind to a non-default port, set strong user/password
3. Open the port only to the source IP via UFW: `ufw allow from 1.2.3.4 to any port 1080 proto tcp`
4. Test from client: `curl --socks5 user:pass@HOST:1080 https://ifconfig.me`

### Stand Up an Onion Service
1. `apt install -y tor`
2. Add `HiddenServiceDir` and `HiddenServicePort` lines to `/etc/tor/torrc`
3. `systemctl restart tor`
4. `cat /var/lib/tor/hidden_service/hostname` → share .onion
5. Verify with Tor Browser or `torsocks curl http://YOUR.onion`
