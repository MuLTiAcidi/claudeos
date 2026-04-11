# Load Balancer

> Distribute traffic across backend servers and manage backends dynamically. Configures Nginx and HAProxy load balancing with multiple algorithms, health checks, sticky sessions, SSL termination, rate limiting, and runtime backend management.

## Safety Rules

- NEVER apply load balancer config changes without validating syntax first
- NEVER remove the last healthy backend from a pool
- NEVER expose backend server IPs to external clients unless intended
- ALWAYS back up current configuration before making changes
- ALWAYS test config with dry-run before reload
- ALWAYS drain connections gracefully before removing a backend
- ALWAYS monitor error rates after any configuration change
- NEVER disable SSL termination on public-facing endpoints without explicit confirmation

---

## 1. Nginx Load Balancing

### Install Nginx

```bash
apt-get update && apt-get install -y nginx
```

### Round-Robin (default)

```nginx
# /etc/nginx/conf.d/load-balancer.conf
upstream app_backend {
    # Round-robin is the default — requests distributed evenly
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
}

server {
    listen 80;
    server_name app.example.com;

    location / {
        proxy_pass http://app_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

### Least Connections

```nginx
upstream app_backend {
    least_conn;
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
}
```

### IP Hash (session persistence by client IP)

```nginx
upstream app_backend {
    ip_hash;
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
}
```

### Weighted Load Balancing

```nginx
upstream app_backend {
    server 10.0.1.10:8080 weight=5;   # Gets 5x more traffic
    server 10.0.1.11:8080 weight=3;   # Gets 3x more traffic
    server 10.0.1.12:8080 weight=1;   # Gets 1x traffic (baseline)
}
```

### Server parameters

```nginx
upstream app_backend {
    least_conn;

    # Active server with health check params
    server 10.0.1.10:8080 weight=3 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8080 weight=2 max_fails=3 fail_timeout=30s;

    # Backup — only used when all primary servers are down
    server 10.0.1.12:8080 backup;

    # Temporarily removed from rotation
    server 10.0.1.13:8080 down;
}
```

### Validate and reload Nginx

```bash
# Validate configuration syntax
nginx -t

# Reload without dropping connections
systemctl reload nginx

# Or signal directly
nginx -s reload
```

---

## 2. Nginx Health Checks

### Passive health checks (built-in)

```nginx
upstream app_backend {
    server 10.0.1.10:8080 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8080 max_fails=3 fail_timeout=30s;
    # After 3 failures, server is marked down for 30 seconds
}
```

### Custom health check endpoint

```nginx
server {
    listen 80;

    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
```

### External health check script for Nginx backends

```bash
#!/bin/bash
# /usr/local/bin/nginx-health-check.sh
BACKENDS=("10.0.1.10:8080" "10.0.1.11:8080" "10.0.1.12:8080")
NGINX_CONF="/etc/nginx/conf.d/load-balancer.conf"

for BACKEND in "${BACKENDS[@]}"; do
    HOST=$(echo "$BACKEND" | cut -d: -f1)
    PORT=$(echo "$BACKEND" | cut -d: -f2)

    if curl -sf --max-time 5 "http://${BACKEND}/health" > /dev/null 2>&1; then
        echo "$BACKEND: HEALTHY"
        # Ensure server is not marked as down
        sed -i "s/server ${BACKEND}.*down;/server ${BACKEND};/" "$NGINX_CONF"
    else
        echo "$BACKEND: UNHEALTHY"
        # Mark server as down (if not already)
        if ! grep -q "server ${BACKEND}.*down;" "$NGINX_CONF"; then
            sed -i "s/server ${BACKEND};/server ${BACKEND} down;/" "$NGINX_CONF"
            nginx -t && nginx -s reload
        fi
    fi
done
```

---

## 3. Nginx Sticky Sessions

### Cookie-based sticky sessions

```nginx
upstream app_backend {
    # Nginx Plus feature; for open source use ip_hash or third-party module
    ip_hash;
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
}

# Alternative: application-level sticky via cookie routing
map $cookie_SERVERID $sticky_backend {
    server1 10.0.1.10:8080;
    server2 10.0.1.11:8080;
    default 10.0.1.10:8080;
}
```

### Hash-based persistence

```nginx
upstream app_backend {
    hash $request_uri consistent;
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
}
```

---

## 4. Nginx SSL Termination

### SSL termination configuration

```nginx
server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate /etc/ssl/certs/app.example.com.crt;
    ssl_certificate_key /etc/ssl/private/app.example.com.key;

    # Modern SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 1.1.1.1 valid=300s;

    # SSL session cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://app_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name app.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Let's Encrypt SSL with certbot

```bash
# Install certbot
apt-get install -y certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d app.example.com --non-interactive --agree-tos -m admin@example.com

# Auto-renewal (certbot installs a systemd timer by default)
certbot renew --dry-run
```

---

## 5. Nginx Rate Limiting

### Rate limiting configuration

```nginx
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=3r/s;

# Connection limiting
limit_conn_zone $binary_remote_addr zone=addr:10m;

server {
    listen 80;

    # General rate limit with burst
    location / {
        limit_req zone=general burst=20 nodelay;
        limit_conn addr 20;
        proxy_pass http://app_backend;
    }

    # Stricter rate limit for API
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://app_backend;
    }

    # Very strict for login
    location /login {
        limit_req zone=login burst=5;
        proxy_pass http://app_backend;
    }

    # Custom error page for rate-limited requests
    error_page 429 /429.html;
    location = /429.html {
        return 429 '{"error": "Too many requests. Please try again later."}';
        add_header Content-Type application/json;
    }
}
```

---

## 6. HAProxy Load Balancing

### Install HAProxy

```bash
apt-get update && apt-get install -y haproxy
```

### Comprehensive HAProxy configuration

```haproxy
# /etc/haproxy/haproxy.cfg
global
    log /dev/log local0
    log /dev/log local1 notice
    maxconn 50000
    user haproxy
    group haproxy
    daemon
    stats socket /var/run/haproxy.sock mode 660 level admin expose-fd listeners
    stats timeout 30s

    # SSL tuning
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    tune.ssl.default-dh-param 2048

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  forwardfor
    option  http-server-close
    retries 3
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout http-request 10s
    timeout queue 60s
    errorfile 503 /etc/haproxy/errors/503.http

# Stats dashboard
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 5s
    stats auth admin:securepassword
    stats admin if TRUE

# HTTP frontend
frontend http_front
    bind *:80
    bind *:443 ssl crt /etc/ssl/private/combined.pem

    # Redirect HTTP to HTTPS
    http-request redirect scheme https unless { ssl_fc }

    # Rate limiting with stick-table
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }

    # ACL-based routing
    acl is_api path_beg /api
    acl is_static path_beg /static /images /css /js
    acl is_websocket hdr(Upgrade) -i WebSocket

    use_backend api_servers if is_api
    use_backend static_servers if is_static
    use_backend websocket_servers if is_websocket
    default_backend app_servers

# Application backend — round robin
backend app_servers
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200

    # Cookie-based sticky sessions
    cookie SERVERID insert indirect nocache

    server app1 10.0.1.10:8080 check inter 5s fall 3 rise 2 cookie app1
    server app2 10.0.1.11:8080 check inter 5s fall 3 rise 2 cookie app2
    server app3 10.0.1.12:8080 check inter 5s fall 3 rise 2 cookie app3

# API backend — least connections
backend api_servers
    balance leastconn
    option httpchk GET /api/health
    http-check expect status 200

    server api1 10.0.2.10:8080 check inter 3s fall 2 rise 2
    server api2 10.0.2.11:8080 check inter 3s fall 2 rise 2

# Static content backend
backend static_servers
    balance roundrobin
    server static1 10.0.3.10:80 check
    server static2 10.0.3.11:80 check

# WebSocket backend
backend websocket_servers
    balance source
    option http-server-close
    timeout tunnel 3600s
    server ws1 10.0.4.10:8080 check
    server ws2 10.0.4.11:8080 check
```

### Validate and manage HAProxy

```bash
# Test configuration
haproxy -c -f /etc/haproxy/haproxy.cfg

# Reload without dropping connections
systemctl reload haproxy

# View stats from command line
echo "show stat" | socat stdio /var/run/haproxy.sock | column -s, -t | less

# Show server info
echo "show info" | socat stdio /var/run/haproxy.sock

# Show active sessions
echo "show sess" | socat stdio /var/run/haproxy.sock
```

---

## 7. HAProxy Runtime Backend Management

### Add/remove servers at runtime

```bash
# Disable a server (stop sending new connections)
echo "set server app_servers/app1 state maint" | socat stdio /var/run/haproxy.sock

# Drain a server (finish existing, no new connections)
echo "set server app_servers/app1 state drain" | socat stdio /var/run/haproxy.sock

# Re-enable a server
echo "set server app_servers/app1 state ready" | socat stdio /var/run/haproxy.sock

# Soft-stop a server (immediately mark down)
echo "disable server app_servers/app1" | socat stdio /var/run/haproxy.sock

# Re-enable
echo "enable server app_servers/app1" | socat stdio /var/run/haproxy.sock

# Change server weight
echo "set weight app_servers/app1 50%" | socat stdio /var/run/haproxy.sock

# Change server address
echo "set server app_servers/app1 addr 10.0.1.20 port 8080" | socat stdio /var/run/haproxy.sock

# Check a specific server's status
echo "show stat" | socat stdio /var/run/haproxy.sock | grep "app_servers,app1"
```

### Backend management script

```bash
#!/bin/bash
# /usr/local/bin/lb-manage.sh
# Usage: lb-manage.sh {add|remove|drain|status} backend server [address:port]

SOCK="/var/run/haproxy.sock"
ACTION="$1"
BACKEND="$2"
SERVER="$3"

case "$ACTION" in
    add)
        ADDRESS="$4"
        echo "set server ${BACKEND}/${SERVER} addr ${ADDRESS%:*} port ${ADDRESS#*:}" | socat stdio "$SOCK"
        echo "set server ${BACKEND}/${SERVER} state ready" | socat stdio "$SOCK"
        echo "Server $SERVER added to $BACKEND at $ADDRESS"
        ;;
    remove)
        echo "set server ${BACKEND}/${SERVER} state maint" | socat stdio "$SOCK"
        echo "Server $SERVER removed from $BACKEND"
        ;;
    drain)
        echo "set server ${BACKEND}/${SERVER} state drain" | socat stdio "$SOCK"
        echo "Server $SERVER draining in $BACKEND"
        ;;
    status)
        echo "show stat" | socat stdio "$SOCK" | grep "$BACKEND" | cut -d',' -f1,2,18,19 | column -s, -t
        ;;
    *)
        echo "Usage: $0 {add|remove|drain|status} backend server [address:port]"
        exit 1
        ;;
esac
```

---

## 8. Connection Draining and Graceful Removal

### Graceful backend removal workflow

```bash
#!/bin/bash
# /usr/local/bin/lb-graceful-remove.sh
# Gracefully remove a server: drain, wait, remove

SOCK="/var/run/haproxy.sock"
BACKEND="$1"
SERVER="$2"
MAX_WAIT=120  # seconds

echo "Step 1: Setting $SERVER to drain mode"
echo "set server ${BACKEND}/${SERVER} state drain" | socat stdio "$SOCK"

echo "Step 2: Waiting for active sessions to complete (max ${MAX_WAIT}s)"
WAITED=0
while [ "$WAITED" -lt "$MAX_WAIT" ]; do
    SESSIONS=$(echo "show stat" | socat stdio "$SOCK" | grep "${BACKEND},${SERVER}" | cut -d',' -f5)
    if [ "$SESSIONS" = "0" ] || [ -z "$SESSIONS" ]; then
        echo "All sessions drained"
        break
    fi
    echo "  $SESSIONS sessions remaining..."
    sleep 5
    WAITED=$((WAITED + 5))
done

echo "Step 3: Disabling server"
echo "set server ${BACKEND}/${SERVER} state maint" | socat stdio "$SOCK"
echo "Done: $SERVER removed from $BACKEND"
```

---

## 9. Monitoring and Metrics

### HAProxy stats via CSV

```bash
# Get stats as CSV
echo "show stat" | socat stdio /var/run/haproxy.sock

# Parse specific metrics
echo "show stat" | socat stdio /var/run/haproxy.sock | awk -F',' '
NR>1 && $2!="BACKEND" && $2!="FRONTEND" {
    printf "%-15s %-10s status=%-5s cur_sess=%-5s tot_sess=%-10s bytes_in=%-12s bytes_out=%-12s\n", $1, $2, $18, $5, $8, $9, $10
}'
```

### Nginx access log analysis

```bash
# Request count per backend (from upstream headers)
awk '{print $NF}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -10

# Slow requests (>1s)
awk '$NF > 1.0 {print}' /var/log/nginx/access.log | tail -20

# Status code distribution
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# Requests per second
awk '{print $4}' /var/log/nginx/access.log | cut -d: -f1-3 | sort | uniq -c | tail -10
```

### Real-time connection monitoring

```bash
# Active connections to load balancer
ss -tn state established '( dport = :80 or dport = :443 )' | wc -l

# Connections per client IP
ss -tn state established '( dport = :80 or dport = :443 )' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# Backend connection status
ss -tn state established '( sport = :80 or sport = :443 )' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
```

---

## 10. Load Testing

### Verify load distribution with ab

```bash
# Apache Bench — send 10000 requests, 100 concurrent
ab -n 10000 -c 100 http://app.example.com/

# With keep-alive
ab -n 10000 -c 100 -k http://app.example.com/
```

### wrk load test

```bash
# 30 second test with 12 threads and 400 connections
wrk -t12 -c400 -d30s http://app.example.com/

# With custom script
wrk -t12 -c400 -d30s -s post.lua http://app.example.com/api/test
```

### Verify distribution across backends

```bash
# Check HAProxy stats for request distribution
echo "show stat" | socat stdio /var/run/haproxy.sock | awk -F',' '$1=="app_servers" && $2!="BACKEND" {printf "%-10s sessions=%-8s requests=%-10s\n", $2, $5, $8}'
```

---

## 11. Blue-Green Deployment Support

### Switch traffic between blue/green backends

```nginx
# /etc/nginx/conf.d/blue-green.conf
upstream blue {
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
}

upstream green {
    server 10.0.2.10:8080;
    server 10.0.2.11:8080;
}

# Symlink or include to choose active
# ln -sf /etc/nginx/conf.d/active-blue.conf /etc/nginx/conf.d/active.conf
```

### Blue-green switch script

```bash
#!/bin/bash
# /usr/local/bin/lb-blue-green-switch.sh
ACTIVE_FILE="/etc/nginx/conf.d/active-backend.conf"
CURRENT=$(cat "$ACTIVE_FILE" 2>/dev/null | grep proxy_pass | awk -F'/' '{print $3}' | tr -d ';')

if [ "$CURRENT" = "blue" ]; then
    NEW="green"
else
    NEW="blue"
fi

cat > "$ACTIVE_FILE" << EOF
location / {
    proxy_pass http://${NEW};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
EOF

nginx -t && nginx -s reload
echo "Switched from $CURRENT to $NEW"
```

### Canary deployment (weighted split)

```nginx
upstream app_backend {
    # 95% to stable, 5% to canary
    server 10.0.1.10:8080 weight=95;  # stable
    server 10.0.2.10:8080 weight=5;   # canary
}
```
