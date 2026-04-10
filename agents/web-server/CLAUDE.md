# Web Server Agent

## Role
Manage Nginx and Apache web servers. Virtual host configuration, performance tuning, SSL/TLS, reverse proxy, load balancing, security hardening, and log analysis.

---

## Capabilities

### Virtual Host Management
- Create, edit, delete, list virtual hosts / server blocks
- Enable/disable sites (sites-available/sites-enabled pattern)
- Domain-based and port-based virtual hosting
- Subdomain wildcard configuration
- Configuration syntax validation before reload

### Performance Tuning
- Worker process and connection optimization
- Keepalive and timeout settings
- Gzip/Brotli compression
- Static file caching with proper cache headers
- Buffer size optimization
- FastCGI/proxy cache configuration
- HTTP/2 and HTTP/3 enablement

### SSL/TLS Configuration
- Let's Encrypt certificate management (certbot)
- Strong cipher suite configuration
- HSTS (HTTP Strict Transport Security)
- OCSP stapling
- SSL session caching
- TLS 1.2/1.3 enforcement
- Certificate renewal automation

### Reverse Proxy & Load Balancing
- Upstream server configuration
- Health checks for backends
- WebSocket proxying
- Load balancing algorithms (round-robin, least_conn, ip_hash)
- Sticky sessions
- Proxy header forwarding

### Security
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
- Rate limiting
- IP whitelisting/blacklisting
- Request size limits
- Directory listing prevention
- Server version hiding
- ModSecurity / WAF integration

### PHP-FPM Integration
- Pool configuration and tuning
- Process manager mode selection (static, dynamic, ondemand)
- Status page monitoring
- Slow log analysis

### Log Analysis
- Access log parsing and statistics
- Error log monitoring and alerting
- Custom log formats
- Log rotation configuration
- Real-time log tailing with filtering

---

## Commands Reference

### Nginx

#### Configuration Management
```bash
# Test configuration syntax
nginx -t

# Reload configuration (graceful)
systemctl reload nginx

# Full restart
systemctl restart nginx

# Show compiled configuration
nginx -T

# List enabled sites
ls -la /etc/nginx/sites-enabled/

# Enable a site
ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/

# Disable a site
rm /etc/nginx/sites-enabled/example.com

# Check which worker processes are running
ps aux | grep nginx
```

#### Performance Tuning — nginx.conf
```nginx
# /etc/nginx/nginx.conf — Main context
worker_processes auto;                  # Match CPU cores
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;            # Per worker
    multi_accept on;
    use epoll;                          # Linux only
}

http {
    # Basic
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    types_hash_max_size 2048;
    server_tokens off;                  # Hide version

    # Timeouts
    keepalive_timeout 65;
    keepalive_requests 1000;
    client_body_timeout 12;
    client_header_timeout 12;
    send_timeout 10;

    # Buffers
    client_body_buffer_size 16K;
    client_header_buffer_size 1k;
    client_max_body_size 50M;
    large_client_header_buffers 4 8k;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_types
        text/plain text/css text/xml text/javascript
        application/json application/javascript application/xml
        application/rss+xml application/atom+xml
        image/svg+xml font/woff2;

    # File cache
    open_file_cache max=10000 inactive=30s;
    open_file_cache_valid 60s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;
}
```

#### SSL Configuration (Strong)
```nginx
# SSL settings (in server block or ssl.conf include)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;

ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;

# HSTS (be careful — hard to undo)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

#### Security Headers
```nginx
# Add to server block
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'self';" always;
```

#### Rate Limiting
```nginx
# In http block
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=3r/m;

# In server/location block
location /api/ {
    limit_req zone=general burst=20 nodelay;
    limit_req_status 429;
}

location /login {
    limit_req zone=login burst=5;
    limit_req_status 429;
}
```

### Apache

#### Configuration Management
```bash
# Test configuration
apachectl configtest
# or
apache2ctl -t

# Reload
systemctl reload apache2

# List enabled modules
apache2ctl -M

# Enable/disable modules
a2enmod rewrite ssl headers proxy proxy_http
a2dismod autoindex

# Enable/disable sites
a2ensite example.com.conf
a2dissite 000-default.conf
```

#### Performance Tuning — apache2.conf / httpd.conf
```apache
# MPM Event (preferred)
<IfModule mpm_event_module>
    StartServers             2
    MinSpareThreads         25
    MaxSpareThreads         75
    ThreadLimit             64
    ThreadsPerChild         25
    MaxRequestWorkers      150
    MaxConnectionsPerChild 10000
</IfModule>

# Keepalive
KeepAlive On
MaxKeepAliveRequests 500
KeepAliveTimeout 5

# Timeouts
Timeout 60

# Server identity
ServerTokens Prod
ServerSignature Off

# Compression
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css
    AddOutputFilterByType DEFLATE application/javascript application/json
    AddOutputFilterByType DEFLATE application/xml application/rss+xml
    AddOutputFilterByType DEFLATE image/svg+xml font/woff2
</IfModule>

# Caching
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/webp "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType font/woff2 "access plus 1 year"
</IfModule>
```

### Let's Encrypt / Certbot
```bash
# Install certbot
apt install certbot python3-certbot-nginx  # Nginx
apt install certbot python3-certbot-apache  # Apache

# Obtain certificate (Nginx)
certbot --nginx -d example.com -d www.example.com

# Obtain certificate (Apache)
certbot --apache -d example.com -d www.example.com

# Standalone (when no web server running)
certbot certonly --standalone -d example.com

# Dry run renewal test
certbot renew --dry-run

# Force renewal
certbot renew --force-renewal

# List certificates
certbot certificates

# Revoke certificate
certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem
```

### PHP-FPM Tuning
```ini
; /etc/php/8.2/fpm/pool.d/www.conf

; Process manager mode
pm = dynamic                 ; static | dynamic | ondemand

; Dynamic mode settings
pm.max_children = 50         ; Max PHP processes (RAM / ~40MB per process)
pm.start_servers = 10
pm.min_spare_servers = 5
pm.max_spare_servers = 20
pm.max_requests = 500        ; Restart worker after N requests (prevent leaks)
pm.process_idle_timeout = 10s

; Slow log
slowlog = /var/log/php-fpm/slow.log
request_slowlog_timeout = 5s

; Status page
pm.status_path = /status
ping.path = /ping
ping.response = pong

; Limits
php_admin_value[memory_limit] = 256M
php_admin_value[max_execution_time] = 30
php_admin_value[upload_max_filesize] = 50M
php_admin_value[post_max_size] = 55M
```

### Log Analysis
```bash
# Top 20 IPs by request count (Nginx/Apache combined log)
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# Top 20 requested URLs
awk '{print $7}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# HTTP status code distribution
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# 5xx errors
awk '$9 >= 500' /var/log/nginx/access.log | tail -50

# Requests per minute (last hour)
awk -v date="$(date -d '1 hour ago' '+%d/%b/%Y:%H')" '$4 ~ date {print substr($4,14,5)}' \
  /var/log/nginx/access.log | sort | uniq -c

# Real-time error monitoring
tail -f /var/log/nginx/error.log | grep -v "favicon"

# GoAccess real-time dashboard
goaccess /var/log/nginx/access.log -o report.html --log-format=COMBINED
```

---

## Site Templates

### WordPress Site (Nginx)
```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.com;
    root /var/www/example.com/public_html;
    index index.php index.html;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    # WordPress permalinks
    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    # PHP-FPM
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
    }

    # Block wp-config.php access
    location ~ /wp-config\.php$ {
        deny all;
    }

    # Block xmlrpc
    location = /xmlrpc.php {
        deny all;
        return 444;
    }

    # Block hidden files
    location ~ /\. {
        deny all;
    }

    # Static file caching
    location ~* \.(js|css|png|jpg|jpeg|gif|webp|ico|svg|woff2|ttf)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Upload size
    client_max_body_size 64M;

    # Logs
    access_log /var/log/nginx/example.com.access.log;
    error_log /var/log/nginx/example.com.error.log;
}
```

### Laravel Site (Nginx)
```nginx
server {
    listen 80;
    server_name app.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;
    root /var/www/app.example.com/public;
    index index.php;

    ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    charset utf-8;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }

    error_page 404 /index.php;

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }

    # Static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|webp|ico|svg|woff2)$ {
        expires 30d;
        add_header Cache-Control "public";
        access_log off;
    }

    client_max_body_size 50M;

    access_log /var/log/nginx/app.example.com.access.log;
    error_log /var/log/nginx/app.example.com.error.log;
}
```

### Node.js Reverse Proxy (Nginx)
```nginx
upstream node_app {
    server 127.0.0.1:3000;
    keepalive 64;
}

server {
    listen 80;
    server_name api.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://node_app;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # WebSocket endpoint (if separate)
    location /ws {
        proxy_pass http://node_app;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }

    # Rate limiting for API
    limit_req zone=api burst=50 nodelay;

    access_log /var/log/nginx/api.example.com.access.log;
    error_log /var/log/nginx/api.example.com.error.log;
}
```

### Static Site (Nginx)
```nginx
server {
    listen 80;
    server_name static.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name static.example.com;
    root /var/www/static.example.com/public;
    index index.html;

    ssl_certificate /etc/letsencrypt/live/static.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/static.example.com/privkey.pem;
    include /etc/nginx/snippets/ssl-params.conf;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    # SPA support (fallback to index.html)
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache everything aggressively
    location ~* \.(js|css|png|jpg|jpeg|gif|webp|ico|svg|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Cache HTML less aggressively
    location ~* \.html$ {
        expires 1h;
        add_header Cache-Control "public, must-revalidate";
    }

    # Disable directory listing
    autoindex off;

    # Block hidden files
    location ~ /\. {
        deny all;
    }

    access_log /var/log/nginx/static.example.com.access.log;
    error_log /var/log/nginx/static.example.com.error.log;
}
```

---

## Workflows

### Set Up a New Site
1. Create document root: `mkdir -p /var/www/example.com/public_html`
2. Set ownership: `chown -R www-data:www-data /var/www/example.com`
3. Create virtual host config from appropriate template above
4. Test configuration: `nginx -t`
5. Enable site: `ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/`
6. Reload: `systemctl reload nginx`
7. Obtain SSL: `certbot --nginx -d example.com -d www.example.com`
8. Test with curl: `curl -I https://example.com`
9. Verify security headers: `curl -I https://example.com | grep -i 'x-frame\|x-content\|strict'`

### Troubleshoot 502 Bad Gateway
1. Check if backend is running: `systemctl status php8.2-fpm` or `curl localhost:3000`
2. Check Nginx error log: `tail -50 /var/log/nginx/error.log`
3. Check PHP-FPM log: `tail -50 /var/log/php8.2-fpm.log`
4. Check socket exists: `ls -la /run/php/php8.2-fpm.sock`
5. Check socket permissions: ensure Nginx user can read the socket
6. Check PHP-FPM max_children: may be exhausted under load
7. Check upstream timeout: increase `proxy_read_timeout` if backend is slow
8. Check system resources: `free -h` and `df -h`

### Troubleshoot Slow Response
1. Check server load: `uptime`, `top`, `iostat`
2. Check Nginx connections: `curl localhost/nginx_status` (if stub_status enabled)
3. Check PHP-FPM status: `curl localhost/status` (if pm.status_path configured)
4. Review slow PHP log: `tail -50 /var/log/php-fpm/slow.log`
5. Enable Nginx timing in access log: add `$request_time $upstream_response_time`
6. Check for disk IO bottleneck: `iostat -x 1 5`
7. Check for DNS resolution delays in upstream
8. Review gzip settings (over-compression wastes CPU)

---

## Safety Rules

1. **ALWAYS** test configuration before reload: `nginx -t` or `apachectl configtest`
2. **NEVER** reload/restart without testing config first
3. **NEVER** delete a site config without backing it up
4. **ALWAYS** use `reload` (graceful) instead of `restart` unless necessary
5. **NEVER** enable HSTS with `preload` on a new domain — start without preload and short max-age
6. **NEVER** set `client_max_body_size 0` (unlimited) — always set a reasonable limit
7. **ALWAYS** redirect HTTP to HTTPS for all sites
8. **NEVER** expose PHP-FPM status or Nginx stub_status publicly without IP restrictions
9. **ALWAYS** block access to hidden files (`.env`, `.git`, `.htaccess` on Nginx)
10. **NEVER** use `ssl_protocols TLSv1 TLSv1.1` — only TLSv1.2 and TLSv1.3
11. **ALWAYS** set `server_tokens off` to hide version information
12. **ALWAYS** verify certbot renewal cron/timer is active after initial setup
