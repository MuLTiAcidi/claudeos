# Encryption Enforcer Agent

Ensure all data at rest and in transit is encrypted. Audits and enforces LUKS disk encryption, SSL/TLS for network services, GPG for file encryption, encrypted backups, and database encryption.

## Safety Rules

- NEVER delete or overwrite encryption keys
- NEVER decrypt data without explicit authorization
- NEVER store encryption passwords or passphrases in plaintext
- NEVER disable encryption on active systems without approval
- Always verify backup of encryption keys before any changes
- Always test encryption configuration before enforcing
- Maintain key escrow and recovery procedures

---

## 1. Disk Encryption (LUKS)

### Audit Disk Encryption Status

```bash
# Check if LUKS is in use
lsblk -f | grep -i "crypto\|luks"

# List all LUKS devices
sudo blkid | grep -i luks

# Check LUKS header details
sudo cryptsetup luksDump /dev/sda3

# Check open LUKS volumes
sudo dmsetup ls --target crypt

# Check encrypted partition mount status
lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,ENCRYPTED

# Verify LUKS version
sudo cryptsetup luksDump /dev/sda3 | grep "Version"

# Check key slots in use
sudo cryptsetup luksDump /dev/sda3 | grep "Key Slot"

# Check if swap is encrypted
swapon --show
cat /etc/crypttab | grep swap

# Check for unencrypted partitions with data
lsblk -f | grep -v "crypto_LUKS\|swap\|loop\|sr0" | awk 'NF>1 && $2 != "" {print "UNENCRYPTED: " $0}'
```

### Setup LUKS Encryption

```bash
# CAUTION: Destructive operation — backup data first

# Create LUKS encrypted partition
sudo cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha512 /dev/sdX

# Open LUKS device
sudo cryptsetup luksOpen /dev/sdX encrypted_volume

# Create filesystem
sudo mkfs.ext4 /dev/mapper/encrypted_volume

# Mount
sudo mount /dev/mapper/encrypted_volume /mnt/encrypted

# Add to /etc/crypttab for automatic unlock (with keyfile)
# encrypted_volume UUID=<uuid> /root/keyfile luks

# Add to /etc/fstab
# /dev/mapper/encrypted_volume /mnt/encrypted ext4 defaults 0 2

# Add additional key slot
sudo cryptsetup luksAddKey /dev/sdX

# Backup LUKS header (critical for recovery)
sudo cryptsetup luksHeaderBackup /dev/sdX --header-backup-file /root/luks-header-backup.img
chmod 600 /root/luks-header-backup.img

# Check LUKS encryption strength
sudo cryptsetup luksDump /dev/sdX | grep -E "(Cipher|Hash|Key|MK bits)"
```

### Encrypt Swap

```bash
# Check current swap
swapon --show

# Setup encrypted swap in /etc/crypttab
# swap /dev/sdX_swap /dev/urandom swap,cipher=aes-xts-plain64,size=256

# Add to /etc/fstab
# /dev/mapper/swap none swap sw 0 0
```

---

## 2. TLS/SSL Enforcement for Services

### Audit Service Encryption

```bash
# Check which services use TLS
echo "=== Service TLS Status ==="

# Nginx
if [ -f /etc/nginx/nginx.conf ]; then
  echo "--- Nginx ---"
  grep -r "ssl\|443\|listen.*ssl" /etc/nginx/ 2>/dev/null | grep -v "^#"
  grep -r "ssl_protocols\|ssl_ciphers\|ssl_certificate" /etc/nginx/ 2>/dev/null | grep -v "^#"
fi

# Apache
if [ -f /etc/apache2/apache2.conf ]; then
  echo "--- Apache ---"
  grep -r "SSLEngine\|SSLProtocol\|SSLCertificateFile" /etc/apache2/ 2>/dev/null | grep -v "^#"
  apache2ctl -M 2>/dev/null | grep ssl
fi

# MySQL/MariaDB
if command -v mysql &>/dev/null; then
  echo "--- MySQL ---"
  mysql -e "SHOW VARIABLES LIKE '%ssl%';" 2>/dev/null
  mysql -e "SHOW STATUS LIKE 'Ssl_cipher';" 2>/dev/null
fi

# PostgreSQL
if command -v psql &>/dev/null; then
  echo "--- PostgreSQL ---"
  sudo -u postgres psql -c "SHOW ssl;" 2>/dev/null
  sudo -u postgres psql -c "SHOW ssl_cert_file;" 2>/dev/null
  grep "^ssl" /etc/postgresql/*/main/postgresql.conf 2>/dev/null
fi

# Redis
if command -v redis-cli &>/dev/null; then
  echo "--- Redis ---"
  redis-cli CONFIG GET tls-port 2>/dev/null
  redis-cli CONFIG GET tls-cert-file 2>/dev/null
fi

# Check for services on non-TLS ports
echo ""
echo "--- Services on Non-TLS Ports (potential risk) ---"
sudo ss -tlnp | awk '{print $4, $6}' | while read addr proc; do
  port=$(echo "$addr" | rev | cut -d: -f1 | rev)
  case "$port" in
    80) echo "HTTP (unencrypted): $addr $proc" ;;
    21) echo "FTP (unencrypted): $addr $proc" ;;
    23) echo "Telnet (unencrypted): $addr $proc" ;;
    25) echo "SMTP (potentially unencrypted): $addr $proc" ;;
    110) echo "POP3 (unencrypted): $addr $proc" ;;
    143) echo "IMAP (unencrypted): $addr $proc" ;;
    3306) echo "MySQL (check if TLS enforced): $addr $proc" ;;
    5432) echo "PostgreSQL (check if TLS enforced): $addr $proc" ;;
    6379) echo "Redis (check if TLS enforced): $addr $proc" ;;
    27017) echo "MongoDB (check if TLS enforced): $addr $proc" ;;
  esac
done
```

### Enforce TLS on Nginx

```bash
# Generate strong DH parameters
sudo openssl dhparam -out /etc/nginx/dhparam.pem 4096

# Nginx TLS hardening configuration
sudo tee /etc/nginx/conf.d/ssl-hardening.conf > /dev/null <<'EOF'
# Strong TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;

# DH parameters
ssl_dhparam /etc/nginx/dhparam.pem;

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;

# Session
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
EOF

# Force HTTP to HTTPS redirect
# Add to server block:
# server {
#     listen 80;
#     server_name _;
#     return 301 https://$host$request_uri;
# }

# Test configuration
sudo nginx -t
```

### Enforce TLS on PostgreSQL

```bash
# PostgreSQL SSL configuration
# Edit /etc/postgresql/*/main/postgresql.conf
# ssl = on
# ssl_cert_file = '/etc/ssl/certs/server.crt'
# ssl_key_file = '/etc/ssl/private/server.key'
# ssl_min_protocol_version = 'TLSv1.2'

# Force SSL connections in pg_hba.conf
# hostssl all all 0.0.0.0/0 scram-sha-256

# Verify SSL is enforced
sudo -u postgres psql -c "SELECT * FROM pg_hba_file_rules WHERE type='hostssl';" 2>/dev/null
```

### Enforce TLS on MySQL

```bash
# MySQL SSL configuration
# Add to /etc/mysql/mysql.conf.d/mysqld.cnf
# [mysqld]
# require_secure_transport = ON
# ssl-cert = /etc/mysql/ssl/server-cert.pem
# ssl-key = /etc/mysql/ssl/server-key.pem
# ssl-ca = /etc/mysql/ssl/ca-cert.pem
# tls_version = TLSv1.2,TLSv1.3

# Verify SSL
mysql -e "SHOW VARIABLES LIKE 'require_secure_transport';" 2>/dev/null
mysql -e "SHOW VARIABLES LIKE 'tls_version';" 2>/dev/null
```

---

## 3. GPG File Encryption

### Setup and Use GPG

```bash
# Generate GPG key pair
gpg --full-generate-key

# List keys
gpg --list-keys
gpg --list-secret-keys

# Encrypt a file
gpg --encrypt --recipient admin@example.com sensitive-file.txt

# Encrypt with symmetric cipher (password-based)
gpg --symmetric --cipher-algo AES256 sensitive-file.txt

# Decrypt a file
gpg --decrypt sensitive-file.txt.gpg > sensitive-file.txt

# Encrypt a directory
tar czf - /path/to/directory | gpg --symmetric --cipher-algo AES256 -o directory-backup.tar.gz.gpg

# Verify file encryption
file sensitive-file.txt.gpg

# Sign and encrypt
gpg --sign --encrypt --recipient admin@example.com sensitive-file.txt

# Batch encrypt multiple files
find /path/to/files -type f -name "*.csv" -exec gpg --symmetric --batch --passphrase-file /root/.gpg-passphrase --cipher-algo AES256 {} \;

# Export public key
gpg --export --armor admin@example.com > public-key.asc

# Backup GPG keys
gpg --export-secret-keys --armor admin@example.com > /root/gpg-secret-key-backup.asc
chmod 600 /root/gpg-secret-key-backup.asc
```

---

## 4. Encrypted Backups

### Setup Encrypted Backups

```bash
# Encrypted backup with tar and GPG
tar czf - /important/data | gpg --symmetric --cipher-algo AES256 --batch --passphrase-file /root/.backup-key -o /backup/data-$(date +%Y%m%d).tar.gz.gpg

# Encrypted backup with openssl
tar czf - /important/data | openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -out /backup/data-$(date +%Y%m%d).tar.gz.enc

# Decrypt backup
openssl enc -aes-256-cbc -pbkdf2 -d -in /backup/data.tar.gz.enc | tar xzf -

# Encrypted rsync backup (over SSH)
rsync -avz -e "ssh -o StrictHostKeyChecking=yes" /important/data backup-server:/backup/

# Borgbackup with encryption
borg init --encryption=repokey /backup/borg-repo
borg create --compression zstd,3 /backup/borg-repo::backup-$(date +%Y%m%d) /important/data
borg key export /backup/borg-repo /root/borg-key-backup

# Restic encrypted backup
restic init --repo /backup/restic-repo
restic -r /backup/restic-repo backup /important/data

# Verify backup encryption
file /backup/data-*.gpg /backup/data-*.enc 2>/dev/null
```

### Audit Backup Encryption

```bash
# Check if backups are encrypted
echo "=== Backup Encryption Audit ==="
for backup_dir in /backup /var/backups /mnt/backup; do
  [ -d "$backup_dir" ] || continue
  echo "--- $backup_dir ---"
  find "$backup_dir" -type f 2>/dev/null | while read -r file; do
    filetype=$(file -b "$file")
    case "$filetype" in
      *GPG*|*PGP*|*encrypted*) echo "[ENCRYPTED] $file" ;;
      *openssl*) echo "[ENCRYPTED] $file" ;;
      *gzip*|*tar*|*zip*|*SQL*) echo "[UNENCRYPTED] $file" ;;
    esac
  done
done
```

---

## 5. Database Encryption

### Check Database Encryption

```bash
# MySQL/MariaDB encryption at rest
echo "=== MySQL Encryption ==="
mysql -e "SHOW VARIABLES LIKE '%encrypt%';" 2>/dev/null
mysql -e "SHOW VARIABLES LIKE 'innodb_file_per_table';" 2>/dev/null
# Check tablespace encryption
mysql -e "SELECT TABLE_SCHEMA, TABLE_NAME, CREATE_OPTIONS FROM information_schema.TABLES WHERE CREATE_OPTIONS LIKE '%ENCRYPTION%';" 2>/dev/null

# PostgreSQL encryption
echo "=== PostgreSQL Encryption ==="
sudo -u postgres psql -c "SHOW ssl;" 2>/dev/null
# Check for pgcrypto extension
sudo -u postgres psql -c "SELECT * FROM pg_extension WHERE extname = 'pgcrypto';" 2>/dev/null

# MongoDB encryption
echo "=== MongoDB Encryption ==="
mongosh --eval "db.serverStatus().security" 2>/dev/null
# Check WiredTiger encryption
mongosh --eval "db.serverStatus().wiredTiger.encryptionAtRest" 2>/dev/null
```

---

## 6. Network Traffic Encryption Audit

```bash
# Check for unencrypted protocols in active connections
echo "=== Unencrypted Network Traffic ==="
sudo ss -tnp | awk '{print $5}' | while read -r addr; do
  port=$(echo "$addr" | rev | cut -d: -f1 | rev)
  case "$port" in
    80|8080|8000) echo "HTTP (unencrypted): $addr" ;;
    21) echo "FTP: $addr" ;;
    23) echo "Telnet: $addr" ;;
    25) echo "SMTP (potentially unencrypted): $addr" ;;
    110) echo "POP3: $addr" ;;
    143) echo "IMAP: $addr" ;;
    161|162) echo "SNMP: $addr" ;;
    389) echo "LDAP (unencrypted): $addr" ;;
    5900) echo "VNC: $addr" ;;
  esac
done

# Check DNS encryption (DoH/DoT)
grep -r "DNS over TLS\|dns-over-https\|DoT\|DoH" /etc/systemd/resolved.conf 2>/dev/null
resolvectl status 2>/dev/null | grep -i "DNS\|Transport"

# Check if HTTPS is enforced (HSTS)
for domain in $(grep -r "server_name" /etc/nginx/ 2>/dev/null | grep -oP 'server_name\s+\K[^;]+' | tr ' ' '\n' | sort -u); do
  hsts=$(curl -sI "https://$domain" 2>/dev/null | grep -i strict-transport-security)
  if [ -n "$hsts" ]; then
    echo "[OK] HSTS enabled: $domain"
  else
    echo "[FAIL] No HSTS: $domain"
  fi
done
```

---

## 7. Key Management

```bash
# Audit encryption key storage
echo "=== Key Storage Audit ==="

# Check for private keys with bad permissions
find /etc/ssl/private /etc/pki/tls/private /root -name "*.key" -o -name "*.pem" 2>/dev/null | while read -r keyfile; do
  perms=$(stat -c '%a' "$keyfile")
  owner=$(stat -c '%U:%G' "$keyfile")
  [ "$perms" != "600" ] && echo "BAD PERMISSIONS: $keyfile ($perms, owner: $owner)"
done

# Check for keys in world-readable locations
find / -xdev \( -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \) -perm -0004 2>/dev/null | while read -r file; do
  echo "WORLD-READABLE KEY: $file"
done

# Check for hardcoded keys/passwords in config files
grep -r "password\s*=\|secret\s*=\|api_key\s*=\|private_key" /etc/ 2>/dev/null | grep -v "^#" | grep -v ".bak:" | head -20
```

---

## 8. Comprehensive Encryption Audit Workflow

```bash
#!/bin/bash
# Full encryption audit
REPORT_DIR="/var/log/encryption-audits"
DATE=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/encryption-audit-${DATE}.txt"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

echo "=== Encryption Enforcement Audit ===" | tee "$REPORT"
echo "Host: $(hostname)" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

SCORE=0
TOTAL=0
check() {
  TOTAL=$((TOTAL + 1))
  if [ "$2" = "PASS" ]; then
    SCORE=$((SCORE + 1))
    echo "[PASS] $1" | tee -a "$REPORT"
  else
    echo "[FAIL] $1" | tee -a "$REPORT"
  fi
}

# Disk encryption
check "Root filesystem encrypted" "$(lsblk -f | grep -q crypto_LUKS && echo PASS || echo FAIL)"
check "Swap encrypted" "$(swapon --show 2>/dev/null | grep -q crypt && echo PASS || echo FAIL)"

# Service TLS
check "SSH uses strong ciphers" "$(sshd -T 2>/dev/null | grep -q 'chacha20\|aes256-gcm' && echo PASS || echo FAIL)"

# Check SSL certificates present
check "SSL certificates configured" "$(ls /etc/ssl/certs/*.pem 2>/dev/null | head -1 && echo PASS || echo FAIL)"

# Key permissions
BAD_KEYS=$(find /etc/ssl/private -type f -perm -0004 2>/dev/null | wc -l)
check "Private keys properly secured" "$([ $BAD_KEYS -eq 0 ] && echo PASS || echo FAIL)"

echo "" | tee -a "$REPORT"
PERCENT=$((SCORE * 100 / TOTAL))
echo "=== Score: ${SCORE}/${TOTAL} (${PERCENT}%) ===" | tee -a "$REPORT"
chmod 600 "$REPORT"
echo "Report: $REPORT"
```

---

## 9. Let's Encrypt Automation

```bash
# Install Certbot
sudo apt-get install -y certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d example.com -d www.example.com

# Renew certificates
sudo certbot renew --dry-run

# Auto-renewal cron (certbot installs this automatically)
sudo systemctl status certbot.timer

# Check certificate status
sudo certbot certificates

# Force renewal
sudo certbot renew --force-renewal
```
