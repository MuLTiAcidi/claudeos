# Failover Manager

> Automatic failover between primary and backup systems. Manages Keepalived/VRRP, HAProxy, database replication failover, DNS failover, and floating IP management to ensure zero-downtime transitions when primary services fail.

## Safety Rules

- NEVER trigger failover without verifying the primary is truly down (minimum 3 consecutive failed checks)
- NEVER perform failover on databases without confirming replication lag is acceptable
- NEVER modify production Keepalived or HAProxy configs without backing up current config first
- NEVER promote a replica that has unresolved replication errors
- ALWAYS log every failover event with timestamp, reason, and outcome
- ALWAYS verify the backup/secondary is healthy before promoting it
- ALWAYS notify operators before and after any failover action
- ALWAYS test failback procedures in staging before applying in production

---

## 1. Keepalived / VRRP Setup

### Install Keepalived

```bash
apt-get update && apt-get install -y keepalived
```

### Primary (MASTER) Keepalived configuration

```bash
# /etc/keepalived/keepalived.conf on MASTER
cat > /etc/keepalived/keepalived.conf << 'CONF'
global_defs {
    router_id LVS_PRIMARY
    script_user root
    enable_script_security
}

vrrp_script check_service {
    script "/usr/local/bin/failover-check.sh"
    interval 2
    weight -20
    fall 3
    rise 2
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass secretpass123
    }
    virtual_ipaddress {
        192.168.1.100/24 dev eth0
    }
    track_script {
        check_service
    }
    notify /usr/local/bin/keepalived-notify.sh
}
CONF
```

### Backup (BACKUP) Keepalived configuration

```bash
# /etc/keepalived/keepalived.conf on BACKUP
cat > /etc/keepalived/keepalived.conf << 'CONF'
global_defs {
    router_id LVS_BACKUP
    script_user root
    enable_script_security
}

vrrp_script check_service {
    script "/usr/local/bin/failover-check.sh"
    interval 2
    weight -20
    fall 3
    rise 2
}

vrrp_instance VI_1 {
    state BACKUP
    interface eth0
    virtual_router_id 51
    priority 90
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass secretpass123
    }
    virtual_ipaddress {
        192.168.1.100/24 dev eth0
    }
    track_script {
        check_service
    }
    notify /usr/local/bin/keepalived-notify.sh
}
CONF
```

### Keepalived health check script

```bash
#!/bin/bash
# /usr/local/bin/failover-check.sh
# Exit 0 = healthy, Exit 1 = unhealthy

# Check if the main application is responding
if curl -sf --max-time 3 http://localhost/health > /dev/null 2>&1; then
    exit 0
fi

# Check if nginx is running
if systemctl is-active --quiet nginx; then
    exit 0
fi

exit 1
```

### Keepalived notification script

```bash
#!/bin/bash
# /usr/local/bin/keepalived-notify.sh
TYPE=$1
NAME=$2
STATE=$3
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

LOG_FILE="/var/log/failover-manager/keepalived.log"
mkdir -p "$(dirname "$LOG_FILE")"

echo "$TIMESTAMP VRRP $NAME transitioned to $STATE" >> "$LOG_FILE"

case $STATE in
    "MASTER")
        echo "$TIMESTAMP This node is now MASTER — starting services" >> "$LOG_FILE"
        systemctl start nginx 2>/dev/null
        # Send alert
        curl -s -X POST "${SLACK_WEBHOOK_URL}" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"Failover: $(hostname) is now MASTER for $NAME\"}" 2>/dev/null
        ;;
    "BACKUP")
        echo "$TIMESTAMP This node is now BACKUP — standing by" >> "$LOG_FILE"
        ;;
    "FAULT")
        echo "$TIMESTAMP This node is in FAULT state" >> "$LOG_FILE"
        ;;
esac
```

### Manage Keepalived

```bash
# Start/enable
systemctl enable --now keepalived

# Check status
systemctl status keepalived --no-pager

# View VRRP state
journalctl -u keepalived --no-pager -n 20

# Check which node holds the VIP
ip addr show eth0 | grep "192.168.1.100"
```

---

## 2. HAProxy Failover

### Install HAProxy

```bash
apt-get update && apt-get install -y haproxy
```

### HAProxy with primary/backup servers

```bash
# /etc/haproxy/haproxy.cfg
cat > /etc/haproxy/haproxy.cfg << 'CONF'
global
    log /dev/log local0
    maxconn 4096
    user haproxy
    group haproxy
    daemon
    stats socket /var/run/haproxy.sock mode 660 level admin

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  redispatch
    retries 3
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend http_front
    bind *:80
    default_backend app_servers

backend app_servers
    option httpchk GET /health
    http-check expect status 200

    # Primary server
    server primary 10.0.1.10:8080 check inter 3s fall 3 rise 2
    # Backup server — only used if primary is down
    server backup  10.0.1.11:8080 check inter 3s fall 3 rise 2 backup

listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 5s
    stats auth admin:password
CONF
```

### HAProxy runtime management via socket

```bash
# Check server states
echo "show stat" | socat stdio /var/run/haproxy.sock | cut -d',' -f1,2,18 | column -s, -t

# Disable a backend server (for maintenance)
echo "disable server app_servers/primary" | socat stdio /var/run/haproxy.sock

# Enable a backend server
echo "enable server app_servers/primary" | socat stdio /var/run/haproxy.sock

# Set server weight
echo "set weight app_servers/primary 50%" | socat stdio /var/run/haproxy.sock

# Drain connections from a server (graceful)
echo "set server app_servers/primary state drain" | socat stdio /var/run/haproxy.sock

# Force server to ready
echo "set server app_servers/primary state ready" | socat stdio /var/run/haproxy.sock
```

### Validate and reload HAProxy

```bash
# Test config syntax
haproxy -c -f /etc/haproxy/haproxy.cfg

# Graceful reload (no dropped connections)
systemctl reload haproxy
```

---

## 3. PostgreSQL Streaming Replication Failover

### Check replication status on primary

```bash
sudo -u postgres psql -c "SELECT client_addr, state, sent_lsn, write_lsn, flush_lsn, replay_lsn, sync_state FROM pg_stat_replication;"
```

### Check replication lag

```bash
# On replica — check lag in bytes
sudo -u postgres psql -c "SELECT CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0 ELSE EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp()) END AS replication_lag_seconds;"

# On primary — check lag per replica
sudo -u postgres psql -c "SELECT client_addr, pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS replay_lag_bytes FROM pg_stat_replication;"
```

### Promote PostgreSQL replica to primary

```bash
#!/bin/bash
# /usr/local/bin/pg-failover.sh
set -euo pipefail

LOG="/var/log/failover-manager/pg-failover.log"
mkdir -p "$(dirname "$LOG")"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "$TIMESTAMP Starting PostgreSQL failover" >> "$LOG"

# Step 1: Verify primary is truly down
if pg_isready -h PRIMARY_HOST -p 5432 -t 5 2>/dev/null; then
    echo "$TIMESTAMP ABORT: Primary is still responding" >> "$LOG"
    exit 1
fi

# Step 2: Check replication lag before promoting
LAG=$(sudo -u postgres psql -t -c "SELECT EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp());" 2>/dev/null | tr -d ' ')
if [ -n "$LAG" ] && [ "$(echo "$LAG > 30" | bc -l)" -eq 1 ]; then
    echo "$TIMESTAMP WARNING: Replication lag is ${LAG}s — waiting for catchup" >> "$LOG"
    sleep 10
fi

# Step 3: Promote replica
echo "$TIMESTAMP Promoting replica to primary" >> "$LOG"
sudo -u postgres pg_ctl promote -D /var/lib/postgresql/15/main
# Or for newer versions:
# sudo -u postgres psql -c "SELECT pg_promote();"

# Step 4: Verify promotion
sleep 5
IS_RECOVERY=$(sudo -u postgres psql -t -c "SELECT pg_is_in_recovery();" | tr -d ' ')
if [ "$IS_RECOVERY" = "f" ]; then
    echo "$TIMESTAMP SUCCESS: Replica promoted to primary" >> "$LOG"
else
    echo "$TIMESTAMP FAILED: Replica still in recovery mode" >> "$LOG"
    exit 1
fi

# Step 5: Update connection strings / pgbouncer
# Update pgbouncer to point to new primary
# sed -i 's/host=OLD_PRIMARY/host=NEW_PRIMARY/' /etc/pgbouncer/pgbouncer.ini
# systemctl reload pgbouncer

echo "$TIMESTAMP PostgreSQL failover complete" >> "$LOG"
```

### PostgreSQL recovery.conf (standby setup for failback)

```bash
# /var/lib/postgresql/15/main/postgresql.auto.conf additions for standby
cat >> /var/lib/postgresql/15/main/postgresql.auto.conf << 'CONF'
primary_conninfo = 'host=10.0.1.10 port=5432 user=replicator password=replpass application_name=standby1'
CONF

# Create standby signal file
touch /var/lib/postgresql/15/main/standby.signal
chown postgres:postgres /var/lib/postgresql/15/main/standby.signal
```

---

## 4. MySQL Master-Slave Failover

### Check replication status

```bash
mysql -e "SHOW SLAVE STATUS\G" | grep -E "Slave_IO_Running|Slave_SQL_Running|Seconds_Behind_Master|Last_Error"
```

### MySQL failover procedure

```bash
#!/bin/bash
# /usr/local/bin/mysql-failover.sh
set -euo pipefail

LOG="/var/log/failover-manager/mysql-failover.log"
mkdir -p "$(dirname "$LOG")"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

MASTER_HOST="10.0.1.10"
SLAVE_HOST="10.0.1.11"

echo "$TIMESTAMP Starting MySQL failover" >> "$LOG"

# Step 1: Verify master is down
if mysqladmin ping -h "$MASTER_HOST" --connect-timeout=5 2>/dev/null; then
    echo "$TIMESTAMP ABORT: Master is still responding" >> "$LOG"
    exit 1
fi

# Step 2: Stop slave and check position
mysql -h "$SLAVE_HOST" -e "STOP SLAVE;"
mysql -h "$SLAVE_HOST" -e "SHOW SLAVE STATUS\G" >> "$LOG"

# Step 3: Wait for relay log to finish applying
echo "$TIMESTAMP Waiting for relay log replay..." >> "$LOG"
BEHIND=1
while [ "$BEHIND" -ne 0 ]; do
    BEHIND=$(mysql -h "$SLAVE_HOST" -N -e "SELECT COUNT(*) FROM performance_schema.replication_applier_status WHERE SERVICE_STATE='ON';" 2>/dev/null || echo "0")
    sleep 1
done

# Step 4: Promote slave to master
mysql -h "$SLAVE_HOST" -e "STOP SLAVE; RESET SLAVE ALL;"
mysql -h "$SLAVE_HOST" -e "SET GLOBAL read_only = OFF;"
mysql -h "$SLAVE_HOST" -e "SET GLOBAL super_read_only = OFF;"

echo "$TIMESTAMP MySQL slave promoted to master on $SLAVE_HOST" >> "$LOG"

# Step 5: Verify
WRITABLE=$(mysql -h "$SLAVE_HOST" -N -e "SELECT @@read_only;")
if [ "$WRITABLE" = "0" ]; then
    echo "$TIMESTAMP SUCCESS: $SLAVE_HOST is now writable" >> "$LOG"
else
    echo "$TIMESTAMP FAILED: $SLAVE_HOST is still read-only" >> "$LOG"
    exit 1
fi
```

### Using mysqlfailover (MySQL Utilities)

```bash
# Automatic failover monitoring
mysqlfailover --master=root:pass@10.0.1.10:3306 \
  --slaves=root:pass@10.0.1.11:3306,root:pass@10.0.1.12:3306 \
  --failover-mode=auto
```

---

## 5. DNS Failover

### DNS failover with health-check driven updates (Cloudflare API)

```bash
#!/bin/bash
# /usr/local/bin/dns-failover.sh
set -euo pipefail

CF_API_TOKEN="${CLOUDFLARE_API_TOKEN}"
CF_ZONE_ID="${CLOUDFLARE_ZONE_ID}"
RECORD_ID="${CLOUDFLARE_RECORD_ID}"
DOMAIN="app.example.com"

PRIMARY_IP="10.0.1.10"
BACKUP_IP="10.0.1.11"
PRIMARY_URL="http://${PRIMARY_IP}/health"

LOG="/var/log/failover-manager/dns-failover.log"
STATE_FILE="/var/lib/failover-manager/dns-state"
mkdir -p "$(dirname "$LOG")" "$(dirname "$STATE_FILE")"

CURRENT_STATE=$(cat "$STATE_FILE" 2>/dev/null || echo "primary")

# Check primary health
PRIMARY_OK=false
if curl -sf --max-time 5 "$PRIMARY_URL" > /dev/null 2>&1; then
    PRIMARY_OK=true
fi

update_dns() {
    local IP="$1"
    curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${RECORD_ID}" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${IP}\",\"ttl\":60,\"proxied\":false}"
}

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [ "$PRIMARY_OK" = false ] && [ "$CURRENT_STATE" = "primary" ]; then
    echo "$TIMESTAMP Failing over DNS to backup ($BACKUP_IP)" >> "$LOG"
    update_dns "$BACKUP_IP"
    echo "backup" > "$STATE_FILE"
elif [ "$PRIMARY_OK" = true ] && [ "$CURRENT_STATE" = "backup" ]; then
    echo "$TIMESTAMP Failing back DNS to primary ($PRIMARY_IP)" >> "$LOG"
    update_dns "$PRIMARY_IP"
    echo "primary" > "$STATE_FILE"
fi
```

### Route53 DNS failover (AWS CLI)

```bash
# Create a health check
aws route53 create-health-check --caller-reference "$(date +%s)" \
  --health-check-config '{
    "IPAddress": "10.0.1.10",
    "Port": 443,
    "Type": "HTTPS",
    "ResourcePath": "/health",
    "FailureThreshold": 3,
    "RequestInterval": 10
  }'

# Create failover record set
aws route53 change-resource-record-sets --hosted-zone-id ZONE_ID \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "app.example.com",
        "Type": "A",
        "SetIdentifier": "primary",
        "Failover": "PRIMARY",
        "TTL": 60,
        "ResourceRecords": [{"Value": "10.0.1.10"}],
        "HealthCheckId": "HEALTH_CHECK_ID"
      }
    }]
  }'
```

---

## 6. Floating IP Management

### Add a floating IP to an interface

```bash
# Add floating IP
ip addr add 192.168.1.100/24 dev eth0

# Verify
ip addr show eth0

# Send gratuitous ARP to update network
arping -U -c 3 -I eth0 192.168.1.100
```

### Remove floating IP

```bash
ip addr del 192.168.1.100/24 dev eth0
```

### Floating IP failover script

```bash
#!/bin/bash
# /usr/local/bin/floating-ip-failover.sh
set -euo pipefail

VIP="192.168.1.100"
INTERFACE="eth0"
PRIMARY_HOST="10.0.1.10"
CHECK_URL="http://${PRIMARY_HOST}/health"

LOG="/var/log/failover-manager/floating-ip.log"
mkdir -p "$(dirname "$LOG")"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

FAIL_COUNT=0
THRESHOLD=3

while true; do
    if curl -sf --max-time 5 "$CHECK_URL" > /dev/null 2>&1; then
        FAIL_COUNT=0
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "$TIMESTAMP Primary check failed ($FAIL_COUNT/$THRESHOLD)" >> "$LOG"
    fi

    if [ "$FAIL_COUNT" -ge "$THRESHOLD" ]; then
        # Check if we already have the VIP
        if ! ip addr show "$INTERFACE" | grep -q "$VIP"; then
            echo "$TIMESTAMP Acquiring floating IP $VIP" >> "$LOG"
            ip addr add "${VIP}/24" dev "$INTERFACE"
            arping -U -c 3 -I "$INTERFACE" "$VIP" 2>/dev/null
            echo "$TIMESTAMP Floating IP $VIP acquired" >> "$LOG"
        fi
    fi

    sleep 5
done
```

### DigitalOcean floating IP reassignment

```bash
# Reassign floating IP via DO API
curl -s -X POST "https://api.digitalocean.com/v2/floating_ips/${FLOATING_IP}/actions" \
  -H "Authorization: Bearer ${DO_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"type\": \"assign\", \"droplet_id\": ${BACKUP_DROPLET_ID}}"
```

---

## 7. Health-Check Driven Failover Orchestrator

### Comprehensive failover orchestrator

```bash
#!/bin/bash
# /usr/local/bin/failover-orchestrator.sh
set -euo pipefail

CONFIG="/etc/failover-manager/config.env"
source "$CONFIG"

LOG="/var/log/failover-manager/orchestrator.log"
STATE_DIR="/var/lib/failover-manager"
mkdir -p "$(dirname "$LOG")" "$STATE_DIR"

log() {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$LOG"
}

check_primary() {
    local checks_passed=0
    local checks_total=0

    # HTTP health check
    checks_total=$((checks_total + 1))
    if curl -sf --max-time 5 "http://${PRIMARY_HOST}:${PRIMARY_PORT}/health" > /dev/null 2>&1; then
        checks_passed=$((checks_passed + 1))
    fi

    # TCP port check
    checks_total=$((checks_total + 1))
    if nc -z -w3 "$PRIMARY_HOST" "$PRIMARY_PORT" 2>/dev/null; then
        checks_passed=$((checks_passed + 1))
    fi

    # Ping check
    checks_total=$((checks_total + 1))
    if ping -c 1 -W 3 "$PRIMARY_HOST" > /dev/null 2>&1; then
        checks_passed=$((checks_passed + 1))
    fi

    if [ "$checks_passed" -eq "$checks_total" ]; then
        return 0
    fi
    return 1
}

perform_failover() {
    log "=== FAILOVER INITIATED ==="
    log "Primary $PRIMARY_HOST is unresponsive"
    log "Promoting backup $BACKUP_HOST"

    # 1. Update load balancer
    if [ -S /var/run/haproxy.sock ]; then
        echo "disable server backend/primary" | socat stdio /var/run/haproxy.sock
        echo "enable server backend/backup" | socat stdio /var/run/haproxy.sock
        log "HAProxy updated"
    fi

    # 2. Update DNS if configured
    if [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
        /usr/local/bin/dns-failover.sh
        log "DNS updated"
    fi

    # 3. Acquire floating IP if configured
    if [ -n "${FLOATING_IP:-}" ]; then
        ip addr add "${FLOATING_IP}/24" dev eth0 2>/dev/null || true
        arping -U -c 3 -I eth0 "$FLOATING_IP" 2>/dev/null
        log "Floating IP acquired"
    fi

    # 4. Send notification
    log "=== FAILOVER COMPLETE ==="
    echo "failover" > "$STATE_DIR/current-state"
}

perform_failback() {
    log "=== FAILBACK INITIATED ==="
    log "Primary $PRIMARY_HOST is back online"

    if [ -S /var/run/haproxy.sock ]; then
        echo "enable server backend/primary" | socat stdio /var/run/haproxy.sock
        log "HAProxy restored"
    fi

    echo "normal" > "$STATE_DIR/current-state"
    log "=== FAILBACK COMPLETE ==="
}

# Main loop
FAIL_COUNT=0
FAIL_THRESHOLD=${FAIL_THRESHOLD:-3}
CHECK_INTERVAL=${CHECK_INTERVAL:-5}
CURRENT_STATE=$(cat "$STATE_DIR/current-state" 2>/dev/null || echo "normal")

while true; do
    if check_primary; then
        if [ "$CURRENT_STATE" = "failover" ]; then
            # Primary is back — consider failback
            log "Primary recovered — initiating failback"
            perform_failback
            CURRENT_STATE="normal"
        fi
        FAIL_COUNT=0
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        log "Primary check failed ($FAIL_COUNT/$FAIL_THRESHOLD)"

        if [ "$FAIL_COUNT" -ge "$FAIL_THRESHOLD" ] && [ "$CURRENT_STATE" = "normal" ]; then
            perform_failover
            CURRENT_STATE="failover"
        fi
    fi

    sleep "$CHECK_INTERVAL"
done
```

### Configuration file

```bash
# /etc/failover-manager/config.env
PRIMARY_HOST=10.0.1.10
PRIMARY_PORT=8080
BACKUP_HOST=10.0.1.11
BACKUP_PORT=8080
FAIL_THRESHOLD=3
CHECK_INTERVAL=5
FLOATING_IP=192.168.1.100
```

---

## 8. Failover Testing

### Simulate primary failure

```bash
# On primary node — stop the service to trigger failover
systemctl stop nginx

# Verify failover occurred
# On backup: check if VIP is assigned
ip addr show eth0 | grep "192.168.1.100"

# Check HAProxy stats
echo "show stat" | socat stdio /var/run/haproxy.sock | grep -E "primary|backup"
```

### Test failback

```bash
# Restart primary service
systemctl start nginx

# Verify failback
# Wait for health checks to detect recovery
sleep 30

# Check VIP moved back
ip addr show eth0 | grep "192.168.1.100"
```

### Automated failover drill

```bash
#!/bin/bash
# /usr/local/bin/failover-drill.sh
echo "=== Failover Drill Started at $(date -u) ==="
echo "Step 1: Recording current state"
echo "show stat" | socat stdio /var/run/haproxy.sock 2>/dev/null

echo "Step 2: Simulating primary failure"
systemctl stop nginx
echo "Primary nginx stopped"

echo "Step 3: Waiting for failover detection (15s)"
sleep 15

echo "Step 4: Checking failover status"
echo "show stat" | socat stdio /var/run/haproxy.sock 2>/dev/null

echo "Step 5: Verifying backup is serving traffic"
curl -s -o /dev/null -w "HTTP %{http_code}" http://192.168.1.100/health

echo "Step 6: Restoring primary"
systemctl start nginx
sleep 10

echo "Step 7: Final state"
echo "show stat" | socat stdio /var/run/haproxy.sock 2>/dev/null

echo "=== Failover Drill Complete ==="
```
