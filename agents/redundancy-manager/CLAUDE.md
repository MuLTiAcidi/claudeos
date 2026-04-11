# Redundancy Manager Agent

Manages replicas, mirrors, and high-availability clusters: DRBD block-level replication, rsync mirroring, GlusterFS volumes, PostgreSQL streaming replication, MySQL master/slave, Redis Sentinel, Pacemaker/Corosync clusters, and replica health monitoring with split-brain prevention.

---

## Safety Rules

- NEVER promote a replica to primary without confirming the original primary is dead (split-brain).
- ALWAYS use STONITH/fencing in Pacemaker clusters — no fencing means data corruption.
- NEVER run `pg_basebackup` against a busy primary without `--checkpoint=fast` planning.
- ALWAYS verify replication lag before failover.
- ALWAYS have an odd number of nodes for quorum (3, 5, 7) — never 2 without a witness/qdevice.
- NEVER delete the WAL/binlog before replicas have consumed it.
- ALWAYS test failover in a non-production environment first.
- Encrypt replication links over untrusted networks (TLS, SSH tunnels, WireGuard).
- Log every promotion / demotion / failover to `/var/log/redundancy-manager.log`.
- Backup `/etc/drbd.d/`, `/var/lib/pgsql/`, `corosync.conf` before changes.

---

## 1. DRBD — Block-Level Disk Replication

### Install on Both Nodes

```bash
apt install -y drbd-utils linux-headers-$(uname -r)
modprobe drbd
echo drbd >> /etc/modules
```

### Resource Definition

```ini
# /etc/drbd.d/r0.res (identical on both nodes)
resource r0 {
  protocol C;
  on node1 {
    device    /dev/drbd0;
    disk      /dev/sdb1;
    address   10.0.0.1:7788;
    meta-disk internal;
  }
  on node2 {
    device    /dev/drbd0;
    disk      /dev/sdb1;
    address   10.0.0.2:7788;
    meta-disk internal;
  }
}
```

### Initialize Metadata (Both Nodes)

```bash
drbdadm create-md r0
systemctl enable --now drbd
drbdadm up r0
```

### Force Initial Sync (Primary Node Only)

```bash
drbdadm primary --force r0
cat /proc/drbd
drbdadm status
```

### Create Filesystem and Mount (Primary)

```bash
mkfs.ext4 /dev/drbd0
mkdir -p /mnt/drbd
mount /dev/drbd0 /mnt/drbd
```

### Failover (manual)

```bash
# On old primary
umount /mnt/drbd
drbdadm secondary r0

# On new primary
drbdadm primary r0
mount /dev/drbd0 /mnt/drbd
```

### Resolve Split-Brain (Discard Survivor’s Changes)

```bash
# Victim node
drbdadm secondary r0
drbdadm disconnect r0
drbdadm -- --discard-my-data connect r0

# Survivor node
drbdadm connect r0
drbdadm status
```

---

## 2. rsync Mirror Automation

### One-Shot Pull

```bash
rsync -aHAX --delete --numeric-ids \
  -e "ssh -i /root/.ssh/mirror_key -o StrictHostKeyChecking=accept-new" \
  primary.example.com:/srv/data/ /srv/data/
```

### Continuous Mirror Script

```bash
#!/usr/bin/env bash
# /usr/local/bin/mirror-sync.sh
set -euo pipefail
SRC="primary.example.com:/srv/data/"
DST="/srv/data/"
LOG=/var/log/redundancy-manager.log
LOCK=/var/run/mirror-sync.lock

exec 9>"$LOCK"
flock -n 9 || { echo "[$(date -Iseconds)] mirror already running"; exit 0; }

rsync -aHAX --delete --numeric-ids --partial --inplace \
  --bwlimit=50000 \
  -e "ssh -i /root/.ssh/mirror_key" \
  "$SRC" "$DST" 2>&1 \
  | tee -a "$LOG"

echo "[$(date -Iseconds)] mirror-sync done" >> "$LOG"
```

### Schedule via Cron (Every 5 Minutes)

```bash
chmod +x /usr/local/bin/mirror-sync.sh
( crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/mirror-sync.sh" ) | crontab -
```

### Verify Mirror Integrity

```bash
rsync -ani --delete primary:/srv/data/ /srv/data/ | head
```

---

## 3. GlusterFS Distributed Replicated Volume

### Install on All Nodes

```bash
apt install -y glusterfs-server
systemctl enable --now glusterd
```

### Probe Peers (from node1)

```bash
gluster peer probe node2
gluster peer probe node3
gluster peer status
```

### Create Replica 3 Volume

```bash
mkdir -p /data/brick1/gv0   # on each node
gluster volume create gv0 replica 3 \
  node1:/data/brick1/gv0 \
  node2:/data/brick1/gv0 \
  node3:/data/brick1/gv0
gluster volume start gv0
gluster volume info gv0
```

### Mount on Clients

```bash
mkdir -p /mnt/gluster
mount -t glusterfs node1:/gv0 /mnt/gluster
echo "node1:/gv0 /mnt/gluster glusterfs defaults,_netdev,backup-volfile-servers=node2:node3 0 0" >> /etc/fstab
```

### Heal Status

```bash
gluster volume heal gv0 info
gluster volume heal gv0
gluster volume status gv0
```

---

## 4. PostgreSQL Streaming Replication

### Primary Configuration `/etc/postgresql/16/main/postgresql.conf`

```conf
listen_addresses = '*'
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10
hot_standby = on
wal_keep_size = 1GB
```

### Primary `pg_hba.conf`

```
host replication replicator 10.0.0.0/24 scram-sha-256
```

### Create Replication User

```sql
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'STRONGPASS';
SELECT pg_create_physical_replication_slot('replica1');
```

### Bootstrap Replica with pg_basebackup

```bash
systemctl stop postgresql@16-main
rm -rf /var/lib/postgresql/16/main/*

PGPASSWORD=STRONGPASS pg_basebackup \
  -h primary.example.com -U replicator \
  -D /var/lib/postgresql/16/main \
  -Fp -Xs -P -R --slot=replica1

chown -R postgres:postgres /var/lib/postgresql/16/main
systemctl start postgresql@16-main
```

### Verify Replication

```bash
# On primary
sudo -u postgres psql -c "SELECT client_addr, state, sync_state, write_lag, flush_lag, replay_lag FROM pg_stat_replication;"

# On replica
sudo -u postgres psql -c "SELECT pg_is_in_recovery();"
sudo -u postgres psql -c "SELECT now() - pg_last_xact_replay_timestamp() AS lag;"
```

### Promote Replica (Failover)

```bash
sudo -u postgres pg_ctl promote -D /var/lib/postgresql/16/main
sudo -u postgres psql -c "SELECT pg_is_in_recovery();"  # should be f
```

---

## 5. MySQL / MariaDB Master-Slave Replication

### Master `/etc/mysql/mariadb.conf.d/50-server.cnf`

```ini
[mysqld]
server-id        = 1
log_bin          = /var/log/mysql/mysql-bin.log
binlog_format    = ROW
binlog_do_db     = appdb
expire_logs_days = 7
```

### Create Replication User

```sql
CREATE USER 'repl'@'10.0.0.%' IDENTIFIED BY 'STRONGPASS';
GRANT REPLICATION SLAVE ON *.* TO 'repl'@'10.0.0.%';
FLUSH PRIVILEGES;
SHOW MASTER STATUS;
-- Note File and Position
```

### Dump for Replica Bootstrap

```bash
mysqldump --all-databases --master-data=2 --single-transaction --quick \
  -uroot -p > /tmp/master.sql
scp /tmp/master.sql replica:/tmp/
```

### Slave `/etc/mysql/mariadb.conf.d/50-server.cnf`

```ini
[mysqld]
server-id        = 2
relay_log        = /var/log/mysql/mysql-relay-bin.log
read_only        = 1
```

### Restore + Configure on Slave

```bash
mysql -uroot -p < /tmp/master.sql
```

```sql
CHANGE MASTER TO
  MASTER_HOST='10.0.0.1',
  MASTER_USER='repl',
  MASTER_PASSWORD='STRONGPASS',
  MASTER_LOG_FILE='mysql-bin.000001',
  MASTER_LOG_POS=12345;
START SLAVE;
SHOW SLAVE STATUS\G
```

### Healthy Output

```
Slave_IO_Running: Yes
Slave_SQL_Running: Yes
Seconds_Behind_Master: 0
```

### Promote Slave on Failover

```sql
STOP SLAVE;
RESET SLAVE ALL;
SET GLOBAL read_only = 0;
SHOW MASTER STATUS;
```

---

## 6. Redis Sentinel HA

### Redis Master `/etc/redis/redis.conf`

```conf
bind 0.0.0.0
protected-mode no
requirepass STRONGPASS
masterauth STRONGPASS
```

### Replica `/etc/redis/redis.conf`

```conf
bind 0.0.0.0
replicaof 10.0.0.1 6379
masterauth STRONGPASS
requirepass STRONGPASS
```

### Sentinel Config `/etc/redis/sentinel.conf` (3 sentinels minimum)

```conf
port 26379
sentinel monitor mymaster 10.0.0.1 6379 2
sentinel auth-pass mymaster STRONGPASS
sentinel down-after-milliseconds mymaster 5000
sentinel parallel-syncs mymaster 1
sentinel failover-timeout mymaster 10000
```

### Start Sentinel

```bash
redis-sentinel /etc/redis/sentinel.conf
# or via systemd
systemctl enable --now redis-sentinel
```

### Check Status

```bash
redis-cli -p 26379 sentinel masters
redis-cli -p 26379 sentinel slaves mymaster
redis-cli -p 26379 sentinel get-master-addr-by-name mymaster
```

### Manual Failover

```bash
redis-cli -p 26379 sentinel failover mymaster
```

---

## 7. Pacemaker / Corosync Cluster

### Install on All Nodes

```bash
apt install -y pacemaker corosync pcs fence-agents
systemctl enable --now pcsd
echo "hacluster:STRONGPASS" | chpasswd
```

### Authenticate Nodes

```bash
pcs host auth node1 node2 node3 -u hacluster -p STRONGPASS
pcs cluster setup mycluster node1 node2 node3
pcs cluster start --all
pcs cluster enable --all
pcs status
```

### Configure Fencing (REQUIRED)

```bash
pcs stonith create fence_node1 fence_ipmilan \
  ipaddr=10.0.0.101 login=admin passwd=PASS \
  pcmk_host_list=node1
pcs property set stonith-enabled=true
```

### Add a Floating VIP Resource

```bash
pcs resource create VIP ocf:heartbeat:IPaddr2 \
  ip=10.0.0.100 cidr_netmask=24 \
  op monitor interval=10s
```

### Add a Service Resource

```bash
pcs resource create WebSite ocf:heartbeat:nginx \
  configfile=/etc/nginx/nginx.conf \
  op monitor interval=30s
pcs constraint colocation add WebSite with VIP INFINITY
pcs constraint order VIP then WebSite
```

### Cluster Status

```bash
pcs status
crm_mon -1
pcs resource status
```

### Manual Move

```bash
pcs resource move WebSite node2
pcs resource clear WebSite
```

---

## 8. Application Clustering — keepalived (VRRP)

### Install on Both Nodes

```bash
apt install -y keepalived
```

### MASTER Config `/etc/keepalived/keepalived.conf`

```conf
vrrp_script chk_nginx {
  script "/usr/bin/pgrep nginx"
  interval 2
  weight 2
}

vrrp_instance VI_1 {
  state MASTER
  interface eth0
  virtual_router_id 51
  priority 110
  advert_int 1
  authentication {
    auth_type PASS
    auth_pass STRONGPASS
  }
  virtual_ipaddress {
    10.0.0.100/24
  }
  track_script {
    chk_nginx
  }
}
```

### BACKUP differs in `state BACKUP` and `priority 100`.

```bash
systemctl enable --now keepalived
ip addr show eth0 | grep 10.0.0.100
```

---

## 9. Replica Health Monitoring

### Generic Lag-Check Script

```bash
#!/usr/bin/env bash
# /usr/local/bin/replica-healthcheck.sh
set -euo pipefail
LOG=/var/log/redundancy-manager.log
WARN=10
CRIT=60

# PostgreSQL
if command -v psql >/dev/null && sudo -u postgres psql -tAc "SELECT pg_is_in_recovery();" 2>/dev/null | grep -q t; then
  LAG=$(sudo -u postgres psql -tAc "SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::int")
  echo "[$(date -Iseconds)] pg_lag=${LAG}s" >> "$LOG"
  [ "$LAG" -ge "$CRIT" ] && /usr/local/bin/redundancy-notify.sh "PG replica lag CRIT ${LAG}s"
fi

# MySQL
if command -v mysql >/dev/null; then
  LAG=$(mysql -uroot -pSTRONGPASS -e "SHOW SLAVE STATUS\G" 2>/dev/null | awk -F': ' '/Seconds_Behind_Master/{print $2}')
  if [ -n "${LAG:-}" ] && [ "$LAG" != "NULL" ]; then
    echo "[$(date -Iseconds)] mysql_lag=${LAG}s" >> "$LOG"
    [ "$LAG" -ge "$CRIT" ] && /usr/local/bin/redundancy-notify.sh "MySQL replica lag CRIT ${LAG}s"
  fi
fi

# DRBD
if command -v drbdadm >/dev/null; then
  STATE=$(drbdadm status r0 2>/dev/null | awk '/role:/ {print $2}')
  echo "[$(date -Iseconds)] drbd_state=$STATE" >> "$LOG"
fi

# Redis
if command -v redis-cli >/dev/null; then
  ROLE=$(redis-cli -a STRONGPASS info replication 2>/dev/null | awk -F: '/^role/{print $2}' | tr -d '\r')
  echo "[$(date -Iseconds)] redis_role=$ROLE" >> "$LOG"
fi
```

### Run Every Minute

```bash
chmod +x /usr/local/bin/replica-healthcheck.sh
( crontab -l 2>/dev/null; echo "* * * * * /usr/local/bin/replica-healthcheck.sh" ) | crontab -
```

---

## 10. Split-Brain Prevention

### Quorum (Pacemaker)

```bash
pcs property set no-quorum-policy=stop
corosync-quorumtool
```

### qdevice for 2-Node Clusters

```bash
apt install -y corosync-qdevice corosync-qnetd
pcs qdevice setup model net --enable --start
pcs cluster auth qnet-host
pcs quorum device add model net host=qnet-host algorithm=ffsplit
```

### MySQL Group Replication / Galera (avoids split-brain by design)

```bash
# Galera node config
[galera]
wsrep_on=ON
wsrep_provider=/usr/lib/galera/libgalera_smm.so
wsrep_cluster_address="gcomm://10.0.0.1,10.0.0.2,10.0.0.3"
wsrep_node_address="10.0.0.1"
wsrep_sst_method=rsync
binlog_format=ROW
default_storage_engine=InnoDB
innodb_autoinc_lock_mode=2
```

---

## 11. Backup of Replication Configuration

```bash
mkdir -p /var/backups/redundancy/$(date +%F)
cp -a /etc/drbd.d /var/backups/redundancy/$(date +%F)/ 2>/dev/null || true
cp -a /etc/postgresql /var/backups/redundancy/$(date +%F)/ 2>/dev/null || true
cp -a /etc/mysql /var/backups/redundancy/$(date +%F)/ 2>/dev/null || true
cp -a /etc/corosync /var/backups/redundancy/$(date +%F)/ 2>/dev/null || true
cp -a /etc/redis /var/backups/redundancy/$(date +%F)/ 2>/dev/null || true
```

---

## 12. Failover Workflow

1. **Detect**: replica monitor reports primary unreachable for >N seconds.
2. **Verify**: independent check (ICMP + TCP + app health) from a 3rd witness.
3. **Fence**: STONITH the dead primary (or confirm power-off).
4. **Promote**: pg_ctl promote / `STOP SLAVE; RESET SLAVE ALL` / `drbdadm primary`.
5. **Reroute**: keepalived/Pacemaker moves the VIP, or update DNS/HAProxy.
6. **Notify**: webhook/email/Slack.
7. **Re-bootstrap old primary** as a new replica once recovered.
8. **Document**: append failover event to `/var/log/redundancy-manager.log`.

---

## 13. Notification Helper

```bash
#!/usr/bin/env bash
# /usr/local/bin/redundancy-notify.sh
MSG="$1"
HOST=$(hostname)
[ -n "${REDUNDANCY_WEBHOOK:-}" ] && curl -fsS -X POST "$REDUNDANCY_WEBHOOK" \
  -H 'Content-Type: application/json' \
  -d "{\"text\":\"[$HOST] redundancy: $MSG\"}" >/dev/null || true
echo "[$(date -Iseconds)] $MSG" >> /var/log/redundancy-manager.log
```

```bash
chmod +x /usr/local/bin/redundancy-notify.sh
```

---

## 14. Verification Checklist

```bash
# DRBD
drbdadm status

# PostgreSQL
sudo -u postgres psql -c "SELECT * FROM pg_stat_replication;"

# MySQL
mysql -uroot -p -e "SHOW SLAVE STATUS\G" | grep -E "Slave_(IO|SQL)_Running|Seconds_Behind"

# Redis Sentinel
redis-cli -p 26379 sentinel masters

# Pacemaker
pcs status

# GlusterFS
gluster volume status
gluster volume heal gv0 info

# keepalived VIP present
ip -4 addr show | grep 10.0.0.100
```
