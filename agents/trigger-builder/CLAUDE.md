# Trigger Builder Agent

Build custom "if X happens, do Y" rules for any Linux server. Triggers can fire on metric thresholds (CPU, RAM, disk, load), log pattern matches (regex over journald or files), time schedules (cron), and compound boolean conditions (AND/OR). Triggers are persisted in SQLite, managed via a CLI, and evaluated by a worker on a schedule.

---

## Safety Rules

- NEVER let a trigger run an unverified command from an untrusted source.
- ALWAYS sandbox trigger actions to a non-root user when possible.
- ALWAYS rate-limit trigger firings (cooldown) to prevent action storms.
- ALWAYS log every trigger evaluation and firing to `/var/log/trigger-builder.log`.
- NEVER allow triggers to delete files or stop services without an `allow_destructive=true` flag.
- ALWAYS validate the action command with `bash -n` before saving the trigger.
- ALWAYS persist trigger state (last_fired, fire_count) for audit.
- Triggers MUST have a max-fires-per-hour cap.

---

## 1. Required Tools

```bash
sudo apt update
sudo apt install -y sqlite3 jq yq curl coreutils gawk procps systemd flock
```

### Verify

```bash
for t in sqlite3 jq awk grep journalctl flock; do
    command -v "$t" >/dev/null && echo "OK: $t" || echo "MISSING: $t"
done
```

---

## 2. Trigger Storage (SQLite)

### Schema

```bash
DB=/var/lib/trigger-builder/triggers.db
sudo mkdir -p /var/lib/trigger-builder
sudo sqlite3 "$DB" <<'SQL'
CREATE TABLE IF NOT EXISTS triggers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,
    type            TEXT NOT NULL,        -- threshold|pattern|time|compound
    condition       TEXT NOT NULL,        -- JSON describing the condition
    action          TEXT NOT NULL,        -- shell command to run
    enabled         INTEGER NOT NULL DEFAULT 1,
    cooldown_sec    INTEGER NOT NULL DEFAULT 300,
    max_per_hour    INTEGER NOT NULL DEFAULT 12,
    last_fired_at   INTEGER,
    fire_count      INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS firings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger_id  INTEGER NOT NULL,
    fired_at    INTEGER NOT NULL,
    matched     TEXT,
    exit_code   INTEGER,
    output      TEXT
);
CREATE INDEX IF NOT EXISTS idx_fired ON firings(fired_at);
SQL

sudo chmod 660 "$DB"
```

---

## 3. YAML Rule Definitions

### Optional file-based rules `/etc/trigger-builder/rules.yaml`

```yaml
triggers:
  - name: high_cpu
    type: threshold
    condition:
      metric: cpu
      op: ">"
      value: 80
      duration_sec: 60
    action: "/usr/local/bin/notify --severity warning --message 'CPU > 80%'"
    cooldown_sec: 600

  - name: disk_full
    type: threshold
    condition:
      metric: disk
      mount: "/"
      op: ">"
      value: 90
    action: "/usr/local/bin/cleanup-automator.sh && /usr/local/bin/notify --severity critical --message 'Disk > 90% — cleanup ran'"
    cooldown_sec: 1800

  - name: ssh_brute_force
    type: pattern
    condition:
      source: "journalctl -u ssh.service --since '5 minutes ago'"
      regex: "Failed password.*from ([0-9.]+)"
      min_count: 10
    action: "/usr/local/bin/block-ip.sh"
    cooldown_sec: 300

  - name: nightly_backup
    type: time
    condition:
      cron: "0 2 * * *"
    action: "/usr/local/bin/backup.sh"

  - name: db_overload
    type: compound
    condition:
      op: AND
      checks:
        - { metric: cpu, op: ">", value: 70 }
        - { metric: load1, op: ">", value: 4 }
    action: "/usr/local/bin/notify --severity critical --message 'DB overload'"
```

### Import YAML to SQLite

```bash
yq -o=json '.triggers[]' /etc/trigger-builder/rules.yaml \
  | jq -c '.' \
  | while read T; do
        NAME=$(echo "$T" | jq -r .name)
        TYPE=$(echo "$T" | jq -r .type)
        COND=$(echo "$T" | jq -c .condition)
        ACT=$(echo "$T" | jq -r .action)
        CD=$(echo "$T" | jq -r '.cooldown_sec // 300')
        NOW=$(date +%s)
        sqlite3 "$DB" "INSERT OR REPLACE INTO triggers (name,type,condition,action,enabled,cooldown_sec,created_at,updated_at) VALUES ('$NAME','$TYPE','$COND','$ACT',1,$CD,$NOW,$NOW);"
    done
```

---

## 4. Metric Collection Helpers

### CPU Percent

```bash
cpu_used() {
    top -bn1 | awk '/^%Cpu/ {print 100 - $8}' | head -1
}
cpu_used   # -> 14.3
```

### Memory Percent Used

```bash
mem_used() {
    free | awk 'NR==2 {printf "%.1f", $3*100/$2}'
}
```

### Disk Percent for a Mount

```bash
disk_used() {
    local M="${1:-/}"
    df "$M" | awk 'NR==2 {gsub("%","",$5); print $5}'
}
disk_used /
disk_used /var
```

### Load Averages

```bash
load1()  { uptime | awk -F'load average:' '{print $2}' | awk '{gsub(",",""); print $1}'; }
load5()  { uptime | awk -F'load average:' '{print $2}' | awk '{gsub(",",""); print $2}'; }
load15() { uptime | awk -F'load average:' '{print $2}' | awk '{gsub(",",""); print $3}'; }
```

### Inode Used Percent

```bash
inode_used() {
    df -i "${1:-/}" | awk 'NR==2 {gsub("%","",$5); print $5}'
}
```

### Process Count by Name

```bash
pcount() { pgrep -c "$1" 2>/dev/null || echo 0; }
pcount nginx
```

### Service Active

```bash
svc_active() { systemctl is-active "$1" >/dev/null 2>&1 && echo 1 || echo 0; }
```

### TCP Port Listening

```bash
port_open() { ss -tln | awk '{print $4}' | grep -q ":$1\$" && echo 1 || echo 0; }
```

---

## 5. Threshold Trigger Evaluator

### Evaluate One Threshold Condition (returns 0 if matched)

```bash
eval_threshold() {
    local METRIC="$1"
    local OP="$2"
    local VALUE="$3"
    local MOUNT="${4:-/}"
    local CURRENT
    case "$METRIC" in
        cpu)    CURRENT=$(cpu_used);;
        mem)    CURRENT=$(mem_used);;
        disk)   CURRENT=$(disk_used "$MOUNT");;
        load1)  CURRENT=$(load1);;
        load5)  CURRENT=$(load5);;
        load15) CURRENT=$(load15);;
        inode)  CURRENT=$(inode_used "$MOUNT");;
        *) return 1;;
    esac
    awk -v c="$CURRENT" -v v="$VALUE" -v op="$OP" 'BEGIN {
        if (op == ">"  && c >  v) exit 0;
        if (op == ">=" && c >= v) exit 0;
        if (op == "<"  && c <  v) exit 0;
        if (op == "<=" && c <= v) exit 0;
        if (op == "==" && c == v) exit 0;
        exit 1;
    }'
}

eval_threshold cpu ">" 80 && echo "MATCH"
eval_threshold disk ">" 90 / && echo "MATCH"
```

---

## 6. Pattern (log regex) Trigger Evaluator

### Match Regex N Times Within Window

```bash
eval_pattern() {
    local SOURCE_CMD="$1"   # e.g. journalctl -u ssh.service --since '5 minutes ago'
    local REGEX="$2"
    local MIN="${3:-1}"
    local COUNT
    COUNT=$(bash -c "$SOURCE_CMD" 2>/dev/null | grep -cE "$REGEX")
    [ "$COUNT" -ge "$MIN" ]
}

eval_pattern "journalctl -u ssh.service --since '5 minutes ago'" "Failed password" 10 \
    && echo "BRUTE FORCE DETECTED"
```

### File-Based Pattern

```bash
eval_file_pattern() {
    local FILE="$1"
    local REGEX="$2"
    local MIN="${3:-1}"
    local COUNT=$(grep -cE "$REGEX" "$FILE" 2>/dev/null || echo 0)
    [ "$COUNT" -ge "$MIN" ]
}
```

### Capture Match Variables

```bash
journalctl -u ssh.service --since '5 minutes ago' \
    | grep -oP 'Failed password.*from \K[0-9.]+' \
    | sort | uniq -c | sort -rn | head -5
```

---

## 7. Time Trigger (cron-style)

### Time triggers leverage cron itself

```bash
# When you persist a time trigger, also write a cron entry pointing to the trigger runner
add_time_trigger_cron() {
    local NAME="$1"
    local CRON="$2"
    echo "$CRON /usr/local/bin/triggerctl fire '$NAME'" \
        | sudo tee -a /etc/cron.d/trigger-builder
    sudo systemctl restart cron
}
add_time_trigger_cron nightly_backup "0 2 * * *"
```

### Reload Cron After Changes

```bash
sudo systemctl reload cron
```

---

## 8. Compound Conditions (AND / OR)

### Evaluate JSON Compound Condition

```bash
eval_compound() {
    local JSON="$1"
    local OP=$(echo "$JSON" | jq -r .op)
    local CHECKS=$(echo "$JSON" | jq -c '.checks[]')
    local MATCH_ANY=0
    local MATCH_ALL=1
    while read -r C; do
        local M=$(echo "$C" | jq -r .metric)
        local O=$(echo "$C" | jq -r .op)
        local V=$(echo "$C" | jq -r .value)
        if eval_threshold "$M" "$O" "$V"; then
            MATCH_ANY=1
        else
            MATCH_ALL=0
        fi
    done <<<"$CHECKS"

    if [ "$OP" = "AND" ]; then
        [ "$MATCH_ALL" = "1" ]
    else
        [ "$MATCH_ANY" = "1" ]
    fi
}

# Example
eval_compound '{"op":"AND","checks":[{"metric":"cpu","op":">","value":70},{"metric":"load1","op":">","value":4}]}' \
    && echo "DB OVERLOAD"
```

---

## 9. Trigger Runner (Worker)

### Save as `/usr/local/bin/trigger-runner.sh`

```bash
#!/bin/bash
set -uo pipefail
DB=/var/lib/trigger-builder/triggers.db
LOG=/var/log/trigger-builder.log

log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }

exec 9>/var/lock/trigger-runner.lock
flock -n 9 || exit 0

NOW=$(date +%s)
HOUR_AGO=$((NOW - 3600))

# Source the helper functions
source /usr/local/lib/trigger-helpers.sh

sqlite3 -separator $'\t' "$DB" "
SELECT id, name, type, condition, action, cooldown_sec, max_per_hour, COALESCE(last_fired_at,0)
FROM triggers WHERE enabled=1;
" | while IFS=$'\t' read -r ID NAME TYPE COND ACTION COOLDOWN MAXPH LAST; do

    # Cooldown check
    if [ "$LAST" -gt 0 ] && [ $((NOW - LAST)) -lt "$COOLDOWN" ]; then
        continue
    fi

    # Hourly cap
    RECENT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM firings WHERE trigger_id=$ID AND fired_at > $HOUR_AGO;")
    if [ "$RECENT" -ge "$MAXPH" ]; then
        log "CAP $NAME hit max_per_hour=$MAXPH"
        continue
    fi

    MATCHED=0
    case "$TYPE" in
        threshold)
            METRIC=$(echo "$COND" | jq -r .metric)
            OP=$(echo "$COND" | jq -r .op)
            VALUE=$(echo "$COND" | jq -r .value)
            MOUNT=$(echo "$COND" | jq -r '.mount // "/"')
            eval_threshold "$METRIC" "$OP" "$VALUE" "$MOUNT" && MATCHED=1
            ;;
        pattern)
            SRC=$(echo "$COND" | jq -r .source)
            RE=$(echo "$COND" | jq -r .regex)
            MIN=$(echo "$COND" | jq -r '.min_count // 1')
            eval_pattern "$SRC" "$RE" "$MIN" && MATCHED=1
            ;;
        compound)
            eval_compound "$COND" && MATCHED=1
            ;;
        time)
            # Time triggers fire from cron, not from this loop
            continue
            ;;
    esac

    if [ "$MATCHED" = "1" ]; then
        log "FIRE $NAME"
        OUT=$(bash -c "$ACTION" 2>&1); EC=$?
        SAFE=$(echo "$OUT" | sed "s/'/''/g" | head -c 2000)
        sqlite3 "$DB" "
INSERT INTO firings (trigger_id, fired_at, exit_code, output) VALUES ($ID, $NOW, $EC, '$SAFE');
UPDATE triggers SET last_fired_at=$NOW, fire_count=fire_count+1, updated_at=$NOW WHERE id=$ID;
"
        log "DONE $NAME ec=$EC"
    fi
done
```

### Helper Functions File `/usr/local/lib/trigger-helpers.sh`

```bash
sudo tee /usr/local/lib/trigger-helpers.sh <<'EOF'
cpu_used()  { top -bn1 | awk '/^%Cpu/ {print 100 - $8}' | head -1; }
mem_used()  { free | awk 'NR==2 {printf "%.1f", $3*100/$2}'; }
disk_used() { df "${1:-/}" | awk 'NR==2 {gsub("%","",$5); print $5}'; }
load1()     { uptime | awk -F'load average:' '{print $2}' | awk '{gsub(",",""); print $1}'; }
load5()     { uptime | awk -F'load average:' '{print $2}' | awk '{gsub(",",""); print $2}'; }
load15()    { uptime | awk -F'load average:' '{print $2}' | awk '{gsub(",",""); print $3}'; }
inode_used(){ df -i "${1:-/}" | awk 'NR==2 {gsub("%","",$5); print $5}'; }

eval_threshold() {
    local METRIC="$1" OP="$2" VALUE="$3" MOUNT="${4:-/}"
    local CURRENT
    case "$METRIC" in
        cpu)   CURRENT=$(cpu_used);;
        mem)   CURRENT=$(mem_used);;
        disk)  CURRENT=$(disk_used "$MOUNT");;
        load1) CURRENT=$(load1);;
        load5) CURRENT=$(load5);;
        inode) CURRENT=$(inode_used "$MOUNT");;
    esac
    awk -v c="$CURRENT" -v v="$VALUE" -v op="$OP" 'BEGIN {
        if (op==">" && c>v) exit 0; if (op==">=" && c>=v) exit 0;
        if (op=="<" && c<v) exit 0; if (op=="<=" && c<=v) exit 0;
        if (op=="==" && c==v) exit 0; exit 1;
    }'
}

eval_pattern() {
    local SRC="$1" RE="$2" MIN="${3:-1}"
    local C=$(bash -c "$SRC" 2>/dev/null | grep -cE "$RE")
    [ "$C" -ge "$MIN" ]
}

eval_compound() {
    local JSON="$1"
    local OP=$(echo "$JSON" | jq -r .op)
    local ANY=0 ALL=1
    while read -r C; do
        local M=$(echo "$C" | jq -r .metric)
        local O=$(echo "$C" | jq -r .op)
        local V=$(echo "$C" | jq -r .value)
        if eval_threshold "$M" "$O" "$V"; then ANY=1; else ALL=0; fi
    done < <(echo "$JSON" | jq -c '.checks[]')
    if [ "$OP" = "AND" ]; then [ "$ALL" = "1" ]; else [ "$ANY" = "1" ]; fi
}
EOF
sudo chmod 644 /usr/local/lib/trigger-helpers.sh
```

### Make Runner Executable

```bash
sudo chmod +x /usr/local/bin/trigger-runner.sh
```

### Run Every Minute

```bash
* * * * * /usr/local/bin/trigger-runner.sh >/dev/null 2>&1
```

---

## 10. CLI Tool: triggerctl

### Save as `/usr/local/bin/triggerctl`

```bash
#!/bin/bash
DB=/var/lib/trigger-builder/triggers.db

case "$1" in
    add)
        # triggerctl add <name> <type> '<json-condition>' '<action>' [cooldown]
        NAME="$2"; TYPE="$3"; COND="$4"; ACT="$5"; CD="${6:-300}"
        # Validate action syntax
        bash -n -c "$ACT" || { echo "Invalid action shell"; exit 1; }
        NOW=$(date +%s)
        sqlite3 "$DB" "INSERT INTO triggers (name,type,condition,action,enabled,cooldown_sec,created_at,updated_at) VALUES ('$NAME','$TYPE','$COND','$ACT',1,$CD,$NOW,$NOW);"
        echo "Added trigger: $NAME"
        ;;
    list)
        sqlite3 -column -header "$DB" "SELECT id,name,type,enabled,cooldown_sec,fire_count,datetime(last_fired_at,'unixepoch') AS last FROM triggers ORDER BY id;"
        ;;
    show)
        sqlite3 -line "$DB" "SELECT * FROM triggers WHERE name='$2';"
        ;;
    enable)
        sqlite3 "$DB" "UPDATE triggers SET enabled=1 WHERE name='$2';"
        ;;
    disable)
        sqlite3 "$DB" "UPDATE triggers SET enabled=0 WHERE name='$2';"
        ;;
    remove)
        sqlite3 "$DB" "DELETE FROM triggers WHERE name='$2';"
        ;;
    fire)
        # Force-fire by name (used by cron for time triggers)
        ACT=$(sqlite3 "$DB" "SELECT action FROM triggers WHERE name='$2' AND enabled=1;")
        [ -z "$ACT" ] && { echo "no such trigger"; exit 1; }
        bash -c "$ACT"
        NOW=$(date +%s)
        sqlite3 "$DB" "UPDATE triggers SET last_fired_at=$NOW, fire_count=fire_count+1 WHERE name='$2';"
        ;;
    history)
        sqlite3 -column -header "$DB" "SELECT firings.id, t.name, datetime(fired_at,'unixepoch') AS at, exit_code FROM firings JOIN triggers t ON t.id=trigger_id ORDER BY fired_at DESC LIMIT 30;"
        ;;
    test)
        # triggerctl test <name>  — evaluate without firing action
        ROW=$(sqlite3 -separator '|' "$DB" "SELECT type,condition FROM triggers WHERE name='$2';")
        IFS='|' read -r T C <<<"$ROW"
        source /usr/local/lib/trigger-helpers.sh
        case "$T" in
            threshold)
                M=$(echo "$C" | jq -r .metric); O=$(echo "$C" | jq -r .op); V=$(echo "$C" | jq -r .value)
                MNT=$(echo "$C" | jq -r '.mount // "/"')
                eval_threshold "$M" "$O" "$V" "$MNT" && echo "WOULD FIRE" || echo "no match";;
            pattern)
                S=$(echo "$C" | jq -r .source); R=$(echo "$C" | jq -r .regex); N=$(echo "$C" | jq -r '.min_count // 1')
                eval_pattern "$S" "$R" "$N" && echo "WOULD FIRE" || echo "no match";;
            compound)
                eval_compound "$C" && echo "WOULD FIRE" || echo "no match";;
        esac
        ;;
    *)
        echo "Usage: triggerctl {add|list|show|enable|disable|remove|fire|history|test}"
        ;;
esac
```

### Make Executable

```bash
sudo chmod +x /usr/local/bin/triggerctl
```

---

## 11. Examples

### Add CPU Threshold Trigger

```bash
triggerctl add high_cpu threshold \
    '{"metric":"cpu","op":">","value":80}' \
    '/usr/local/bin/notify --severity warning --message "CPU above 80%"' \
    600
```

### Add Disk Threshold Trigger

```bash
triggerctl add disk_alert threshold \
    '{"metric":"disk","mount":"/","op":">","value":90}' \
    '/usr/local/bin/cleanup-automator.sh'
```

### Add SSH Brute Force Pattern Trigger

```bash
triggerctl add ssh_brute pattern \
    '{"source":"journalctl -u ssh.service --since \"5 minutes ago\"","regex":"Failed password","min_count":10}' \
    'fail2ban-client set sshd banip $(journalctl -u ssh.service --since "5 minutes ago" | grep -oP "from \\K[0-9.]+" | sort | uniq -c | sort -rn | awk "NR==1{print \\$2}")'
```

### Add Compound Condition

```bash
triggerctl add db_overload compound \
    '{"op":"AND","checks":[{"metric":"cpu","op":">","value":70},{"metric":"load1","op":">","value":4}]}' \
    '/usr/local/bin/notify --severity critical --message "DB overload"'
```

### Add Time Trigger via Cron

```bash
triggerctl add nightly_backup time \
    '{"cron":"0 2 * * *"}' \
    '/usr/local/bin/backup.sh' \
    0
echo "0 2 * * * root /usr/local/bin/triggerctl fire nightly_backup" \
    | sudo tee -a /etc/cron.d/trigger-builder
sudo systemctl reload cron
```

### Test a Trigger Without Firing

```bash
triggerctl test high_cpu
```

### Show History

```bash
triggerctl history
```

---

## 12. Common Workflows

### "If disk > 90%, run cleanup"

```bash
triggerctl add cleanup_full threshold \
    '{"metric":"disk","mount":"/","op":">","value":90}' \
    '/usr/local/bin/cleanup-automator.sh'
```

### "If 10 ssh failures in 5 min, ban the IP"

```bash
triggerctl add ssh_ban pattern \
    '{"source":"journalctl _SYSTEMD_UNIT=ssh.service --since \"5 minutes ago\"","regex":"Failed password","min_count":10}' \
    'IP=$(journalctl _SYSTEMD_UNIT=ssh.service --since "5 minutes ago" | grep -oP "from \\K[0-9.]+" | sort | uniq -c | sort -rn | awk "NR==1{print \\$2}"); [ -n "$IP" ] && fail2ban-client set sshd banip "$IP"'
```

### "Restart nginx if it stops"

```bash
triggerctl add nginx_watch threshold \
    '{"metric":"svc_active","value":0,"op":"=="}' \
    'systemctl restart nginx'
```

### "Disable a noisy trigger temporarily"

```bash
triggerctl disable high_cpu
```

### "List all firings today"

```bash
sqlite3 /var/lib/trigger-builder/triggers.db \
    "SELECT t.name, datetime(fired_at,'unixepoch') FROM firings JOIN triggers t ON t.id=trigger_id WHERE fired_at > strftime('%s','now','start of day');"
```

---

## 13. Troubleshooting

### Trigger Never Fires

```bash
triggerctl test <name>
tail -30 /var/log/trigger-builder.log
sqlite3 "$DB" "SELECT enabled,cooldown_sec,last_fired_at FROM triggers WHERE name='<name>';"
```

### Trigger Fires Too Often

```bash
sqlite3 "$DB" "UPDATE triggers SET cooldown_sec=1800, max_per_hour=2 WHERE name='<name>';"
```

### Action Command Has Syntax Error

```bash
bash -n -c "$ACTION_COMMAND"
```

### Runner Not Running

```bash
ls -l /var/lock/trigger-runner.lock
sudo /usr/local/bin/trigger-runner.sh
crontab -l | grep trigger-runner
```

### sqlite database locked

```bash
sqlite3 "$DB" "PRAGMA journal_mode=WAL;"
```

---

## 14. Backup Triggers

### Export All Triggers to JSON

```bash
sqlite3 -json "$DB" "SELECT * FROM triggers;" > /var/backups/triggers-$(date +%F).json
```

### Restore From JSON

```bash
jq -c '.[]' /var/backups/triggers-2026-04-09.json | while read T; do
    NAME=$(echo "$T" | jq -r .name)
    TYPE=$(echo "$T" | jq -r .type)
    COND=$(echo "$T" | jq -r .condition)
    ACT=$(echo "$T" | jq -r .action)
    CD=$(echo "$T" | jq -r .cooldown_sec)
    NOW=$(date +%s)
    sqlite3 "$DB" "INSERT OR REPLACE INTO triggers (name,type,condition,action,enabled,cooldown_sec,created_at,updated_at) VALUES ('$NAME','$TYPE','$COND','$ACT',1,$CD,$NOW,$NOW);"
done
```

---

## Output Format

When operating triggers, always show:

1. **Trigger name / type / condition / action**
2. **Match result** (matched or not, current vs threshold value)
3. **Cooldown remaining / hourly cap remaining**
4. **Action exit code + truncated output**
5. **Updated last_fired_at and fire_count**
6. **Log line written** to `/var/log/trigger-builder.log`
