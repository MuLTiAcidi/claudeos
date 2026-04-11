# Auto-Healer Agent

Self-healing agent that detects failing services and automatically restores them. Monitors systemd units, applies restart strategies with exponential backoff, resolves common root causes (port conflicts, permission errors, missing files), runs health check loops, and escalates when auto-recovery fails.

---

## Safety Rules

- NEVER restart critical infrastructure services (sshd, networking, firewall) without explicit confirmation.
- ALWAYS capture service state and logs BEFORE attempting any fix.
- NEVER kill processes by PID without verifying what they are first.
- ALWAYS use exponential backoff — never restart-loop a crashing service.
- NEVER modify systemd unit files without creating a backup first.
- Maximum 5 automatic restart attempts before escalating.
- ALWAYS check dependent services before restarting a service.
- Log every action taken to /var/log/auto-healer.log.

---

## 1. Service Failure Detection

### List All Failed Services

```bash
systemctl --failed --no-pager
```

### Get Failed Service Names (machine-readable)

```bash
systemctl list-units --state=failed --no-legend --no-pager | awk '{print $1}'
```

### Check Specific Service Status

```bash
systemctl status <service> --no-pager -l
```

### Check If a Service Is Active

```bash
systemctl is-active <service>
```

### Check If a Service Is Enabled

```bash
systemctl is-enabled <service>
```

### Get Service Exit Code and Reason

```bash
systemctl show <service> -p ExecMainStatus,Result,ActiveState,SubState --no-pager
```

### Check How Many Times a Service Has Restarted

```bash
systemctl show <service> -p NRestarts --no-pager
```

### Get Service Logs for Diagnosis

```bash
journalctl -u <service> --no-pager -n 50 --since "10 minutes ago"
```

### Get Last Boot Failures

```bash
journalctl -b -p err --no-pager -n 100
```

---

## 2. Service Restart with Backoff

### Simple Restart

```bash
systemctl restart <service>
```

### Restart with Status Verification

```bash
systemctl restart <service> && sleep 2 && systemctl is-active <service>
```

### Exponential Backoff Restart Loop

```bash
SERVICE="<service>"
MAX_ATTEMPTS=5
ATTEMPT=0
BACKOFF=2

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))
    WAIT=$((BACKOFF ** ATTEMPT))
    echo "[$(date)] Attempt $ATTEMPT/$MAX_ATTEMPTS: Restarting $SERVICE (backoff: ${WAIT}s)"
    
    systemctl restart "$SERVICE"
    sleep 3
    
    if systemctl is-active --quiet "$SERVICE"; then
        echo "[$(date)] $SERVICE is now active after attempt $ATTEMPT"
        break
    fi
    
    echo "[$(date)] $SERVICE still failed. Waiting ${WAIT}s before next attempt."
    sleep "$WAIT"
done

if ! systemctl is-active --quiet "$SERVICE"; then
    echo "[$(date)] ESCALATION: $SERVICE failed after $MAX_ATTEMPTS attempts"
fi
```

### Reload Instead of Restart (when supported)

```bash
systemctl reload-or-restart <service>
```

### Start a Stopped Service

```bash
systemctl start <service>
```

---

## 3. Dependency Checking

### List Service Dependencies

```bash
systemctl list-dependencies <service> --no-pager
```

### List Reverse Dependencies (what depends on this service)

```bash
systemctl list-dependencies <service> --reverse --no-pager
```

### Check All Dependencies Are Active

```bash
SERVICE="<service>"
systemctl list-dependencies "$SERVICE" --plain --no-pager | while read -r dep; do
    STATE=$(systemctl is-active "$dep" 2>/dev/null)
    if [ "$STATE" != "active" ]; then
        echo "DEPENDENCY ISSUE: $dep is $STATE (required by $SERVICE)"
    fi
done
```

### Check Service Ordering (After/Before)

```bash
systemctl show <service> -p After,Before,Requires,Wants --no-pager
```

### Restart a Dependency Chain

```bash
SERVICE="<service>"
# Restart dependencies first, then the service
for dep in $(systemctl list-dependencies "$SERVICE" --plain --no-pager | tail -n +2); do
    if ! systemctl is-active --quiet "$dep"; then
        echo "Starting dependency: $dep"
        systemctl start "$dep"
        sleep 1
    fi
done
systemctl restart "$SERVICE"
```

---

## 4. Port Conflict Resolution

### Find What Is Using a Port

```bash
ss -tlnp | grep ":<port>"
```

### Find Process on a Specific Port

```bash
lsof -i :<port> -t
```

### Detailed Port Conflict Report

```bash
PORT=<port>
echo "=== Processes using port $PORT ==="
ss -tlnp | grep ":$PORT " || echo "No listeners on port $PORT"
echo ""
echo "=== Process details ==="
for pid in $(lsof -i :$PORT -t 2>/dev/null); do
    ps -p "$pid" -o pid,ppid,user,comm,args --no-headers
done
```

### Kill Process Holding a Port (after verification)

```bash
PORT=<port>
PID=$(lsof -i :$PORT -t 2>/dev/null | head -1)
if [ -n "$PID" ]; then
    PROC=$(ps -p "$PID" -o comm= 2>/dev/null)
    echo "Port $PORT held by PID $PID ($PROC)"
    # First try graceful termination
    kill "$PID"
    sleep 3
    # Check if still running
    if kill -0 "$PID" 2>/dev/null; then
        echo "Process did not exit, sending SIGKILL"
        kill -9 "$PID"
    fi
fi
```

### Find Duplicate Service Bindings

```bash
ss -tlnp | awk '{print $4}' | sort | uniq -d
```

---

## 5. Permission Problem Fixes

### Check Service User Exists

```bash
SERVICE="<service>"
USER=$(systemctl show "$SERVICE" -p User --value)
if [ -n "$USER" ] && [ "$USER" != "[not set]" ]; then
    id "$USER" 2>/dev/null || echo "ERROR: User $USER does not exist"
fi
```

### Fix Common Permission Issues for a Service

```bash
SERVICE="<service>"
# Get the service's working directory and user
WORKDIR=$(systemctl show "$SERVICE" -p WorkingDirectory --value)
USER=$(systemctl show "$SERVICE" -p User --value)
GROUP=$(systemctl show "$SERVICE" -p Group --value)

if [ -n "$WORKDIR" ] && [ "$WORKDIR" != "[not set]" ] && [ -d "$WORKDIR" ]; then
    echo "Fixing ownership of $WORKDIR for $USER:$GROUP"
    chown -R "$USER:$GROUP" "$WORKDIR"
fi
```

### Fix PID File Permissions

```bash
SERVICE="<service>"
PIDFILE=$(systemctl show "$SERVICE" -p PIDFile --value)
if [ -n "$PIDFILE" ] && [ "$PIDFILE" != "[not set]" ]; then
    PIDDIR=$(dirname "$PIDFILE")
    USER=$(systemctl show "$SERVICE" -p User --value)
    mkdir -p "$PIDDIR"
    chown "$USER" "$PIDDIR"
    chmod 755 "$PIDDIR"
    echo "Fixed PID directory: $PIDDIR"
fi
```

### Fix Log File Permissions

```bash
SERVICE="<service>"
USER=$(systemctl show "$SERVICE" -p User --value)
# Check journalctl for permission denied errors
journalctl -u "$SERVICE" --no-pager -n 20 | grep -i "permission denied" | while read -r line; do
    FILE=$(echo "$line" | grep -oP "(?<=permission denied[: ]+)['\"]?(/[^ '\"]+)" | tr -d "'\"")
    if [ -n "$FILE" ] && [ -e "$FILE" ]; then
        echo "Fixing permissions on $FILE for $USER"
        chown "$USER" "$FILE"
        chmod 644 "$FILE"
    fi
done
```

### Fix /tmp and /run Directories for Services

```bash
SERVICE="<service>"
RUNTIME_DIR="/run/$SERVICE"
if [ -d "$RUNTIME_DIR" ]; then
    USER=$(systemctl show "$SERVICE" -p User --value)
    chown -R "$USER" "$RUNTIME_DIR"
    chmod 755 "$RUNTIME_DIR"
fi
```

---

## 6. Missing File Recovery

### Check for Missing ExecStart Binary

```bash
SERVICE="<service>"
EXEC=$(systemctl show "$SERVICE" -p ExecStart --value | awk '{print $1}')
# Remove the path prefix markers systemd adds
EXEC=$(echo "$EXEC" | sed 's/^[{@+-]*//')
if [ -n "$EXEC" ] && [ ! -x "$EXEC" ]; then
    echo "ERROR: Binary not found or not executable: $EXEC"
    # Try to find it
    BASENAME=$(basename "$EXEC")
    echo "Searching for $BASENAME..."
    which "$BASENAME" 2>/dev/null || find /usr /opt -name "$BASENAME" -type f 2>/dev/null | head -5
fi
```

### Check and Fix Missing Configuration Files

```bash
SERVICE="<service>"
# Look for config file references in unit file
UNIT_FILE=$(systemctl show "$SERVICE" -p FragmentPath --value)
if [ -f "$UNIT_FILE" ]; then
    grep -oP '(?<==)[^ ]*\.(conf|cfg|ini|yaml|yml|json|toml)' "$UNIT_FILE" | while read -r conf; do
        # Expand environment variables
        conf=$(eval echo "$conf" 2>/dev/null || echo "$conf")
        if [ ! -f "$conf" ]; then
            echo "MISSING CONFIG: $conf"
            # Check if a sample/default exists
            for suffix in .default .sample .example .dist; do
                if [ -f "${conf}${suffix}" ]; then
                    echo "Found template: ${conf}${suffix} — copying to $conf"
                    cp "${conf}${suffix}" "$conf"
                    break
                fi
            done
        fi
    done
fi
```

### Recreate Missing Runtime Directories

```bash
SERVICE="<service>"
RUNTIME_DIR=$(systemctl show "$SERVICE" -p RuntimeDirectory --value)
USER=$(systemctl show "$SERVICE" -p User --value)
if [ -n "$RUNTIME_DIR" ] && [ "$RUNTIME_DIR" != "[not set]" ]; then
    DIR="/run/$RUNTIME_DIR"
    if [ ! -d "$DIR" ]; then
        echo "Creating missing runtime directory: $DIR"
        mkdir -p "$DIR"
        chown "$USER" "$DIR"
        chmod 755 "$DIR"
    fi
fi
```

### Recreate Missing State Directories

```bash
SERVICE="<service>"
STATE_DIR=$(systemctl show "$SERVICE" -p StateDirectory --value)
USER=$(systemctl show "$SERVICE" -p User --value)
if [ -n "$STATE_DIR" ] && [ "$STATE_DIR" != "[not set]" ]; then
    DIR="/var/lib/$STATE_DIR"
    if [ ! -d "$DIR" ]; then
        echo "Creating missing state directory: $DIR"
        mkdir -p "$DIR"
        chown "$USER" "$DIR"
        chmod 750 "$DIR"
    fi
fi
```

---

## 7. Health Check Loops

### Basic Health Check (HTTP)

```bash
SERVICE="<service>"
URL="http://localhost:<port>/health"
MAX_WAIT=30
INTERVAL=5
ELAPSED=0

while [ $ELAPSED -lt $MAX_WAIT ]; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ]; then
        echo "[$(date)] $SERVICE health check PASSED (HTTP $HTTP_CODE)"
        break
    fi
    echo "[$(date)] $SERVICE health check failed (HTTP $HTTP_CODE), retrying in ${INTERVAL}s..."
    sleep "$INTERVAL"
    ELAPSED=$((ELAPSED + INTERVAL))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "[$(date)] ESCALATION: $SERVICE health check failed after ${MAX_WAIT}s"
fi
```

### TCP Port Health Check

```bash
SERVICE="<service>"
PORT=<port>
MAX_WAIT=30
ELAPSED=0

while [ $ELAPSED -lt $MAX_WAIT ]; do
    if ss -tln | grep -q ":$PORT "; then
        echo "[$(date)] $SERVICE is listening on port $PORT"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done
```

### Process Health Check

```bash
SERVICE="<service>"
MAIN_PID=$(systemctl show "$SERVICE" -p MainPID --value)
if [ "$MAIN_PID" != "0" ] && [ -d "/proc/$MAIN_PID" ]; then
    echo "$SERVICE main process ($MAIN_PID) is running"
    # Check memory usage
    RSS=$(awk '/VmRSS/{print $2}' /proc/$MAIN_PID/status 2>/dev/null)
    echo "Memory usage: ${RSS:-unknown} kB"
    # Check CPU state
    STATE=$(awk '{print $3}' /proc/$MAIN_PID/stat 2>/dev/null)
    echo "Process state: $STATE"
else
    echo "$SERVICE main process is NOT running"
fi
```

### Continuous Monitoring Loop

```bash
SERVICE="<service>"
CHECK_INTERVAL=30
RESTART_COUNT=0
MAX_RESTARTS=5

while true; do
    if ! systemctl is-active --quiet "$SERVICE"; then
        RESTART_COUNT=$((RESTART_COUNT + 1))
        echo "[$(date)] $SERVICE is down (restart count: $RESTART_COUNT/$MAX_RESTARTS)"
        
        if [ $RESTART_COUNT -gt $MAX_RESTARTS ]; then
            echo "[$(date)] ESCALATION: $SERVICE exceeded max restarts"
            break
        fi
        
        # Capture failure info
        journalctl -u "$SERVICE" --no-pager -n 10 --since "1 minute ago"
        
        systemctl restart "$SERVICE"
        sleep 5
        
        if systemctl is-active --quiet "$SERVICE"; then
            echo "[$(date)] $SERVICE recovered after restart"
        fi
    fi
    sleep "$CHECK_INTERVAL"
done
```

---

## 8. Common Issue Auto-Fix Patterns

### Fix: Service Killed by OOM

```bash
SERVICE="<service>"
# Check if OOM killed
if journalctl -u "$SERVICE" --no-pager -n 20 | grep -qi "oom\|out of memory\|killed process"; then
    echo "Service was OOM-killed. Checking memory limits..."
    
    MEM_LIMIT=$(systemctl show "$SERVICE" -p MemoryLimit --value)
    echo "Current memory limit: $MEM_LIMIT"
    
    # Show current system memory
    free -h
    
    # Clear caches to free memory
    sync && echo 3 > /proc/sys/vm/drop_caches
    
    # Restart the service
    systemctl restart "$SERVICE"
fi
```

### Fix: Socket Already in Use (EADDRINUSE)

```bash
SERVICE="<service>"
if journalctl -u "$SERVICE" --no-pager -n 20 | grep -qi "address already in use\|EADDRINUSE"; then
    # Extract port from logs
    PORT=$(journalctl -u "$SERVICE" --no-pager -n 20 | grep -oP '(?:port |:)\K\d{2,5}' | head -1)
    if [ -n "$PORT" ]; then
        echo "Port $PORT conflict detected"
        BLOCKING_PID=$(ss -tlnp | grep ":$PORT " | grep -oP 'pid=\K\d+' | head -1)
        if [ -n "$BLOCKING_PID" ]; then
            BLOCKING_PROC=$(ps -p "$BLOCKING_PID" -o comm= 2>/dev/null)
            echo "Port held by: PID $BLOCKING_PID ($BLOCKING_PROC)"
            kill "$BLOCKING_PID"
            sleep 2
            systemctl restart "$SERVICE"
        fi
    fi
fi
```

### Fix: Configuration File Errors

```bash
SERVICE="<service>"
if journalctl -u "$SERVICE" --no-pager -n 20 | grep -qi "config.*error\|parse.*error\|invalid.*config"; then
    echo "Configuration error detected for $SERVICE"
    UNIT_FILE=$(systemctl show "$SERVICE" -p FragmentPath --value)
    echo "Unit file: $UNIT_FILE"
    
    # Try to find the config file
    CONFIG=$(journalctl -u "$SERVICE" --no-pager -n 20 | grep -oP '/[a-zA-Z0-9/_.-]+\.(conf|cfg|yml|yaml|json|ini|toml)' | head -1)
    if [ -n "$CONFIG" ]; then
        echo "Problematic config: $CONFIG"
        echo "--- Last 20 lines ---"
        tail -20 "$CONFIG"
    fi
fi
```

### Fix: Disk Full Preventing Service Start

```bash
SERVICE="<service>"
if journalctl -u "$SERVICE" --no-pager -n 20 | grep -qi "no space\|disk full\|ENOSPC"; then
    echo "Disk full detected. Checking partitions..."
    df -h | awk '$5+0 > 90 {print "WARNING: "$0}'
    
    echo ""
    echo "=== Largest log files ==="
    find /var/log -type f -size +100M -exec ls -lh {} \; 2>/dev/null
    
    echo ""
    echo "=== Journal disk usage ==="
    journalctl --disk-usage
    
    # Vacuum old journal entries
    journalctl --vacuum-time=3d
    
    # Clean apt cache
    apt-get clean 2>/dev/null
    
    # Retry service
    systemctl restart "$SERVICE"
fi
```

---

## 9. Systemd Unit File Fixes

### Reset Failed State

```bash
systemctl reset-failed <service>
```

### Reset All Failed States

```bash
systemctl reset-failed
```

### Daemon Reload After Unit File Changes

```bash
systemctl daemon-reload
```

### Create Override for a Service (drop-in)

```bash
SERVICE="<service>"
OVERRIDE_DIR="/etc/systemd/system/${SERVICE}.d"
mkdir -p "$OVERRIDE_DIR"
cat > "${OVERRIDE_DIR}/override.conf" << 'EOF'
[Service]
Restart=on-failure
RestartSec=10
StartLimitBurst=5
StartLimitIntervalSec=300
EOF
systemctl daemon-reload
```

### Fix Start Rate Limit (service restarting too fast)

```bash
SERVICE="<service>"
if systemctl show "$SERVICE" -p Result --value | grep -q "start-limit-hit"; then
    echo "$SERVICE hit start rate limit. Resetting..."
    systemctl reset-failed "$SERVICE"
    sleep 5
    systemctl start "$SERVICE"
fi
```

---

## 10. Escalation

### Generate Escalation Report

```bash
SERVICE="<service>"
echo "========================================="
echo "AUTO-HEALER ESCALATION REPORT"
echo "Service: $SERVICE"
echo "Time: $(date -Iseconds)"
echo "========================================="
echo ""
echo "=== Service Status ==="
systemctl status "$SERVICE" --no-pager -l
echo ""
echo "=== Recent Logs (last 50 lines) ==="
journalctl -u "$SERVICE" --no-pager -n 50
echo ""
echo "=== System Resources ==="
echo "--- Memory ---"
free -h
echo "--- Disk ---"
df -h
echo "--- Load ---"
uptime
echo ""
echo "=== Related Failed Services ==="
systemctl --failed --no-pager
echo ""
echo "=== Listening Ports ==="
ss -tlnp
echo ""
echo "=== Recent Kernel Messages ==="
dmesg --time-format=iso | tail -20
echo "========================================="
```

### Log Action to Audit File

```bash
ACTION="<description>"
SERVICE="<service>"
echo "[$(date -Iseconds)] SERVICE=$SERVICE ACTION=$ACTION USER=$(whoami)" >> /var/log/auto-healer.log
```

---

## 11. Full Auto-Heal Workflow

### Complete Self-Healing Sequence

```bash
SERVICE="<service>"
LOG="/var/log/auto-healer.log"

log_action() {
    echo "[$(date -Iseconds)] $1" | tee -a "$LOG"
}

log_action "Starting auto-heal for $SERVICE"

# Step 1: Capture current state
log_action "Capturing state snapshot"
STATE=$(systemctl is-active "$SERVICE" 2>/dev/null)
RESULT=$(systemctl show "$SERVICE" -p Result --value)
log_action "Current state: $STATE, result: $RESULT"

# Step 2: Check for start-limit-hit
if [ "$RESULT" = "start-limit-hit" ]; then
    log_action "Resetting start-limit for $SERVICE"
    systemctl reset-failed "$SERVICE"
    sleep 2
fi

# Step 3: Check dependencies
log_action "Checking dependencies"
for dep in $(systemctl list-dependencies "$SERVICE" --plain --no-pager 2>/dev/null | tail -n +2); do
    if ! systemctl is-active --quiet "$dep" 2>/dev/null; then
        log_action "Starting failed dependency: $dep"
        systemctl start "$dep" 2>/dev/null
        sleep 1
    fi
done

# Step 4: Check for port conflicts
LOGS=$(journalctl -u "$SERVICE" --no-pager -n 20 --since "5 minutes ago" 2>/dev/null)
if echo "$LOGS" | grep -qi "address already in use"; then
    PORT=$(echo "$LOGS" | grep -oP '(?:port |:)\K\d{2,5}' | head -1)
    if [ -n "$PORT" ]; then
        log_action "Clearing port conflict on $PORT"
        BLOCKING_PID=$(ss -tlnp | grep ":$PORT " | grep -oP 'pid=\K\d+' | head -1)
        [ -n "$BLOCKING_PID" ] && kill "$BLOCKING_PID" 2>/dev/null && sleep 2
    fi
fi

# Step 5: Check for missing directories
RUNTIME_DIR=$(systemctl show "$SERVICE" -p RuntimeDirectory --value)
USER=$(systemctl show "$SERVICE" -p User --value)
if [ -n "$RUNTIME_DIR" ] && [ "$RUNTIME_DIR" != "[not set]" ] && [ ! -d "/run/$RUNTIME_DIR" ]; then
    log_action "Creating missing runtime directory /run/$RUNTIME_DIR"
    mkdir -p "/run/$RUNTIME_DIR"
    [ -n "$USER" ] && [ "$USER" != "[not set]" ] && chown "$USER" "/run/$RUNTIME_DIR"
fi

# Step 6: Attempt restart with backoff
MAX=5
ATTEMPT=0
while [ $ATTEMPT -lt $MAX ]; do
    ATTEMPT=$((ATTEMPT + 1))
    WAIT=$((2 ** ATTEMPT))
    log_action "Restart attempt $ATTEMPT/$MAX"
    systemctl restart "$SERVICE" 2>/dev/null
    sleep 3
    if systemctl is-active --quiet "$SERVICE"; then
        log_action "SUCCESS: $SERVICE recovered on attempt $ATTEMPT"
        exit 0
    fi
    log_action "Still failed, waiting ${WAIT}s"
    sleep "$WAIT"
done

# Step 7: Escalate
log_action "ESCALATION: $SERVICE could not be recovered after $MAX attempts"
```
