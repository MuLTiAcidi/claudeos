# Retry Engine Agent

Auto-retries failed jobs with configurable backoff strategies (linear, exponential, jittered), max-retry caps, dead letter queue for permanently failed work, alert escalation on final failure, and a circuit breaker to stop hammering broken downstreams. Pure bash + sqlite, no external job server required.

---

## Safety Rules

- ALWAYS cap retries — never run an unbounded retry loop.
- ALWAYS use jittered backoff for distributed retries to avoid thundering herd.
- NEVER retry non-idempotent jobs without an idempotency key.
- ALWAYS write failed jobs to a dead letter queue (DLQ) — never silently drop.
- ALWAYS log every attempt with timestamp, exit code, and duration.
- NEVER bypass the circuit breaker without explicit override flag.
- ALWAYS alert on final failure (final retry exhausted).
- Maximum default retries = 5; maximum default backoff = 300 seconds.

---

## 1. Required Tools

```bash
sudo apt update
sudo apt install -y bash coreutils sqlite3 jq curl flock util-linux
```

### Verify

```bash
for t in bash sqlite3 jq curl flock; do
    command -v "$t" >/dev/null && echo "OK: $t" || echo "MISSING: $t"
done
```

---

## 2. State Storage (SQLite)

### Schema

```bash
DB=/var/lib/retry-engine/state.db
sudo mkdir -p /var/lib/retry-engine
sudo sqlite3 "$DB" <<'SQL'
CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    command      TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending',  -- pending|running|success|failed|dlq
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_retries  INTEGER NOT NULL DEFAULT 5,
    strategy     TEXT NOT NULL DEFAULT 'exponential',  -- linear|exponential|jittered
    base_delay   INTEGER NOT NULL DEFAULT 2,
    last_error   TEXT,
    next_run_at  INTEGER,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_state ON jobs(state);
CREATE INDEX IF NOT EXISTS idx_next  ON jobs(next_run_at);

CREATE TABLE IF NOT EXISTS attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT NOT NULL,
    attempt    INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER,
    exit_code  INTEGER,
    duration   INTEGER,
    output     TEXT
);

CREATE TABLE IF NOT EXISTS dlq (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id       TEXT NOT NULL,
    name         TEXT NOT NULL,
    command      TEXT NOT NULL,
    failed_at    INTEGER NOT NULL,
    final_error  TEXT,
    attempts     INTEGER
);

CREATE TABLE IF NOT EXISTS circuit (
    name        TEXT PRIMARY KEY,
    state       TEXT NOT NULL,            -- closed|open|half_open
    fail_count  INTEGER NOT NULL DEFAULT 0,
    opened_at   INTEGER,
    threshold   INTEGER NOT NULL DEFAULT 5,
    cooldown    INTEGER NOT NULL DEFAULT 60
);
SQL

sudo chmod 660 "$DB"
```

---

## 3. Backoff Strategies

### Linear Backoff (delay = base * attempt)

```bash
linear_delay() {
    local BASE=$1
    local ATTEMPT=$2
    echo $((BASE * ATTEMPT))
}
linear_delay 5 3   # -> 15
```

### Exponential Backoff (delay = base * 2^attempt)

```bash
exponential_delay() {
    local BASE=$1
    local ATTEMPT=$2
    local MAX=${3:-300}
    local D=$((BASE * (2 ** ATTEMPT)))
    [ $D -gt $MAX ] && D=$MAX
    echo $D
}
exponential_delay 2 5      # -> 64
exponential_delay 2 10 300 # -> 300 (capped)
```

### Jittered Exponential (full jitter)

```bash
jittered_delay() {
    local BASE=$1
    local ATTEMPT=$2
    local MAX=${3:-300}
    local CAP=$((BASE * (2 ** ATTEMPT)))
    [ $CAP -gt $MAX ] && CAP=$MAX
    echo $((RANDOM % (CAP + 1)))
}
jittered_delay 2 4
```

### Equal Jitter

```bash
equal_jitter() {
    local BASE=$1
    local ATTEMPT=$2
    local MAX=${3:-300}
    local CAP=$((BASE * (2 ** ATTEMPT)))
    [ $CAP -gt $MAX ] && CAP=$MAX
    local HALF=$((CAP / 2))
    echo $((HALF + (RANDOM % (HALF + 1))))
}
```

### Decorrelated Jitter

```bash
decorrelated_jitter() {
    local BASE=$1
    local PREV=$2
    local MAX=${3:-300}
    local UPPER=$((PREV * 3))
    [ $UPPER -gt $MAX ] && UPPER=$MAX
    [ $UPPER -lt $BASE ] && UPPER=$BASE
    echo $((BASE + (RANDOM % (UPPER - BASE + 1))))
}
```

---

## 4. Inline Retry Loop (One-Shot)

### Retry Any Command Up To N Times

```bash
retry() {
    local MAX=${MAX_RETRIES:-5}
    local BASE=${BASE_DELAY:-2}
    local ATTEMPT=0
    while true; do
        ATTEMPT=$((ATTEMPT + 1))
        if "$@"; then
            echo "Success on attempt $ATTEMPT"
            return 0
        fi
        if [ $ATTEMPT -ge $MAX ]; then
            echo "Failed after $ATTEMPT attempts" >&2
            return 1
        fi
        local DELAY=$((BASE * (2 ** (ATTEMPT - 1))))
        echo "Attempt $ATTEMPT failed, sleeping ${DELAY}s"
        sleep $DELAY
    done
}

# Usage:
retry curl -fsS https://api.example.com/health
MAX_RETRIES=10 BASE_DELAY=3 retry ./flaky-script.sh
```

### Retry With Jitter Inline

```bash
retry_jittered() {
    local MAX=${MAX_RETRIES:-5}
    local BASE=${BASE_DELAY:-2}
    local CAP=${MAX_DELAY:-300}
    local A=0
    while true; do
        A=$((A + 1))
        "$@" && return 0
        [ $A -ge $MAX ] && return 1
        local EXP=$((BASE * (2 ** (A - 1))))
        [ $EXP -gt $CAP ] && EXP=$CAP
        local DELAY=$((RANDOM % (EXP + 1)))
        echo "attempt=$A delay=${DELAY}s"
        sleep $DELAY
    done
}
```

### Retry Until a Condition Holds

```bash
retry_until() {
    local TIMEOUT=$1; shift
    local DEADLINE=$(( $(date +%s) + TIMEOUT ))
    while [ $(date +%s) -lt $DEADLINE ]; do
        "$@" && return 0
        sleep 2
    done
    return 1
}

retry_until 60 curl -fsS http://127.0.0.1:8080/health
```

---

## 5. Job Queue Operations

### Enqueue a Job

```bash
enqueue() {
    local NAME="$1"
    local CMD="$2"
    local MAX="${3:-5}"
    local STRATEGY="${4:-exponential}"
    local ID="job-$(date +%s)-$$-$RANDOM"
    local NOW=$(date +%s)
    sqlite3 "$DB" <<SQL
INSERT INTO jobs (id, name, command, state, max_retries, strategy, next_run_at, created_at, updated_at)
VALUES ('$ID', '$NAME', \$\$$CMD\$\$, 'pending', $MAX, '$STRATEGY', $NOW, $NOW, $NOW);
SQL
    echo "$ID"
}

enqueue "send-report" "/usr/local/bin/send-daily-report.sh" 5 exponential
```

### List Pending Jobs

```bash
sqlite3 "$DB" "SELECT id, name, attempts, state, datetime(next_run_at,'unixepoch') FROM jobs WHERE state IN ('pending','failed') ORDER BY next_run_at;"
```

### List DLQ

```bash
sqlite3 "$DB" "SELECT id, job_id, name, datetime(failed_at,'unixepoch'), attempts FROM dlq ORDER BY failed_at DESC LIMIT 20;"
```

### Requeue a DLQ Job

```bash
requeue_dlq() {
    local DLQ_ID="$1"
    local ROW=$(sqlite3 -separator '|' "$DB" "SELECT job_id, name, command FROM dlq WHERE id=$DLQ_ID;")
    IFS='|' read -r JID NAME CMD <<<"$ROW"
    enqueue "$NAME" "$CMD"
    sqlite3 "$DB" "DELETE FROM dlq WHERE id=$DLQ_ID;"
}
```

---

## 6. Worker Loop

### Save as `/usr/local/bin/retry-worker.sh`

```bash
#!/bin/bash
set -uo pipefail
DB=/var/lib/retry-engine/state.db
LOG=/var/log/retry-engine.log

log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }

# Single instance
exec 9>/var/lock/retry-worker.lock
flock -n 9 || { log "Worker already running"; exit 0; }

NOW=$(date +%s)

# Pull a due job
ROW=$(sqlite3 -separator '|' "$DB" "
SELECT id, name, command, attempts, max_retries, strategy, base_delay
FROM jobs
WHERE state IN ('pending','failed') AND next_run_at <= $NOW
ORDER BY next_run_at LIMIT 1;
")

[ -z "$ROW" ] && exit 0

IFS='|' read -r ID NAME CMD ATTEMPTS MAX STRATEGY BASE <<<"$ROW"
ATTEMPT=$((ATTEMPTS + 1))

# Mark running
sqlite3 "$DB" "UPDATE jobs SET state='running', updated_at=$NOW WHERE id='$ID';"

log "RUN id=$ID name=$NAME attempt=$ATTEMPT/$MAX"
START=$(date +%s)
OUT=$(bash -c "$CMD" 2>&1); EC=$?
END=$(date +%s)
DUR=$((END - START))

# Record attempt (escape single quotes)
SAFE_OUT=$(echo "$OUT" | sed "s/'/''/g" | head -c 4000)
sqlite3 "$DB" "INSERT INTO attempts (job_id, attempt, started_at, ended_at, exit_code, duration, output) VALUES ('$ID', $ATTEMPT, $START, $END, $EC, $DUR, '$SAFE_OUT');"

if [ $EC -eq 0 ]; then
    sqlite3 "$DB" "UPDATE jobs SET state='success', attempts=$ATTEMPT, updated_at=$END WHERE id='$ID';"
    log "OK id=$ID dur=${DUR}s"
    exit 0
fi

log "FAIL id=$ID ec=$EC"

if [ $ATTEMPT -ge $MAX ]; then
    # Move to DLQ
    SAFE_ERR=$(echo "$OUT" | tail -c 1000 | sed "s/'/''/g")
    sqlite3 "$DB" "
INSERT INTO dlq (job_id, name, command, failed_at, final_error, attempts)
VALUES ('$ID', '$NAME', \$\$$CMD\$\$, $END, '$SAFE_ERR', $ATTEMPT);
UPDATE jobs SET state='dlq', attempts=$ATTEMPT, last_error='$SAFE_ERR', updated_at=$END WHERE id='$ID';
"
    log "DLQ id=$ID after $ATTEMPT attempts"
    /usr/local/bin/notify --severity critical --source retry-engine \
        --message "Job $NAME ($ID) moved to DLQ after $ATTEMPT attempts" 2>/dev/null || true
    exit 1
fi

# Schedule next attempt by strategy
case "$STRATEGY" in
    linear)      DELAY=$((BASE * ATTEMPT));;
    exponential) DELAY=$((BASE * (2 ** ATTEMPT))); [ $DELAY -gt 300 ] && DELAY=300;;
    jittered)    EXP=$((BASE * (2 ** ATTEMPT))); [ $EXP -gt 300 ] && EXP=300; DELAY=$((RANDOM % (EXP + 1)));;
    *)           DELAY=$((BASE * (2 ** ATTEMPT)));;
esac

NEXT=$((END + DELAY))
sqlite3 "$DB" "UPDATE jobs SET state='failed', attempts=$ATTEMPT, next_run_at=$NEXT, updated_at=$END WHERE id='$ID';"
log "RETRY id=$ID in ${DELAY}s (strategy=$STRATEGY)"
```

### Make Executable

```bash
sudo chmod +x /usr/local/bin/retry-worker.sh
```

### Run Every Minute via Cron

```bash
* * * * * /usr/local/bin/retry-worker.sh >/dev/null 2>&1
```

### Or systemd Timer

```bash
sudo tee /etc/systemd/system/retry-worker.service <<'EOF'
[Unit]
Description=Retry engine worker
[Service]
Type=oneshot
ExecStart=/usr/local/bin/retry-worker.sh
EOF

sudo tee /etc/systemd/system/retry-worker.timer <<'EOF'
[Unit]
Description=Run retry worker every minute
[Timer]
OnUnitActiveSec=60s
OnBootSec=60s
[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now retry-worker.timer
```

---

## 7. Circuit Breaker

### Update Circuit on Failure / Success

```bash
DB=/var/lib/retry-engine/state.db

circuit_record() {
    local NAME="$1"
    local OK="$2"   # 1 = success, 0 = failure
    local NOW=$(date +%s)
    sqlite3 "$DB" <<SQL
INSERT INTO circuit (name, state, fail_count) VALUES ('$NAME','closed',0)
ON CONFLICT(name) DO NOTHING;
SQL
    if [ "$OK" = "1" ]; then
        sqlite3 "$DB" "UPDATE circuit SET fail_count=0, state='closed', opened_at=NULL WHERE name='$NAME';"
    else
        sqlite3 "$DB" "UPDATE circuit SET fail_count=fail_count+1 WHERE name='$NAME';"
        local F=$(sqlite3 "$DB" "SELECT fail_count FROM circuit WHERE name='$NAME';")
        local T=$(sqlite3 "$DB" "SELECT threshold FROM circuit WHERE name='$NAME';")
        if [ "$F" -ge "$T" ]; then
            sqlite3 "$DB" "UPDATE circuit SET state='open', opened_at=$NOW WHERE name='$NAME';"
        fi
    fi
}

circuit_check() {
    local NAME="$1"
    local NOW=$(date +%s)
    local ROW=$(sqlite3 -separator '|' "$DB" "SELECT state, opened_at, cooldown FROM circuit WHERE name='$NAME';")
    [ -z "$ROW" ] && return 0
    IFS='|' read -r ST OPEN CD <<<"$ROW"
    case "$ST" in
        closed)    return 0;;
        open)
            if [ $((NOW - OPEN)) -ge "$CD" ]; then
                sqlite3 "$DB" "UPDATE circuit SET state='half_open' WHERE name='$NAME';"
                return 0
            fi
            return 1;;
        half_open) return 0;;
    esac
}
```

### Use Circuit in a Wrapper

```bash
guarded_run() {
    local NAME="$1"; shift
    if ! circuit_check "$NAME"; then
        echo "Circuit OPEN for $NAME — refusing"
        return 99
    fi
    if "$@"; then
        circuit_record "$NAME" 1
        return 0
    else
        circuit_record "$NAME" 0
        return 1
    fi
}

guarded_run "external-api" curl -fsS https://api.example.com/data
```

### Reset a Circuit Manually

```bash
sqlite3 "$DB" "UPDATE circuit SET state='closed', fail_count=0, opened_at=NULL WHERE name='external-api';"
```

---

## 8. Dead Letter Queue Management

### Inspect DLQ

```bash
sqlite3 "$DB" "SELECT id, name, datetime(failed_at,'unixepoch'), attempts, substr(final_error,1,80) FROM dlq ORDER BY failed_at DESC;"
```

### Replay All DLQ Items

```bash
sqlite3 "$DB" "SELECT id FROM dlq;" | while read DID; do
    requeue_dlq "$DID"
done
```

### Purge DLQ Older Than 30 Days

```bash
sqlite3 "$DB" "DELETE FROM dlq WHERE failed_at < strftime('%s','now','-30 days');"
```

### Export DLQ to JSON

```bash
sqlite3 -json "$DB" "SELECT * FROM dlq;" > /var/lib/retry-engine/dlq-$(date +%F).json
```

---

## 9. Failure Logging and Alerts

### Tail the Log

```bash
tail -f /var/log/retry-engine.log
```

### Count Failures Today

```bash
grep "$(date +%F)" /var/log/retry-engine.log | grep -c FAIL
```

### Alert via notify on Final Failure (built into worker)

```bash
/usr/local/bin/notify --severity critical --source retry-engine \
    --message "Job $NAME ($ID) moved to DLQ after $ATTEMPTS attempts"
```

### Alert if Worker Hasn't Run in 5 Minutes

```bash
LAST=$(stat -c %Y /var/log/retry-engine.log 2>/dev/null || echo 0)
NOW=$(date +%s)
if [ $((NOW - LAST)) -gt 300 ]; then
    /usr/local/bin/notify --severity warning --message "retry-worker hasn't logged in $((NOW-LAST))s"
fi
```

---

## 10. Configurable Retry Strategies (per job)

### Strategy Profiles

```bash
# In sqlite, set strategy column when enqueuing
enqueue "linear-job" "./script.sh" 5 linear
enqueue "expo-job" "./script.sh" 5 exponential
enqueue "jittered-job" "./script.sh" 5 jittered
```

### Override Base Delay

```bash
sqlite3 "$DB" "UPDATE jobs SET base_delay=10 WHERE id='job-xxxxx';"
```

---

## 11. CLI Wrapper

### Save as `/usr/local/bin/retryctl`

```bash
#!/bin/bash
DB=/var/lib/retry-engine/state.db

case "$1" in
    enqueue)
        shift
        NAME="$1"; CMD="$2"; MAX="${3:-5}"; STRATEGY="${4:-exponential}"
        ID="job-$(date +%s)-$$-$RANDOM"
        NOW=$(date +%s)
        sqlite3 "$DB" "INSERT INTO jobs (id,name,command,state,max_retries,strategy,next_run_at,created_at,updated_at) VALUES ('$ID','$NAME',\$\$$CMD\$\$,'pending',$MAX,'$STRATEGY',$NOW,$NOW,$NOW);"
        echo "$ID"
        ;;
    list)
        sqlite3 -column -header "$DB" "SELECT id,name,state,attempts,max_retries,datetime(next_run_at,'unixepoch') AS next FROM jobs ORDER BY updated_at DESC LIMIT 30;"
        ;;
    dlq)
        sqlite3 -column -header "$DB" "SELECT id,job_id,name,datetime(failed_at,'unixepoch') AS failed,attempts FROM dlq ORDER BY failed_at DESC LIMIT 30;"
        ;;
    replay)
        DID="$2"
        ROW=$(sqlite3 -separator '|' "$DB" "SELECT name, command FROM dlq WHERE id=$DID;")
        IFS='|' read -r NAME CMD <<<"$ROW"
        $0 enqueue "$NAME" "$CMD"
        sqlite3 "$DB" "DELETE FROM dlq WHERE id=$DID;"
        ;;
    cancel)
        sqlite3 "$DB" "UPDATE jobs SET state='cancelled' WHERE id='$2';"
        ;;
    show)
        sqlite3 -line "$DB" "SELECT * FROM jobs WHERE id='$2';"
        sqlite3 -column -header "$DB" "SELECT attempt,datetime(started_at,'unixepoch'),exit_code,duration FROM attempts WHERE job_id='$2' ORDER BY attempt;"
        ;;
    circuit)
        sqlite3 -column -header "$DB" "SELECT * FROM circuit;"
        ;;
    reset-circuit)
        sqlite3 "$DB" "UPDATE circuit SET state='closed', fail_count=0, opened_at=NULL WHERE name='$2';"
        ;;
    *)
        echo "Usage: retryctl {enqueue|list|dlq|replay|cancel|show|circuit|reset-circuit}"
        ;;
esac
```

### Make Executable

```bash
sudo chmod +x /usr/local/bin/retryctl
```

### Examples

```bash
retryctl enqueue "fetch-data" "/usr/local/bin/fetch.sh" 10 jittered
retryctl list
retryctl dlq
retryctl replay 3
retryctl show job-1712345-12345-678
retryctl circuit
```

---

## 12. Common Workflows

### "Retry a flaky curl call until it works"

```bash
retry curl -fsS --max-time 10 https://api.example.com/v1/users
```

### "Schedule a job to retry on failure"

```bash
retryctl enqueue "send-report" "/usr/local/bin/send-report.sh" 5 exponential
```

### "Show jobs that exhausted retries"

```bash
retryctl dlq
```

### "Replay everything in DLQ"

```bash
retryctl dlq | awk 'NR>2 {print $1}' | while read id; do retryctl replay "$id"; done
```

### "Stop retrying a known-broken job"

```bash
retryctl cancel job-xxxxx
```

### "Reset a tripped circuit breaker"

```bash
retryctl reset-circuit external-api
```

---

## 13. Tuning

### Adjust Defaults Globally

```bash
# Edit /etc/default/retry-engine
sudo tee /etc/default/retry-engine <<'EOF'
DEFAULT_MAX_RETRIES=5
DEFAULT_BASE_DELAY=2
DEFAULT_MAX_DELAY=300
DEFAULT_STRATEGY=exponential
EOF
```

### Worker Concurrency (multiple workers)

```bash
# Run N workers concurrently — each will pick a different job
for i in 1 2 3; do
    /usr/local/bin/retry-worker.sh &
done
wait
```

---

## 14. Troubleshooting

### Worker Won't Run

```bash
ls -l /var/lock/retry-worker.lock
fuser /var/lock/retry-worker.lock
sudo rm /var/lock/retry-worker.lock  # only if no process holds it
```

### Job Stuck in 'running'

```bash
sqlite3 "$DB" "SELECT * FROM jobs WHERE state='running';"
sqlite3 "$DB" "UPDATE jobs SET state='failed' WHERE id='job-xxxx';"
```

### DLQ Growing Unbounded

```bash
retryctl dlq | head -50
sqlite3 "$DB" "DELETE FROM dlq WHERE failed_at < strftime('%s','now','-30 days');"
```

### Circuit Stuck Open

```bash
sqlite3 "$DB" "SELECT * FROM circuit WHERE state='open';"
retryctl reset-circuit <name>
```

### sqlite3 'database is locked'

```bash
# Use WAL mode for concurrent reads
sqlite3 "$DB" "PRAGMA journal_mode=WAL;"
```

---

## Output Format

When operating on the queue, always show:

1. **Job ID / name / command**
2. **Attempt N of MAX**
3. **Strategy + computed delay before next try**
4. **Exit code + truncated stderr**
5. **Final state** (success / retrying / dlq)
6. **Circuit breaker status** for the related dependency
