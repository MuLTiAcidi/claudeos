# Deploy Automator Agent

End-to-end deployment automation for Linux servers. Pulls code from Git, runs build steps (`npm`/`maven`/`cargo`/`go`), executes tests, restarts systemd services, runs health checks with retries, performs blue-green or rollback on failure, and notifies via Slack/Telegram webhooks. Logs every deploy to a deploy log for audit.

---

## Safety Rules

- ALWAYS deploy from a clean working tree — refuse if `git status` shows local changes.
- ALWAYS run health checks after restart — rollback if health fails.
- NEVER deploy directly to production without a rollback target (previous commit/release).
- ALWAYS create a deploy lock file to prevent concurrent deploys.
- NEVER `git push --force` to production branches.
- ALWAYS log deploys to `/var/log/deploy-automator.log` with commit SHA, user, time, status.
- NEVER skip tests on a production deploy unless explicitly flagged.
- ALWAYS notify channels on success AND failure.

---

## 1. Required Tools

```bash
sudo apt update
sudo apt install -y git curl jq build-essential
# Optional language toolchains
sudo apt install -y nodejs npm openjdk-17-jdk maven golang rustc cargo
```

### Verify

```bash
for t in git curl jq systemctl; do
    command -v "$t" >/dev/null && echo "OK: $t" || echo "MISSING: $t"
done
```

---

## 2. Deploy Lock

### Create / Check Lock

```bash
LOCK=/var/lock/deploy.lock
if [ -e "$LOCK" ]; then
    echo "Another deploy is running (PID $(cat $LOCK)). Aborting."
    exit 1
fi
echo $$ > "$LOCK"
trap 'rm -f "$LOCK"' EXIT INT TERM
```

### flock Alternative (preferred)

```bash
exec 9>/var/lock/deploy.lock
flock -n 9 || { echo "Deploy locked"; exit 1; }
```

---

## 3. Git Operations

### Clean Working Tree Check

```bash
cd /srv/myapp
if [ -n "$(git status --porcelain)" ]; then
    echo "Working tree dirty — aborting"
    git status
    exit 1
fi
```

### Fetch and Reset to Remote main

```bash
cd /srv/myapp
git fetch --all --prune
git checkout main
git reset --hard origin/main
```

### Pull Specific Release Tag

```bash
TAG="v1.4.2"
git fetch --tags
git checkout "tags/$TAG"
```

### Capture Current and Previous SHA

```bash
PREV_SHA=$(git rev-parse HEAD)
git pull --ff-only origin main
NEW_SHA=$(git rev-parse HEAD)
echo "Deploying $PREV_SHA -> $NEW_SHA"
```

### Show Changed Files Between Deploys

```bash
git diff --name-only "$PREV_SHA" "$NEW_SHA"
```

### Show Changelog Since Last Deploy

```bash
git log --oneline "$PREV_SHA..$NEW_SHA"
```

---

## 4. Build Steps

### Node.js / npm

```bash
cd /srv/myapp
npm ci --omit=dev
npm run build
```

### Node.js / pnpm

```bash
pnpm install --frozen-lockfile
pnpm build
```

### Java / Maven

```bash
cd /srv/myapp
mvn -B clean package -DskipTests=false
```

### Java / Gradle

```bash
./gradlew clean build --no-daemon
```

### Rust / Cargo

```bash
cd /srv/myapp
cargo build --release
```

### Go

```bash
cd /srv/myapp
go mod download
go build -o bin/myapp ./cmd/myapp
```

### Python (venv + requirements)

```bash
cd /srv/myapp
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

### PHP / Composer

```bash
cd /srv/myapp
composer install --no-dev --optimize-autoloader
```

### Docker Image Build

```bash
cd /srv/myapp
docker build -t myapp:$NEW_SHA .
docker tag myapp:$NEW_SHA myapp:latest
```

---

## 5. Test Execution

### Node.js

```bash
npm test -- --ci
```

### Maven

```bash
mvn -B test
```

### Cargo

```bash
cargo test --release
```

### Go

```bash
go test ./... -count=1
```

### Python pytest

```bash
.venv/bin/pytest -q
```

### Abort on Test Failure

```bash
if ! npm test -- --ci; then
    echo "Tests failed — aborting deploy"
    exit 1
fi
```

---

## 6. Database Migrations

### Node.js (Knex / Prisma)

```bash
npx knex migrate:latest
# or
npx prisma migrate deploy
```

### Rails

```bash
RAILS_ENV=production bundle exec rake db:migrate
```

### Django

```bash
.venv/bin/python manage.py migrate --noinput
```

### Flyway / Liquibase

```bash
flyway -url=jdbc:mysql://localhost/myapp -user=app migrate
```

### Backup DB Before Migration

```bash
mysqldump --single-transaction myapp > /var/backups/myapp-$(date +%F-%H%M).sql
```

---

## 7. Service Restart

### systemd Reload Then Restart

```bash
sudo systemctl daemon-reload
sudo systemctl restart myapp.service
```

### Graceful Reload (if supported)

```bash
sudo systemctl reload myapp.service
```

### Check Service is Active

```bash
sudo systemctl is-active myapp.service
sudo systemctl status myapp.service --no-pager -l
```

### Restart Multiple Services

```bash
for svc in myapp-api myapp-worker myapp-scheduler; do
    sudo systemctl restart "$svc"
    sleep 2
done
```

### Reload Nginx (after static asset changes)

```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## 8. Health Check with Retries

### Curl with Retry Loop

```bash
HEALTH_URL="http://127.0.0.1:8080/health"
MAX_TRIES=20
SLEEP=3

for i in $(seq 1 $MAX_TRIES); do
    if curl -fsS --max-time 5 "$HEALTH_URL" >/dev/null; then
        echo "Health OK on attempt $i"
        exit 0
    fi
    echo "Attempt $i failed, retrying in ${SLEEP}s..."
    sleep $SLEEP
done

echo "Health check failed after $MAX_TRIES attempts"
exit 1
```

### Curl Built-in Retry

```bash
curl --retry 10 --retry-delay 3 --retry-connrefused -fsS \
    http://127.0.0.1:8080/health
```

### Check JSON Response Field

```bash
RESP=$(curl -fsS http://127.0.0.1:8080/health)
echo "$RESP" | jq -e '.status == "ok"' >/dev/null
```

### Check via systemd + Port

```bash
systemctl is-active myapp.service && \
    ss -tln | grep -q ':8080 '
```

---

## 9. Rollback on Failure

### Git Revert + Restart

```bash
rollback() {
    echo "Rolling back to $PREV_SHA"
    cd /srv/myapp
    git reset --hard "$PREV_SHA"
    npm ci --omit=dev && npm run build
    sudo systemctl restart myapp.service
    sleep 5
    curl -fsS http://127.0.0.1:8080/health && echo "Rollback OK" || echo "Rollback FAILED"
}
trap rollback ERR
```

### Symlink-Based Rollback (release directories)

```bash
# Layout: /srv/myapp/releases/<sha>/
#         /srv/myapp/current -> releases/<sha>
RELEASES=/srv/myapp/releases
CURRENT=/srv/myapp/current
PREV=$(readlink -f "$CURRENT")

# After failure:
ln -sfn "$PREV" "$CURRENT"
sudo systemctl restart myapp.service
```

### Docker Tag Rollback

```bash
docker tag myapp:$PREV_SHA myapp:latest
docker compose up -d myapp
```

---

## 10. Blue-Green Deployment

### Layout

```bash
# Two systemd services on different ports
# myapp-blue.service  -> port 8081
# myapp-green.service -> port 8082
# Nginx upstream switches between them
```

### Deploy to Idle Color

```bash
ACTIVE=$(cat /etc/myapp/active-color)   # "blue" or "green"
if [ "$ACTIVE" = "blue" ]; then
    IDLE="green"; PORT=8082
else
    IDLE="blue"; PORT=8081
fi

echo "Deploying to $IDLE (port $PORT)"
cd "/srv/myapp-$IDLE"
git fetch && git reset --hard origin/main
npm ci --omit=dev && npm run build
sudo systemctl restart "myapp-$IDLE.service"

# Health check the idle color
for i in {1..20}; do
    curl -fsS "http://127.0.0.1:$PORT/health" && break
    sleep 3
done || { echo "Idle health failed"; exit 1; }

# Switch nginx upstream
sudo sed -i "s/server 127.0.0.1:[0-9]*/server 127.0.0.1:$PORT/" /etc/nginx/conf.d/myapp.conf
sudo nginx -t && sudo systemctl reload nginx

echo "$IDLE" > /etc/myapp/active-color
echo "Switched to $IDLE"
```

---

## 11. Deploy Logging

### Append Structured Log Line

```bash
LOG=/var/log/deploy-automator.log
log_event() {
    local STATUS="$1"
    local SHA="$2"
    local NOTE="$3"
    echo "$(date -Is) status=$STATUS sha=$SHA user=$(whoami) note=\"$NOTE\"" \
        | tee -a "$LOG"
}

log_event "STARTED" "$NEW_SHA" "deploy from main"
log_event "SUCCESS" "$NEW_SHA" "build+test+restart OK"
log_event "FAILED"  "$NEW_SHA" "health check failed, rolled back"
```

### Per-Deploy Detailed Log

```bash
RUNLOG=/var/log/deploys/$(date +%F-%H%M%S)-${NEW_SHA:0:7}.log
mkdir -p /var/log/deploys
exec > >(tee -a "$RUNLOG") 2>&1
```

---

## 12. Notifications (Webhook)

### Slack

```bash
slack_notify() {
    local MSG="$1"
    curl -X POST -H 'Content-Type: application/json' \
        --data "{\"text\":\"$MSG\"}" \
        "$SLACK_WEBHOOK_URL"
}

slack_notify ":rocket: Deploy started for myapp ($NEW_SHA)"
slack_notify ":white_check_mark: Deploy SUCCESS ($NEW_SHA)"
slack_notify ":x: Deploy FAILED ($NEW_SHA), rolled back"
```

### Telegram

```bash
telegram_notify() {
    local MSG="$1"
    curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -d chat_id="${TG_CHAT_ID}" \
        --data-urlencode text="$MSG"
}
telegram_notify "Deploy of myapp succeeded ($NEW_SHA)"
```

### Discord

```bash
curl -X POST -H 'Content-Type: application/json' \
    --data "{\"content\":\"Deploy SUCCESS $NEW_SHA\"}" \
    "$DISCORD_WEBHOOK_URL"
```

### Generic Webhook with JSON

```bash
curl -X POST "$WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc \
        --arg app myapp \
        --arg sha "$NEW_SHA" \
        --arg status "$STATUS" \
        '{app:$app, sha:$sha, status:$status, ts:now|todateiso8601}')"
```

---

## 13. Full Deploy Script

### Save as `/usr/local/bin/deploy-myapp.sh`

```bash
#!/bin/bash
set -euo pipefail

APP=myapp
APP_DIR=/srv/$APP
BRANCH=${BRANCH:-main}
HEALTH_URL=http://127.0.0.1:8080/health
SVC=$APP.service
LOG=/var/log/deploy-automator.log
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"

log() { echo "[$(date -Is)] $*" | tee -a "$LOG"; }
notify() {
    [ -z "$SLACK_WEBHOOK_URL" ] && return
    curl -sS -X POST -H 'Content-Type: application/json' \
        --data "{\"text\":\"$1\"}" "$SLACK_WEBHOOK_URL" >/dev/null || true
}

# Lock
exec 9>/var/lock/deploy-$APP.lock
flock -n 9 || { log "Another deploy in progress"; exit 1; }

cd "$APP_DIR"

# Capture current SHA for rollback
PREV_SHA=$(git rev-parse HEAD)
log "Current SHA: $PREV_SHA"

notify ":rocket: Deploy of $APP starting from $PREV_SHA"
log "STARTED"

# Pull latest
git fetch --all --prune
git checkout "$BRANCH"
git reset --hard "origin/$BRANCH"
NEW_SHA=$(git rev-parse HEAD)
log "Target SHA: $NEW_SHA"

if [ "$PREV_SHA" = "$NEW_SHA" ]; then
    log "Already at $NEW_SHA — nothing to deploy"
    notify ":information_source: $APP already at $NEW_SHA"
    exit 0
fi

# Rollback handler
rollback() {
    log "FAILURE — rolling back to $PREV_SHA"
    notify ":x: Deploy of $APP FAILED, rolling back to $PREV_SHA"
    cd "$APP_DIR"
    git reset --hard "$PREV_SHA"
    npm ci --omit=dev >/dev/null && npm run build >/dev/null || true
    sudo systemctl restart "$SVC" || true
    log "Rollback complete"
    notify ":leftwards_arrow_with_hook: Rollback to $PREV_SHA done"
    exit 1
}
trap rollback ERR

# Build
log "Installing dependencies"
npm ci --omit=dev

log "Running build"
npm run build

log "Running tests"
npm test -- --ci

# Migrations (optional)
if [ -f "scripts/migrate.sh" ]; then
    log "Running migrations"
    ./scripts/migrate.sh
fi

# Restart
log "Restarting $SVC"
sudo systemctl daemon-reload
sudo systemctl restart "$SVC"

# Health
log "Health check"
for i in {1..20}; do
    if curl -fsS --max-time 5 "$HEALTH_URL" >/dev/null; then
        log "Health OK on attempt $i"
        break
    fi
    sleep 3
    [ "$i" = 20 ] && false
done

log "SUCCESS sha=$NEW_SHA"
notify ":white_check_mark: Deploy of $APP succeeded ($NEW_SHA)"
```

### Make Executable

```bash
sudo chmod +x /usr/local/bin/deploy-myapp.sh
```

### Run

```bash
sudo /usr/local/bin/deploy-myapp.sh
```

---

## 14. Triggering Deploys

### Manual

```bash
sudo /usr/local/bin/deploy-myapp.sh
```

### Cron Nightly

```bash
0 2 * * * /usr/local/bin/deploy-myapp.sh >/dev/null 2>&1
```

### Webhook Listener (simple, via socat or systemd socket)

```bash
# Inetd-style listener using systemd
sudo tee /etc/systemd/system/deploy-listener.socket <<'EOF'
[Socket]
ListenStream=127.0.0.1:9999
Accept=yes

[Install]
WantedBy=sockets.target
EOF

sudo tee /etc/systemd/system/deploy-listener@.service <<'EOF'
[Service]
ExecStart=/usr/local/bin/deploy-myapp.sh
StandardInput=socket
EOF

sudo systemctl enable --now deploy-listener.socket
```

---

## 15. Common Workflows

### "Deploy main to production"

```bash
sudo /usr/local/bin/deploy-myapp.sh
```

### "Deploy a specific tag"

```bash
sudo BRANCH=v1.5.0 /usr/local/bin/deploy-myapp.sh
```

### "Roll back to previous release"

```bash
cd /srv/myapp
PREV=$(git log --format=%H -n 2 | tail -1)
git reset --hard "$PREV"
npm ci && npm run build && sudo systemctl restart myapp
```

### "Check last 10 deploys"

```bash
grep -E 'STARTED|SUCCESS|FAILED' /var/log/deploy-automator.log | tail -30
```

### "Show what changed in the last deploy"

```bash
cd /srv/myapp
git log -1 --stat
```

### "Health check the running app"

```bash
curl -fsS http://127.0.0.1:8080/health | jq .
```

---

## 16. Troubleshooting

### Deploy Hangs on npm ci

```bash
# Clear cache and retry
npm cache clean --force
rm -rf node_modules
npm ci
```

### git pull Fails Due to Local Changes

```bash
cd /srv/myapp
git stash push -m "pre-deploy autostash"
git pull --ff-only
git stash pop  # if needed
```

### Health Check Always Fails

```bash
# Check if service is bound
ss -tlnp | grep :8080
journalctl -u myapp.service --no-pager -n 50
curl -v http://127.0.0.1:8080/health
```

### Lock File Stale

```bash
ls -l /var/lock/deploy-myapp.lock
# Check PID and confirm not running
sudo rm /var/lock/deploy-myapp.lock
```

### Rollback Itself Fails

```bash
journalctl -u myapp.service -n 100 --no-pager
sudo systemctl status myapp.service
# Manual: revert to last known-good tag
git checkout v1.4.0 && npm ci && npm run build && sudo systemctl restart myapp
```

---

## Output Format

When deploying, always show:

1. **App / branch / target SHA / previous SHA**
2. **Build & test results** (pass/fail per step)
3. **Restart & health-check outcome**
4. **Rollback action if any**
5. **Notification status** (slack/telegram/discord delivered)
6. **Log file path** (`/var/log/deploys/<timestamp>-<sha>.log`)
