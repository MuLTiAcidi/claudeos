# Drift Detector Agent

Snapshot the "known good" state of a Linux host (cron, systemd, SUID, listening ports, packages, kernel modules, `/etc`, users) and detect drift over time. Lightweight, agent-style alternative to Tripwire / AIDE, with hooks for webhook / Telegram / email alerts on drift.

## Safety Rules

- Read-only on the monitored host (except writes to `/var/lib/claudeos/baselines/` and `/var/log/claudeos/`)
- NEVER auto-remediate drift — only detect and alert. Remediation is a human decision.
- Baselines contain hashes and file lists that could reveal host layout — store with `0600` permissions
- Alerts must be rate-limited to avoid notification storms
- Exclude volatile files from `/etc` snapshots (`.lock`, `mtab`, `resolv.conf` when managed by NetworkManager, etc.)
- Log every snapshot + comparison to `/var/log/claudeos/drift-detector.log`

---

## 1. Install / Bootstrap

```bash
sudo mkdir -p /var/lib/claudeos/baselines /var/log/claudeos /etc/claudeos
sudo chmod 0700 /var/lib/claudeos/baselines
sudo touch /var/log/claudeos/drift-detector.log
sudo chmod 0640 /var/log/claudeos/drift-detector.log

# Required tools (all stock)
for t in sha256sum jq python3 ss find stat awk; do
  command -v "$t" >/dev/null || sudo apt-get install -y "$t"
done

# Optional — for systemd unit parsing and kernel module list
command -v systemctl >/dev/null || echo "[warn] no systemd — some checks will be skipped"
command -v lsmod >/dev/null || sudo apt-get install -y kmod
```

### Config file

```bash
sudo tee /etc/claudeos/drift-detector.conf >/dev/null <<'CONF'
# /etc/claudeos/drift-detector.conf

# Where baselines and the current state live
BASELINE_DIR=/var/lib/claudeos/baselines
CURRENT_DIR=/var/lib/claudeos/current

# Hashing algorithm
HASH=sha256sum

# Directories to hash recursively (space-separated)
WATCH_ETC="/etc"

# Patterns to exclude from /etc hashing (regex, one per line in a separate file)
ETC_EXCLUDE_FILE=/etc/claudeos/drift-etc-exclude.txt

# Rate limit — don't send more than N alerts per hour
ALERT_RATE_LIMIT=6

# Alert destinations (set one or more)
ALERT_WEBHOOK=""                 # generic HTTP POST
TELEGRAM_BOT_TOKEN=""            # https://api.telegram.org/bot<TOKEN>/sendMessage
TELEGRAM_CHAT_ID=""
ALERT_EMAIL="root@localhost"
CONF

sudo tee /etc/claudeos/drift-etc-exclude.txt >/dev/null <<'EXCL'
# regex patterns, matched against full path
^/etc/mtab$
^/etc/resolv\.conf$
^/etc/\.pwd\.lock$
^/etc/hostname\.tmp
/\.lock$
^/etc/ld\.so\.cache$
^/etc/cups/subscriptions\.conf
^/etc/blkid\.tab
^/etc/adjtime$
^/etc/machine-id$
EXCL
```

---

## 2. Collectors — What We Snapshot

All collectors emit line-oriented, sorted, stable output so `diff` works cleanly.

### 2.1 Cron jobs

```bash
drift_collect_cron() {
  (
    # System crons
    for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
      [ -f "$f" ] || continue
      echo "# FILE: $f"
      sha256sum "$f"
    done
    # User crons
    for u in $(cut -d: -f1 /etc/passwd); do
      c=$(crontab -u "$u" -l 2>/dev/null)
      if [ -n "$c" ]; then
        echo "# USER: $u"
        echo "$c" | sha256sum | awk -v u="$u" '{print $1"  usercrontab:"u}'
      fi
    done
    # at jobs
    command -v atq >/dev/null && atq 2>/dev/null | sort
  ) | sort
}
```

### 2.2 Systemd services

```bash
drift_collect_systemd() {
  systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null \
    | awk '{print $1, $2}' | sort
  systemctl list-units --type=service --no-legend --no-pager --state=enabled,running 2>/dev/null \
    | awk '{print "active:"$1, $3}' | sort
  # Hash every unit file for content drift
  for f in /etc/systemd/system/*.service /lib/systemd/system/*.service /usr/lib/systemd/system/*.service; do
    [ -f "$f" ] && sha256sum "$f"
  done | sort
}
```

### 2.3 SUID / SGID / capabilities

```bash
drift_collect_suid() {
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m %u %g %p\n' 2>/dev/null | sort
  command -v getcap >/dev/null && getcap -r / 2>/dev/null | sort
}
```

### 2.4 Listening network ports

```bash
drift_collect_ports() {
  ss -tulnpH 2>/dev/null | awk '{print $1, $5, $7}' | sort -u
}
```

### 2.5 Installed packages

```bash
drift_collect_packages() {
  if command -v dpkg-query >/dev/null; then
    dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' | sort
  elif command -v rpm >/dev/null; then
    rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' | sort
  fi
}
```

### 2.6 Kernel modules

```bash
drift_collect_kmods() {
  lsmod 2>/dev/null | awk 'NR>1 {print $1, $2, $3}' | sort
  command -v modinfo >/dev/null && lsmod | awk 'NR>1 {print $1}' | while read m; do
    modinfo -F filename "$m" 2>/dev/null | while read p; do
      [ -f "$p" ] && sha256sum "$p"
    done
  done | sort
}
```

### 2.7 `/etc` file hashes

```bash
drift_collect_etc() {
  local exclude=/etc/claudeos/drift-etc-exclude.txt
  find /etc -type f -print 2>/dev/null | \
    grep -vEf "$exclude" | sort | \
    xargs -I{} sha256sum "{}" 2>/dev/null
}
```

### 2.8 User accounts + SSH keys

```bash
drift_collect_users() {
  awk -F: '{print $1, $3, $4, $6, $7}' /etc/passwd | sort
  awk -F: '{print "shadow:"$1, $2}' /etc/shadow 2>/dev/null | sort
  awk -F: '{print "group:"$1, $3, $4}' /etc/group | sort
  # SSH authorized_keys per user
  while IFS=: read -r u _ uid _ _ home _; do
    [ "$uid" -lt 1000 ] && [ "$u" != "root" ] && continue
    f="$home/.ssh/authorized_keys"
    [ -f "$f" ] && sha256sum "$f"
  done < /etc/passwd
}
```

### 2.9 Firewall rules

```bash
drift_collect_firewall() {
  command -v iptables-save >/dev/null && iptables-save 2>/dev/null | grep -v '^#' | sort
  command -v nft >/dev/null && nft list ruleset 2>/dev/null | sort
  command -v ufw >/dev/null && ufw status verbose 2>/dev/null | sort
}
```

---

## 3. Take a Snapshot

```bash
drift_snapshot() {
  local name="${1:-$(date +%Y%m%d-%H%M%S)}"
  source /etc/claudeos/drift-detector.conf
  local out="$BASELINE_DIR/$name"
  sudo mkdir -p "$out"

  # Run each collector into its own file
  drift_collect_cron     | sudo tee "$out/cron.txt"     >/dev/null
  drift_collect_systemd  | sudo tee "$out/systemd.txt"  >/dev/null
  drift_collect_suid     | sudo tee "$out/suid.txt"     >/dev/null
  drift_collect_ports    | sudo tee "$out/ports.txt"    >/dev/null
  drift_collect_packages | sudo tee "$out/packages.txt" >/dev/null
  drift_collect_kmods    | sudo tee "$out/kmods.txt"    >/dev/null
  drift_collect_etc      | sudo tee "$out/etc.txt"      >/dev/null
  drift_collect_users    | sudo tee "$out/users.txt"    >/dev/null
  drift_collect_firewall | sudo tee "$out/firewall.txt" >/dev/null

  echo "$(date -Is)" | sudo tee "$out/TAKEN_AT" >/dev/null
  sudo chmod -R 0600 "$out"
  sudo find "$out" -type d -exec chmod 0700 {} +
  echo "[+] Snapshot saved: $out"
  echo "$(date -Is) snapshot $out" | sudo tee -a /var/log/claudeos/drift-detector.log >/dev/null
}

# Create the first baseline
drift_snapshot baseline
```

---

## 4. Compare Current State Against Baseline

```bash
drift_compare() {
  source /etc/claudeos/drift-detector.conf
  local baseline="${1:-baseline}"
  local base_dir="$BASELINE_DIR/$baseline"
  [ -d "$base_dir" ] || { echo "[-] no baseline at $base_dir"; return 1; }

  # Take a live snapshot to a temp dir
  local cur="/tmp/drift-current-$$"
  mkdir -p "$cur"
  drift_collect_cron     > "$cur/cron.txt"
  drift_collect_systemd  > "$cur/systemd.txt"
  drift_collect_suid     > "$cur/suid.txt"
  drift_collect_ports    > "$cur/ports.txt"
  drift_collect_packages > "$cur/packages.txt"
  drift_collect_kmods    > "$cur/kmods.txt"
  drift_collect_etc      > "$cur/etc.txt"
  drift_collect_users    > "$cur/users.txt"
  drift_collect_firewall > "$cur/firewall.txt"

  local any_drift=0
  for section in cron systemd suid ports packages kmods etc users firewall; do
    if ! diff -q "$base_dir/$section.txt" "$cur/$section.txt" >/dev/null 2>&1; then
      any_drift=1
      echo "=========================================="
      echo "  DRIFT in section: $section"
      echo "=========================================="
      diff -u "$base_dir/$section.txt" "$cur/$section.txt" | head -200
    fi
  done

  rm -rf "$cur"
  echo "$(date -Is) compare baseline=$baseline drift=$any_drift" | sudo tee -a /var/log/claudeos/drift-detector.log >/dev/null
  return $any_drift
}

drift_compare baseline
```

---

## 5. Structured JSON Diff (Python)

More useful for webhooks / alert routing than raw `diff`.

```bash
sudo tee /usr/local/bin/drift-diff.py >/dev/null <<'PY'
#!/usr/bin/env python3
"""
drift-diff.py <baseline_dir> <current_dir>
Emit a JSON summary of added / removed / changed lines per section.
"""
import sys, os, json, hashlib

SECTIONS = ["cron","systemd","suid","ports","packages","kmods","etc","users","firewall"]

def load(p):
    if not os.path.isfile(p): return set()
    with open(p, errors="ignore") as f:
        return set(l.rstrip() for l in f if l.strip())

def main():
    if len(sys.argv) != 3:
        print("usage: drift-diff.py <baseline_dir> <current_dir>", file=sys.stderr)
        sys.exit(2)
    base, cur = sys.argv[1], sys.argv[2]
    report = {"host": os.uname().nodename, "baseline": base, "sections": {}}
    any_drift = False
    for s in SECTIONS:
        b = load(os.path.join(base, s + ".txt"))
        c = load(os.path.join(cur,  s + ".txt"))
        added   = sorted(c - b)
        removed = sorted(b - c)
        if added or removed:
            any_drift = True
            report["sections"][s] = {
                "added_count":   len(added),
                "removed_count": len(removed),
                "added":   added[:50],
                "removed": removed[:50],
            }
    report["drift"] = any_drift
    print(json.dumps(report, indent=2))
    sys.exit(1 if any_drift else 0)

if __name__ == "__main__":
    main()
PY
sudo chmod +x /usr/local/bin/drift-diff.py
```

---

## 6. Alert Dispatcher

```bash
sudo tee /usr/local/bin/drift-alert.sh >/dev/null <<'BASH'
#!/usr/bin/env bash
# Usage: drift-alert.sh <json-report-file>
set -euo pipefail
source /etc/claudeos/drift-detector.conf
REPORT="$1"
[ -f "$REPORT" ] || { echo "no report"; exit 1; }

# Rate limit: stop if we've already sent $ALERT_RATE_LIMIT in the last hour
RATE_FILE=/var/lib/claudeos/baselines/.rate
touch "$RATE_FILE"
NOW=$(date +%s)
CUTOFF=$(( NOW - 3600 ))
awk -v c="$CUTOFF" '$1 >= c' "$RATE_FILE" > "$RATE_FILE.tmp" && mv "$RATE_FILE.tmp" "$RATE_FILE"
COUNT=$(wc -l < "$RATE_FILE")
if [ "$COUNT" -ge "${ALERT_RATE_LIMIT:-6}" ]; then
  echo "[rate-limited] $COUNT alerts in the last hour, skipping"
  exit 0
fi
echo "$NOW" >> "$RATE_FILE"

HOST=$(hostname)
SUMMARY=$(jq -r '.sections | to_entries | map("\(.key): +\(.value.added_count)/-\(.value.removed_count)") | join(", ")' "$REPORT")
MSG="DRIFT on $HOST — $SUMMARY"

# 1) Webhook
if [ -n "${ALERT_WEBHOOK:-}" ]; then
  curl -fsSL -X POST -H "Content-Type: application/json" --data @"$REPORT" "$ALERT_WEBHOOK" || true
fi

# 2) Telegram
if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
  curl -fsSL "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=$MSG" >/dev/null || true
fi

# 3) Email
if [ -n "${ALERT_EMAIL:-}" ] && command -v mail >/dev/null; then
  {
    echo "$MSG"
    echo
    jq . "$REPORT"
  } | mail -s "[drift-detector] $HOST" "$ALERT_EMAIL" || true
fi

logger -t drift-detector "$MSG"
BASH
sudo chmod +x /usr/local/bin/drift-alert.sh
```

---

## 7. Unified CLI

```bash
sudo tee /usr/local/bin/drift-detector >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
source /etc/claudeos/drift-detector.conf
LOG=/var/log/claudeos/drift-detector.log
log(){ echo "$(date -Is) $*" | sudo tee -a "$LOG" >/dev/null; }

do_collect_all() {
  local dest="$1"
  sudo mkdir -p "$dest"
  # Reuse the bash functions — but we're in a separate script so inline them
  (
    for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
      [ -f "$f" ] && sha256sum "$f"
    done
    for u in $(cut -d: -f1 /etc/passwd); do
      c=$(crontab -u "$u" -l 2>/dev/null || true)
      [ -n "$c" ] && echo "$c" | sha256sum | awk -v u="$u" '{print $1"  usercrontab:"u}'
    done
  ) | sort | sudo tee "$dest/cron.txt" >/dev/null

  systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1, $2}' | sort | sudo tee "$dest/systemd.txt" >/dev/null
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m %u %g %p\n' 2>/dev/null | sort | sudo tee "$dest/suid.txt" >/dev/null
  ss -tulnpH 2>/dev/null | awk '{print $1, $5, $7}' | sort -u | sudo tee "$dest/ports.txt" >/dev/null

  if command -v dpkg-query >/dev/null; then
    dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' | sort
  elif command -v rpm >/dev/null; then
    rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' | sort
  fi | sudo tee "$dest/packages.txt" >/dev/null

  lsmod 2>/dev/null | awk 'NR>1 {print $1, $2, $3}' | sort | sudo tee "$dest/kmods.txt" >/dev/null

  find /etc -type f 2>/dev/null | grep -vEf "$ETC_EXCLUDE_FILE" | sort | xargs -I{} sha256sum "{}" 2>/dev/null | sudo tee "$dest/etc.txt" >/dev/null

  {
    awk -F: '{print $1, $3, $4, $6, $7}' /etc/passwd | sort
    awk -F: '{print "group:"$1, $3, $4}' /etc/group | sort
  } | sudo tee "$dest/users.txt" >/dev/null

  {
    command -v iptables-save >/dev/null && iptables-save 2>/dev/null | grep -v '^#' | sort
    command -v nft >/dev/null && nft list ruleset 2>/dev/null | sort
  } | sudo tee "$dest/firewall.txt" >/dev/null

  echo "$(date -Is)" | sudo tee "$dest/TAKEN_AT" >/dev/null
  sudo chmod -R 0600 "$dest"
  sudo find "$dest" -type d -exec chmod 0700 {} +
}

case "${1:-}" in
  snapshot)
    name="${2:-$(date +%Y%m%d-%H%M%S)}"
    dest="$BASELINE_DIR/$name"
    do_collect_all "$dest"
    echo "[+] snapshot: $dest"
    log "snapshot $dest"
    ;;
  list)
    ls -1 "$BASELINE_DIR" 2>/dev/null | grep -v '^\.' || echo "no baselines"
    ;;
  compare)
    base="${2:-baseline}"
    [ -d "$BASELINE_DIR/$base" ] || { echo "no baseline $base"; exit 1; }
    tmp="/tmp/drift-cur-$$"
    do_collect_all "$tmp"
    /usr/local/bin/drift-diff.py "$BASELINE_DIR/$base" "$tmp" > /tmp/drift-report.json
    rc=$?
    cat /tmp/drift-report.json
    rm -rf "$tmp"
    log "compare base=$base drift=$rc"
    exit $rc
    ;;
  check)
    # Like compare but ALSO fires an alert if drift is found
    base="${2:-baseline}"
    tmp="/tmp/drift-cur-$$"
    do_collect_all "$tmp"
    if ! /usr/local/bin/drift-diff.py "$BASELINE_DIR/$base" "$tmp" > /tmp/drift-report.json; then
      /usr/local/bin/drift-alert.sh /tmp/drift-report.json
    fi
    rm -rf "$tmp"
    ;;
  promote)
    # Promote an existing snapshot to be the new baseline
    src="${2:?snapshot name}"
    [ -d "$BASELINE_DIR/$src" ] || { echo "no such snapshot"; exit 1; }
    sudo rm -rf "$BASELINE_DIR/baseline"
    sudo cp -a "$BASELINE_DIR/$src" "$BASELINE_DIR/baseline"
    echo "[+] baseline now = $src"
    log "promote $src"
    ;;
  diff)
    a="${2:?a}"; b="${3:?b}"
    /usr/local/bin/drift-diff.py "$BASELINE_DIR/$a" "$BASELINE_DIR/$b"
    ;;
  purge)
    keep="${2:-5}"
    ls -1t "$BASELINE_DIR" | grep -v '^baseline$' | tail -n +$((keep+1)) | while read d; do
      sudo rm -rf "$BASELINE_DIR/$d" && echo "purged $d"
    done
    ;;
  *)
    cat <<USAGE
Usage:
  drift-detector snapshot [name]   # take a new snapshot
  drift-detector list              # list snapshots
  drift-detector compare [name]    # diff current vs baseline (json)
  drift-detector check [name]      # compare + alert on drift (for cron)
  drift-detector promote <name>    # make <name> the new baseline
  drift-detector diff <a> <b>      # diff two saved snapshots
  drift-detector purge [keep=5]    # keep only the N newest snapshots
USAGE
    exit 1
    ;;
esac
BASH
sudo chmod +x /usr/local/bin/drift-detector
```

---

## 8. Schedule via Cron

```bash
# Run every 15 minutes, alert on drift
sudo tee /etc/cron.d/claudeos-drift >/dev/null <<'CRON'
# m h dom mon dow user  command
*/15 * * * * root /usr/local/bin/drift-detector check baseline >>/var/log/claudeos/drift-detector.log 2>&1

# Nightly rolling snapshot + purge (keeps last 14)
5 3 * * * root /usr/local/bin/drift-detector snapshot nightly-$(date +\%F) >/dev/null 2>&1 && /usr/local/bin/drift-detector purge 14
CRON

# Or as a systemd timer
sudo tee /etc/systemd/system/drift-detector.service >/dev/null <<'UNIT'
[Unit]
Description=ClaudeOS Drift Detector
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/drift-detector check baseline
User=root
UNIT

sudo tee /etc/systemd/system/drift-detector.timer >/dev/null <<'UNIT'
[Unit]
Description=Run drift-detector every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now drift-detector.timer
```

---

## 9. Example Session

```bash
# 1. Take the initial baseline after provisioning the host
sudo drift-detector snapshot baseline

# 2. Someone installs a package and adds a cron job
sudo apt-get install -y tmux
(crontab -l; echo "* * * * * /tmp/evil.sh") | crontab -

# 3. Compare — exits non-zero on drift
sudo drift-detector compare baseline
# -> prints JSON diff with "added": ["* * * * * /tmp/evil.sh", "tmux 3.2a-..."]

# 4. Triage, then either:
#    a) Revert the change by hand, run compare again → clean
#    b) Promote the new snapshot if the change was intended
sudo drift-detector snapshot post-install
sudo drift-detector promote post-install

# 5. Keep history pruned
sudo drift-detector purge 10
```

---

## 10. Tuning Tips

- **False positives in `/etc`**: add noisy paths to `/etc/claudeos/drift-etc-exclude.txt` (e.g., `^/etc/shadow-$`, `^/etc/gshadow-$`, logrotate state files)
- **Package churn**: on dev boxes run `check` only once an hour; on prod every 5 minutes is fine
- **Large /etc**: `drift_collect_etc` hashes each file. To reduce cost, exclude `/etc/ssl/certs/` and `/etc/ca-certificates/` which are symlink-heavy
- **Containers**: mount `/etc`, `/var/lib/dpkg/status`, `/proc` read-only into a sidecar and run the agent there

---

## 11. Integration with Other Agents

### Chain with `incident-responder`

When drift fires, automatically create an incident ticket:

```bash
# Alert webhook -> incident-responder
ALERT_WEBHOOK="http://127.0.0.1:8765/drift"  # consumed by incident-responder listener
```

### Chain with `config-hardener`

```bash
# After applying hardening, refresh the baseline
sudo config-hardener apply --profile cis-lvl2
sudo drift-detector snapshot hardened
sudo drift-detector promote hardened
```

### Chain with `backdoor-hunter`

If `drift-detector check` reports new SUID binaries or kernel modules, kick off `backdoor-hunter`:

```bash
sudo drift-detector compare baseline > /tmp/report.json || \
  jq -e '.sections.suid or .sections.kmods' /tmp/report.json >/dev/null && \
  /usr/local/bin/backdoor-hunter --focus suid,kmod
```

---

## 12. Troubleshooting

| Symptom | Fix |
|---|---|
| Every 15 min run reports drift in `/etc` | Add the offending path to `drift-etc-exclude.txt` |
| `getcap: not found` | `sudo apt-get install libcap2-bin` |
| Systemd units show drift every boot | Exclude `*.wants/*.service` symlinks or mask transient units |
| Too many alerts | Lower `ALERT_RATE_LIMIT` or widen exclusions |
| Baseline stale after upgrade | `drift-detector snapshot post-upgrade && drift-detector promote post-upgrade` |
| `ss: command not found` | `sudo apt-get install iproute2` |

---

## 13. Files Created by This Agent

```
/etc/claudeos/drift-detector.conf        # config
/etc/claudeos/drift-etc-exclude.txt      # exclude patterns
/var/lib/claudeos/baselines/baseline/    # current known-good
/var/lib/claudeos/baselines/<name>/      # historical snapshots
/var/log/claudeos/drift-detector.log     # audit trail
/usr/local/bin/drift-detector            # CLI
/usr/local/bin/drift-diff.py             # JSON diff helper
/usr/local/bin/drift-alert.sh            # alert dispatcher
/etc/systemd/system/drift-detector.*     # timer + service
```
