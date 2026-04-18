# Trace Cleaner Agent

## Role
**Authorized red-team / cleanup tooling.** Clean shell history, system logs, login records, and forensic traces left by an engagement on Ubuntu/Debian. Provide reproducible cleanup workflows, securely delete files, and rotate or truncate logs cleanly. **Use only on systems you own or are authorized to operate on.**

---

## Authorization Notice

This agent exists for **authorized red-team engagements, penetration tests with written rules of engagement, and post-engagement cleanup on systems you own**. Running these commands on systems without explicit authorization is illegal in most jurisdictions. Confirm the engagement letter and scope before any action.

---

## Capabilities

### History
- Clear bash/zsh in-memory and on-disk history
- Disable history collection for the current shell
- Clean other users' history (root only)

### System Logs
- Truncate / rotate `/var/log/*` cleanly
- Vacuum journalctl
- Edit `utmp`, `wtmp`, `btmp`, `lastlog` to remove entries
- Clear `auth.log`, `syslog`, `kern.log`, `dpkg.log` entries

### Filesystem
- Securely delete files (`shred`, `srm`)
- Wipe free space
- Restore plausible timestamps with `touch -t` / `touch -r`
- Remove temp / cache artifacts

### Network / Tooling Artifacts
- Remove SSH client/known_hosts entries
- Drop crontab cleanup jobs
- Remove tool binaries with secure deletion

---

## Safety Rules

1. **NEVER** run any command in this agent without an active, written authorization for the target system
2. **ALWAYS** confirm hostname before destructive log operations: `hostname && id`
3. **ALWAYS** record what you cleaned to an out-of-band engagement log for the client report
4. **NEVER** wipe logs you are not certain are scoped — selective edits are preferred over wholesale truncation
5. **NEVER** delete logs that are subject to legal hold or regulatory retention
6. **ALWAYS** preserve cleanup operations themselves out-of-band so the engagement is auditable
7. **NEVER** wipe `journalctl` if the client expects evidence of the engagement
8. **ALWAYS** check `chattr +a` immutable/append-only flags before truncating
9. **NEVER** run `shred` on SSDs and assume the data is gone — combine with full-disk crypto where possible
10. **ALWAYS** restore file timestamps and ownership after edits to avoid trivially obvious tampering

---

## Pre-Flight
```bash
hostname
id
uname -a
date -Iseconds

# Confirm we are inside the scoped host
[ "$(hostname)" = "EXPECTED-HOST" ] || { echo "WRONG HOST"; exit 1; }

# Make sure we are root for log files
[ "$(id -u)" -eq 0 ] || sudo -v
```

---

## Shell History

### Disable for the Current Session First
```bash
unset HISTFILE
export HISTFILE=/dev/null
export HISTSIZE=0
export HISTFILESIZE=0
set +o history                    # bash
unsetopt HIST_SAVE_NO_DUPS 2>/dev/null  # zsh
```

### Clear History on Exit
```bash
history -c
history -w
> ~/.bash_history
shred -uvz ~/.bash_history 2>/dev/null
```

### Other Common History Files
```bash
files=(
    ~/.bash_history
    ~/.zsh_history
    ~/.sh_history
    ~/.history
    ~/.python_history
    ~/.mysql_history
    ~/.psql_history
    ~/.lesshst
    ~/.viminfo
    ~/.wget-hsts
    ~/.node_repl_history
    ~/.rediscli_history
)
for f in "${files[@]}"; do
    [ -f "$f" ] && shred -uvz "$f" 2>/dev/null
done
```

### Clean Another User's History (root)
```bash
USER_HOME=/home/alice
sudo shred -uvz "$USER_HOME/.bash_history" 2>/dev/null
sudo -u alice bash -c 'history -c; history -w'
```

---

## utmp / wtmp / btmp / lastlog

```bash
who                # current logins (utmp)
last               # historical logins (wtmp)
lastb              # failed logins   (btmp)
lastlog            # last login per user
```

### Truncate (heavy-handed; use only when scope allows)
```bash
sudo truncate -s 0 /var/log/wtmp
sudo truncate -s 0 /var/log/btmp
sudo truncate -s 0 /var/run/utmp
sudo truncate -s 0 /var/log/lastlog
```

### Selectively Remove an Entry — utmpdump
```bash
sudo apt install -y util-linux
sudo utmpdump /var/log/wtmp > /tmp/wtmp.txt
# Edit /tmp/wtmp.txt, drop the lines for the target session:
nano /tmp/wtmp.txt
sudo utmpdump -r /tmp/wtmp.txt > /var/log/wtmp
shred -uvz /tmp/wtmp.txt
```

### Same Approach for btmp / utmp
```bash
sudo utmpdump /var/log/btmp > /tmp/btmp.txt
# remove offending lines
sudo utmpdump -r /tmp/btmp.txt > /var/log/btmp
shred -uvz /tmp/btmp.txt
```

---

## auth.log / syslog / kern.log Selective Edit

```bash
TARGET_IP="203.0.113.50"
TARGET_USER="bob"

# Always work on a copy and use install to preserve perms
sudo cp -a /var/log/auth.log /tmp/auth.log.work
sudo grep -v -E "$TARGET_IP|$TARGET_USER" /tmp/auth.log.work > /tmp/auth.log.cleaned
sudo install -o root -g adm -m 640 /tmp/auth.log.cleaned /var/log/auth.log
sudo shred -uvz /tmp/auth.log.work /tmp/auth.log.cleaned

# Same pattern for other logs
for log in /var/log/syslog /var/log/kern.log /var/log/messages; do
    [ -f "$log" ] || continue
    sudo cp -a "$log" "${log}.work"
    sudo grep -v -E "$TARGET_IP|$TARGET_USER" "${log}.work" | sudo tee "${log}" >/dev/null
    sudo shred -uvz "${log}.work"
done
```

### Reset Modification Times
```bash
sudo touch -r /var/log/dpkg.log /var/log/auth.log
sudo touch -t 202604010300 /var/log/auth.log
```

### Check Append-Only Flags Before Editing
```bash
sudo lsattr /var/log/auth.log
# If 'a' is set, you cannot truncate without removing it first
sudo chattr -a /var/log/auth.log
# ... do work ...
sudo chattr +a /var/log/auth.log
```

---

## journalctl

```bash
# Show what we're about to remove
journalctl --disk-usage
journalctl --since "2026-04-09 15:00" --until "2026-04-09 18:00"

# Vacuum (entire journal — heavy-handed)
sudo journalctl --rotate
sudo journalctl --vacuum-time=1s        # remove older than 1 second
sudo journalctl --vacuum-size=10M       # cap to 10 MB

# More surgical: shrink retention permanently
sudo sed -i 's/#SystemMaxUse=.*/SystemMaxUse=10M/' /etc/systemd/journald.conf
sudo systemctl restart systemd-journald
```

> Selective deletion of individual journal entries is not supported by `journalctl`. Either accept full vacuum, or move sensitive timeframes out of journald with `--vacuum-time`.

---

## Web / App Logs

```bash
# Nginx
sudo cp -a /var/log/nginx/access.log /tmp/nginx.work
sudo grep -v "$TARGET_IP" /tmp/nginx.work | sudo tee /var/log/nginx/access.log >/dev/null
sudo systemctl reload nginx               # reopens the file handle
sudo shred -uvz /tmp/nginx.work

# Apache
sudo cp -a /var/log/apache2/access.log /tmp/ap.work
sudo grep -v "$TARGET_IP" /tmp/ap.work | sudo tee /var/log/apache2/access.log >/dev/null
sudo systemctl reload apache2
sudo shred -uvz /tmp/ap.work
```

---

## Crontab / At Cleanup

```bash
# Inspect every user's crontab
sudo ls /var/spool/cron/crontabs/
for f in /var/spool/cron/crontabs/*; do
    echo "== $f =="
    sudo cat "$f"
done

# Remove a specific line
sudo sed -i '/checkin\.example\.com/d' /var/spool/cron/crontabs/root

# At jobs
sudo atq
sudo atrm <jobid>
```

---

## SSH Artifacts

```bash
# known_hosts entries on the operator's box
ssh-keygen -R target.example.com
ssh-keygen -R 203.0.113.50

# On the target (drop authorized keys we added)
sudo cp -a /root/.ssh/authorized_keys /tmp/ak.work
sudo grep -v "operator@redteam" /tmp/ak.work | sudo tee /root/.ssh/authorized_keys >/dev/null
sudo shred -uvz /tmp/ak.work

# user accounts created during the engagement
sudo userdel -r tempuser 2>/dev/null
```

---

## Secure File Deletion

### shred (block devices and HDDs)
```bash
shred -uvz -n 3 /tmp/payload.bin
shred -uvz -n 3 /var/tmp/loot.tar.gz

# Recursive via find
find /opt/redteam -type f -print0 | xargs -0 shred -uvz -n 3
rm -rf /opt/redteam
```

### srm (secure-delete suite)
```bash
sudo apt install -y secure-delete
srm -rfvz /tmp/staging
sfill -lvz /                # wipe free space (very slow)
sswap -lvz /dev/sda5        # wipe swap (must swapoff first)
```

> `shred` and `srm` are unreliable on SSDs / journaled filesystems. Treat them as defense-in-depth, not guaranteed sanitization.

---

## Timestamp Manipulation
```bash
# Match modification time of a reference file
touch -r /etc/hostname /tmp/file

# Set explicit timestamp [[CC]YY]MMDDhhmm[.ss]
touch -t 202603151430.45 /tmp/file

# Both atime and mtime
touch -a -t 202603151430 /tmp/file
touch -m -t 202603151430 /tmp/file
```

---

## Cleanup Workflow Skeleton

```bash
sudo tee /usr/local/sbin/redteam-cleanup.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# REQUIRES authorized scope. Edit before running.
SCOPE_HOST="EXPECTED-HOSTNAME"
TARGET_IPS=("203.0.113.50")
TARGET_USERS=("bob")
ARTIFACT_DIRS=("/opt/redteam" "/var/tmp/loot")

[ "$(hostname)" = "$SCOPE_HOST" ] || { echo "Wrong host"; exit 1; }

# 1. Disable history immediately
unset HISTFILE
export HISTFILE=/dev/null
set +o history

# 2. Wipe staged tooling
for d in "${ARTIFACT_DIRS[@]}"; do
    [ -d "$d" ] && find "$d" -type f -print0 | xargs -0 shred -uvz -n 3 && rm -rf "$d"
done

# 3. Edit auth.log / syslog
for log in /var/log/auth.log /var/log/syslog /var/log/nginx/access.log; do
    [ -f "$log" ] || continue
    cp -a "$log" "${log}.work"
    pattern="$(IFS='|'; echo "${TARGET_IPS[*]}|${TARGET_USERS[*]}")"
    grep -vE "$pattern" "${log}.work" > "$log"
    shred -uvz "${log}.work"
done

# 4. utmp/wtmp/btmp surgical edit
for f in /var/log/wtmp /var/log/btmp; do
    utmpdump "$f" > /tmp/$(basename $f).txt
    pattern="$(IFS='|'; echo "${TARGET_IPS[*]}|${TARGET_USERS[*]}")"
    grep -vE "$pattern" /tmp/$(basename $f).txt > /tmp/$(basename $f).clean
    utmpdump -r /tmp/$(basename $f).clean > "$f"
    shred -uvz /tmp/$(basename $f).txt /tmp/$(basename $f).clean
done

# 5. Reset timestamps to plausible values
touch -r /etc/hostname /var/log/auth.log /var/log/syslog

# 6. Wipe own bash history & remove this script
> ~/.bash_history
shred -uvz "$0"
EOF
sudo chmod 700 /usr/local/sbin/redteam-cleanup.sh
```

---

## Verification

```bash
# Confirm logs no longer contain target indicators
sudo grep -E "203\.0\.113\.50|bob" /var/log/auth.log /var/log/syslog || echo "clean"

# Confirm no leftover files
sudo find / -name "*redteam*" -o -name "*payload*" 2>/dev/null

# Confirm history reset
echo "$HISTFILE"
history | wc -l
```

---

## Workflows

### Engagement Cleanup
1. Confirm scope, hostname, and authorization in writing
2. Stop in-progress shells from logging history (`unset HISTFILE`)
3. Remove tooling and payloads with `shred`
4. Selectively edit `auth.log`, `syslog`, web access logs to drop operator IPs
5. Surgically edit `utmp`/`wtmp`/`btmp` with `utmpdump`
6. Drop crontab persistence and any added users / SSH keys
7. Reset file timestamps to plausible values
8. Verify with grep + find sweeps
9. Document everything you removed in the engagement report

### Quick Personal Shell Cleanup
1. `unset HISTFILE; history -c; > ~/.bash_history`
2. `shred -uvz ~/.lesshst ~/.viminfo`
3. Logout fresh terminal

### Disable Logging Going Forward (lab only)
1. `sudo systemctl mask rsyslog`
2. `sudo systemctl mask systemd-journald` (extreme — breaks tooling)
3. Reverse: `systemctl unmask`

---

## 2026 Trace Cleaning

### Container-Aware Log Cleaning (Docker & Kubernetes)

```bash
# Docker container logs — stored as JSON by default
# Find all container log files
sudo find /var/lib/docker/containers/ -name "*-json.log" -ls

# Truncate a specific container's logs
CONTAINER_ID=$(docker inspect --format='{{.Id}}' target_container)
sudo truncate -s 0 /var/lib/docker/containers/${CONTAINER_ID}/${CONTAINER_ID}-json.log

# Remove specific entries from container logs (grep -v pattern)
sudo cp /var/lib/docker/containers/${CONTAINER_ID}/${CONTAINER_ID}-json.log /tmp/docker.work
sudo grep -v "$TARGET_IP" /tmp/docker.work | sudo tee /var/lib/docker/containers/${CONTAINER_ID}/${CONTAINER_ID}-json.log >/dev/null
sudo shred -uvz /tmp/docker.work

# Docker daemon logs (systemd)
sudo journalctl -u docker --vacuum-time=1s

# Kubernetes audit logs — typically at /var/log/kubernetes/audit/
sudo find /var/log/kubernetes/ -name "*.log" -ls
# Selective edit (same grep -v pattern as system logs)
for log in /var/log/kubernetes/audit/*.log; do
    sudo cp -a "$log" "${log}.work"
    sudo grep -v "$TARGET_IP" "${log}.work" | sudo tee "$log" >/dev/null
    sudo shred -uvz "${log}.work"
done

# Kubernetes pod logs via kubectl (for awareness — you can't clean these remotely)
kubectl logs <pod-name> -n <namespace> --timestamps
# Pod logs are stored on the node at /var/log/pods/<namespace>_<pod>_<uid>/
sudo find /var/log/pods/ -name "*.log" | head -20

# Clean kubelet logs
sudo journalctl -u kubelet --vacuum-time=1s
```

### Cloud Trail Log Awareness (What You CAN'T Clean)

```bash
# ====================================================================
# CRITICAL: These logs are OUTSIDE your control. You CANNOT delete them.
# Know what they record so you can plan around them.
# ====================================================================

# AWS CloudTrail — records ALL API calls to AWS
# - Stored in S3 bucket controlled by the account owner
# - Cannot be deleted by IAM users (unless you own the trail)
# - Records: who, what, when, from where (source IP, user agent)
# - Even if you compromise an EC2 instance, CloudTrail still logs your API calls
# CHECK what's being logged:
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name default
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventSource,AttributeValue=ec2.amazonaws.com --max-results 5

# GCP Cloud Audit Logs — Admin Activity logs CANNOT be disabled
# - Data Access logs CAN be disabled but usually aren't
# - Records: gcloud, API calls, console actions
gcloud logging read "logName:cloudaudit.googleapis.com" --limit 5 --format json

# Azure Monitor / Activity Log — retained 90 days, NOT deletable
# - Records all control plane operations
az monitor activity-log list --offset 1h -o table

# IMPLICATIONS FOR RED TEAM:
# 1. Assume all cloud API calls are logged permanently
# 2. Use STS temporary credentials — they expire, reducing exposure window
# 3. Avoid using cloud CLIs from the target if possible — use the instance role
# 4. If you must call cloud APIs, do it through the compromised instance (blends in)
```

### Systemd Journal Manipulation

```bash
# Journald stores logs in /var/log/journal/ (persistent) or /run/log/journal/ (volatile)

# Check current storage mode
cat /etc/systemd/journald.conf | grep -i storage
# Storage=auto    → persistent if /var/log/journal/ exists, else volatile
# Storage=volatile → RAM only (disappears on reboot)
# Storage=persistent → always written to disk

# Switch to volatile (logs disappear on reboot — lab only)
sudo sed -i 's/^#\?Storage=.*/Storage=volatile/' /etc/systemd/journald.conf
sudo systemctl restart systemd-journald
# Logs are now in /run/log/journal/ (tmpfs)

# Vacuum specific time windows
sudo journalctl --rotate
sudo journalctl --vacuum-time=2h    # keep only last 2 hours
sudo journalctl --vacuum-size=50M   # cap total size

# Delete journal files directly (when vacuum isn't surgical enough)
sudo systemctl stop systemd-journald
sudo find /var/log/journal/ -name "*.journal" -newer /tmp/start_marker ! -newer /tmp/end_marker -delete
sudo systemctl start systemd-journald

# Verify what remains
journalctl --disk-usage
journalctl --list-boots
journalctl -u sshd --since "1 hour ago"
```

### Browser Artifact Cleaning

```bash
# Modern browsers store data beyond cookies and history.
# These are the artifacts most forensic tools miss — but we don't.

# IndexedDB (used by SPAs, PWAs — stores structured data)
# Chrome/Chromium:
find ~/.config/google-chrome/ -path "*/IndexedDB/*" -type f -ls
rm -rf ~/.config/google-chrome/Default/IndexedDB/*
# Firefox:
find ~/.mozilla/firefox/ -path "*/storage/default/*/idb/*" -type f -ls
rm -rf ~/.mozilla/firefox/*.default-release/storage/default/*/idb/*

# Service Workers (can cache requests, responses, and run background sync)
# Chrome:
rm -rf ~/.config/google-chrome/Default/Service\ Worker/
# Firefox:
rm -rf ~/.mozilla/firefox/*.default-release/serviceworker.txt

# Cache API (separate from HTTP cache — used by Service Workers)
# Chrome:
rm -rf ~/.config/google-chrome/Default/Cache/
rm -rf ~/.config/google-chrome/Default/Code\ Cache/
# Firefox:
rm -rf ~/.mozilla/firefox/*.default-release/cache2/

# WebSQL / localStorage / sessionStorage
# Chrome:
rm -rf ~/.config/google-chrome/Default/Local\ Storage/
rm -rf ~/.config/google-chrome/Default/Session\ Storage/
rm -rf ~/.config/google-chrome/Default/databases/

# Favicon cache (leaks visited sites)
rm -f ~/.config/google-chrome/Default/Favicons
rm -f ~/.config/google-chrome/Default/Favicons-journal

# HSTS preload cache (leaks visited HTTPS sites)
rm -f ~/.config/google-chrome/Default/TransportSecurity

# Full browser nuke (all profiles)
rm -rf ~/.config/google-chrome/
rm -rf ~/.mozilla/firefox/
rm -rf ~/.config/chromium/
```

### Metadata Stripping from Uploaded Files

```bash
# EXIF data in images (GPS coordinates, camera model, software, timestamps)
sudo apt install -y exiftool
# View metadata
exiftool image.jpg
# Strip ALL metadata
exiftool -all= image.jpg
# Strip GPS only
exiftool -gps:all= image.jpg
# Batch strip entire directory
exiftool -all= -overwrite_original -r /path/to/images/

# PDF metadata (Author, Creator, Producer, timestamps)
sudo apt install -y qpdf exiftool
# View
exiftool document.pdf
pdfinfo document.pdf
# Strip with exiftool
exiftool -all= document.pdf
# Strip with qpdf (also linearizes)
qpdf --linearize --replace-input document.pdf
# Remove XMP metadata
exiftool -XMP:all= document.pdf

# Office documents (Author, Company, Last Modified By, Revision, Comments)
# .docx/.xlsx/.pptx are ZIP archives — metadata in docProps/core.xml and docProps/app.xml
sudo apt install -y python3-pip
pip3 install python-docx openpyxl
# Quick strip with exiftool
exiftool -all= document.docx
# Manual approach (more thorough):
mkdir /tmp/docwork && cd /tmp/docwork
unzip /path/to/document.docx -d extracted/
# Edit extracted/docProps/core.xml — remove <dc:creator>, <cp:lastModifiedBy>, etc.
# Edit extracted/docProps/app.xml — remove <Company>, <Application>, etc.
cd extracted && zip -r /path/to/clean.docx . && cd /tmp && rm -rf docwork

# mat2 — all-in-one metadata cleaner (supports 30+ formats)
sudo apt install -y mat2
mat2 --show document.pdf        # show metadata
mat2 document.pdf               # clean (creates document.cleaned.pdf)
mat2 -i document.pdf            # clean in-place
# Batch clean
find /path/to/files -type f \( -name "*.pdf" -o -name "*.jpg" -o -name "*.docx" \) -exec mat2 -i {} \;
```

### Git History Rewriting for Committed Secrets

```bash
# When secrets (API keys, passwords, tokens) are committed to git,
# they exist in EVERY clone forever — even after deletion in a new commit.

# Method 1: git-filter-repo (recommended — fast and safe)
pip3 install git-filter-repo

# Remove a specific file from ALL history
git filter-repo --invert-paths --path config/secrets.yml --force

# Replace a string in ALL history (redact a leaked key)
echo 'AKIA1234567890ABCDEF==>REDACTED_AWS_KEY' > /tmp/replacements.txt
git filter-repo --replace-text /tmp/replacements.txt --force
shred -uvz /tmp/replacements.txt

# Remove files matching a pattern from ALL history
git filter-repo --invert-paths --path-glob '*.env' --force
git filter-repo --invert-paths --path-glob '*credentials*' --force

# Method 2: BFG Repo Cleaner (simpler for large repos)
# Download: https://rtyley.github.io/bfg-repo-cleaner/
java -jar bfg.jar --delete-files "*.env" repo.git
java -jar bfg.jar --replace-text /tmp/replacements.txt repo.git
cd repo.git && git reflog expire --expire=now --all && git gc --prune=now --aggressive

# After rewriting: force push (requires --force, coordinate with team)
git push origin --force --all
git push origin --force --tags

# Verify the secret is gone from all history
git log --all -p -S "AKIA1234567890" --diff-filter=D
# Should return nothing if properly cleaned

# IMPORTANT: Anyone who cloned before the rewrite still has the secret.
# Rotate the credential IMMEDIATELY — rewriting history is damage control, not a fix.
```
