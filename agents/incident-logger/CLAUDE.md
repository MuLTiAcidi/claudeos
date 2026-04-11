# Incident Logger Agent

Real-time security incident logging and evidence collection. Provides structured incident documentation, evidence preservation, chain of custody tracking, timeline generation, and forensic image creation.

## Safety Rules

- NEVER modify or delete evidence
- NEVER tamper with logs or audit trails
- ALWAYS maintain chain of custody for all evidence
- NEVER share incident data without authorization
- Preserve original evidence — work only on copies
- Timestamp all actions in UTC
- Store all incident data with restricted permissions (0600/0700)
- Document every investigative step taken

---

## 1. Incident Initialization

### Create Incident Record

```bash
# Initialize a new security incident
create_incident() {
  local SEVERITY="$1"  # critical, high, medium, low
  local TYPE="$2"      # intrusion, malware, data-breach, dos, unauthorized-access, other
  local DESCRIPTION="$3"
  
  INCIDENT_ID="INC-$(date +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
  INCIDENT_DIR="/var/log/incidents/${INCIDENT_ID}"
  
  mkdir -p "${INCIDENT_DIR}"/{evidence,timeline,notes,forensics}
  chmod 700 "${INCIDENT_DIR}"
  
  cat > "${INCIDENT_DIR}/incident.json" <<EOF
{
  "incident_id": "${INCIDENT_ID}",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "severity": "${SEVERITY}",
  "type": "${TYPE}",
  "description": "${DESCRIPTION}",
  "status": "open",
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)",
  "reporter": "$(whoami)",
  "last_updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
  
  chmod 600 "${INCIDENT_DIR}/incident.json"
  echo "Incident created: ${INCIDENT_ID}"
  echo "Directory: ${INCIDENT_DIR}"
}

# Usage:
# create_incident "high" "intrusion" "Suspicious SSH activity from unknown IP"
```

### Incident Status Management

```bash
# Update incident status
update_incident_status() {
  local INCIDENT_DIR="$1"
  local STATUS="$2"  # open, investigating, contained, eradicated, recovered, closed
  local NOTE="$3"
  
  # Update status in incident file
  python3 -c "
import json
with open('${INCIDENT_DIR}/incident.json', 'r') as f:
    data = json.load(f)
data['status'] = '${STATUS}'
data['last_updated'] = '$(date -u +%Y-%m-%dT%H:%M:%SZ)'
with open('${INCIDENT_DIR}/incident.json', 'w') as f:
    json.dump(data, f, indent=2)
"
  
  # Add timeline entry
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | STATUS_CHANGE | Status changed to: ${STATUS} | ${NOTE}" >> "${INCIDENT_DIR}/timeline/timeline.log"
  
  echo "Incident updated to: ${STATUS}"
}

# List all incidents
list_incidents() {
  echo "=== Active Incidents ==="
  for dir in /var/log/incidents/INC-*; do
    [ -d "$dir" ] || continue
    if [ -f "$dir/incident.json" ]; then
      python3 -c "
import json
with open('$dir/incident.json') as f:
    d = json.load(f)
print(f\"{d['incident_id']} | {d['severity']} | {d['status']} | {d['type']} | {d['description'][:60]}\")
" 2>/dev/null
    fi
  done
}
```

---

## 2. Evidence Collection

### System State Capture

```bash
# Capture current system state as evidence
capture_system_state() {
  local EVIDENCE_DIR="$1"
  local TAG="$2"
  local TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
  local STATE_DIR="${EVIDENCE_DIR}/system-state-${TIMESTAMP}"
  
  mkdir -p "$STATE_DIR"
  
  echo "Capturing system state..."
  
  # Process information
  ps auxf > "${STATE_DIR}/processes.txt" 2>/dev/null
  ps -eo pid,ppid,user,stat,args --sort=-pcpu > "${STATE_DIR}/processes-sorted.txt" 2>/dev/null
  
  # Network connections
  sudo ss -tnpa > "${STATE_DIR}/connections.txt" 2>/dev/null
  sudo ss -ulnpa > "${STATE_DIR}/udp-connections.txt" 2>/dev/null
  sudo netstat -tlnp > "${STATE_DIR}/listening-ports.txt" 2>/dev/null
  
  # Network configuration
  ip addr show > "${STATE_DIR}/ip-addresses.txt" 2>/dev/null
  ip route show > "${STATE_DIR}/routes.txt" 2>/dev/null
  ip neigh show > "${STATE_DIR}/arp-table.txt" 2>/dev/null
  
  # Active users
  who -a > "${STATE_DIR}/logged-in-users.txt" 2>/dev/null
  w > "${STATE_DIR}/user-activity.txt" 2>/dev/null
  last -20 > "${STATE_DIR}/recent-logins.txt" 2>/dev/null
  lastb -20 > "${STATE_DIR}/failed-logins.txt" 2>/dev/null
  
  # Open files
  sudo lsof -nP > "${STATE_DIR}/open-files.txt" 2>/dev/null
  
  # Loaded kernel modules
  lsmod > "${STATE_DIR}/kernel-modules.txt" 2>/dev/null
  
  # Cron jobs
  for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u "$user" -l > "${STATE_DIR}/cron-${user}.txt" 2>/dev/null
  done
  
  # Scheduled timers
  systemctl list-timers --all > "${STATE_DIR}/systemd-timers.txt" 2>/dev/null
  
  # Services
  systemctl list-units --type=service --state=running > "${STATE_DIR}/running-services.txt" 2>/dev/null
  
  # DNS cache
  resolvectl statistics > "${STATE_DIR}/dns-stats.txt" 2>/dev/null
  
  # Environment
  env > "${STATE_DIR}/environment.txt" 2>/dev/null
  
  # Generate hash manifest
  find "$STATE_DIR" -type f -exec sha256sum {} \; > "${STATE_DIR}/MANIFEST.sha256"
  
  chmod -R 600 "$STATE_DIR"/*
  echo "System state captured: $STATE_DIR"
}

# Usage:
# capture_system_state "/var/log/incidents/INC-xxx/evidence" "initial-capture"
```

### Log Evidence Collection

```bash
# Collect and preserve log evidence
collect_log_evidence() {
  local EVIDENCE_DIR="$1"
  local HOURS_BACK="${2:-24}"
  local TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
  local LOG_DIR="${EVIDENCE_DIR}/logs-${TIMESTAMP}"
  
  mkdir -p "$LOG_DIR"
  
  echo "Collecting log evidence (last ${HOURS_BACK} hours)..."
  
  # System logs
  for logfile in /var/log/auth.log /var/log/syslog /var/log/kern.log \
    /var/log/daemon.log /var/log/messages /var/log/secure \
    /var/log/audit/audit.log /var/log/faillog; do
    if [ -f "$logfile" ]; then
      cp "$logfile" "${LOG_DIR}/$(basename $logfile)"
      # Also capture rotated logs
      for rotated in ${logfile}.[0-9]* ${logfile}.*.gz; do
        [ -f "$rotated" ] && cp "$rotated" "${LOG_DIR}/"
      done
    fi
  done
  
  # Application logs
  for logdir in /var/log/nginx /var/log/apache2 /var/log/mysql /var/log/postgresql; do
    if [ -d "$logdir" ]; then
      cp -r "$logdir" "${LOG_DIR}/"
    fi
  done
  
  # Journalctl export
  journalctl --since "${HOURS_BACK} hours ago" --no-pager > "${LOG_DIR}/journal-full.log" 2>/dev/null
  journalctl --since "${HOURS_BACK} hours ago" -p err --no-pager > "${LOG_DIR}/journal-errors.log" 2>/dev/null
  journalctl --since "${HOURS_BACK} hours ago" -u sshd --no-pager > "${LOG_DIR}/journal-sshd.log" 2>/dev/null
  
  # Audit log export
  ausearch -ts "$(date -d "${HOURS_BACK} hours ago" +%m/%d/%Y)" 2>/dev/null > "${LOG_DIR}/audit-search.log"
  
  # Generate hashes for evidence integrity
  find "$LOG_DIR" -type f -exec sha256sum {} \; > "${LOG_DIR}/MANIFEST.sha256"
  
  chmod -R 600 "$LOG_DIR"/*
  echo "Log evidence collected: $LOG_DIR"
}
```

### File Evidence Collection

```bash
# Collect file-based evidence
collect_file_evidence() {
  local EVIDENCE_DIR="$1"
  local TARGET_FILE="$2"
  local DESCRIPTION="$3"
  local TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
  local FILE_DIR="${EVIDENCE_DIR}/file-evidence-${TIMESTAMP}"
  
  mkdir -p "$FILE_DIR"
  
  # Copy the file
  cp -p "$TARGET_FILE" "$FILE_DIR/"
  
  # Record metadata
  cat > "${FILE_DIR}/metadata.json" <<EOF
{
  "original_path": "${TARGET_FILE}",
  "collection_time": "${TIMESTAMP}",
  "description": "${DESCRIPTION}",
  "file_info": "$(file -b "$TARGET_FILE")",
  "size_bytes": $(stat -c '%s' "$TARGET_FILE" 2>/dev/null || stat -f '%z' "$TARGET_FILE" 2>/dev/null),
  "permissions": "$(stat -c '%a' "$TARGET_FILE" 2>/dev/null)",
  "owner": "$(stat -c '%U:%G' "$TARGET_FILE" 2>/dev/null)",
  "modified": "$(stat -c '%y' "$TARGET_FILE" 2>/dev/null)",
  "accessed": "$(stat -c '%x' "$TARGET_FILE" 2>/dev/null)",
  "changed": "$(stat -c '%z' "$TARGET_FILE" 2>/dev/null)",
  "md5": "$(md5sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')",
  "sha256": "$(sha256sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')"
}
EOF
  
  # Extended attributes
  getfattr -d "$TARGET_FILE" > "${FILE_DIR}/xattrs.txt" 2>/dev/null
  
  # ACLs
  getfacl "$TARGET_FILE" > "${FILE_DIR}/acls.txt" 2>/dev/null
  
  chmod -R 600 "$FILE_DIR"/*
  echo "File evidence collected: $FILE_DIR"
}
```

---

## 3. Chain of Custody

```bash
# Log chain of custody entry
log_custody() {
  local INCIDENT_DIR="$1"
  local ACTION="$2"
  local HANDLER="$3"
  local DETAILS="$4"
  local CUSTODY_LOG="${INCIDENT_DIR}/chain-of-custody.log"
  
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | ${HANDLER} | ${ACTION} | ${DETAILS}" >> "$CUSTODY_LOG"
  chmod 600 "$CUSTODY_LOG"
}

# View chain of custody
view_custody() {
  local INCIDENT_DIR="$1"
  echo "=== Chain of Custody ==="
  echo "Incident: $(basename $INCIDENT_DIR)"
  echo ""
  printf "%-25s | %-15s | %-20s | %s\n" "Timestamp" "Handler" "Action" "Details"
  echo "-------------------------------------------------------------------"
  cat "${INCIDENT_DIR}/chain-of-custody.log" 2>/dev/null | while IFS='|' read -r ts handler action details; do
    printf "%-25s |%-15s |%-20s |%s\n" "$ts" "$handler" "$action" "$details"
  done
}

# Usage:
# log_custody "/var/log/incidents/INC-xxx" "EVIDENCE_COLLECTED" "admin" "System state captured"
# log_custody "/var/log/incidents/INC-xxx" "EVIDENCE_TRANSFERRED" "admin" "Copied to secure storage"
# log_custody "/var/log/incidents/INC-xxx" "ANALYSIS_STARTED" "analyst" "Beginning log analysis"
```

---

## 4. Timeline Generation

### Build Incident Timeline

```bash
# Add timeline entry
add_timeline_entry() {
  local INCIDENT_DIR="$1"
  local EVENT_TIME="$2"     # ISO 8601 UTC
  local EVENT_TYPE="$3"     # detection, analysis, containment, eradication, recovery, lesson
  local SOURCE="$4"         # log file, tool, analyst
  local DESCRIPTION="$5"
  
  echo "${EVENT_TIME} | ${EVENT_TYPE} | ${SOURCE} | ${DESCRIPTION}" >> "${INCIDENT_DIR}/timeline/timeline.log"
  # Keep sorted
  sort -o "${INCIDENT_DIR}/timeline/timeline.log" "${INCIDENT_DIR}/timeline/timeline.log"
}

# Auto-generate timeline from logs
generate_timeline_from_logs() {
  local INCIDENT_DIR="$1"
  local SEARCH_TERM="$2"
  local HOURS_BACK="${3:-24}"
  local TIMELINE="${INCIDENT_DIR}/timeline/auto-timeline.log"
  
  echo "=== Auto-Generated Timeline ===" > "$TIMELINE"
  echo "Search term: ${SEARCH_TERM}" >> "$TIMELINE"
  echo "Period: Last ${HOURS_BACK} hours" >> "$TIMELINE"
  echo "" >> "$TIMELINE"
  
  # Auth log events
  if [ -f /var/log/auth.log ]; then
    grep -i "$SEARCH_TERM" /var/log/auth.log | tail -100 | while read -r line; do
      echo "AUTH | $line" >> "$TIMELINE"
    done
  fi
  
  # Syslog events
  if [ -f /var/log/syslog ]; then
    grep -i "$SEARCH_TERM" /var/log/syslog | tail -100 | while read -r line; do
      echo "SYSLOG | $line" >> "$TIMELINE"
    done
  fi
  
  # Kernel log events
  if [ -f /var/log/kern.log ]; then
    grep -i "$SEARCH_TERM" /var/log/kern.log | tail -50 | while read -r line; do
      echo "KERNEL | $line" >> "$TIMELINE"
    done
  fi
  
  # Audit events
  ausearch -i -ts "$(date -d "${HOURS_BACK} hours ago" +%m/%d/%Y)" 2>/dev/null | grep -i "$SEARCH_TERM" | tail -50 | while read -r line; do
    echo "AUDIT | $line" >> "$TIMELINE"
  done
  
  # Web server logs
  for log in /var/log/nginx/access.log /var/log/apache2/access.log; do
    [ -f "$log" ] && grep -i "$SEARCH_TERM" "$log" | tail -50 | while read -r line; do
      echo "WEB | $line" >> "$TIMELINE"
    done
  done
  
  # Sort timeline
  sort -o "$TIMELINE" "$TIMELINE"
  chmod 600 "$TIMELINE"
  echo "Timeline generated: $TIMELINE"
  echo "Total events: $(wc -l < "$TIMELINE")"
}

# Generate timeline for a specific IP
# generate_timeline_from_logs "/var/log/incidents/INC-xxx" "192.168.1.100" 48
```

### Export Timeline

```bash
# Export timeline as CSV
export_timeline_csv() {
  local INCIDENT_DIR="$1"
  local OUTPUT="${INCIDENT_DIR}/timeline/timeline.csv"
  
  echo "timestamp,event_type,source,description" > "$OUTPUT"
  cat "${INCIDENT_DIR}/timeline/timeline.log" | while IFS='|' read -r ts type source desc; do
    ts=$(echo "$ts" | tr -d ' ')
    type=$(echo "$type" | tr -d ' ')
    source=$(echo "$source" | tr -d ' ')
    desc=$(echo "$desc" | sed 's/,/;/g' | tr -d '"')
    echo "\"$ts\",\"$type\",\"$source\",\"$desc\""
  done >> "$OUTPUT"
  
  echo "Timeline exported: $OUTPUT"
}

# Export timeline as JSON
export_timeline_json() {
  local INCIDENT_DIR="$1"
  local OUTPUT="${INCIDENT_DIR}/timeline/timeline.json"
  
  python3 -c "
import json
events = []
with open('${INCIDENT_DIR}/timeline/timeline.log') as f:
    for line in f:
        parts = line.strip().split('|')
        if len(parts) >= 4:
            events.append({
                'timestamp': parts[0].strip(),
                'event_type': parts[1].strip(),
                'source': parts[2].strip(),
                'description': parts[3].strip()
            })
with open('$OUTPUT', 'w') as f:
    json.dump({'events': events}, f, indent=2)
"
  echo "Timeline exported: $OUTPUT"
}
```

---

## 5. Forensic Image Creation

### Create Disk Forensic Image

```bash
# Create forensic disk image with dd
create_disk_image() {
  local SOURCE="$1"      # /dev/sda
  local DEST_DIR="$2"    # Evidence directory
  local TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
  local IMAGE="${DEST_DIR}/disk-image-${TIMESTAMP}.dd"
  
  echo "Creating forensic image of $SOURCE..."
  echo "WARNING: This may take a long time for large disks"
  
  # Create raw image with dd
  sudo dd if="$SOURCE" of="$IMAGE" bs=64K conv=noerror,sync status=progress
  
  # Generate hash
  echo "Generating SHA256 hash..."
  sha256sum "$IMAGE" > "${IMAGE}.sha256"
  
  # Record metadata
  cat > "${DEST_DIR}/image-metadata-${TIMESTAMP}.json" <<EOF
{
  "source": "${SOURCE}",
  "image_file": "$(basename $IMAGE)",
  "created": "${TIMESTAMP}",
  "sha256": "$(cat ${IMAGE}.sha256 | awk '{print $1}')",
  "size_bytes": $(stat -c '%s' "$IMAGE" 2>/dev/null || stat -f '%z' "$IMAGE"),
  "source_info": "$(sudo fdisk -l $SOURCE 2>/dev/null | head -5 | tr '\n' ' ')"
}
EOF
  
  chmod 600 "$IMAGE" "${IMAGE}.sha256"
  echo "Forensic image created: $IMAGE"
}

# Create memory dump
create_memory_dump() {
  local DEST_DIR="$1"
  local TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
  
  # Using /proc/kcore (requires root)
  sudo cp /proc/kcore "${DEST_DIR}/memory-dump-${TIMESTAMP}.core" 2>/dev/null
  
  # Using LiME (if installed)
  # sudo insmod /opt/lime/lime.ko "path=${DEST_DIR}/memory-${TIMESTAMP}.lime format=lime"
  
  # Using fmem (if available)
  # sudo dd if=/dev/fmem of="${DEST_DIR}/memory-${TIMESTAMP}.dd" bs=1M
  
  echo "Memory dump saved to: ${DEST_DIR}"
}

# Create process memory dump
dump_process_memory() {
  local PID="$1"
  local DEST_DIR="$2"
  local TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
  
  # Using gcore
  sudo gcore -o "${DEST_DIR}/process-${PID}-${TIMESTAMP}" "$PID" 2>/dev/null
  
  # Capture process info
  cat > "${DEST_DIR}/process-${PID}-metadata.json" <<EOF
{
  "pid": $PID,
  "cmdline": "$(cat /proc/$PID/cmdline 2>/dev/null | tr '\0' ' ')",
  "exe": "$(readlink /proc/$PID/exe 2>/dev/null)",
  "cwd": "$(readlink /proc/$PID/cwd 2>/dev/null)",
  "user": "$(stat -c '%U' /proc/$PID 2>/dev/null)",
  "start_time": "$(stat -c '%y' /proc/$PID 2>/dev/null)",
  "environ": "$(cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' | head -20)"
}
EOF
  
  # Capture /proc information
  for f in maps status io fd; do
    cat "/proc/$PID/$f" > "${DEST_DIR}/process-${PID}-${f}.txt" 2>/dev/null
  done
  ls -la "/proc/$PID/fd/" > "${DEST_DIR}/process-${PID}-fds.txt" 2>/dev/null
}
```

---

## 6. Real-Time Monitoring

### Live Incident Monitoring

```bash
# Monitor for specific suspicious activity in real time
monitor_live() {
  local INCIDENT_DIR="$1"
  local SEARCH_TERM="$2"
  local MONITOR_LOG="${INCIDENT_DIR}/timeline/live-monitor.log"
  
  echo "Starting live monitoring for: $SEARCH_TERM"
  echo "Logging to: $MONITOR_LOG"
  echo "Press Ctrl+C to stop"
  
  tail -f /var/log/auth.log /var/log/syslog /var/log/kern.log 2>/dev/null | \
    grep --line-buffered -i "$SEARCH_TERM" | \
    while read -r line; do
      echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | $line" | tee -a "$MONITOR_LOG"
    done
}

# Monitor specific IP
monitor_ip() {
  local IP="$1"
  echo "=== Monitoring activity from $IP ==="
  
  # Watch auth log
  tail -f /var/log/auth.log 2>/dev/null | grep --line-buffered "$IP" &
  
  # Watch connections
  watch -n 5 "ss -tnp | grep '$IP'"
}

# Monitor file changes
monitor_files() {
  local WATCH_DIR="$1"
  local LOG="$2"
  
  # Using inotifywait
  inotifywait -m -r -e modify,create,delete,move "$WATCH_DIR" 2>/dev/null | while read -r dir event file; do
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | $event | ${dir}${file}" | tee -a "$LOG"
  done
}
```

---

## 7. Incident Report Generation

```bash
# Generate formal incident report
generate_report() {
  local INCIDENT_DIR="$1"
  local REPORT="${INCIDENT_DIR}/incident-report.txt"
  
  # Read incident data
  INCIDENT_DATA=$(cat "${INCIDENT_DIR}/incident.json" 2>/dev/null)
  
  cat > "$REPORT" <<EOF
===============================================================================
                     SECURITY INCIDENT REPORT
===============================================================================

INCIDENT ID: $(echo "$INCIDENT_DATA" | python3 -c "import sys,json;print(json.load(sys.stdin)['incident_id'])" 2>/dev/null)
CREATED:     $(echo "$INCIDENT_DATA" | python3 -c "import sys,json;print(json.load(sys.stdin)['created'])" 2>/dev/null)
SEVERITY:    $(echo "$INCIDENT_DATA" | python3 -c "import sys,json;print(json.load(sys.stdin)['severity'])" 2>/dev/null)
TYPE:        $(echo "$INCIDENT_DATA" | python3 -c "import sys,json;print(json.load(sys.stdin)['type'])" 2>/dev/null)
STATUS:      $(echo "$INCIDENT_DATA" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])" 2>/dev/null)
HOSTNAME:    $(echo "$INCIDENT_DATA" | python3 -c "import sys,json;print(json.load(sys.stdin)['hostname'])" 2>/dev/null)

DESCRIPTION:
$(echo "$INCIDENT_DATA" | python3 -c "import sys,json;print(json.load(sys.stdin)['description'])" 2>/dev/null)

===============================================================================
                          TIMELINE
===============================================================================
$(cat "${INCIDENT_DIR}/timeline/timeline.log" 2>/dev/null)

===============================================================================
                     CHAIN OF CUSTODY
===============================================================================
$(cat "${INCIDENT_DIR}/chain-of-custody.log" 2>/dev/null)

===============================================================================
                      EVIDENCE LIST
===============================================================================
$(find "${INCIDENT_DIR}/evidence" -type f 2>/dev/null | while read -r f; do
  echo "  $(basename $f) ($(sha256sum "$f" 2>/dev/null | awk '{print $1}'))"
done)

===============================================================================
                    ANALYST NOTES
===============================================================================
$(cat "${INCIDENT_DIR}/notes/"*.txt 2>/dev/null)

===============================================================================
Report generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

  chmod 600 "$REPORT"
  echo "Report generated: $REPORT"
}
```

---

## 8. Full Incident Response Workflow

```bash
#!/bin/bash
# Automated incident response collection
SEVERITY="${1:-high}"
TYPE="${2:-unknown}"
DESCRIPTION="${3:-Automated incident response triggered}"

INCIDENT_ID="INC-$(date +%Y%m%d%H%M%S)-$(openssl rand -hex 4)"
INCIDENT_DIR="/var/log/incidents/${INCIDENT_ID}"
mkdir -p "${INCIDENT_DIR}"/{evidence,timeline,notes,forensics}
chmod 700 "${INCIDENT_DIR}"

echo "=== Incident Response: ${INCIDENT_ID} ===" | tee "${INCIDENT_DIR}/response.log"
echo "Severity: ${SEVERITY}" | tee -a "${INCIDENT_DIR}/response.log"
echo "Type: ${TYPE}" | tee -a "${INCIDENT_DIR}/response.log"
echo "Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "${INCIDENT_DIR}/response.log"
echo "" | tee -a "${INCIDENT_DIR}/response.log"

# Step 1: Capture volatile evidence
echo "--- Capturing volatile evidence ---" | tee -a "${INCIDENT_DIR}/response.log"
ps auxf > "${INCIDENT_DIR}/evidence/processes.txt" 2>/dev/null
sudo ss -tnpa > "${INCIDENT_DIR}/evidence/connections.txt" 2>/dev/null
who -a > "${INCIDENT_DIR}/evidence/users.txt" 2>/dev/null
sudo lsof -nP > "${INCIDENT_DIR}/evidence/open-files.txt" 2>/dev/null
ip addr > "${INCIDENT_DIR}/evidence/network.txt" 2>/dev/null
ip route > "${INCIDENT_DIR}/evidence/routes.txt" 2>/dev/null
ip neigh > "${INCIDENT_DIR}/evidence/arp.txt" 2>/dev/null
lsmod > "${INCIDENT_DIR}/evidence/modules.txt" 2>/dev/null
mount > "${INCIDENT_DIR}/evidence/mounts.txt" 2>/dev/null
df -h > "${INCIDENT_DIR}/evidence/disk-usage.txt" 2>/dev/null
uptime > "${INCIDENT_DIR}/evidence/uptime.txt" 2>/dev/null
date -u > "${INCIDENT_DIR}/evidence/timestamp.txt" 2>/dev/null

# Step 2: Collect log evidence
echo "--- Collecting log evidence ---" | tee -a "${INCIDENT_DIR}/response.log"
for logfile in /var/log/auth.log /var/log/syslog /var/log/kern.log; do
  [ -f "$logfile" ] && cp "$logfile" "${INCIDENT_DIR}/evidence/"
done
journalctl --since "24 hours ago" --no-pager > "${INCIDENT_DIR}/evidence/journal.log" 2>/dev/null

# Step 3: Generate evidence hashes
echo "--- Hashing evidence ---" | tee -a "${INCIDENT_DIR}/response.log"
find "${INCIDENT_DIR}/evidence" -type f -exec sha256sum {} \; > "${INCIDENT_DIR}/evidence/MANIFEST.sha256"

# Step 4: Initialize chain of custody
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | system | INCIDENT_CREATED | Automated response initiated" > "${INCIDENT_DIR}/chain-of-custody.log"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | system | EVIDENCE_COLLECTED | Volatile and log evidence captured" >> "${INCIDENT_DIR}/chain-of-custody.log"

# Step 5: Create incident record
cat > "${INCIDENT_DIR}/incident.json" <<EOF
{
  "incident_id": "${INCIDENT_ID}",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "severity": "${SEVERITY}",
  "type": "${TYPE}",
  "description": "${DESCRIPTION}",
  "status": "investigating",
  "hostname": "$(hostname)",
  "kernel": "$(uname -r)"
}
EOF

chmod -R 600 "${INCIDENT_DIR}"/evidence/*
chmod 600 "${INCIDENT_DIR}"/incident.json "${INCIDENT_DIR}"/chain-of-custody.log

echo "" | tee -a "${INCIDENT_DIR}/response.log"
echo "=== Incident Response Complete ===" | tee -a "${INCIDENT_DIR}/response.log"
echo "Incident ID: ${INCIDENT_ID}" | tee -a "${INCIDENT_DIR}/response.log"
echo "Evidence directory: ${INCIDENT_DIR}" | tee -a "${INCIDENT_DIR}/response.log"
echo "Next steps:" | tee -a "${INCIDENT_DIR}/response.log"
echo "  1. Review evidence in ${INCIDENT_DIR}/evidence/" | tee -a "${INCIDENT_DIR}/response.log"
echo "  2. Add analyst notes to ${INCIDENT_DIR}/notes/" | tee -a "${INCIDENT_DIR}/response.log"
echo "  3. Update timeline in ${INCIDENT_DIR}/timeline/" | tee -a "${INCIDENT_DIR}/response.log"
echo "  4. Generate report when investigation completes" | tee -a "${INCIDENT_DIR}/response.log"
```

---

## 9. Evidence Integrity Verification

```bash
# Verify evidence integrity
verify_evidence() {
  local EVIDENCE_DIR="$1"
  local MANIFEST="${EVIDENCE_DIR}/MANIFEST.sha256"
  
  if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: No manifest found at $MANIFEST"
    return 1
  fi
  
  echo "=== Evidence Integrity Verification ==="
  TOTAL=0
  PASSED=0
  FAILED=0
  
  while read -r expected_hash filepath; do
    TOTAL=$((TOTAL + 1))
    actual_hash=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
    if [ "$expected_hash" = "$actual_hash" ]; then
      PASSED=$((PASSED + 1))
      echo "[OK] $(basename $filepath)"
    else
      FAILED=$((FAILED + 1))
      echo "[TAMPERED] $(basename $filepath)"
      echo "  Expected: $expected_hash"
      echo "  Actual:   $actual_hash"
    fi
  done < "$MANIFEST"
  
  echo ""
  echo "Total: $TOTAL | Passed: $PASSED | Failed: $FAILED"
  [ "$FAILED" -gt 0 ] && echo "WARNING: Evidence integrity compromised!" && return 1
  echo "All evidence integrity verified."
  return 0
}
```

---

## 10. Incident Archival

```bash
# Archive closed incident
archive_incident() {
  local INCIDENT_DIR="$1"
  local ARCHIVE_DIR="/var/log/incidents/archive"
  local INCIDENT_ID=$(basename "$INCIDENT_DIR")
  
  mkdir -p "$ARCHIVE_DIR"
  
  # Generate final report
  generate_report "$INCIDENT_DIR"
  
  # Create encrypted archive
  tar czf - "$INCIDENT_DIR" | gpg --symmetric --cipher-algo AES256 --batch \
    --passphrase-file /root/.incident-key -o "${ARCHIVE_DIR}/${INCIDENT_ID}.tar.gz.gpg"
  
  # Generate archive hash
  sha256sum "${ARCHIVE_DIR}/${INCIDENT_ID}.tar.gz.gpg" > "${ARCHIVE_DIR}/${INCIDENT_ID}.sha256"
  
  # Log archival
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | system | ARCHIVED | Incident archived to ${ARCHIVE_DIR}" >> "${INCIDENT_DIR}/chain-of-custody.log"
  
  echo "Incident archived: ${ARCHIVE_DIR}/${INCIDENT_ID}.tar.gz.gpg"
  echo "Retain for minimum 1 year per compliance requirements"
}
```
