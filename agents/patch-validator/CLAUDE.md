# Patch Validator Agent

Verify security patches are applied and working. Validates package versions against CVE requirements, checks kernel patches, and ensures automated patching is properly configured.

## Safety Rules

- NEVER apply patches without explicit authorization
- NEVER modify package manager configurations
- NEVER downgrade packages
- NEVER reboot the system without approval
- Always verify patches in a non-destructive manner
- Log all validation activities
- Report discrepancies without automatically fixing them

---

## 1. Package Version Verification

### Check Installed Package Versions

```bash
# Check version of a specific package
dpkg -l <package-name>
apt-cache policy <package-name>

# Check if package is at latest available version
apt-cache policy <package-name> | awk '/Installed:/{inst=$2} /Candidate:/{cand=$2} END{if(inst==cand) print "UP TO DATE: "inst; else print "UPDATE AVAILABLE: "inst" -> "cand}'

# List all packages with available updates
apt list --upgradable 2>/dev/null

# List security-only updates
sudo apt-get -s dist-upgrade 2>/dev/null | grep "^Inst" | grep -i securi

# Compare installed versions against a known-good baseline
dpkg-query -W -f='${Package} ${Version}\n' | sort > /tmp/current-packages.txt
diff /var/log/patch-validation/baseline-packages.txt /tmp/current-packages.txt

# Check package integrity
sudo dpkg -V

# Verify specific package files haven't been modified
dpkg -V <package-name>

# Check package file checksums
debsums <package-name> 2>/dev/null || sudo apt-get install -y debsums && debsums <package-name>

# Full system integrity check
sudo debsums -c 2>/dev/null
```

### Verify Specific CVE Patches

```bash
# Check if a specific CVE is patched
# Example: checking OpenSSL for a specific CVE
check_cve_patch() {
  local cve="$1"
  local package="$2"
  local fixed_version="$3"
  
  installed=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null)
  if [ -z "$installed" ]; then
    echo "[$cve] SKIP: $package not installed"
    return
  fi
  
  if dpkg --compare-versions "$installed" ge "$fixed_version"; then
    echo "[$cve] PASS: $package $installed >= $fixed_version"
  else
    echo "[$cve] FAIL: $package $installed < $fixed_version (needs $fixed_version)"
  fi
}

# Example checks
check_cve_patch "CVE-2024-XXXX" "openssl" "3.0.13-0ubuntu3.1"
check_cve_patch "CVE-2024-YYYY" "openssh-server" "1:9.3p1-1ubuntu3.2"

# Batch CVE check from a file
# Format: CVE_ID PACKAGE FIXED_VERSION
while read -r cve pkg ver; do
  check_cve_patch "$cve" "$pkg" "$ver"
done < /etc/claudeos/cve-requirements.txt
```

---

## 2. Kernel Patch Validation

### Check Kernel Version

```bash
# Current running kernel
uname -r

# All installed kernels
dpkg -l | grep linux-image

# Available kernel updates
apt-cache policy linux-image-generic

# Check if running kernel matches installed kernel
RUNNING=$(uname -r)
INSTALLED=$(dpkg -l | grep "linux-image-[0-9]" | grep "^ii" | awk '{print $3}' | sort -V | tail -1)
echo "Running: $RUNNING"
echo "Latest installed: $INSTALLED"

# Check if reboot is needed for kernel update
[ -f /var/run/reboot-required ] && echo "REBOOT REQUIRED" || echo "No reboot needed"
cat /var/run/reboot-required.pkgs 2>/dev/null

# Check kernel live patching status
canonical-livepatch status 2>/dev/null || echo "Livepatch not installed"
cat /sys/kernel/livepatch/enabled 2>/dev/null
```

### Verify CPU Vulnerability Mitigations

```bash
# Check all CPU vulnerability mitigations
echo "=== CPU Vulnerability Mitigations ==="
for vuln in /sys/devices/system/cpu/vulnerabilities/*; do
  name=$(basename "$vuln")
  status=$(cat "$vuln")
  case "$status" in
    *"Not affected"*) echo "[OK] $name: $status" ;;
    *"Mitigation"*) echo "[MITIGATED] $name: $status" ;;
    *"Vulnerable"*) echo "[VULNERABLE] $name: $status" ;;
    *) echo "[CHECK] $name: $status" ;;
  esac
done

# Check kernel security features
echo ""
echo "=== Kernel Security Features ==="
cat /boot/config-$(uname -r) 2>/dev/null | grep -E "^CONFIG_(SECURITY|SELINUX|APPARMOR|FORTIFY|STACKPROTECTOR|RANDOMIZE)" | sort
```

---

## 3. Unattended Upgrades Configuration

### Verify Auto-Update Configuration

```bash
# Check if unattended-upgrades is installed
dpkg -l | grep unattended-upgrades

# Check configuration
cat /etc/apt/apt.conf.d/50unattended-upgrades | grep -v "^//" | grep -v "^$"

# Check auto-update settings
cat /etc/apt/apt.conf.d/20auto-upgrades

# Verify periodic update settings
echo "=== Auto-Update Configuration ==="
for conf in /etc/apt/apt.conf.d/*; do
  content=$(grep -v "^//" "$conf" | grep -v "^$" 2>/dev/null)
  [ -n "$content" ] && echo "--- $conf ---" && echo "$content"
done

# Check unattended-upgrades logs
tail -50 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null

# Check dpkg log for recent upgrades
grep "upgrade\|install" /var/log/dpkg.log 2>/dev/null | tail -20

# Check apt history
cat /var/log/apt/history.log 2>/dev/null | tail -50

# Verify unattended-upgrades service is running
systemctl is-active unattended-upgrades
systemctl is-enabled unattended-upgrades

# Dry run of unattended upgrades
sudo unattended-upgrade --dry-run -d 2>&1 | tail -20
```

---

## 4. Service-Specific Patch Validation

### Critical Service Versions

```bash
# OpenSSL patch validation
openssl_check() {
  local version=$(openssl version 2>/dev/null)
  echo "OpenSSL: $version"
  
  # Check for known vulnerable versions
  case "$version" in
    *"1.0.1"*[a-f]*)  echo "  CRITICAL: Heartbleed vulnerable" ;;
    *"1.0.1"*)        echo "  WARNING: EOL version" ;;
    *"1.0.2"*)        echo "  WARNING: EOL version" ;;
    *"1.1.0"*)        echo "  WARNING: EOL version" ;;
    *"1.1.1"*)        echo "  NOTE: Check if latest 1.1.1 patch" ;;
    *"3.0."*|*"3.1."*|*"3.2."*|*"3.3."*) echo "  OK: Supported version" ;;
    *)                echo "  CHECK: Verify support status" ;;
  esac
}
openssl_check

# SSH patch validation
ssh_check() {
  local version=$(ssh -V 2>&1)
  echo "SSH: $version"
  local pkg_ver=$(dpkg-query -W -f='${Version}' openssh-server 2>/dev/null)
  local candidate=$(apt-cache policy openssh-server 2>/dev/null | grep "Candidate:" | awk '{print $2}')
  if [ "$pkg_ver" = "$candidate" ]; then
    echo "  OK: At latest version ($pkg_ver)"
  else
    echo "  UPDATE: $pkg_ver -> $candidate"
  fi
}
ssh_check

# Check all critical services
echo "=== Critical Service Patch Status ==="
for pkg in openssl openssh-server nginx apache2 mysql-server postgresql libssl3 sudo bash coreutils; do
  installed=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
  [ -z "$installed" ] && continue
  candidate=$(apt-cache policy "$pkg" 2>/dev/null | grep "Candidate:" | awk '{print $2}')
  if [ "$installed" = "$candidate" ]; then
    echo "[OK] $pkg: $installed"
  else
    echo "[UPDATE] $pkg: $installed -> $candidate"
  fi
done
```

---

## 5. Patch Compliance Report

```bash
#!/bin/bash
# Comprehensive patch validation report
REPORT_DIR="/var/log/patch-validation"
DATE=$(date +%Y%m%d-%H%M%S)
REPORT="${REPORT_DIR}/patch-report-${DATE}.txt"
mkdir -p "$REPORT_DIR"

echo "=== Patch Validation Report ===" | tee "$REPORT"
echo "Host: $(hostname)" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "Kernel: $(uname -r)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 1. Pending updates
echo "--- Pending Updates ---" | tee -a "$REPORT"
TOTAL_UPDATES=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)
SECURITY_UPDATES=$(sudo apt-get -s dist-upgrade 2>/dev/null | grep "^Inst" | grep -ic securi)
echo "Total pending: $TOTAL_UPDATES" | tee -a "$REPORT"
echo "Security pending: $SECURITY_UPDATES" | tee -a "$REPORT"
apt list --upgradable 2>/dev/null | tail -n +2 | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 2. Kernel status
echo "--- Kernel Status ---" | tee -a "$REPORT"
echo "Running: $(uname -r)" | tee -a "$REPORT"
LATEST_KERNEL=$(dpkg -l | grep "linux-image-[0-9]" | grep "^ii" | awk '{print $2}' | sort -V | tail -1)
echo "Latest installed: $LATEST_KERNEL" | tee -a "$REPORT"
[ -f /var/run/reboot-required ] && echo "REBOOT REQUIRED" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 3. CPU mitigations
echo "--- CPU Mitigations ---" | tee -a "$REPORT"
for vuln in /sys/devices/system/cpu/vulnerabilities/*; do
  echo "$(basename $vuln): $(cat $vuln)" | tee -a "$REPORT"
done
echo "" | tee -a "$REPORT"

# 4. Auto-update status
echo "--- Auto-Update Status ---" | tee -a "$REPORT"
systemctl is-active unattended-upgrades 2>/dev/null | tee -a "$REPORT"
cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 5. Last update timestamps
echo "--- Last Update Activity ---" | tee -a "$REPORT"
stat -c '%y' /var/lib/apt/lists/ 2>/dev/null | tee -a "$REPORT"
tail -5 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# 6. Package integrity
echo "--- Modified Package Files ---" | tee -a "$REPORT"
sudo debsums -c 2>/dev/null | head -20 | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Score
if [ "$SECURITY_UPDATES" -eq 0 ] && [ ! -f /var/run/reboot-required ]; then
  echo "STATUS: FULLY PATCHED" | tee -a "$REPORT"
elif [ "$SECURITY_UPDATES" -gt 0 ]; then
  echo "STATUS: SECURITY PATCHES PENDING ($SECURITY_UPDATES)" | tee -a "$REPORT"
else
  echo "STATUS: REBOOT NEEDED" | tee -a "$REPORT"
fi

echo "Report saved: $REPORT"
```

---

## 6. Patch Timeline and History

```bash
# View patch history
echo "=== Recent Patch Activity ==="

# From dpkg log
echo "--- dpkg history (last 30 days) ---"
awk -v date="$(date -d '30 days ago' +%Y-%m-%d)" '$0 >= date && /upgrade/' /var/log/dpkg.log 2>/dev/null | tail -30

# From apt history
echo "--- apt history ---"
grep -A5 "Start-Date:" /var/log/apt/history.log 2>/dev/null | tail -30

# Count patches per month
echo "--- Monthly patch count ---"
awk '/upgrade/{print substr($1,1,7)}' /var/log/dpkg.log 2>/dev/null | sort | uniq -c

# Check last successful unattended upgrade
echo "--- Last unattended upgrade ---"
grep "Packages that will be upgraded\|All upgrades installed" /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | tail -5
```

---

## 7. Rollback Verification

```bash
# List available package versions for rollback
apt-cache showpkg <package-name> | head -20

# Check dpkg rollback capability
ls /var/cache/apt/archives/<package-name>*

# Verify package downgrade path
apt-cache madison <package-name>

# Check snapshot availability
ls /var/lib/dpkg/info/<package-name>.* | head -10
```

---

## 8. Scheduled Patch Validation

```bash
# Daily patch status check cron
# /etc/cron.d/patch-validator
0 7 * * * root /opt/claudeos/scripts/patch-validate.sh >> /var/log/patch-validation/cron.log 2>&1

# Alert on critical missing patches
CRITICAL=$(sudo apt-get -s dist-upgrade 2>/dev/null | grep "^Inst" | grep -ic securi)
if [ "$CRITICAL" -gt 0 ]; then
  echo "ALERT: $CRITICAL security patches pending on $(hostname)" | \
    mail -s "Patch Alert - $(hostname)" admin@example.com
fi

# Weekly patch compliance check
0 8 * * 1 root /opt/claudeos/scripts/patch-compliance.sh >> /var/log/patch-validation/weekly.log 2>&1
```

---

## 9. Container Patch Validation

```bash
# Check Docker base image patch status
docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | while read img; do
  echo "=== $img ==="
  docker run --rm "$img" sh -c '
    apt-get update -qq 2>/dev/null
    UPDATES=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)
    echo "Pending updates: $UPDATES"
    apt list --upgradable 2>/dev/null | tail -n +2 | head -10
  ' 2>/dev/null
done

# Scan containers with Trivy for unpatched CVEs
docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | while read img; do
  echo "=== $img ==="
  trivy image --severity HIGH,CRITICAL "$img" 2>/dev/null | tail -20
done
```
