# Dependency Resolver Agent

Fixes broken package dependencies, held packages, and library conflicts across system (apt/dpkg) and language-level (pip, npm, gem) package managers. Resolves shared library issues, version conflicts, and corrupted installations.

---

## Safety Rules

- NEVER run `apt-get autoremove --purge` without explicit confirmation — it can remove needed packages.
- NEVER force-remove packages that other critical packages depend on.
- ALWAYS run dependency fixes in the correct order: dpkg first, then apt.
- NEVER upgrade all packages as a fix — only fix the broken ones.
- ALWAYS capture the current package state before making changes.
- NEVER add third-party PPAs or repositories without confirmation.
- Log all package operations to /var/log/dependency-resolver.log.
- ALWAYS check if a reboot is required after fixes.

---

## 1. System State Assessment

### Check for Broken Packages

```bash
apt list --broken 2>/dev/null
```

### Check dpkg State

```bash
dpkg --audit
```

### List Packages in Bad State

```bash
dpkg -l | grep -E '^.[^i ]|^.H'
```

### Check for Held Packages

```bash
dpkg --get-selections | grep 'hold'
apt-mark showhold
```

### Check if Reboot Required

```bash
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required || echo "No reboot required"
```

### Show Package Manager Lock Status

```bash
# Check for apt locks
lsof /var/lib/dpkg/lock-frontend 2>/dev/null
lsof /var/lib/apt/lists/lock 2>/dev/null
lsof /var/cache/apt/archives/lock 2>/dev/null
```

### List Recently Installed/Changed Packages

```bash
grep -E "install|upgrade|remove" /var/log/dpkg.log | tail -30
```

---

## 2. APT/DPKG Repair

### Fix Broken Installs

```bash
apt-get --fix-broken install -y
```

### Reconfigure Unconfigured Packages

```bash
dpkg --configure -a
```

### Complete Repair Sequence

```bash
echo "=== Step 1: Fix dpkg ==="
dpkg --configure -a

echo "=== Step 2: Fix broken apt ==="
apt-get --fix-broken install -y

echo "=== Step 3: Update package lists ==="
apt-get update

echo "=== Step 4: Fix missing dependencies ==="
apt-get install -f -y

echo "=== Step 5: Clean package cache ==="
apt-get autoclean
```

### Fix Corrupted Package Database

```bash
# Backup current state
cp -r /var/lib/dpkg /var/lib/dpkg.backup.$(date +%Y%m%d)

# Rebuild available database
dpkg --clear-avail
apt-get update
```

### Fix Interrupted dpkg

```bash
# If dpkg was interrupted
dpkg --configure -a --force-confold
```

### Remove Stale Locks

```bash
# Only use if NO apt/dpkg process is running
if ! pgrep -x "apt|apt-get|dpkg" > /dev/null; then
    rm -f /var/lib/dpkg/lock-frontend
    rm -f /var/lib/dpkg/lock
    rm -f /var/cache/apt/archives/lock
    rm -f /var/lib/apt/lists/lock
    dpkg --configure -a
    echo "Locks cleared and dpkg reconfigured"
else
    echo "Package manager is still running — do NOT remove locks"
fi
```

### Force Reinstall a Broken Package

```bash
PACKAGE="<package>"
apt-get install --reinstall "$PACKAGE" -y
```

### Fix Package with Missing Files

```bash
PACKAGE="<package>"
# Check for missing files
dpkg -V "$PACKAGE" 2>&1
# Reinstall to restore files
apt-get install --reinstall "$PACKAGE" -y
```

---

## 3. Held Package Resolution

### Show Why a Package Is Held

```bash
PACKAGE="<package>"
apt-mark showhold | grep "$PACKAGE"
aptitude why-not "$PACKAGE" 2>/dev/null || echo "aptitude not installed, trying apt"
apt-get install "$PACKAGE" -s 2>&1 | head -20
```

### Unhold a Package

```bash
PACKAGE="<package>"
apt-mark unhold "$PACKAGE"
```

### Unhold All Packages

```bash
apt-mark showhold | xargs -r apt-mark unhold
```

### Resolve Held Package Conflicts

```bash
PACKAGE="<package>"
# Check what would happen if we upgrade
apt-get install "$PACKAGE" -s 2>&1

# Check for conflicting packages
apt-cache depends "$PACKAGE" 2>/dev/null | grep -i conflict
apt-cache rdepends "$PACKAGE" 2>/dev/null | head -20
```

### Simulate Upgrade to Find Blockers

```bash
apt-get dist-upgrade -s 2>&1 | head -40
```

---

## 4. Version Conflict Resolution

### Check Package Version and Available Versions

```bash
PACKAGE="<package>"
echo "=== Installed ==="
dpkg -l "$PACKAGE" 2>/dev/null | tail -1
echo "=== Available ==="
apt-cache policy "$PACKAGE"
```

### Find Packages Depending on a Specific Version

```bash
PACKAGE="<package>"
apt-cache rdepends "$PACKAGE" --installed 2>/dev/null
```

### Downgrade a Package to a Specific Version

```bash
PACKAGE="<package>"
VERSION="<version>"
apt-get install "${PACKAGE}=${VERSION}" -y
```

### Pin a Package to Prevent Upgrades

```bash
PACKAGE="<package>"
VERSION="<version>"
cat >> /etc/apt/preferences.d/"$PACKAGE" << EOF
Package: $PACKAGE
Pin: version $VERSION
Pin-Priority: 1001
EOF
echo "Pinned $PACKAGE to version $VERSION"
```

### Find Conflicting Package Versions

```bash
PACKAGE="<package>"
apt-cache showpkg "$PACKAGE" 2>/dev/null | grep -A 999 "^Reverse Depends:" | head -30
```

---

## 5. Shared Library Fixes

### Check for Missing Shared Libraries

```bash
ldconfig -p | wc -l
echo "---"
ldconfig 2>&1 | head -20
```

### Find Missing Libraries for a Binary

```bash
BINARY="<path>"
ldd "$BINARY" 2>&1 | grep "not found"
```

### Find Which Package Provides a Library

```bash
LIBRARY="<libname>"
dpkg -S "$LIBRARY" 2>/dev/null || apt-file search "$LIBRARY" 2>/dev/null
```

### Rebuild Library Cache

```bash
ldconfig
echo "Library cache rebuilt"
ldconfig -p | tail -5
```

### Fix Missing Library Symlinks

```bash
LIBRARY="<libname>"
# Find the actual library file
ACTUAL=$(find /usr/lib /usr/local/lib /lib -name "${LIBRARY}*" -type f 2>/dev/null | head -1)
if [ -n "$ACTUAL" ]; then
    LIBDIR=$(dirname "$ACTUAL")
    echo "Found: $ACTUAL"
    # Create symlink if needed
    if [ ! -e "${LIBDIR}/${LIBRARY}" ]; then
        ln -s "$ACTUAL" "${LIBDIR}/${LIBRARY}"
        ldconfig
        echo "Created symlink: ${LIBDIR}/${LIBRARY} -> $ACTUAL"
    fi
else
    echo "Library $LIBRARY not found on system"
    echo "Try: apt-file search $LIBRARY"
fi
```

### Check for Library Version Mismatches

```bash
BINARY="<path>"
ldd "$BINARY" 2>&1 | while read -r line; do
    LIB=$(echo "$line" | awk '{print $1}')
    PATH_RESOLVED=$(echo "$line" | awk '{print $3}')
    if [ -n "$PATH_RESOLVED" ] && [ -f "$PATH_RESOLVED" ]; then
        FILE_TYPE=$(file "$PATH_RESOLVED" | grep -oP 'ELF \d+-bit')
        BIN_TYPE=$(file "$BINARY" | grep -oP 'ELF \d+-bit')
        if [ "$FILE_TYPE" != "$BIN_TYPE" ]; then
            echo "ARCHITECTURE MISMATCH: $LIB ($FILE_TYPE vs binary $BIN_TYPE)"
        fi
    fi
done
```

### Install Missing Library Dependencies

```bash
BINARY="<path>"
ldd "$BINARY" 2>&1 | grep "not found" | awk '{print $1}' | while read -r lib; do
    echo "Missing: $lib"
    PKG=$(apt-file search "$lib" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -n "$PKG" ]; then
        echo "  -> Provided by: $PKG"
        apt-get install -y "$PKG"
    else
        echo "  -> No package found providing $lib"
    fi
done
```

---

## 6. pip Dependency Fixes

### Check for Broken pip Packages

```bash
pip check 2>&1
```

### Check pip3 Specifically

```bash
pip3 check 2>&1
```

### Fix Broken pip Install

```bash
PACKAGE="<package>"
pip install --force-reinstall "$PACKAGE"
```

### Fix Version Conflicts in pip

```bash
PACKAGE="<package>"
# Show current dependency tree
pip show "$PACKAGE" 2>/dev/null | grep -E "^(Name|Version|Requires|Required-by)"

# Try upgrading to resolve
pip install --upgrade "$PACKAGE"
```

### Reinstall All Packages in a virtualenv

```bash
VENV="<path>"
source "$VENV/bin/activate"
pip freeze > /tmp/requirements_backup.txt
pip install --force-reinstall -r /tmp/requirements_backup.txt
```

### Fix pip Itself

```bash
python3 -m pip install --upgrade pip setuptools wheel
```

### Fix Externally Managed Environment Error (PEP 668)

```bash
# Use a virtual environment instead
python3 -m venv /opt/venvs/<name>
source /opt/venvs/<name>/bin/activate
pip install <package>
```

---

## 7. npm Dependency Fixes

### Check for npm Issues

```bash
npm doctor 2>&1
```

### Audit and Fix npm Vulnerabilities

```bash
cd <project_dir>
npm audit
npm audit fix
```

### Fix Broken npm Install

```bash
cd <project_dir>
rm -rf node_modules package-lock.json
npm install
```

### Clear npm Cache

```bash
npm cache clean --force
npm cache verify
```

### Fix Global npm Permissions

```bash
# Check current global prefix
npm config get prefix

# Fix ownership if needed
NPM_PREFIX=$(npm config get prefix)
if [ -d "$NPM_PREFIX/lib/node_modules" ]; then
    USER=$(logname 2>/dev/null || echo "$SUDO_USER")
    chown -R "$USER" "$NPM_PREFIX/lib/node_modules"
    chown -R "$USER" "$NPM_PREFIX/bin"
fi
```

### Resolve Peer Dependency Conflicts

```bash
cd <project_dir>
npm install --legacy-peer-deps
```

### Fix node_modules Corruption

```bash
cd <project_dir>
rm -rf node_modules/.cache
npm rebuild
npm install
```

### Check for Duplicate Packages

```bash
cd <project_dir>
npm dedupe
```

---

## 8. gem (Ruby) Dependency Fixes

### Check for Broken Gems

```bash
gem check --doctor 2>&1
```

### Fix Gem Permissions

```bash
gem env home
GEM_HOME=$(gem env home)
chown -R "$(logname 2>/dev/null || echo "$USER")" "$GEM_HOME"
```

### Reinstall Broken Gem

```bash
GEM="<gem>"
gem uninstall "$GEM" --all --force 2>/dev/null
gem install "$GEM"
```

### Fix Native Extension Build Issues

```bash
# Install build dependencies
apt-get install -y build-essential ruby-dev libffi-dev

GEM="<gem>"
gem install "$GEM" -- --use-system-libraries
```

### Clean Up Old Gem Versions

```bash
gem cleanup
```

### Fix Bundler Issues

```bash
cd <project_dir>
bundle config set --local path 'vendor/bundle'
bundle install --jobs 4
```

---

## 9. Multi-Architecture Issues

### Check for Multi-Arch Problems

```bash
dpkg --print-architecture
dpkg --print-foreign-architectures
```

### Fix i386/amd64 Conflicts

```bash
PACKAGE="<package>"
# Check which architectures are installed
dpkg -l "${PACKAGE}:*" 2>/dev/null

# Remove conflicting architecture
dpkg --remove --force-depends "${PACKAGE}:i386"
apt-get install --fix-broken -y
```

### Remove Foreign Architecture

```bash
ARCH="<arch>"
# First remove all packages from that arch
dpkg -l | grep ":${ARCH}" | awk '{print $2}' | xargs -r dpkg --remove --force-depends 2>/dev/null
dpkg --remove-architecture "$ARCH"
apt-get update
```

---

## 10. Diagnostics and Reporting

### Full Dependency Health Check

```bash
echo "============================================"
echo "DEPENDENCY HEALTH REPORT"
echo "Time: $(date -Iseconds)"
echo "============================================"

echo ""
echo "=== System Package Manager ==="
echo "--- Broken Packages ---"
apt list --broken 2>/dev/null | tail -n +2

echo "--- Held Packages ---"
apt-mark showhold

echo "--- dpkg Audit ---"
dpkg --audit 2>&1 | head -20

echo "--- Unconfigured Packages ---"
dpkg -l | grep '^[a-z]C' | head -10

echo ""
echo "=== Shared Libraries ==="
ldconfig 2>&1 | head -10

echo ""
echo "=== pip (if available) ==="
pip3 check 2>&1 | head -20

echo ""
echo "=== npm (if available) ==="
if command -v npm >/dev/null 2>&1; then
    npm -g ls --depth=0 2>&1 | grep -i "ERR\|WARN" | head -10
fi

echo ""
echo "=== Reboot Required? ==="
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required || echo "No"

echo "============================================"
```

---

## 11. Full Dependency Resolution Workflow

### Automated Fix Sequence

```bash
LOG="/var/log/dependency-resolver.log"

log_action() {
    echo "[$(date -Iseconds)] $1" | tee -a "$LOG"
}

log_action "Starting dependency resolution"

# Step 1: Check for active package manager processes
if pgrep -x "apt|apt-get|dpkg" > /dev/null; then
    log_action "ERROR: Package manager is already running. Aborting."
    exit 1
fi

# Step 2: Capture current state
log_action "Capturing package state"
dpkg --get-selections > /tmp/dpkg-selections-backup-$(date +%Y%m%d).txt

# Step 3: Fix dpkg first
log_action "Running dpkg --configure -a"
dpkg --configure -a 2>&1 | tee -a "$LOG"

# Step 4: Fix broken apt packages
log_action "Running apt --fix-broken install"
apt-get --fix-broken install -y 2>&1 | tee -a "$LOG"

# Step 5: Update package lists
log_action "Updating package lists"
apt-get update 2>&1 | tee -a "$LOG"

# Step 6: Install missing dependencies
log_action "Installing missing dependencies"
apt-get install -f -y 2>&1 | tee -a "$LOG"

# Step 7: Check shared libraries
log_action "Rebuilding library cache"
ldconfig 2>&1 | tee -a "$LOG"

# Step 8: Check pip if available
if command -v pip3 >/dev/null 2>&1; then
    log_action "Checking pip dependencies"
    BROKEN_PIP=$(pip3 check 2>&1)
    if [ -n "$BROKEN_PIP" ]; then
        log_action "pip issues found: $BROKEN_PIP"
    fi
fi

# Step 9: Verify
BROKEN=$(apt list --broken 2>/dev/null | tail -n +2 | wc -l)
if [ "$BROKEN" -eq 0 ]; then
    log_action "SUCCESS: All system dependencies resolved"
else
    log_action "WARNING: $BROKEN packages still broken"
    apt list --broken 2>/dev/null | tee -a "$LOG"
fi

# Step 10: Check reboot
[ -f /var/run/reboot-required ] && log_action "NOTE: Reboot required"

log_action "Dependency resolution complete"
```
