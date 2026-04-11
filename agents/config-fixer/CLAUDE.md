# Config Fixer Agent

Detects and repairs misconfigurations across web servers, application configs, and system files. Validates syntax for nginx, Apache, JSON, YAML, TOML, and INI files. Auto-backs up before any modification and applies targeted fixes for common misconfiguration patterns.

---

## Safety Rules

- ALWAYS create a timestamped backup before modifying ANY config file.
- NEVER overwrite a config file — apply surgical edits only.
- NEVER modify /etc/shadow, /etc/sudoers directly, or SSH authorized_keys.
- ALWAYS validate the new config before reloading/restarting a service.
- NEVER remove comments from config files during fixes.
- ALWAYS show a diff of changes made.
- Keep at most 10 backup copies per config file to avoid disk bloat.
- Log all changes to /var/log/config-fixer.log.

---

## 1. Backup Before Fix

### Create Timestamped Backup

```bash
CONFIG_FILE="<path>"
BACKUP_DIR="/var/backups/config-fixer"
mkdir -p "$BACKUP_DIR"
BASENAME=$(echo "$CONFIG_FILE" | tr '/' '_')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
cp -a "$CONFIG_FILE" "${BACKUP_DIR}/${BASENAME}.${TIMESTAMP}.bak"
echo "Backup created: ${BACKUP_DIR}/${BASENAME}.${TIMESTAMP}.bak"
```

### Restore from Backup

```bash
CONFIG_FILE="<path>"
BACKUP_DIR="/var/backups/config-fixer"
BASENAME=$(echo "$CONFIG_FILE" | tr '/' '_')
LATEST=$(ls -t "${BACKUP_DIR}/${BASENAME}".*.bak 2>/dev/null | head -1)
if [ -n "$LATEST" ]; then
    cp -a "$LATEST" "$CONFIG_FILE"
    echo "Restored from: $LATEST"
else
    echo "No backup found for $CONFIG_FILE"
fi
```

### Rotate Old Backups (keep latest 10)

```bash
CONFIG_FILE="<path>"
BACKUP_DIR="/var/backups/config-fixer"
BASENAME=$(echo "$CONFIG_FILE" | tr '/' '_')
ls -t "${BACKUP_DIR}/${BASENAME}".*.bak 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
```

---

## 2. Nginx Configuration Validation and Fixes

### Validate Nginx Config

```bash
nginx -t 2>&1
```

### Get Nginx Config Parse Errors with Line Numbers

```bash
nginx -t 2>&1 | grep -E "emerg|error" | head -20
```

### List All Included Nginx Config Files

```bash
nginx -T 2>/dev/null | grep "# configuration file" | awk '{print $4}' | tr -d ':'
```

### Check for Common Nginx Misconfigs

```bash
echo "=== Checking Nginx Configuration ==="

# Check main config exists
NGINX_CONF="/etc/nginx/nginx.conf"
if [ ! -f "$NGINX_CONF" ]; then
    echo "ERROR: $NGINX_CONF not found"
fi

# Check for missing semicolons (common error)
grep -n '[^;{}\s#]$' /etc/nginx/sites-enabled/* 2>/dev/null | grep -v '^\s*#' | grep -v '{' | grep -v '}' | head -10

# Check for duplicate server_name
grep -rh 'server_name' /etc/nginx/sites-enabled/ 2>/dev/null | sed 's/server_name//;s/;//' | tr ' ' '\n' | sort | uniq -d | while read -r name; do
    [ -n "$name" ] && echo "DUPLICATE server_name: $name"
done

# Check for broken symlinks in sites-enabled
find /etc/nginx/sites-enabled/ -type l ! -exec test -e {} \; -print 2>/dev/null | while read -r link; do
    echo "BROKEN SYMLINK: $link -> $(readlink "$link")"
done

# Check SSL cert files exist
grep -rh 'ssl_certificate' /etc/nginx/sites-enabled/ 2>/dev/null | awk '{print $2}' | tr -d ';' | while read -r cert; do
    [ -n "$cert" ] && [ ! -f "$cert" ] && echo "MISSING SSL CERT: $cert"
done

# Check upstream blocks point to valid backends
grep -rh 'proxy_pass' /etc/nginx/sites-enabled/ 2>/dev/null | awk '{print $2}' | tr -d ';' | while read -r url; do
    HOST=$(echo "$url" | sed 's|.*://||;s|[:/].*||')
    PORT=$(echo "$url" | grep -oP ':\K\d+' | head -1)
    if [ -n "$PORT" ]; then
        ss -tln | grep -q ":$PORT " || echo "BACKEND DOWN: $url (port $PORT not listening)"
    fi
done
```

### Fix: Remove Broken Symlinks in sites-enabled

```bash
find /etc/nginx/sites-enabled/ -type l ! -exec test -e {} \; -delete -print 2>/dev/null
```

### Fix: Add Missing Semicolons (targeted)

```bash
FILE="<path>"
LINE=<line_number>
# Add semicolon at end of specific line if missing
sed -i "${LINE}s/[^;{} ]$/&;/" "$FILE"
```

### Reload Nginx After Fix

```bash
nginx -t 2>&1 && systemctl reload nginx
```

---

## 3. Apache Configuration Validation and Fixes

### Validate Apache Config

```bash
apachectl configtest 2>&1
```

### Alternative Validation Commands

```bash
apache2ctl -t 2>&1
# or
httpd -t 2>&1
```

### List All Loaded Apache Modules

```bash
apachectl -M 2>/dev/null | sort
```

### Check for Common Apache Misconfigs

```bash
echo "=== Checking Apache Configuration ==="

# Check for syntax errors
apachectl configtest 2>&1

# Check for missing modules referenced in config
grep -rh 'LoadModule\|IfModule' /etc/apache2/ 2>/dev/null | grep -oP 'mod_\w+' | sort -u | while read -r mod; do
    if ! apachectl -M 2>/dev/null | grep -qi "${mod}"; then
        echo "WARNING: $mod referenced but may not be available"
    fi
done

# Check for broken DocumentRoot paths
grep -rh 'DocumentRoot' /etc/apache2/sites-enabled/ 2>/dev/null | awk '{print $2}' | tr -d '"' | while read -r docroot; do
    [ -n "$docroot" ] && [ ! -d "$docroot" ] && echo "MISSING DocumentRoot: $docroot"
done

# Check for broken SSL cert files
grep -rh 'SSLCertificateFile\|SSLCertificateKeyFile' /etc/apache2/sites-enabled/ 2>/dev/null | awk '{print $2}' | while read -r cert; do
    [ -n "$cert" ] && [ ! -f "$cert" ] && echo "MISSING SSL FILE: $cert"
done

# Check for broken symlinks
find /etc/apache2/sites-enabled/ -type l ! -exec test -e {} \; -print 2>/dev/null
```

### Enable a Missing Apache Module

```bash
a2enmod <module>
systemctl restart apache2
```

### Fix: Create Missing DocumentRoot

```bash
DOCROOT="<path>"
mkdir -p "$DOCROOT"
chown www-data:www-data "$DOCROOT"
chmod 755 "$DOCROOT"
```

### Reload Apache After Fix

```bash
apachectl configtest 2>&1 && systemctl reload apache2
```

---

## 4. JSON Validation and Fixes

### Validate JSON File

```bash
python3 -m json.tool < "<file>" > /dev/null 2>&1 && echo "VALID" || echo "INVALID"
```

### Get JSON Syntax Error Details

```bash
python3 -m json.tool < "<file>" 2>&1
```

### Validate JSON with jq

```bash
jq empty "<file>" 2>&1
```

### Find JSON Syntax Errors (line and column)

```bash
python3 -c "
import json, sys
try:
    with open('$FILE') as f:
        json.load(f)
    print('VALID')
except json.JSONDecodeError as e:
    print(f'ERROR at line {e.lineno}, column {e.colno}: {e.msg}')
"
```

### Fix: Remove Trailing Commas in JSON

```bash
FILE="<path>"
# Backup first
cp "$FILE" "${FILE}.bak"
# Remove trailing commas before } or ]
sed -i 's/,\s*}/}/g; s/,\s*]/]/g' "$FILE"
python3 -m json.tool < "$FILE" > /dev/null 2>&1 && echo "FIXED" || echo "Still invalid"
```

### Fix: Pretty-Print / Reformat JSON

```bash
FILE="<path>"
cp "$FILE" "${FILE}.bak"
python3 -m json.tool < "${FILE}.bak" > "$FILE"
```

---

## 5. YAML Validation and Fixes

### Validate YAML File

```bash
python3 -c "import yaml; yaml.safe_load(open('<file>'))" 2>&1
```

### Get YAML Error Details

```bash
python3 -c "
import yaml, sys
try:
    with open('$FILE') as f:
        yaml.safe_load(f)
    print('VALID')
except yaml.YAMLError as e:
    print(f'ERROR: {e}')
"
```

### Check for Tab Characters in YAML (common error)

```bash
grep -nP '\t' "<file>" | head -10
```

### Fix: Replace Tabs with Spaces in YAML

```bash
FILE="<path>"
cp "$FILE" "${FILE}.bak"
sed -i 's/\t/  /g' "$FILE"
echo "Replaced tabs with spaces in $FILE"
```

### Fix: Normalize YAML Indentation

```bash
FILE="<path>"
cp "$FILE" "${FILE}.bak"
python3 -c "
import yaml
with open('$FILE') as f:
    data = yaml.safe_load(f)
with open('$FILE', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, indent=2)
print('YAML normalized')
"
```

---

## 6. TOML Validation and Fixes

### Validate TOML File (Python 3.11+)

```bash
python3 -c "import tomllib; tomllib.load(open('<file>', 'rb'))" 2>&1
```

### Validate TOML File (older Python)

```bash
python3 -c "
try:
    import tomllib
except ImportError:
    import pip._vendor.tomli as tomllib
with open('$FILE', 'rb') as f:
    tomllib.load(f)
print('VALID')
" 2>&1
```

### Check for Common TOML Errors

```bash
FILE="<path>"
# Check for unquoted strings with special characters
grep -nP '=\s*[^"\[\]{}\d][^#]*[=\[\]]' "$FILE" | head -10
# Check for missing closing brackets
OPEN=$(grep -c '\[' "$FILE")
CLOSE=$(grep -c '\]' "$FILE")
[ "$OPEN" != "$CLOSE" ] && echo "WARNING: Mismatched brackets (open: $OPEN, close: $CLOSE)"
```

---

## 7. INI File Validation

### Validate INI File

```bash
python3 -c "
import configparser
c = configparser.ConfigParser()
c.read('$FILE')
print('VALID - Sections:', c.sections())
" 2>&1
```

### Check for Duplicate Sections/Keys

```bash
FILE="<path>"
# Duplicate sections
grep '^\[' "$FILE" | sort | uniq -d | while read -r section; do
    echo "DUPLICATE SECTION: $section"
done
```

---

## 8. Permission and Ownership Validation

### Check Config File Permissions

```bash
FILE="<path>"
PERMS=$(stat -c '%a' "$FILE")
OWNER=$(stat -c '%U:%G' "$FILE")
echo "File: $FILE"
echo "Permissions: $PERMS"
echo "Owner: $OWNER"

# Common permission checks
case "$FILE" in
    */ssl/*|*.key|*.pem)
        [ "$PERMS" != "600" ] && [ "$PERMS" != "640" ] && echo "WARNING: SSL key should be 600 or 640, is $PERMS"
        ;;
    */nginx/*|*/apache2/*)
        [ "$PERMS" != "644" ] && echo "WARNING: Web server config should be 644, is $PERMS"
        ;;
    */shadow|*/gshadow)
        [ "$PERMS" != "640" ] && echo "WARNING: Shadow file should be 640, is $PERMS"
        ;;
esac
```

### Fix Config File Permissions

```bash
FILE="<path>"
# Set standard readable config permissions
chmod 644 "$FILE"
chown root:root "$FILE"
```

### Fix SSL Key Permissions

```bash
FILE="<path>"
chmod 600 "$FILE"
chown root:root "$FILE"
```

### Scan for World-Writable Config Files

```bash
find /etc -type f -perm -002 -name "*.conf" -o -name "*.cfg" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" 2>/dev/null | while read -r f; do
    echo "WORLD-WRITABLE: $f ($(stat -c '%a' "$f"))"
done
```

---

## 9. Include Path and Reference Validation

### Check for Missing Includes in Nginx

```bash
grep -rn 'include ' /etc/nginx/ 2>/dev/null | while IFS=: read -r file line content; do
    INC_PATH=$(echo "$content" | awk '{print $2}' | tr -d ';')
    # Skip wildcard includes that match nothing
    if [[ "$INC_PATH" != *"*"* ]] && [ ! -f "$INC_PATH" ]; then
        echo "MISSING INCLUDE in $file:$line -> $INC_PATH"
    elif [[ "$INC_PATH" == *"*"* ]]; then
        MATCH_COUNT=$(ls $INC_PATH 2>/dev/null | wc -l)
        [ "$MATCH_COUNT" -eq 0 ] && echo "WARNING: No files match include pattern in $file:$line -> $INC_PATH"
    fi
done
```

### Check for Missing Includes in Apache

```bash
grep -rn 'Include\|IncludeOptional' /etc/apache2/ 2>/dev/null | while IFS=: read -r file line content; do
    INC_PATH=$(echo "$content" | awk '{print $2}')
    if echo "$content" | grep -q 'IncludeOptional'; then
        continue  # Optional includes are OK to be missing
    fi
    if [[ "$INC_PATH" != *"*"* ]] && [ ! -f "$INC_PATH" ] && [ ! -d "$INC_PATH" ]; then
        echo "MISSING INCLUDE in $file:$line -> $INC_PATH"
    fi
done
```

### Check for Bad Paths in Config Files

```bash
FILE="<path>"
# Find all absolute paths in the config
grep -oP '/[a-zA-Z0-9/._-]+' "$FILE" | sort -u | while read -r path; do
    # Skip common patterns that aren't filesystem paths
    echo "$path" | grep -qP '^/(http|https|ftp|tcp|udp|unix)' && continue
    # Check if path exists
    if [ ! -e "$path" ] && [[ "$path" != *"*"* ]]; then
        echo "MISSING PATH: $path"
    fi
done
```

---

## 10. SSH Config Validation

### Validate sshd_config

```bash
sshd -t 2>&1
```

### Extended sshd_config Test

```bash
sshd -T 2>&1 | head -50
```

### Check for Insecure SSH Settings

```bash
SSHD_CONF="/etc/ssh/sshd_config"
echo "=== SSH Security Check ==="
grep -i "^PermitRootLogin" "$SSHD_CONF" || echo "WARNING: PermitRootLogin not explicitly set"
grep -i "^PasswordAuthentication" "$SSHD_CONF" || echo "INFO: PasswordAuthentication not explicitly set"
grep -i "^PermitEmptyPasswords" "$SSHD_CONF" | grep -qi "yes" && echo "DANGER: PermitEmptyPasswords is yes"
grep -i "^X11Forwarding" "$SSHD_CONF" | grep -qi "yes" && echo "INFO: X11Forwarding is enabled"
grep -i "^Protocol" "$SSHD_CONF" | grep -q "1" && echo "DANGER: SSH Protocol 1 is enabled"
```

---

## 11. Systemd Unit File Validation

### Check Unit File Syntax

```bash
systemd-analyze verify <unit-file> 2>&1
```

### Validate All System Unit Files

```bash
systemd-analyze verify /etc/systemd/system/*.service 2>&1 | head -50
```

### Check for Common Unit File Issues

```bash
UNIT="<path>"
echo "=== Checking $UNIT ==="
# Check ExecStart binary exists
EXEC=$(grep -P '^ExecStart=' "$UNIT" | head -1 | sed 's/ExecStart=//;s/ .*//' | sed 's/^[-@+!]//')
[ -n "$EXEC" ] && [ ! -x "$EXEC" ] && echo "ERROR: ExecStart binary not found: $EXEC"

# Check User exists
USER=$(grep -P '^User=' "$UNIT" | sed 's/User=//')
[ -n "$USER" ] && ! id "$USER" >/dev/null 2>&1 && echo "ERROR: User does not exist: $USER"

# Check Group exists
GROUP=$(grep -P '^Group=' "$UNIT" | sed 's/Group=//')
[ -n "$GROUP" ] && ! getent group "$GROUP" >/dev/null 2>&1 && echo "ERROR: Group does not exist: $GROUP"

# Check WorkingDirectory exists
WD=$(grep -P '^WorkingDirectory=' "$UNIT" | sed 's/WorkingDirectory=//')
[ -n "$WD" ] && [ ! -d "$WD" ] && echo "ERROR: WorkingDirectory not found: $WD"
```

---

## 12. Full Config Fixer Workflow

### Complete Config Validation and Repair

```bash
CONFIG_FILE="<path>"
SERVICE="<service>"
LOG="/var/log/config-fixer.log"
BACKUP_DIR="/var/backups/config-fixer"

log_action() {
    echo "[$(date -Iseconds)] $1" | tee -a "$LOG"
}

# Step 1: Backup
mkdir -p "$BACKUP_DIR"
BASENAME=$(echo "$CONFIG_FILE" | tr '/' '_')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP="${BACKUP_DIR}/${BASENAME}.${TIMESTAMP}.bak"
cp -a "$CONFIG_FILE" "$BACKUP"
log_action "Backup: $BACKUP"

# Step 2: Detect file type and validate
EXT="${CONFIG_FILE##*.}"
VALID=true

case "$EXT" in
    json)
        if ! python3 -m json.tool < "$CONFIG_FILE" > /dev/null 2>&1; then
            VALID=false
            ERROR=$(python3 -m json.tool < "$CONFIG_FILE" 2>&1)
            log_action "JSON validation failed: $ERROR"
        fi
        ;;
    yml|yaml)
        if ! python3 -c "import yaml; yaml.safe_load(open('$CONFIG_FILE'))" 2>/dev/null; then
            VALID=false
            log_action "YAML validation failed"
            # Auto-fix: replace tabs
            if grep -qP '\t' "$CONFIG_FILE"; then
                sed -i 's/\t/  /g' "$CONFIG_FILE"
                log_action "Fixed: replaced tabs with spaces"
            fi
        fi
        ;;
    conf|cfg)
        # Check for service-specific validation
        case "$SERVICE" in
            nginx)
                if ! nginx -t 2>/dev/null; then
                    VALID=false
                    log_action "Nginx config validation failed"
                fi
                ;;
            apache2|httpd)
                if ! apachectl configtest 2>/dev/null; then
                    VALID=false
                    log_action "Apache config validation failed"
                fi
                ;;
        esac
        ;;
esac

# Step 3: Check permissions
PERMS=$(stat -c '%a' "$CONFIG_FILE")
if [ "$PERMS" = "777" ] || [ "$PERMS" = "666" ]; then
    log_action "Fixing insecure permissions: $PERMS -> 644"
    chmod 644 "$CONFIG_FILE"
fi

# Step 4: Validate after fixes
if [ "$VALID" = false ]; then
    # Re-validate
    case "$EXT" in
        json) python3 -m json.tool < "$CONFIG_FILE" > /dev/null 2>&1 && log_action "Config now valid after fixes" ;;
        yml|yaml) python3 -c "import yaml; yaml.safe_load(open('$CONFIG_FILE'))" 2>/dev/null && log_action "Config now valid after fixes" ;;
    esac
fi

# Step 5: Show diff
diff "$BACKUP" "$CONFIG_FILE" && log_action "No changes made" || log_action "Changes applied (see diff above)"

# Step 6: Reload service if applicable
if [ -n "$SERVICE" ]; then
    case "$SERVICE" in
        nginx) nginx -t 2>&1 && systemctl reload nginx && log_action "Nginx reloaded" ;;
        apache2) apachectl configtest 2>&1 && systemctl reload apache2 && log_action "Apache reloaded" ;;
        *) systemctl reload "$SERVICE" 2>/dev/null || systemctl restart "$SERVICE" && log_action "$SERVICE restarted" ;;
    esac
fi

# Step 7: Rotate backups
ls -t "${BACKUP_DIR}/${BASENAME}".*.bak 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
```
