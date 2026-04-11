# Script Builder Agent

> Generate and deploy bash/python automation scripts with proper structure, error handling, logging, and scheduling.

## Safety Rules

- NEVER overwrite existing scripts without creating a backup first
- NEVER deploy scripts to production paths without testing
- NEVER store credentials or secrets in plain text within scripts
- ALWAYS set appropriate file permissions (chmod 700 for sensitive scripts)
- ALWAYS validate script syntax before deployment (bash -n, python -m py_compile)
- ALWAYS use shellcheck for bash scripts before deployment
- NEVER use `rm -rf /` or unguarded recursive deletes in generated scripts

---

## 1. Bash Script Templates

### Minimal Bash Script
```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Description: <SCRIPT_PURPOSE>
# Author: ClaudeOS Script Builder
# Date: $(date +%Y-%m-%d)
# Version: 1.0.0

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

main() {
    echo "Running ${SCRIPT_NAME}..."
    # Main logic here
}

main "$@"
```

### Full-Featured Bash Script with Argument Parsing
```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Description: <SCRIPT_PURPOSE>
# Author: ClaudeOS Script Builder
# Date: $(date +%Y-%m-%d)
# Version: 1.0.0

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly LOG_FILE="/var/log/${SCRIPT_NAME%.sh}.log"

# Default values
VERBOSE=false
DRY_RUN=false
CONFIG_FILE=""
TARGET=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${timestamp} [${level}] ${msg}" | tee -a "${LOG_FILE}"
}

log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "${YELLOW}$*${NC}"; }
log_error() { log "ERROR" "${RED}$*${NC}"; }
log_debug() { [[ "${VERBOSE}" == true ]] && log "DEBUG" "$@"; }

cleanup() {
    local exit_code=$?
    log_info "Cleanup: exit code ${exit_code}"
    # Remove temp files, release locks, etc.
    if [[ -n "${TEMP_DIR:-}" && -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
    exit "${exit_code}"
}
trap cleanup EXIT
trap 'log_error "Script interrupted"; exit 130' INT TERM

usage() {
    cat <<USAGE
Usage: ${SCRIPT_NAME} [OPTIONS] <target>

Description:
    <SCRIPT_PURPOSE>

Options:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    -n, --dry-run       Show what would be done without doing it
    -c, --config FILE   Path to configuration file
    -V, --version       Show version

Examples:
    ${SCRIPT_NAME} -v /path/to/target
    ${SCRIPT_NAME} --config /etc/myapp.conf --dry-run target

USAGE
    exit 0
}

version() {
    echo "${SCRIPT_NAME} version 1.0.0"
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)    usage ;;
            -v|--verbose) VERBOSE=true; shift ;;
            -n|--dry-run) DRY_RUN=true; shift ;;
            -c|--config)  CONFIG_FILE="$2"; shift 2 ;;
            -V|--version) version ;;
            --)           shift; break ;;
            -*)           log_error "Unknown option: $1"; usage ;;
            *)            TARGET="$1"; shift ;;
        esac
    done

    if [[ -z "${TARGET}" ]]; then
        log_error "Target is required"
        usage
    fi
}

check_dependencies() {
    local deps=("curl" "jq" "awk")
    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" &>/dev/null; then
            log_error "Missing dependency: ${dep}"
            exit 1
        fi
    done
}

validate_config() {
    if [[ -n "${CONFIG_FILE}" ]]; then
        if [[ ! -f "${CONFIG_FILE}" ]]; then
            log_error "Config file not found: ${CONFIG_FILE}"
            exit 1
        fi
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
        log_info "Loaded config: ${CONFIG_FILE}"
    fi
}

main() {
    parse_args "$@"
    check_dependencies
    validate_config

    log_info "Starting ${SCRIPT_NAME} with target: ${TARGET}"

    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY RUN] Would process: ${TARGET}"
        return 0
    fi

    # Main logic here
    log_info "Processing ${TARGET}..."

    log_info "Completed successfully"
}

main "$@"
```

### Getopts-Style Argument Parsing
```bash
parse_args() {
    local OPTIND opt
    while getopts ":hvnc:o:" opt; do
        case "${opt}" in
            h) usage ;;
            v) VERBOSE=true ;;
            n) DRY_RUN=true ;;
            c) CONFIG_FILE="${OPTARG}" ;;
            o) OUTPUT_DIR="${OPTARG}" ;;
            :) log_error "Option -${OPTARG} requires an argument"; exit 1 ;;
            \?) log_error "Unknown option: -${OPTARG}"; usage ;;
        esac
    done
    shift $((OPTIND - 1))
    POSITIONAL_ARGS=("$@")
}
```

---

## 2. Python Script Templates

### Minimal Python Script
```python
#!/usr/bin/env python3
"""<SCRIPT_PURPOSE>"""

import sys

def main():
    """Main entry point."""
    print("Running script...")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

### Full-Featured Python Script with Argparse
```python
#!/usr/bin/env python3
"""
<SCRIPT_PURPOSE>

Author: ClaudeOS Script Builder
Version: 1.0.0
"""

import argparse
import logging
import os
import sys
import json
from datetime import datetime
from pathlib import Path

__version__ = "1.0.0"

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(verbose: bool = False, log_file: str = None) -> logging.Logger:
    """Configure logging with console and optional file output."""
    logger = logging.getLogger(__name__)
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
        logger.addHandler(file_handler)

    return logger


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="<SCRIPT_PURPOSE>",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -v /path/to/target
  %(prog)s --config /etc/myapp.json --dry-run target
        """,
    )
    parser.add_argument("target", help="Target to process")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-n", "--dry-run", action="store_true", help="Show what would be done")
    parser.add_argument("-c", "--config", type=Path, help="Path to config file")
    parser.add_argument("-o", "--output", type=Path, default=Path("."), help="Output directory")
    parser.add_argument("--log-file", type=Path, help="Log file path")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args()


def load_config(config_path: Path) -> dict:
    """Load configuration from JSON file."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path) as f:
        return json.load(f)


def main() -> int:
    """Main entry point."""
    args = parse_args()
    logger = setup_logging(verbose=args.verbose, log_file=str(args.log_file) if args.log_file else None)

    logger.info("Starting script with target: %s", args.target)

    config = {}
    if args.config:
        try:
            config = load_config(args.config)
            logger.info("Loaded config from %s", args.config)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error("Failed to load config: %s", e)
            return 1

    if args.dry_run:
        logger.info("[DRY RUN] Would process: %s", args.target)
        return 0

    try:
        # Main logic here
        logger.info("Processing %s...", args.target)
        logger.info("Completed successfully")
        return 0
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

---

## 3. Error Handling Patterns

### Bash Error Handling
```bash
# Strict mode
set -euo pipefail

# Trap errors with line number
trap 'log_error "Error on line ${LINENO}: command \"${BASH_COMMAND}\" failed with exit code $?"' ERR

# Retry function
retry() {
    local max_attempts="$1"
    local delay="$2"
    shift 2
    local cmd=("$@")
    local attempt=1

    while (( attempt <= max_attempts )); do
        if "${cmd[@]}"; then
            return 0
        fi
        log_warn "Attempt ${attempt}/${max_attempts} failed. Retrying in ${delay}s..."
        sleep "${delay}"
        (( attempt++ ))
        delay=$(( delay * 2 ))
    done
    log_error "All ${max_attempts} attempts failed for: ${cmd[*]}"
    return 1
}

# Usage: retry 3 5 curl -f https://example.com/api

# Safe temporary directory
TEMP_DIR="$(mktemp -d -t "${SCRIPT_NAME}.XXXXXX")"
trap 'rm -rf "${TEMP_DIR}"' EXIT

# Lock file to prevent concurrent execution
LOCK_FILE="/var/lock/${SCRIPT_NAME}.lock"
exec 200>"${LOCK_FILE}"
if ! flock -n 200; then
    log_error "Another instance is already running"
    exit 1
fi
```

### Python Error Handling
```python
import signal
import tempfile
import atexit
import fcntl

class GracefulShutdown:
    """Handle graceful shutdown on signals."""
    def __init__(self):
        self.shutdown_requested = False
        signal.signal(signal.SIGTERM, self._handler)
        signal.signal(signal.SIGINT, self._handler)

    def _handler(self, signum, frame):
        self.shutdown_requested = True

class FileLock:
    """Simple file-based lock."""
    def __init__(self, path):
        self.path = path
        self.fd = None

    def acquire(self):
        self.fd = open(self.path, 'w')
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False

    def release(self):
        if self.fd:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            self.fd.close()
```

---

## 4. Logging Patterns

### Bash Structured Logging
```bash
# JSON-structured logging
log_json() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '{"timestamp":"%s","level":"%s","script":"%s","message":"%s"}\n' \
        "${timestamp}" "${level}" "${SCRIPT_NAME}" "${msg}" >> "${LOG_FILE}"
}

# Rotating log setup
setup_log_rotation() {
    local max_size="${1:-10485760}"  # 10MB default
    local max_files="${2:-5}"

    if [[ -f "${LOG_FILE}" ]]; then
        local size
        size=$(stat -c%s "${LOG_FILE}" 2>/dev/null || echo 0)
        if (( size > max_size )); then
            for i in $(seq "$((max_files - 1))" -1 1); do
                [[ -f "${LOG_FILE}.${i}" ]] && mv "${LOG_FILE}.${i}" "${LOG_FILE}.$((i + 1))"
            done
            mv "${LOG_FILE}" "${LOG_FILE}.1"
            : > "${LOG_FILE}"
        fi
    fi
}
```

### Python Rotating Logger
```python
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

def setup_rotating_log(log_file, max_bytes=10*1024*1024, backup_count=5):
    handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    return handler

def setup_timed_log(log_file, when='midnight', interval=1, backup_count=30):
    handler = TimedRotatingFileHandler(log_file, when=when, interval=interval, backupCount=backup_count)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
    return handler
```

---

## 5. Cron Deployment

### Install Script as Cron Job
```bash
# Add a cron job
install_cron() {
    local schedule="$1"
    local script_path="$2"
    local job_line="${schedule} ${script_path} >> /var/log/$(basename "${script_path}" .sh).log 2>&1"

    # Check if already installed
    if crontab -l 2>/dev/null | grep -qF "${script_path}"; then
        echo "Cron job already exists for ${script_path}"
        return 0
    fi

    (crontab -l 2>/dev/null; echo "${job_line}") | crontab -
    echo "Installed cron job: ${job_line}"
}

# Common schedules
# Every 5 minutes:  */5 * * * *
# Hourly:           0 * * * *
# Daily at 2am:     0 2 * * *
# Weekly Sunday:    0 0 * * 0
# Monthly 1st:      0 0 1 * *

# Remove a cron job
remove_cron() {
    local script_path="$1"
    crontab -l 2>/dev/null | grep -vF "${script_path}" | crontab -
    echo "Removed cron job for ${script_path}"
}

# List cron jobs
list_cron() {
    crontab -l 2>/dev/null || echo "No crontab configured"
}
```

---

## 6. Systemd Timer Units

### Create Systemd Service + Timer
```bash
create_systemd_timer() {
    local name="$1"
    local script_path="$2"
    local schedule="$3"  # OnCalendar format: daily, hourly, *-*-* 02:00:00
    local description="${4:-Automated script}"
    local user="${5:-root}"

    # Create service unit
    cat > "/etc/systemd/system/${name}.service" <<EOF
[Unit]
Description=${description}
After=network.target

[Service]
Type=oneshot
ExecStart=${script_path}
User=${user}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${name}
EOF

    # Create timer unit
    cat > "/etc/systemd/system/${name}.timer" <<EOF
[Unit]
Description=Timer for ${description}

[Timer]
OnCalendar=${schedule}
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "${name}.timer"
    echo "Created and enabled timer: ${name}.timer"
}

# Check timer status
# systemctl list-timers --all
# systemctl status <name>.timer
# journalctl -u <name>.service --since today
```

### OnCalendar Schedule Examples
```
# Every 15 minutes
OnCalendar=*:0/15

# Every hour at :30
OnCalendar=*:30

# Daily at 3am
OnCalendar=*-*-* 03:00:00

# Weekdays at 9am
OnCalendar=Mon..Fri *-*-* 09:00:00

# First Monday of month
OnCalendar=Mon *-*-1..7 00:00:00

# Every 6 hours
OnCalendar=0/6:00:00
```

---

## 7. Script Testing

### Bash Script Testing with Bats
```bash
# Install bats
# git clone https://github.com/bats-core/bats-core.git && cd bats-core && ./install.sh /usr/local

# Test file: test_myscript.bats
#!/usr/bin/env bats

setup() {
    SCRIPT_DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)"
    source "${SCRIPT_DIR}/../myscript.sh" --source-only 2>/dev/null || true
}

@test "script exists and is executable" {
    [ -x "${SCRIPT_DIR}/../myscript.sh" ]
}

@test "displays usage with -h flag" {
    run "${SCRIPT_DIR}/../myscript.sh" -h
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "fails with missing target" {
    run "${SCRIPT_DIR}/../myscript.sh"
    [ "$status" -ne 0 ]
}

@test "dry run does not modify files" {
    run "${SCRIPT_DIR}/../myscript.sh" -n /tmp/test
    [ "$status" -eq 0 ]
    [[ "$output" == *"DRY RUN"* ]]
}
```

### Python Script Testing with pytest
```python
# test_myscript.py
import pytest
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "myscript.py"

def test_script_exists():
    assert SCRIPT.exists()

def test_help_flag():
    result = subprocess.run([str(SCRIPT), "-h"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()

def test_version_flag():
    result = subprocess.run([str(SCRIPT), "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "1.0.0" in result.stdout

def test_missing_target():
    result = subprocess.run([str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode != 0

def test_dry_run():
    result = subprocess.run([str(SCRIPT), "-n", "/tmp/test"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "DRY RUN" in result.stdout
```

### Script Validation Commands
```bash
# Bash syntax check
bash -n myscript.sh

# Shellcheck static analysis
shellcheck -s bash -e SC1090,SC2034 myscript.sh

# Python syntax check
python3 -m py_compile myscript.py

# Python linting
python3 -m pylint myscript.py
python3 -m flake8 myscript.py

# Python type checking
python3 -m mypy myscript.py

# Make script executable
chmod +x myscript.sh
chmod +x myscript.py
```

---

## 8. Script Deployment Workflow

### Full Deployment Pipeline
```bash
deploy_script() {
    local src="$1"
    local dest="$2"
    local schedule="${3:-}"

    # Step 1: Validate
    if [[ "${src}" == *.sh ]]; then
        bash -n "${src}" || { echo "Syntax error in bash script"; return 1; }
        shellcheck "${src}" || { echo "Shellcheck warnings found"; return 1; }
    elif [[ "${src}" == *.py ]]; then
        python3 -m py_compile "${src}" || { echo "Syntax error in python script"; return 1; }
    fi

    # Step 2: Backup existing
    if [[ -f "${dest}" ]]; then
        cp "${dest}" "${dest}.bak.$(date +%Y%m%d%H%M%S)"
    fi

    # Step 3: Deploy
    cp "${src}" "${dest}"
    chmod 700 "${dest}"
    chown root:root "${dest}"

    # Step 4: Install schedule if specified
    if [[ -n "${schedule}" ]]; then
        install_cron "${schedule}" "${dest}"
    fi

    echo "Deployed: ${dest}"
}

# Deploy with systemd timer
deploy_with_timer() {
    local src="$1"
    local dest="$2"
    local name="$3"
    local schedule="$4"

    deploy_script "${src}" "${dest}"
    create_systemd_timer "${name}" "${dest}" "${schedule}"
}
```

---

## 9. Common Script Utilities

### Bash Utility Functions Library
```bash
# Source this file in scripts: source /usr/local/lib/claudeos/utils.sh

# Check if running as root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" >&2
        exit 1
    fi
}

# Confirm action
confirm() {
    local msg="${1:-Are you sure?}"
    read -rp "${msg} [y/N] " response
    [[ "${response}" =~ ^[Yy]$ ]]
}

# Check command exists
require_cmd() {
    for cmd in "$@"; do
        command -v "${cmd}" &>/dev/null || { echo "Required command not found: ${cmd}" >&2; exit 1; }
    done
}

# Safe file write (atomic)
safe_write() {
    local dest="$1"
    local content="$2"
    local tmpfile
    tmpfile="$(mktemp "${dest}.XXXXXX")"
    echo "${content}" > "${tmpfile}"
    mv "${tmpfile}" "${dest}"
}

# Duration formatting
format_duration() {
    local seconds="$1"
    printf '%dd %dh %dm %ds' $((seconds/86400)) $((seconds%86400/3600)) $((seconds%3600/60)) $((seconds%60))
}

# Bytes formatting
format_bytes() {
    local bytes="$1"
    if (( bytes >= 1073741824 )); then
        printf '%.2f GB' "$(echo "scale=2; ${bytes}/1073741824" | bc)"
    elif (( bytes >= 1048576 )); then
        printf '%.2f MB' "$(echo "scale=2; ${bytes}/1048576" | bc)"
    elif (( bytes >= 1024 )); then
        printf '%.2f KB' "$(echo "scale=2; ${bytes}/1024" | bc)"
    else
        printf '%d B' "${bytes}"
    fi
}

# Send notification on completion
notify_completion() {
    local script_name="$1"
    local status="$2"
    local message="$3"
    local webhook_url="${NOTIFY_WEBHOOK:-}"

    if [[ -n "${webhook_url}" ]]; then
        curl -sf -X POST "${webhook_url}" \
            -H "Content-Type: application/json" \
            -d "{\"script\":\"${script_name}\",\"status\":\"${status}\",\"message\":\"${message}\"}" \
            || true
    fi
}
```

---

## 10. Script Configuration Patterns

### Environment File Pattern
```bash
# /etc/default/myscript or ~/.config/myscript/config
# Load with: set -a; source /etc/default/myscript; set +a

DB_HOST="localhost"
DB_PORT=5432
DB_NAME="myapp"
API_ENDPOINT="https://api.example.com"
LOG_LEVEL="info"
MAX_RETRIES=3
TIMEOUT=30
```

### Config File Loading
```bash
load_env_file() {
    local env_file="$1"
    if [[ -f "${env_file}" ]]; then
        set -a
        # shellcheck source=/dev/null
        source "${env_file}"
        set +a
        log_info "Loaded environment from ${env_file}"
    fi
}

# Load config with defaults
: "${DB_HOST:=localhost}"
: "${DB_PORT:=5432}"
: "${LOG_LEVEL:=info}"
: "${MAX_RETRIES:=3}"
```

### Python Config Loading
```python
import os
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class Config:
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "myapp"
    log_level: str = "info"
    max_retries: int = 3

    @classmethod
    def from_env(cls):
        return cls(
            db_host=os.getenv("DB_HOST", "localhost"),
            db_port=int(os.getenv("DB_PORT", "5432")),
            db_name=os.getenv("DB_NAME", "myapp"),
            log_level=os.getenv("LOG_LEVEL", "info"),
            max_retries=int(os.getenv("MAX_RETRIES", "3")),
        )

    @classmethod
    def from_file(cls, path: Path):
        import json
        with open(path) as f:
            data = json.load(f)
        return cls(**data)
```

---

## 11. Script Packaging

### Create a Self-Contained Script Archive
```bash
# Create self-extracting script
create_shar() {
    local script_dir="$1"
    local output="$2"

    cat > "${output}" <<'HEADER'
#!/usr/bin/env bash
set -euo pipefail
EXTRACT_DIR="$(mktemp -d)"
ARCHIVE_START=$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0}' "$0")
tail -n+"${ARCHIVE_START}" "$0" | tar xz -C "${EXTRACT_DIR}"
cd "${EXTRACT_DIR}"
./install.sh
rm -rf "${EXTRACT_DIR}"
exit 0
__ARCHIVE_BELOW__
HEADER

    tar czf - -C "${script_dir}" . >> "${output}"
    chmod +x "${output}"
}
```

### Python Virtual Environment Script Wrapper
```bash
create_python_wrapper() {
    local script_name="$1"
    local venv_dir="/opt/${script_name}/venv"
    local script_path="/opt/${script_name}/${script_name}.py"
    local requirements="/opt/${script_name}/requirements.txt"

    mkdir -p "/opt/${script_name}"

    # Create venv and install deps
    python3 -m venv "${venv_dir}"
    "${venv_dir}/bin/pip" install -r "${requirements}"

    # Create wrapper
    cat > "/usr/local/bin/${script_name}" <<EOF
#!/usr/bin/env bash
exec ${venv_dir}/bin/python3 ${script_path} "\$@"
EOF
    chmod +x "/usr/local/bin/${script_name}"
}
```
