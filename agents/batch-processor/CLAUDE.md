# Batch Processor Agent

Run batch jobs across files, servers, and databases in parallel. Uses GNU `parallel`, `xargs -P`, `pssh`/`pdsh`, Ansible ad-hoc, and `mysql`/`psql` batch modes. Tracks progress with `pv`, collects errors per task, aggregates results, and logs everything for audit.

---

## Safety Rules

- ALWAYS dry-run with `--dry-run` or `parallel --dry-run` before destructive batches.
- NEVER `rm` or `truncate` from a batch list without verifying the input file.
- ALWAYS use `--joblog` so failed tasks can be re-run with `--retry-failed`.
- ALWAYS cap parallelism — never `-P 0` or `--jobs 0` on production without measuring.
- NEVER pipe untrusted file lists into commands that interpret shell metacharacters.
- ALWAYS log every batch invocation to `/var/log/batch-processor.log`.
- For multi-server runs, ALWAYS limit to a known inventory file (no wildcards).
- For SQL batches, ALWAYS wrap in a transaction with rollback on error.

---

## 1. Required Tools

```bash
sudo apt update
sudo apt install -y parallel pv pssh pdsh ansible mysql-client postgresql-client \
    coreutils findutils util-linux openssh-client jq
```

### Verify

```bash
for t in parallel xargs pv pssh pdsh ansible mysql psql find ssh; do
    command -v "$t" >/dev/null && echo "OK: $t" || echo "MISSING: $t"
done
```

### Disable parallel citation prompt (one-time)

```bash
parallel --citation 2>/dev/null <<<'will cite' || true
```

---

## 2. GNU parallel — File Batches

### Basic: Process Files in Parallel

```bash
ls *.log | parallel -j 4 gzip {}
```

### Process with Job Log (resumable)

```bash
find /data -type f -name "*.csv" \
  | parallel -j 8 --joblog /tmp/jobs.log ./process-csv.sh {}
```

### Show Progress Bar

```bash
find /data -type f -name "*.json" \
  | parallel --bar -j 8 ./normalize.sh {}
```

### ETA / Progress

```bash
find /data -type f | parallel --eta -j 8 ./convert.sh {}
```

### Limit by Memory / Load

```bash
find . -type f | parallel --load 80% --memfree 1G ./heavy-task.sh {}
```

### Use Number of CPU Cores

```bash
find . -type f -name "*.png" | parallel -j+0 convert {} {.}.webp
```

### Pass Multiple Args

```bash
parallel -j 4 'curl -fsS -o {1}.html https://example.com/{1}' ::: page1 page2 page3 page4
```

### Combinations of Inputs

```bash
parallel -j 4 echo {1} {2} ::: A B C ::: 1 2 3
```

### Re-run Only Failed Jobs

```bash
parallel --joblog /tmp/jobs.log --retry-failed
```

### Dry Run

```bash
find . -type f | parallel --dry-run gzip {}
```

### Halt on First Failure

```bash
find . -type f | parallel --halt now,fail=1 ./strict.sh {}
```

### Stop After N Failures

```bash
find . -type f | parallel --halt soon,fail=5 ./task.sh {}
```

---

## 3. xargs -P Parallelism

### Parallel xargs (4 workers)

```bash
find . -type f -name "*.tmp" -print0 \
  | xargs -0 -n 1 -P 4 rm -f
```

### Curl Many URLs in Parallel

```bash
cat urls.txt | xargs -n 1 -P 8 -I {} curl -fsS -o /dev/null -w "%{url} %{http_code}\n" {}
```

### Combined with find

```bash
find /var/log -type f -name "*.log" -mtime +7 -print0 \
  | xargs -0 -n 10 -P 4 gzip
```

### Compare to parallel

```bash
# xargs is preinstalled and simpler; parallel has joblog, retry, eta
time find . -type f | xargs -P 8 -I {} sha256sum {} > /dev/null
time find . -type f | parallel -j 8 sha256sum > /dev/null
```

---

## 4. Parallel SSH (pssh)

### Run a Command on Many Hosts

```bash
cat > /etc/pssh/hosts.txt <<'EOF'
web01.example.com
web02.example.com
web03.example.com
EOF

pssh -h /etc/pssh/hosts.txt -l ubuntu -p 10 -t 30 -i "uptime"
```

### Save Output Per Host

```bash
pssh -h /etc/pssh/hosts.txt -l ubuntu -p 20 \
    -o /tmp/pssh-stdout -e /tmp/pssh-stderr \
    "df -h / | tail -1"
ls /tmp/pssh-stdout
```

### Copy a File to All Hosts

```bash
pscp -h /etc/pssh/hosts.txt -l ubuntu /tmp/script.sh /tmp/script.sh
```

### Pull a File from All Hosts

```bash
pslurp -h /etc/pssh/hosts.txt -l ubuntu /var/log/syslog ./logs syslog
```

---

## 5. pdsh

### Inline Hosts

```bash
pdsh -w web0[1-5].example.com "uptime"
```

### From File

```bash
pdsh -w ^/etc/pdsh/hosts "free -h"
```

### Aggregated Output

```bash
pdsh -w web0[1-5] "uname -r" | dshbak -c
```

### Limit Concurrency

```bash
pdsh -f 4 -w web0[1-20] "systemctl is-active nginx"
```

---

## 6. Ansible Ad-Hoc

### Inventory File `/etc/ansible/inventory`

```ini
[web]
web01.example.com
web02.example.com
web03.example.com

[db]
db01.example.com
db02.example.com
```

### Run Command on All Web Hosts

```bash
ansible -i /etc/ansible/inventory web -m shell -a "uptime" -f 10
```

### Apt Update Across Fleet

```bash
ansible all -i /etc/ansible/inventory -b -m apt -a "update_cache=yes upgrade=safe"
```

### Copy a File

```bash
ansible web -i /etc/ansible/inventory -m copy \
    -a "src=/local/file.conf dest=/etc/myapp/file.conf owner=root mode=0644" -b
```

### Service Restart

```bash
ansible web -i /etc/ansible/inventory -m systemd -a "name=nginx state=restarted" -b
```

### Limit Hosts

```bash
ansible all -i /etc/ansible/inventory --limit "web01,web02" -m ping
```

---

## 7. SQL Batch Execution

### MySQL: Execute a File

```bash
mysql -u app -p"$DB_PASS" appdb < /path/to/batch.sql
```

### MySQL: Run a Single Statement

```bash
mysql -u app -p"$DB_PASS" -e "UPDATE users SET active=1 WHERE last_login > NOW() - INTERVAL 30 DAY;" appdb
```

### MySQL: Loop Over Tenants

```bash
mysql -N -e "SHOW DATABASES LIKE 'tenant_%';" \
  | while read DB; do
        echo "Migrating $DB"
        mysql "$DB" < /path/to/migration.sql
    done
```

### MySQL: Wrap in Transaction

```bash
mysql appdb <<'SQL'
START TRANSACTION;
UPDATE accounts SET balance = balance - 10 WHERE id = 1;
UPDATE accounts SET balance = balance + 10 WHERE id = 2;
COMMIT;
SQL
```

### PostgreSQL: Execute a File

```bash
psql -U app -d appdb -f /path/to/batch.sql
```

### PostgreSQL: One-Liner

```bash
psql -U app -d appdb -c "VACUUM ANALYZE users;"
```

### Postgres: Loop Over Schemas

```bash
psql -At -c "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'tenant_%';" \
  | while read SCHEMA; do
        psql -d appdb -c "ALTER SCHEMA \"$SCHEMA\" RENAME TO ...;"
    done
```

### Parallel SQL Per DB

```bash
mysql -N -e "SHOW DATABASES LIKE 'tenant_%';" \
  | parallel -j 4 'mysql {} < /path/to/migration.sql'
```

---

## 8. File Batch Processing Patterns

### Resize All Images

```bash
find /data/images -type f -name "*.jpg" \
  | parallel -j 8 --bar 'convert {} -resize 1024x768 {.}-thumb.jpg'
```

### Hash All Files

```bash
find /data -type f -print0 \
  | parallel -0 -j 8 --joblog /tmp/hashes.log sha256sum > /tmp/hashes.txt
```

### Search Large Logs in Parallel

```bash
find /var/log -name "*.gz" \
  | parallel -j 8 'zgrep -l ERROR {}'
```

### Copy Many Files in Parallel (rsync per file)

```bash
find /src -type f \
  | parallel -j 8 'rsync -a {} /dst/'
```

### Compress Old Backups

```bash
find /var/backups -type f -name "*.sql" -mtime +1 ! -name "*.gz" \
  | parallel -j 4 gzip
```

---

## 9. Progress Tracking with pv

### Pipe Through pv

```bash
cat huge.csv | pv -l | wc -l
```

### Show Progress When Copying

```bash
pv /backups/db.sql | mysql appdb
```

### Show Progress Through tar

```bash
tar -cf - /var/www | pv -s $(du -sb /var/www | awk '{print $1}') > /backups/www.tar
```

### Combine with parallel + bar

```bash
find /data -type f | parallel --bar -j 8 ./task.sh {}
```

---

## 10. Error Collection

### Collect Failed Tasks from joblog

```bash
awk 'NR>1 && $7 != 0 {print $NF}' /tmp/jobs.log > /tmp/failed.txt
wc -l /tmp/failed.txt
```

### Re-run Failed Tasks

```bash
parallel --joblog /tmp/jobs.log --retry-failed
# OR manually
parallel -j 4 ./process.sh < /tmp/failed.txt
```

### Capture Per-Task stderr

```bash
find . -type f | parallel --results /tmp/results -j 4 ./task.sh {}
ls /tmp/results/1/
```

### Pssh Failed Hosts

```bash
pssh -h hosts.txt -l ubuntu -p 10 -i "true" 2>&1 | grep FAILURE
```

---

## 11. Result Aggregation

### Concatenate Per-Task Output

```bash
find . -type f -name "*.csv" \
  | parallel -j 8 ./extract.sh {} \
  > /tmp/all-results.txt
```

### Sum Numeric Output Across Hosts

```bash
pssh -h hosts.txt -l ubuntu -i "df / | awk 'NR==2{print \$3}'" 2>/dev/null \
  | grep -E '^[0-9]+$' \
  | awk '{s+=$1} END{print s}'
```

### Aggregate JSON Outputs with jq

```bash
find /tmp/results -name stdout -exec cat {} \; \
  | jq -s 'add'
```

### Count Successes vs Failures

```bash
awk 'NR>1{if($7==0) ok++; else fail++} END {print "ok:",ok,"fail:",fail}' /tmp/jobs.log
```

---

## 12. Master Batch Driver Script

### Save as `/usr/local/bin/batch-run.sh`

```bash
#!/bin/bash
set -uo pipefail

# Usage: batch-run.sh <input-file> <command-template> [-j N] [--dry-run]

INPUT="$1"
CMD="$2"
JOBS=${JOBS:-4}
DRY=""
LOG=/var/log/batch-processor.log
RUN_ID="batch-$(date +%s)-$$"
JOBLOG="/var/log/batch-runs/${RUN_ID}.joblog"
RESULTS="/var/log/batch-runs/${RUN_ID}.results"

mkdir -p /var/log/batch-runs

if [ "${3:-}" = "--dry-run" ]; then DRY="--dry-run"; fi
if [ "${3:-}" = "-j" ]; then JOBS="${4:-4}"; fi

[ -f "$INPUT" ] || { echo "Input file not found: $INPUT"; exit 1; }

LINES=$(wc -l < "$INPUT")
echo "[$(date -Is)] START $RUN_ID lines=$LINES jobs=$JOBS cmd='$CMD'" | tee -a "$LOG"

cat "$INPUT" \
  | parallel $DRY \
        --bar \
        -j "$JOBS" \
        --joblog "$JOBLOG" \
        --results "$RESULTS" \
        "$CMD"

OK=$(awk 'NR>1 && $7==0' "$JOBLOG" | wc -l)
FAIL=$(awk 'NR>1 && $7!=0' "$JOBLOG" | wc -l)
echo "[$(date -Is)] DONE  $RUN_ID ok=$OK fail=$FAIL joblog=$JOBLOG" | tee -a "$LOG"

if [ "$FAIL" -gt 0 ]; then
    echo "Failed inputs:"
    awk 'NR>1 && $7!=0 {print $NF}' "$JOBLOG"
    exit 1
fi
```

### Make Executable

```bash
sudo chmod +x /usr/local/bin/batch-run.sh
```

### Run Examples

```bash
# Compress all logs in /tmp
find /tmp -name "*.log" > /tmp/inputs.txt
sudo /usr/local/bin/batch-run.sh /tmp/inputs.txt "gzip {}" -j 8

# Curl a list of URLs
sudo /usr/local/bin/batch-run.sh urls.txt "curl -fsS -o /dev/null -w '%{http_code} {}\n' {}" -j 16
```

---

## 13. Common Workflows

### "Update apt on all servers"

```bash
ansible all -i /etc/ansible/inventory -b -m apt -a "update_cache=yes upgrade=safe" -f 10
```

### "Restart nginx on all web servers"

```bash
pdsh -f 4 -w web0[1-5] "sudo systemctl restart nginx"
```

### "Hash 100k files across cores"

```bash
find /data -type f -print0 | parallel -0 -j+0 --bar sha256sum > /tmp/hashes.txt
```

### "Run a SQL migration on every tenant DB"

```bash
mysql -N -e "SHOW DATABASES LIKE 'tenant_%';" \
  | parallel -j 4 'mysql {} < /tmp/migration.sql'
```

### "Pull /var/log/syslog from all hosts"

```bash
pslurp -h hosts.txt -l ubuntu /var/log/syslog ./logs syslog
```

### "Convert 50k images to webp"

```bash
find /images -name "*.jpg" \
  | parallel --bar -j+0 'cwebp -q 80 {} -o {.}.webp'
```

### "Re-run failed jobs from last batch"

```bash
parallel --joblog /var/log/batch-runs/batch-1712345.joblog --retry-failed
```

### "Show batch history"

```bash
ls -lht /var/log/batch-runs/ | head -20
grep -E 'START|DONE' /var/log/batch-processor.log | tail -30
```

---

## 14. Performance Tuning

### Pick Job Count

```bash
nproc                            # number of cores
parallel --jobs 200% ...         # 2x cores (CPU + IO blend)
parallel --jobs +0 ...           # equal to nproc
parallel --load 80% ...          # throttle by load average
parallel --memfree 2G ...        # only run if 2G free
```

### Reduce I/O Contention

```bash
ionice -c 3 parallel -j 4 ./io-heavy.sh ::: files...
```

### Nice CPU Priority

```bash
nice -n 10 parallel -j 8 ./task.sh ::: files...
```

---

## 15. Troubleshooting

### parallel: "Cannot find perl"

```bash
sudo apt install -y perl
```

### Quoting Issues with {}

```bash
# Use --quote or single-quote the command
parallel --quote ./script.sh {} ::: 'a b' 'c d'
```

### "Too many open files"

```bash
ulimit -n 65536
```

### pssh Connection Refused

```bash
ssh-keyscan -H web01.example.com >> ~/.ssh/known_hosts
ssh -o StrictHostKeyChecking=no ubuntu@web01.example.com uptime
```

### Ansible Returns "FAILED!"

```bash
ansible web -i inventory -m ping -vvvv
```

### Parallel SQL Locks Up

```bash
# Reduce concurrency, add timeout
parallel -j 2 'mysql --connect-timeout=10 {} < migration.sql'
```

### joblog Shows All Exit Code 1

```bash
# Check the command template by running one input manually
head -1 input.txt | xargs -I {} bash -c 'YOUR_COMMAND'
```

---

## 16. Cron Scheduling

### Nightly Batch Process

```bash
sudo crontab -e
# Add:
0 1 * * * /usr/local/bin/batch-run.sh /var/lib/batches/nightly.txt "/usr/local/bin/process.sh {}" -j 8 >/dev/null 2>&1
```

### systemd Timer Alternative

```bash
sudo tee /etc/systemd/system/batch-nightly.service <<'EOF'
[Unit]
Description=Nightly batch job

[Service]
Type=oneshot
ExecStart=/usr/local/bin/batch-run.sh /var/lib/batches/nightly.txt "/usr/local/bin/process.sh {}"
EOF

sudo tee /etc/systemd/system/batch-nightly.timer <<'EOF'
[Unit]
Description=Run nightly batch
[Timer]
OnCalendar=*-*-* 01:00:00
Persistent=true
[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now batch-nightly.timer
```

---

## Output Format

When running batches, always show:

1. **Run ID + start time**
2. **Input source + total items**
3. **Concurrency (-j N) + tool used (parallel/xargs/pssh/ansible)**
4. **Progress (bar / eta)**
5. **Final tally:** ok / failed counts
6. **Joblog path** for `--retry-failed`
7. **Aggregated result file path**
8. **Log line written** to `/var/log/batch-processor.log`
