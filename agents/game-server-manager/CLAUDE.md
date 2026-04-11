# Game Server Manager Agent

Universal game server lifecycle management for Linux. Install, configure, start, stop, update, and monitor game servers using SteamCMD, LinuxGSM, and direct binaries. Manage resource allocation, crash recovery, and logging.

## Safety Rules

- NEVER run game servers as root — always use a dedicated user account
- NEVER expose RCON or admin ports to the public internet without authentication
- NEVER delete world/save data without explicit confirmation and a verified backup
- NEVER modify firewall rules without showing the planned changes first
- Always verify disk space before installing or updating game servers
- Always confirm before killing processes — check for active players first

## Server Installation

### Create Dedicated Game Server User

```bash
# Create a dedicated user for game servers
sudo useradd -m -s /bin/bash gameserver
sudo passwd gameserver

# Add to appropriate groups
sudo usermod -aG sudo gameserver

# Set up home directory structure
sudo -u gameserver mkdir -p /home/gameserver/{servers,backups,logs,steamcmd,configs}
```

### Install SteamCMD

```bash
# Install dependencies
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install -y lib32gcc-s1 lib32stdc++6 libsdl2-2.0-0:i386 curl wget tar

# Install SteamCMD
sudo -u gameserver mkdir -p /home/gameserver/steamcmd
cd /home/gameserver/steamcmd
sudo -u gameserver wget https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz
sudo -u gameserver tar -xvzf steamcmd_linux.tar.gz
sudo -u gameserver rm steamcmd_linux.tar.gz

# Verify installation
sudo -u gameserver /home/gameserver/steamcmd/steamcmd.sh +quit
```

### Install LinuxGSM

```bash
# Install LinuxGSM dependencies
sudo apt-get install -y curl wget file tar bzip2 gzip unzip bsdmainutils \
    python3 util-linux ca-certificates binutils bc jq tmux netcat-openbsd \
    lib32gcc-s1 lib32stdc++6 libsdl2-2.0-0:i386 steamcmd

# Install LinuxGSM
sudo -u gameserver bash -c 'cd /home/gameserver && curl -Lo linuxgsm.sh https://linuxgsm.sh && chmod +x linuxgsm.sh'

# List available servers
sudo -u gameserver /home/gameserver/linuxgsm.sh list

# Install a specific server (example: CS2)
sudo -u gameserver /home/gameserver/linuxgsm.sh cs2server
sudo -u gameserver /home/gameserver/cs2server install
```

### Install via Direct Binary

```bash
# Example: Install a Java-based server (generic)
sudo apt-get install -y openjdk-21-jre-headless
sudo -u gameserver mkdir -p /home/gameserver/servers/java-server
cd /home/gameserver/servers/java-server
sudo -u gameserver wget <SERVER_JAR_URL> -O server.jar
```

## Server Lifecycle Management

### Start Server

```bash
# Start with screen
sudo -u gameserver screen -dmS <server-name> /home/gameserver/servers/<server-name>/start.sh

# Start with tmux
sudo -u gameserver tmux new-session -d -s <server-name> '/home/gameserver/servers/<server-name>/start.sh'

# Start via LinuxGSM
sudo -u gameserver /home/gameserver/<server-name> start

# Start via systemd service
sudo systemctl start gameserver@<server-name>
```

### Stop Server

```bash
# Graceful stop via LinuxGSM
sudo -u gameserver /home/gameserver/<server-name> stop

# Send stop command via screen
sudo -u gameserver screen -S <server-name> -p 0 -X stuff "quit\n"

# Send stop command via tmux
sudo -u gameserver tmux send-keys -t <server-name> "quit" Enter

# Graceful stop via systemd
sudo systemctl stop gameserver@<server-name>

# Force kill (last resort — check for players first)
# pgrep -f <server-binary> && kill -SIGTERM $(pgrep -f <server-binary>)
```

### Restart Server

```bash
# Via LinuxGSM
sudo -u gameserver /home/gameserver/<server-name> restart

# Via systemd
sudo systemctl restart gameserver@<server-name>

# Scheduled restart with warning
sudo -u gameserver screen -S <server-name> -p 0 -X stuff "say Server restarting in 5 minutes!\n"
sleep 300
sudo -u gameserver /home/gameserver/<server-name> restart
```

### Server Status

```bash
# LinuxGSM status
sudo -u gameserver /home/gameserver/<server-name> details

# Check if process is running
pgrep -fa <server-binary>

# Check port availability
ss -tulnp | grep <port>

# Check resource usage
ps aux | grep <server-binary> | grep -v grep

# Query server (requires gamedig or similar)
# npm install -g gamedig
# gamedig --type <gametype> --host 127.0.0.1 --port <port>
```

## Systemd Service Template

```ini
# /etc/systemd/system/gameserver@.service
[Unit]
Description=Game Server: %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=gameserver
Group=gameserver
WorkingDirectory=/home/gameserver/servers/%i
ExecStart=/home/gameserver/servers/%i/start.sh
ExecStop=/home/gameserver/servers/%i/stop.sh
Restart=on-failure
RestartSec=30
TimeoutStopSec=60

# Resource limits
LimitNOFILE=65535
MemoryMax=8G
CPUQuota=200%

# Security hardening
ProtectSystem=strict
ReadWritePaths=/home/gameserver/servers/%i
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and manage
sudo systemctl daemon-reload
sudo systemctl enable gameserver@<server-name>
sudo systemctl start gameserver@<server-name>
sudo systemctl status gameserver@<server-name>
sudo journalctl -u gameserver@<server-name> -f
```

## Update Management

### SteamCMD Update

```bash
# Update a specific game server
sudo -u gameserver /home/gameserver/steamcmd/steamcmd.sh \
    +force_install_dir /home/gameserver/servers/<server-name> \
    +login anonymous \
    +app_update <APP_ID> validate \
    +quit

# Check if update is available (compare build IDs)
sudo -u gameserver /home/gameserver/steamcmd/steamcmd.sh \
    +login anonymous \
    +app_info_update 1 \
    +app_info_print <APP_ID> \
    +quit 2>/dev/null | grep -A2 "buildid"
```

### LinuxGSM Update

```bash
# Check for updates
sudo -u gameserver /home/gameserver/<server-name> check-update

# Update server
sudo -u gameserver /home/gameserver/<server-name> update

# Update LinuxGSM itself
sudo -u gameserver /home/gameserver/<server-name> update-lgsm
```

### Automated Update Script

```bash
#!/bin/bash
# /home/gameserver/scripts/auto-update.sh
SERVER_NAME="$1"
LGSM_SCRIPT="/home/gameserver/${SERVER_NAME}"

if [ ! -f "$LGSM_SCRIPT" ]; then
    echo "Server script not found: $LGSM_SCRIPT"
    exit 1
fi

# Check for update
UPDATE_CHECK=$("$LGSM_SCRIPT" check-update 2>&1)
if echo "$UPDATE_CHECK" | grep -q "Update available"; then
    echo "[$(date)] Update available for $SERVER_NAME"
    
    # Warn players
    "$LGSM_SCRIPT" send "say Server updating in 5 minutes!" 2>/dev/null
    sleep 300
    
    # Stop, update, start
    "$LGSM_SCRIPT" stop
    sleep 10
    "$LGSM_SCRIPT" update
    "$LGSM_SCRIPT" start
    echo "[$(date)] Update complete for $SERVER_NAME"
else
    echo "[$(date)] No update available for $SERVER_NAME"
fi
```

## Resource Allocation

### CPU Affinity

```bash
# Set CPU affinity for a game server process
# Pin to cores 0-3
taskset -cp 0-3 $(pgrep -f <server-binary>)

# Start with specific CPU affinity
taskset -c 0-3 /home/gameserver/servers/<server-name>/start.sh

# Verify affinity
taskset -cp $(pgrep -f <server-binary>)
```

### Process Priority (nice/renice)

```bash
# Start server with high priority
nice -n -10 /home/gameserver/servers/<server-name>/start.sh

# Renice a running server
sudo renice -n -10 -p $(pgrep -f <server-binary>)

# Set I/O priority
sudo ionice -c 1 -n 0 -p $(pgrep -f <server-binary>)
```

### Memory Limits with cgroups v2

```bash
# Create cgroup for game server
sudo mkdir -p /sys/fs/cgroup/gameservers/<server-name>

# Set memory limit (8GB)
echo 8589934592 | sudo tee /sys/fs/cgroup/gameservers/<server-name>/memory.max

# Set memory high watermark (7GB — triggers reclaim)
echo 7516192768 | sudo tee /sys/fs/cgroup/gameservers/<server-name>/memory.high

# Set CPU weight (relative priority, default 100)
echo 500 | sudo tee /sys/fs/cgroup/gameservers/<server-name>/cpu.weight

# Add server process to cgroup
echo $(pgrep -f <server-binary>) | sudo tee /sys/fs/cgroup/gameservers/<server-name>/cgroup.procs

# Monitor cgroup usage
cat /sys/fs/cgroup/gameservers/<server-name>/memory.current
cat /sys/fs/cgroup/gameservers/<server-name>/cpu.stat
```

### Using systemd Slice for Resource Control

```ini
# /etc/systemd/system/gameservers.slice
[Slice]
Description=Game Servers Resource Slice
MemoryMax=24G
CPUQuota=400%
IOWeight=200
```

```bash
# Move a service into the slice
# Add Slice=gameservers.slice to the [Service] section
sudo systemctl daemon-reload
sudo systemctl restart gameserver@<server-name>

# Monitor slice
systemd-cgtop /gameservers.slice
```

## Log Management

### Log Locations

```bash
# LinuxGSM logs
/home/gameserver/log/<server-name>/*.log

# Screen logs
/home/gameserver/servers/<server-name>/screenlog.0

# Systemd journal
journalctl -u gameserver@<server-name>

# Game-specific logs (vary by game)
/home/gameserver/servers/<server-name>/logs/
```

### Log Rotation

```bash
# /etc/logrotate.d/gameservers
/home/gameserver/log/*/*.log
/home/gameserver/servers/*/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0644 gameserver gameserver
    sharedscripts
    postrotate
        # Signal the server to reopen log files if needed
        true
    endscript
}
```

### Log Monitoring

```bash
# Tail server console log
tail -f /home/gameserver/servers/<server-name>/logs/latest.log

# Search logs for errors
grep -i "error\|exception\|crash\|fatal" /home/gameserver/servers/<server-name>/logs/latest.log

# Count player connections in last 24h
grep -c "joined\|connected" /home/gameserver/servers/<server-name>/logs/latest.log

# Monitor log size
du -sh /home/gameserver/servers/*/logs/
```

## Crash Detection and Recovery

### Crash Detection Script

```bash
#!/bin/bash
# /home/gameserver/scripts/crash-watchdog.sh
SERVER_NAME="$1"
SERVER_BINARY="$2"
CHECK_INTERVAL=30
MAX_RESTARTS=5
RESTART_COUNT=0
RESTART_WINDOW=3600  # Reset counter after 1 hour
LAST_RESTART=$(date +%s)

while true; do
    if ! pgrep -f "$SERVER_BINARY" > /dev/null 2>&1; then
        CURRENT_TIME=$(date +%s)
        TIME_DIFF=$((CURRENT_TIME - LAST_RESTART))
        
        # Reset counter if enough time has passed
        if [ $TIME_DIFF -gt $RESTART_WINDOW ]; then
            RESTART_COUNT=0
        fi
        
        RESTART_COUNT=$((RESTART_COUNT + 1))
        
        if [ $RESTART_COUNT -le $MAX_RESTARTS ]; then
            echo "[$(date)] $SERVER_NAME crashed! Restarting (attempt $RESTART_COUNT/$MAX_RESTARTS)..."
            /home/gameserver/${SERVER_NAME} start
            LAST_RESTART=$(date +%s)
        else
            echo "[$(date)] $SERVER_NAME exceeded max restarts ($MAX_RESTARTS). Manual intervention required."
            # Send alert (webhook, email, etc.)
            curl -s -X POST "$DISCORD_WEBHOOK_URL" \
                -H "Content-Type: application/json" \
                -d "{\"content\":\"ALERT: $SERVER_NAME has crashed $MAX_RESTARTS times. Manual restart required.\"}"
            exit 1
        fi
    fi
    sleep $CHECK_INTERVAL
done
```

### Systemd Crash Recovery

```ini
# In the gameserver@.service file
[Service]
Restart=on-failure
RestartSec=30
StartLimitIntervalSec=600
StartLimitBurst=5

# WatchdogSec for hang detection
WatchdogSec=120
```

### Core Dump Configuration

```bash
# Enable core dumps for crash analysis
echo '/home/gameserver/coredumps/core.%e.%p.%t' | sudo tee /proc/sys/kernel/core_pattern
sudo -u gameserver mkdir -p /home/gameserver/coredumps

# Set core dump size limit
ulimit -c unlimited

# Analyze a core dump
gdb /path/to/server-binary /home/gameserver/coredumps/core.<name>.<pid>.<time>
```

## Server Query and Monitoring

### Query Protocols

```bash
# Install gamedig for server queries
sudo npm install -g gamedig

# Query Source engine servers
gamedig --type csgo --host 127.0.0.1 --port 27015

# Query Minecraft servers
gamedig --type minecraft --host 127.0.0.1 --port 25565

# Query via Python A2S (Source Query Protocol)
pip3 install python-a2s
python3 -c "
import a2s
info = a2s.info(('127.0.0.1', 27015))
print(f'Server: {info.server_name}')
print(f'Players: {info.player_count}/{info.max_players}')
print(f'Map: {info.map_name}')
"
```

### Resource Monitoring Script

```bash
#!/bin/bash
# /home/gameserver/scripts/monitor.sh
SERVER_NAME="$1"
PID=$(pgrep -f "$2")

if [ -z "$PID" ]; then
    echo "Server $SERVER_NAME is NOT running"
    exit 1
fi

echo "=== $SERVER_NAME Status ==="
echo "PID: $PID"
echo "Uptime: $(ps -o etime= -p $PID | tr -d ' ')"
echo "CPU: $(ps -o %cpu= -p $PID | tr -d ' ')%"
echo "Memory: $(ps -o rss= -p $PID | awk '{printf "%.1f MB", $1/1024}') ($(ps -o %mem= -p $PID | tr -d ' ')%)"
echo "Threads: $(ps -o nlwp= -p $PID | tr -d ' ')"
echo "Open Files: $(ls /proc/$PID/fd 2>/dev/null | wc -l)"
echo "Network Connections: $(ss -tunp | grep "pid=$PID" | wc -l)"

# Disk usage
echo "Disk Usage: $(du -sh /home/gameserver/servers/$SERVER_NAME 2>/dev/null | cut -f1)"
```

## Firewall Configuration

```bash
# Open common game server ports
# Source engine (CS2, Garry's Mod, etc.)
sudo ufw allow 27015/tcp comment "Game Server Query"
sudo ufw allow 27015/udp comment "Game Server"
sudo ufw allow 27020/udp comment "Game Server SRCDS"

# Minecraft
sudo ufw allow 25565/tcp comment "Minecraft"

# Valheim
sudo ufw allow 2456:2458/udp comment "Valheim"

# ARK
sudo ufw allow 7777/udp comment "ARK Game"
sudo ufw allow 27015/udp comment "ARK Query"

# RCON (restrict to specific IPs!)
sudo ufw allow from <admin-ip> to any port 27015 proto tcp comment "RCON Admin"

# View rules
sudo ufw status numbered
```

## Multi-Server Management

### List All Servers

```bash
#!/bin/bash
# /home/gameserver/scripts/list-servers.sh
echo "=== Game Servers ==="
printf "%-20s %-10s %-10s %-15s\n" "Server" "Status" "Port" "Players"
echo "-----------------------------------------------------------"

for server_dir in /home/gameserver/servers/*/; do
    server_name=$(basename "$server_dir")
    pid=$(pgrep -f "$server_name" 2>/dev/null)
    
    if [ -n "$pid" ]; then
        status="RUNNING"
        cpu=$(ps -o %cpu= -p $pid 2>/dev/null | tr -d ' ')
        mem=$(ps -o rss= -p $pid 2>/dev/null | awk '{printf "%.0fMB", $1/1024}')
        printf "%-20s %-10s %-10s %-15s\n" "$server_name" "$status" "-" "CPU:${cpu}% MEM:${mem}"
    else
        printf "%-20s %-10s %-10s %-15s\n" "$server_name" "STOPPED" "-" "-"
    fi
done
```

### Bulk Operations

```bash
# Stop all game servers
for script in /home/gameserver/*server; do
    [ -f "$script" ] && sudo -u gameserver "$script" stop
done

# Start all game servers
for script in /home/gameserver/*server; do
    [ -f "$script" ] && sudo -u gameserver "$script" start
done

# Update all game servers
for script in /home/gameserver/*server; do
    [ -f "$script" ] && sudo -u gameserver "$script" update
done
```

## Cron Jobs

```bash
# Edit gameserver crontab
sudo -u gameserver crontab -e

# Auto-restart daily at 5 AM
0 5 * * * /home/gameserver/cs2server restart > /dev/null 2>&1

# Check for updates every 6 hours
0 */6 * * * /home/gameserver/scripts/auto-update.sh cs2server >> /home/gameserver/log/update.log 2>&1

# Monitor every minute
* * * * * /home/gameserver/scripts/crash-watchdog.sh cs2server srcds_linux >> /home/gameserver/log/watchdog.log 2>&1

# Disk space check daily
0 6 * * * df -h /home/gameserver | tail -1 | awk '{if ($5+0 > 90) print "DISK SPACE WARNING: "$5" used"}' >> /home/gameserver/log/disk.log
```

## Troubleshooting

### Common Issues

```bash
# Server won't start — check port conflicts
ss -tulnp | grep <port>

# Permission issues
sudo chown -R gameserver:gameserver /home/gameserver/servers/<server-name>
sudo chmod -R 755 /home/gameserver/servers/<server-name>

# Missing libraries
ldd /home/gameserver/servers/<server-name>/<binary> | grep "not found"
sudo apt-get install -y lib32gcc-s1 lib32stdc++6

# Out of memory
dmesg | grep -i "oom\|killed"
journalctl -k | grep -i "oom"

# Check file descriptor limits
cat /proc/$(pgrep -f <server-binary>)/limits | grep "open files"
# Increase if needed
ulimit -n 65535

# Network issues — check connectivity
nc -zv 127.0.0.1 <port>
ss -s  # Connection summary
```
