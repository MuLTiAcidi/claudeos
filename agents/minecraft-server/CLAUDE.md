# Minecraft Server Agent

Minecraft-specific server management for Linux. Handles Java server setup with Paper, Spigot, Fabric, and Vanilla variants. Manages server.properties, worlds, plugins, whitelists, RCON, JVM tuning, and performance optimization.

## Safety Rules

- NEVER delete world data without explicit confirmation and a verified backup
- NEVER expose RCON to the public internet — bind to localhost or restrict by IP
- NEVER run the Minecraft server as root
- NEVER downgrade a world to an older Minecraft version without backup — this corrupts data
- Always verify free disk space before world operations (backup, restore, generation)
- Always stop the server before modifying world files directly
- Always test plugin compatibility before deploying to production

## Java Installation

```bash
# Install Java 21 (recommended for Minecraft 1.20.5+)
sudo apt-get update
sudo apt-get install -y openjdk-21-jre-headless

# Verify
java -version

# Install Java 17 (for Minecraft 1.17–1.20.4)
sudo apt-get install -y openjdk-17-jre-headless

# Multiple Java versions — select active
sudo update-alternatives --config java

# Check installed versions
update-java-alternatives --list
```

## Server Installation

### Create Server User and Directory

```bash
sudo useradd -m -s /bin/bash minecraft
sudo -u minecraft mkdir -p /home/minecraft/{server,backups,plugins,worlds}
```

### Vanilla Server

```bash
cd /home/minecraft/server

# Download latest vanilla server jar (check https://www.minecraft.net/en-us/download/server)
sudo -u minecraft wget https://piston-data.mojang.com/v1/objects/<hash>/server.jar -O server.jar

# Accept EULA
echo "eula=true" | sudo -u minecraft tee eula.txt

# First run to generate config files
sudo -u minecraft java -Xmx2G -Xms2G -jar server.jar nogui
```

### Paper Server (Recommended)

```bash
cd /home/minecraft/server

# Download Paper (check https://papermc.io/downloads for latest)
MINECRAFT_VERSION="1.21.4"
BUILD=$(curl -s "https://api.papermc.io/v2/projects/paper/versions/${MINECRAFT_VERSION}/builds" | jq '.builds[-1].build')
DOWNLOAD_NAME=$(curl -s "https://api.papermc.io/v2/projects/paper/versions/${MINECRAFT_VERSION}/builds/${BUILD}" | jq -r '.downloads.application.name')

sudo -u minecraft wget "https://api.papermc.io/v2/projects/paper/versions/${MINECRAFT_VERSION}/builds/${BUILD}/downloads/${DOWNLOAD_NAME}" -O paper.jar

echo "eula=true" | sudo -u minecraft tee eula.txt
sudo -u minecraft java -Xmx4G -Xms4G -jar paper.jar nogui
```

### Spigot Server (Build from Source)

```bash
sudo apt-get install -y git openjdk-21-jdk-headless

cd /home/minecraft
sudo -u minecraft mkdir BuildTools && cd BuildTools
sudo -u minecraft wget https://hub.spigotmc.org/jenkins/job/BuildTools/lastSuccessfulBuild/artifact/target/BuildTools.jar

# Build latest version
sudo -u minecraft java -jar BuildTools.jar --rev latest

# Copy to server directory
sudo -u minecraft cp spigot-*.jar /home/minecraft/server/spigot.jar
```

### Fabric Server

```bash
cd /home/minecraft/server

# Download Fabric installer
sudo -u minecraft wget https://maven.fabricmc.net/net/fabricmc/fabric-installer/1.0.1/fabric-installer-1.0.1.jar -O fabric-installer.jar

# Install server
sudo -u minecraft java -jar fabric-installer.jar server -mcversion 1.21.4 -downloadMinecraft

echo "eula=true" | sudo -u minecraft tee eula.txt
sudo -u minecraft java -Xmx4G -Xms4G -jar fabric-server-launch.jar nogui
```

## server.properties Configuration

```properties
# /home/minecraft/server/server.properties

# Core Settings
server-port=25565
server-ip=0.0.0.0
max-players=20
motd=\u00a76My Minecraft Server \u00a77- Welcome!
level-name=world
level-seed=
level-type=minecraft\:normal
gamemode=survival
difficulty=normal
hardcore=false
pvp=true

# Performance
view-distance=10
simulation-distance=8
max-tick-time=60000
network-compression-threshold=256
rate-limit=0
entity-broadcast-range-percentage=100

# Security
online-mode=true
enforce-secure-profile=true
white-list=false
enforce-whitelist=false
enable-rcon=true
rcon.port=25575
rcon.password=CHANGE_THIS_PASSWORD
enable-query=true
query.port=25565

# World
allow-nether=true
spawn-npcs=true
spawn-animals=true
spawn-monsters=true
generate-structures=true
spawn-protection=16
max-world-size=29999984
allow-flight=false

# Misc
enable-command-block=false
enable-status=true
player-idle-timeout=0
prevent-proxy-connections=false
```

### Apply server.properties Changes

```bash
# Edit with sed (examples)
# Change max players
sudo -u minecraft sed -i 's/^max-players=.*/max-players=50/' /home/minecraft/server/server.properties

# Change MOTD
sudo -u minecraft sed -i 's/^motd=.*/motd=\\u00a76Welcome to my server!/' /home/minecraft/server/server.properties

# Change view distance
sudo -u minecraft sed -i 's/^view-distance=.*/view-distance=12/' /home/minecraft/server/server.properties

# Enable whitelist
sudo -u minecraft sed -i 's/^white-list=.*/white-list=true/' /home/minecraft/server/server.properties

# Changes require server restart
sudo systemctl restart minecraft
```

## World Management

### World Backup

```bash
# Stop server first for consistent backup
sudo systemctl stop minecraft

# Backup world with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
sudo -u minecraft tar -czf /home/minecraft/backups/world_${TIMESTAMP}.tar.gz \
    -C /home/minecraft/server world world_nether world_the_end

sudo systemctl start minecraft

# Live backup (Paper — flush chunks first via RCON)
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "save-off"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "save-all flush"
sleep 5
sudo -u minecraft tar -czf /home/minecraft/backups/world_${TIMESTAMP}.tar.gz \
    -C /home/minecraft/server world world_nether world_the_end
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "save-on"
```

### World Restore

```bash
# Stop server
sudo systemctl stop minecraft

# Backup current world first
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
sudo -u minecraft mv /home/minecraft/server/world /home/minecraft/backups/world_pre_restore_${TIMESTAMP}
sudo -u minecraft mv /home/minecraft/server/world_nether /home/minecraft/backups/world_nether_pre_restore_${TIMESTAMP}
sudo -u minecraft mv /home/minecraft/server/world_the_end /home/minecraft/backups/world_the_end_pre_restore_${TIMESTAMP}

# Restore from backup
sudo -u minecraft tar -xzf /home/minecraft/backups/<backup-file>.tar.gz -C /home/minecraft/server/

# Fix permissions
sudo chown -R minecraft:minecraft /home/minecraft/server/world*

sudo systemctl start minecraft
```

### World Seed Management

```bash
# Get current world seed via RCON
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "seed"

# Set seed for new world
sudo -u minecraft sed -i 's/^level-seed=.*/level-seed=123456789/' /home/minecraft/server/server.properties

# Generate new world with specific seed
sudo systemctl stop minecraft
sudo -u minecraft rm -rf /home/minecraft/server/world /home/minecraft/server/world_nether /home/minecraft/server/world_the_end
sudo -u minecraft sed -i 's/^level-seed=.*/level-seed=myseed/' /home/minecraft/server/server.properties
sudo systemctl start minecraft
```

### World Border

```bash
# Set world border via RCON
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "worldborder set 10000"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "worldborder center 0 0"

# Pre-generate chunks (Paper)
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "chunky radius 5000"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "chunky start"
```

## Plugin Management

### Install Plugins (Paper/Spigot)

```bash
# Download plugin to plugins directory
sudo -u minecraft wget <PLUGIN_URL> -O /home/minecraft/server/plugins/<plugin-name>.jar

# List installed plugins
ls -la /home/minecraft/server/plugins/*.jar

# Check plugin via RCON
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "plugins"

# Reload plugins (hot reload — not always reliable)
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "reload confirm"
```

### Common Plugins

```bash
# EssentialsX
sudo -u minecraft wget https://github.com/EssentialsX/Essentials/releases/latest/download/EssentialsX-<version>.jar \
    -O /home/minecraft/server/plugins/EssentialsX.jar

# LuckPerms (permissions)
sudo -u minecraft wget https://download.luckperms.net/1556/bukkit/loader/LuckPerms-Bukkit-5.4.145.jar \
    -O /home/minecraft/server/plugins/LuckPerms.jar

# Chunky (pre-generation)
# Download from https://modrinth.com/plugin/chunky

# WorldGuard + WorldEdit
# Download from https://enginehub.org/worldguard
# Download from https://enginehub.org/worldedit
```

### Plugin Configuration

```bash
# Plugin configs are in /home/minecraft/server/plugins/<PluginName>/
ls /home/minecraft/server/plugins/*/config.yml

# Edit plugin config
sudo -u minecraft nano /home/minecraft/server/plugins/Essentials/config.yml

# Reload specific plugin (if supported)
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "essentials reload"
```

### Fabric Mod Installation

```bash
# Mods go in /home/minecraft/server/mods/
sudo -u minecraft mkdir -p /home/minecraft/server/mods

# Download Fabric API (required for most mods)
sudo -u minecraft wget <FABRIC_API_URL> -O /home/minecraft/server/mods/fabric-api.jar

# Install mods
sudo -u minecraft wget <MOD_URL> -O /home/minecraft/server/mods/<mod-name>.jar

# List mods
ls -la /home/minecraft/server/mods/*.jar
```

## Whitelist and Ops Management

```bash
# Install mcrcon for RCON access
sudo apt-get install -y mcrcon
# Or build from source:
# git clone https://github.com/Tiiffi/mcrcon.git && cd mcrcon && make && sudo make install

# Whitelist management
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "whitelist on"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "whitelist add PlayerName"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "whitelist remove PlayerName"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "whitelist list"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "whitelist reload"

# Operator management
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "op PlayerName"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "deop PlayerName"

# Ban management
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "ban PlayerName Reason here"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "ban-ip 1.2.3.4"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "pardon PlayerName"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "pardon-ip 1.2.3.4"

# Kick player
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "kick PlayerName Reason here"

# Player list
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "list"
```

### Whitelist JSON Format

```json
// /home/minecraft/server/whitelist.json
[
  {
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "name": "PlayerName"
  }
]
```

### Ops JSON Format

```json
// /home/minecraft/server/ops.json
[
  {
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "name": "PlayerName",
    "level": 4,
    "bypassesPlayerLimit": true
  }
]
```

## RCON Commands Reference

```bash
# Server commands via RCON
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "command here"

# Common commands
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "say Server message to all players"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "tell PlayerName Private message"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "tp PlayerName 0 64 0"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "gamemode survival PlayerName"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "difficulty hard"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "time set day"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "weather clear"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "gamerule keepInventory true"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "save-all"
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "stop"

# Performance info
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "tps"          # Paper/Spigot only
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "mspt"         # Paper only
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "timings on"   # Paper/Spigot
mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "spark tps"    # Spark plugin
```

## JVM Tuning

### Recommended JVM Flags (Aikar's Flags)

```bash
# Aikar's recommended flags for Paper/Spigot
# For 4GB allocation:
java -Xms4G -Xmx4G \
    -XX:+UseG1GC \
    -XX:+ParallelRefProcEnabled \
    -XX:MaxGCPauseMillis=200 \
    -XX:+UnlockExperimentalVMOptions \
    -XX:+DisableExplicitGC \
    -XX:+AlwaysPreTouch \
    -XX:G1NewSizePercent=30 \
    -XX:G1MaxNewSizePercent=40 \
    -XX:G1HeapRegionSize=8M \
    -XX:G1ReservePercent=20 \
    -XX:G1HeapWastePercent=5 \
    -XX:G1MixedGCCountTarget=4 \
    -XX:InitiatingHeapOccupancyPercent=15 \
    -XX:G1MixedGCLiveThresholdPercent=90 \
    -XX:G1RSetUpdatingPauseTimePercent=5 \
    -XX:SurvivorRatio=32 \
    -XX:+PerfDisableSharedMem \
    -XX:MaxTenuringThreshold=1 \
    -Dusing.aikars.flags=https://mcflags.emc.gs \
    -Daikars.new.flags=true \
    -jar paper.jar nogui
```

### JVM Memory Guidelines

```bash
# Memory allocation guidelines:
# 1-10 players:  -Xms2G -Xmx2G
# 10-25 players: -Xms4G -Xmx4G
# 25-50 players: -Xms6G -Xmx6G
# 50+ players:   -Xms8G -Xmx8G (consider multiple servers)
# Heavy modpacks: -Xms6G -Xmx8G minimum

# IMPORTANT: Xms and Xmx should be the SAME value for G1GC
# NEVER allocate more than ~12G — G1GC becomes less efficient

# For Fabric servers with many mods:
java -Xms6G -Xmx6G \
    -XX:+UseG1GC \
    -XX:+ParallelRefProcEnabled \
    -XX:MaxGCPauseMillis=200 \
    -XX:+UnlockExperimentalVMOptions \
    -XX:+DisableExplicitGC \
    -XX:+AlwaysPreTouch \
    -jar fabric-server-launch.jar nogui
```

### GC Logging

```bash
# Enable GC logging for performance analysis
java -Xms4G -Xmx4G \
    -Xlog:gc*:file=/home/minecraft/server/logs/gc.log:time,uptime:filecount=5,filesize=10M \
    -jar paper.jar nogui

# Analyze GC logs
grep "Pause" /home/minecraft/server/logs/gc.log | tail -20
```

## Performance Optimization

### Paper Configuration (paper-global.yml)

```yaml
# /home/minecraft/server/config/paper-global.yml
chunk-loading-basic:
  autoconfig-send-distance: true
  player-max-chunk-generate-rate: -1.0
  player-max-chunk-load-rate: -1.0
  player-max-chunk-send-rate: 75.0

chunk-system:
  gen-parallelism: default
  io-threads: -1
  worker-threads: -1

# Async chunk loading (Paper default)
async-chunks:
  threads: -1
```

### Paper World Configuration (paper-world-defaults.yml)

```yaml
# /home/minecraft/server/config/paper-world-defaults.yml
chunks:
  auto-save-interval: 6000
  delay-chunk-unloads-by: 10s
  max-auto-save-chunks-per-tick: 24
  prevent-moving-into-unloaded-chunks: true

entities:
  armor-stands:
    do-collision-entity-lookups: false
    tick: false
  spawning:
    alt-item-despawn-rate:
      enabled: true
      items:
        cobblestone: 300
        netherrack: 300
        sand: 300
        gravel: 300
        dirt: 300
        grass: 300
        pumpkin: 300
        melon_slice: 300
        kelp: 300
        bamboo: 300
        sugar_cane: 300
        twisting_vines: 300
        weeping_vines: 300
        oak_leaves: 300
        spruce_leaves: 300
        birch_leaves: 300
        jungle_leaves: 300
        acacia_leaves: 300
        dark_oak_leaves: 300
        cactus: 300
        diorite: 300
        granite: 300
        andesite: 300
        scaffolding: 300

environment:
  optimize-explosions: true
  treasure-maps:
    enabled: true
    find-already-discovered:
      loot-tables: default
      villager-trade: false

tick-rates:
  container-update: 1
  grass-spread: 4
  mob-spawner: 2
  sensor:
    villager:
      secondarypoisensor: 80
  behavior:
    villager:
      validatenearbypoi: -1
```

### Spigot Configuration (spigot.yml)

```yaml
# /home/minecraft/server/spigot.yml
world-settings:
  default:
    view-distance: default
    simulation-distance: default
    mob-spawn-range: 6
    entity-activation-range:
      animals: 32
      monsters: 32
      raiders: 48
      misc: 16
      water: 16
      villagers: 32
      flying-monsters: 32
    tick-inactive-villagers: true
    entity-tracking-range:
      players: 48
      animals: 48
      monsters: 48
      misc: 32
      display: 128
      other: 64
    merge-radius:
      item: 2.5
      exp: 3.0
    item-despawn-rate: 6000
    nerf-spawner-mobs: false
```

## Systemd Service

```ini
# /etc/systemd/system/minecraft.service
[Unit]
Description=Minecraft Server
After=network-online.target
Wants=network-online.target

[Service]
User=minecraft
Group=minecraft
WorkingDirectory=/home/minecraft/server

ExecStart=/usr/bin/java -Xms4G -Xmx4G \
    -XX:+UseG1GC \
    -XX:+ParallelRefProcEnabled \
    -XX:MaxGCPauseMillis=200 \
    -XX:+UnlockExperimentalVMOptions \
    -XX:+DisableExplicitGC \
    -XX:+AlwaysPreTouch \
    -XX:G1NewSizePercent=30 \
    -XX:G1MaxNewSizePercent=40 \
    -XX:G1HeapRegionSize=8M \
    -XX:G1ReservePercent=20 \
    -XX:G1HeapWastePercent=5 \
    -XX:G1MixedGCCountTarget=4 \
    -XX:InitiatingHeapOccupancyPercent=15 \
    -XX:G1MixedGCLiveThresholdPercent=90 \
    -XX:G1RSetUpdatingPauseTimePercent=5 \
    -XX:SurvivorRatio=32 \
    -XX:+PerfDisableSharedMem \
    -XX:MaxTenuringThreshold=1 \
    -Dusing.aikars.flags=https://mcflags.emc.gs \
    -Daikars.new.flags=true \
    -jar paper.jar nogui

ExecStop=/usr/bin/mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "save-all" "stop"

Restart=on-failure
RestartSec=30
TimeoutStopSec=60

StandardInput=null
StandardOutput=journal
StandardError=journal

LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable minecraft
sudo systemctl start minecraft
sudo systemctl status minecraft
sudo journalctl -u minecraft -f
```

## Monitoring

### TPS Monitoring Script

```bash
#!/bin/bash
# /home/minecraft/scripts/check-tps.sh
TPS=$(mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "tps" 2>/dev/null)
PLAYERS=$(mcrcon -H 127.0.0.1 -P 25575 -p PASSWORD "list" 2>/dev/null)

echo "[$(date)] TPS: $TPS | $PLAYERS"

# Alert if TPS drops below 15
TPS_VALUE=$(echo "$TPS" | grep -oP '\d+\.\d+' | head -1)
if [ "$(echo "$TPS_VALUE < 15" | bc 2>/dev/null)" = "1" ]; then
    echo "WARNING: Low TPS detected: $TPS_VALUE"
fi
```

### Server Status with gamedig

```bash
npm install -g gamedig

gamedig --type minecraft --host 127.0.0.1 --port 25565
```

## Troubleshooting

```bash
# Check if server is running
pgrep -fa java | grep minecraft

# Check memory usage
ps aux | grep java | grep -v grep

# Check open connections
ss -tunp | grep 25565

# Review crash reports
ls -lt /home/minecraft/server/crash-reports/ | head -5
cat /home/minecraft/server/crash-reports/crash-*.txt | head -50

# Check latest log
tail -100 /home/minecraft/server/logs/latest.log

# Common errors:
# "Can't keep up!" — server is lagging, reduce view-distance or simulation-distance
# "OutOfMemoryError" — increase -Xmx value
# "Failed to bind to port" — another process using port 25565
# "Connection refused" — server not running or firewall blocking

# World corruption recovery
# Stop server, restore from backup, or try:
sudo -u minecraft java -jar paper.jar --forceUpgrade --eraseCache
```
