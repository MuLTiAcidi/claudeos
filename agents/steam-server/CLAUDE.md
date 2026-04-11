# Steam Server Agent

SteamCMD-based game server management for Linux. Install, update, and manage dedicated servers for CS2, Valheim, Rust, ARK, Palworld, Project Zomboid, and more. Handles SteamCMD authentication, GSLT tokens, workshop mods, per-game configuration, and screen/tmux session management.

## Safety Rules

- NEVER store Steam credentials in plain text scripts — use environment variables or steamcmd's saved login
- NEVER expose RCON or admin ports to the public internet without strong passwords
- NEVER delete game server files without explicit confirmation and backup verification
- NEVER run game servers as root — always use a dedicated user
- Always verify disk space before installing or updating (some games need 50GB+)
- Always check for active players before stopping or updating a server

## SteamCMD Installation

```bash
# Create dedicated user
sudo useradd -m -s /bin/bash steam
sudo passwd steam

# Install dependencies
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install -y lib32gcc-s1 lib32stdc++6 libsdl2-2.0-0:i386 curl wget tar

# Install SteamCMD
sudo -u steam mkdir -p /home/steam/steamcmd
cd /home/steam/steamcmd
sudo -u steam wget https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz
sudo -u steam tar -xvzf steamcmd_linux.tar.gz
sudo -u steam rm steamcmd_linux.tar.gz

# Verify installation
sudo -u steam /home/steam/steamcmd/steamcmd.sh +quit

# Create server directories
sudo -u steam mkdir -p /home/steam/{servers,backups,configs,workshop,logs}
```

### SteamCMD Login

```bash
# Anonymous login (most dedicated servers)
sudo -u steam /home/steam/steamcmd/steamcmd.sh +login anonymous +quit

# Authenticated login (some games require owning the game)
# First time — will prompt for Steam Guard code
sudo -u steam /home/steam/steamcmd/steamcmd.sh +login YOUR_USERNAME +quit

# After first login, credentials are cached in ~/Steam/
```

### GSLT (Game Server Login Token)

```bash
# Generate GSLT at: https://steamcommunity.com/dev/managegameservers
# Required for: CS2, TF2, Garry's Mod, and other Source/Source 2 games
# Each server needs its own unique GSLT

# Usage in CS2 server launch:
# Add to launch args: +sv_setsteamaccount YOUR_GSLT_TOKEN

# Store GSLT securely
echo "GSLT_TOKEN=YOUR_TOKEN_HERE" | sudo -u steam tee /home/steam/configs/.gslt_cs2
sudo chmod 600 /home/steam/configs/.gslt_cs2
```

## Game Server Installations

### CS2 (Counter-Strike 2) — App ID 730

```bash
# Install CS2 dedicated server
sudo -u steam /home/steam/steamcmd/steamcmd.sh \
    +force_install_dir /home/steam/servers/cs2 \
    +login anonymous \
    +app_update 730 validate \
    +quit

# Create launch script
cat << 'SCRIPT' | sudo -u steam tee /home/steam/servers/cs2/start.sh
#!/bin/bash
source /home/steam/configs/.gslt_cs2

cd /home/steam/servers/cs2

./game/bin/linuxsteamrt64/cs2 \
    -dedicated \
    -console \
    -usercon \
    +game_type 0 \
    +game_mode 0 \
    +map de_dust2 \
    +sv_setsteamaccount $GSLT_TOKEN \
    -maxplayers 10 \
    -port 27015 \
    +rcon_password "YOUR_RCON_PASSWORD" \
    +sv_lan 0
SCRIPT
sudo -u steam chmod +x /home/steam/servers/cs2/start.sh
```

#### CS2 Server Configuration

```cfg
// /home/steam/servers/cs2/game/csgo/cfg/server.cfg
hostname "My CS2 Server"
rcon_password "CHANGE_THIS"
sv_password ""
sv_cheats 0
sv_lan 0
sv_maxrate 0
sv_minrate 128000
sv_maxupdaterate 128
sv_mincmdrate 128
mp_autoteambalance 1
mp_limitteams 1
mp_friendlyfire 0
mp_roundtime 2
mp_freezetime 10
mp_buytime 20
mp_startmoney 800
mp_maxmoney 16000
sv_alltalk 0
bot_quota 0
```

### Valheim — App ID 896660

```bash
# Install Valheim dedicated server
sudo -u steam /home/steam/steamcmd/steamcmd.sh \
    +force_install_dir /home/steam/servers/valheim \
    +login anonymous \
    +app_update 896660 validate \
    +quit

# Install required libs
sudo apt-get install -y libatomic1 libpulse-dev libpulse0

# Create launch script
cat << 'SCRIPT' | sudo -u steam tee /home/steam/servers/valheim/start.sh
#!/bin/bash
export templdpath=$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/home/steam/servers/valheim/linux64:$LD_LIBRARY_PATH
export SteamAppId=892970

cd /home/steam/servers/valheim

./valheim_server.x86_64 \
    -name "My Valheim Server" \
    -port 2456 \
    -world "MyWorld" \
    -password "serverpassword" \
    -savedir "/home/steam/servers/valheim/saves" \
    -public 1 \
    -logFile "/home/steam/logs/valheim.log" \
    -crossplay

export LD_LIBRARY_PATH=$templdpath
SCRIPT
sudo -u steam chmod +x /home/steam/servers/valheim/start.sh
```

#### Valheim Firewall

```bash
sudo ufw allow 2456:2458/udp comment "Valheim"
```

### Rust — App ID 258550

```bash
# Install Rust dedicated server
sudo -u steam /home/steam/steamcmd/steamcmd.sh \
    +force_install_dir /home/steam/servers/rust \
    +login anonymous \
    +app_update 258550 validate \
    +quit

# Create launch script
cat << 'SCRIPT' | sudo -u steam tee /home/steam/servers/rust/start.sh
#!/bin/bash
cd /home/steam/servers/rust

./RustDedicated \
    -batchmode \
    +server.port 28015 \
    +server.queryport 28016 \
    +rcon.port 28017 \
    +rcon.web 1 \
    +rcon.password "YOUR_RCON_PASSWORD" \
    +server.hostname "My Rust Server" \
    +server.identity "myrust" \
    +server.maxplayers 50 \
    +server.worldsize 3000 \
    +server.seed 12345 \
    +server.saveinterval 300 \
    +server.description "Welcome to my Rust server" \
    +server.headerimage "https://example.com/banner.png" \
    -logFile "/home/steam/logs/rust.log"
SCRIPT
sudo -u steam chmod +x /home/steam/servers/rust/start.sh
```

#### Rust Configuration

```bash
# Server config location
/home/steam/servers/rust/server/myrust/cfg/serverauto.cfg

# Common settings in serverauto.cfg
server.hostname "My Rust Server"
server.description "Welcome to my server"
server.maxplayers 50
server.worldsize 3000
server.seed 12345
server.saveinterval 300
decay.scale 1.0
env.time 12
```

#### Rust Firewall

```bash
sudo ufw allow 28015/tcp comment "Rust Game"
sudo ufw allow 28015/udp comment "Rust Game"
sudo ufw allow 28016/udp comment "Rust Query"
sudo ufw allow from <admin-ip> to any port 28017 proto tcp comment "Rust RCON"
```

### ARK: Survival Evolved — App ID 376030

```bash
# Install ARK dedicated server (WARNING: ~60GB+ disk space needed)
sudo -u steam /home/steam/steamcmd/steamcmd.sh \
    +force_install_dir /home/steam/servers/ark \
    +login anonymous \
    +app_update 376030 validate \
    +quit

# Create launch script
cat << 'SCRIPT' | sudo -u steam tee /home/steam/servers/ark/start.sh
#!/bin/bash
cd /home/steam/servers/ark

./ShooterGame/Binaries/Linux/ShooterGameServer \
    "TheIsland?listen?SessionName=MyARKServer?ServerPassword=joinpass?ServerAdminPassword=adminpass?Port=7777?QueryPort=27015?MaxPlayers=40?RCONEnabled=True?RCONPort=27020" \
    -server \
    -log \
    -crossplay \
    -NoBattlEye \
    -automanagedmods
SCRIPT
sudo -u steam chmod +x /home/steam/servers/ark/start.sh
```

#### ARK Configuration

```ini
# /home/steam/servers/ark/ShooterGame/Saved/Config/LinuxServer/GameUserSettings.ini
[ServerSettings]
ServerPassword=joinpass
ServerAdminPassword=adminpass
MaxPlayers=40
DifficultyOffset=0.5
ServerCrosshair=True
ShowMapPlayerLocation=True
EnablePvPGamma=True
AllowFlyerCarryPvE=True
RCONEnabled=True
RCONPort=27020
TheMaxStructuresInRange=10500
AutoSavePeriodMinutes=15
TamingSpeedMultiplier=2.0
HarvestAmountMultiplier=2.0
XPMultiplier=2.0

[SessionSettings]
SessionName=MyARKServer
```

#### ARK Firewall

```bash
sudo ufw allow 7777/udp comment "ARK Game"
sudo ufw allow 7778/udp comment "ARK Raw UDP"
sudo ufw allow 27015/udp comment "ARK Query"
sudo ufw allow from <admin-ip> to any port 27020 proto tcp comment "ARK RCON"
```

### Palworld — App ID 2394010

```bash
# Install Palworld dedicated server
sudo -u steam /home/steam/steamcmd/steamcmd.sh \
    +force_install_dir /home/steam/servers/palworld \
    +login anonymous \
    +app_update 2394010 validate \
    +quit

# Create launch script
cat << 'SCRIPT' | sudo -u steam tee /home/steam/servers/palworld/start.sh
#!/bin/bash
cd /home/steam/servers/palworld

./PalServer.sh \
    -port=8211 \
    -players=32 \
    -useperfthreads \
    -NoAsyncLoadingThread \
    -UseMultithreadForDS \
    EpicApp=PalServer
SCRIPT
sudo -u steam chmod +x /home/steam/servers/palworld/start.sh
```

#### Palworld Configuration

```ini
# /home/steam/servers/palworld/Pal/Saved/Config/LinuxServer/PalWorldSettings.ini
[/Script/Pal.PalGameWorldSettings]
OptionSettings=(Difficulty=None,DayTimeSpeedRate=1.000000,NightTimeSpeedRate=1.000000,ExpRate=1.000000,PalCaptureRate=1.000000,PalSpawnNumRate=1.000000,PalDamageRateAttack=1.000000,PalDamageRateDefense=1.000000,PlayerDamageRateAttack=1.000000,PlayerDamageRateDefense=1.000000,PlayerStomachDecreaceRate=1.000000,PlayerStaminaDecreaceRate=1.000000,PlayerAutoHPRegeneRate=1.000000,PlayerAutoHpRegeneRateInSleep=1.000000,PalStomachDecreaceRate=1.000000,PalStaminaDecreaceRate=1.000000,PalAutoHPRegeneRate=1.000000,PalAutoHpRegeneRateInSleep=1.000000,BuildObjectDamageRate=1.000000,BuildObjectDeteriorationDamageRate=1.000000,CollectionDropRate=1.000000,CollectionObjectHpRate=1.000000,CollectionObjectRespawnSpeedRate=1.000000,EnemyDropItemRate=1.000000,DeathPenalty=All,bEnablePlayerToPlayerDamage=False,bEnableFriendlyFire=False,bEnableInvaderEnemy=True,bActiveUNKO=False,bEnableAimAssistPad=True,bEnableAimAssistKeyboard=False,DropItemMaxNum=3000,DropItemMaxNum_UNKO=100,BaseCampMaxNum=128,BaseCampWorkerMaxNum=15,DropItemAliveMaxHours=1.000000,bAutoResetGuildNoOnlinePlayers=False,AutoResetGuildTimeNoOnlinePlayers=72.000000,GuildPlayerMaxNum=20,PalEggDefaultHatchingTime=72.000000,WorkSpeedRate=1.000000,bIsMultiplay=True,bIsPvP=False,bCanPickupOtherGuildDeathPenaltyDrop=False,bEnableNonLoginPenalty=True,bEnableFastTravel=True,bIsStartLocationSelectByMap=True,bExistPlayerAfterLogout=False,bEnableDefenseOtherGuildPlayer=False,CoopPlayerMaxNum=32,ServerPlayerMaxNum=32,ServerName="My Palworld Server",ServerDescription="Welcome!",AdminPassword="ADMIN_PASSWORD",ServerPassword="",PublicPort=8211,PublicIP="",RCONEnabled=True,RCONPort=25575,Region="",bUseAuth=True,BanListURL="https://api.palworldgame.com/api/banlist.txt")
```

#### Palworld Firewall

```bash
sudo ufw allow 8211/udp comment "Palworld Game"
sudo ufw allow from <admin-ip> to any port 25575 proto tcp comment "Palworld RCON"
```

### Project Zomboid — App ID 380870

```bash
# Install Project Zomboid dedicated server
sudo -u steam /home/steam/steamcmd/steamcmd.sh \
    +force_install_dir /home/steam/servers/zomboid \
    +login anonymous \
    +app_update 380870 validate \
    +quit

# Create launch script
cat << 'SCRIPT' | sudo -u steam tee /home/steam/servers/zomboid/start.sh
#!/bin/bash
cd /home/steam/servers/zomboid

./start-server.sh \
    -servername MyZomboidServer \
    -adminpassword "ADMIN_PASSWORD" \
    -port 16261 \
    -udpport 16262 \
    -players 16 \
    -memory 4096
SCRIPT
sudo -u steam chmod +x /home/steam/servers/zomboid/start.sh
```

#### Project Zomboid Configuration

```ini
# ~/Zomboid/Server/MyZomboidServer.ini (generated on first run)
DefaultPort=16261
UDPPort=16262
MaxPlayers=16
Public=true
PublicName=My Zomboid Server
PublicDescription=Welcome to the apocalypse
Password=
PauseEmpty=true
PVP=true
SpawnPoint=0,0,0
SafeHouse=true
SteamScoreboard=true
SteamPort1=8766
SteamPort2=8767
WorkshopItems=
Mods=
Map=Muldraugh, KY
```

#### Project Zomboid Firewall

```bash
sudo ufw allow 16261/udp comment "Zomboid Game"
sudo ufw allow 16262/udp comment "Zomboid UDP"
sudo ufw allow 8766/udp comment "Zomboid Steam 1"
sudo ufw allow 8767/udp comment "Zomboid Steam 2"
```

## Screen/Tmux Session Management

### Screen Management

```bash
# Start server in screen session
sudo -u steam screen -dmS cs2 /home/steam/servers/cs2/start.sh

# List screen sessions
sudo -u steam screen -ls

# Attach to session
sudo -u steam screen -r cs2

# Detach from session: Ctrl+A, then D

# Send command to server
sudo -u steam screen -S cs2 -p 0 -X stuff "say Hello World\n"

# Kill screen session (last resort)
sudo -u steam screen -S cs2 -X quit

# Scroll in screen: Ctrl+A, then Esc, then use arrow keys/Page Up/Down
# Exit scroll mode: Esc

# Enable screen logging
sudo -u steam screen -dmS cs2 -L -Logfile /home/steam/logs/cs2_screen.log /home/steam/servers/cs2/start.sh
```

### Tmux Management

```bash
# Start server in tmux session
sudo -u steam tmux new-session -d -s cs2 '/home/steam/servers/cs2/start.sh'

# List tmux sessions
sudo -u steam tmux ls

# Attach to session
sudo -u steam tmux attach-session -t cs2

# Detach from session: Ctrl+B, then D

# Send command to server
sudo -u steam tmux send-keys -t cs2 "say Hello World" Enter

# Kill tmux session (last resort)
sudo -u steam tmux kill-session -t cs2

# Split pane for monitoring (Ctrl+B, then %)
# Switch panes (Ctrl+B, then arrow keys)

# Capture pane output to file
sudo -u steam tmux capture-pane -t cs2 -p > /home/steam/logs/cs2_capture.log

# Scroll in tmux: Ctrl+B, then [ (use arrow keys, q to exit)
```

## Workshop Mod Management

### Download Workshop Mods via SteamCMD

```bash
# Download a single workshop item
sudo -u steam /home/steam/steamcmd/steamcmd.sh \
    +force_install_dir /home/steam/servers/<game> \
    +login anonymous \
    +workshop_download_item <APP_ID> <WORKSHOP_ITEM_ID> \
    +quit

# Workshop content is downloaded to:
# /home/steam/steamcmd/steamapps/workshop/content/<APP_ID>/<WORKSHOP_ITEM_ID>/

# Batch download workshop items
cat << 'SCRIPT' | sudo -u steam tee /home/steam/scripts/download_mods.sh
#!/bin/bash
GAME_APP_ID=$1
INSTALL_DIR=$2

shift 2
MOD_IDS="$@"

CMD="/home/steam/steamcmd/steamcmd.sh +force_install_dir $INSTALL_DIR +login anonymous"
for MOD_ID in $MOD_IDS; do
    CMD="$CMD +workshop_download_item $GAME_APP_ID $MOD_ID"
done
CMD="$CMD +quit"

eval $CMD
SCRIPT
sudo -u steam chmod +x /home/steam/scripts/download_mods.sh

# Usage: download multiple ARK mods
sudo -u steam /home/steam/scripts/download_mods.sh 346110 /home/steam/servers/ark 123456789 987654321 111222333
```

### Link Workshop Mods to Server

```bash
# ARK — mods are auto-loaded from Mods folder
# Symlink workshop mods
ln -s /home/steam/steamcmd/steamapps/workshop/content/346110/<MOD_ID> \
    /home/steam/servers/ark/ShooterGame/Content/Mods/<MOD_ID>

# Project Zomboid — add to server config
# Edit ~/Zomboid/Server/MyZomboidServer.ini
# WorkshopItems=<ID1>;<ID2>;<ID3>
# Mods=<ModName1>;<ModName2>;<ModName3>

# Rust — Oxide/uMod mod framework
# Install Oxide: https://umod.org/games/rust
wget https://umod.org/games/rust/download -O /tmp/oxide.zip
sudo -u steam unzip -o /tmp/oxide.zip -d /home/steam/servers/rust/
```

## Update Management

```bash
# Update a specific server
sudo -u steam /home/steam/steamcmd/steamcmd.sh \
    +force_install_dir /home/steam/servers/<game> \
    +login anonymous \
    +app_update <APP_ID> validate \
    +quit

# Common App IDs for updates:
# CS2:              730
# Valheim:          896660
# Rust:             258550
# ARK:              376030
# Palworld:         2394010
# Project Zomboid:  380870
# Garry's Mod:      4020
# TF2:              232250
# 7 Days to Die:    294420
# Satisfactory:     1690800

# Automated update script with player check
cat << 'SCRIPT' | sudo -u steam tee /home/steam/scripts/safe-update.sh
#!/bin/bash
SERVER_NAME=$1
APP_ID=$2
SERVER_DIR=$3
SCREEN_NAME=$4

# Check for players (game-specific — adjust query method)
PLAYER_COUNT=$(gamedig --type $SERVER_NAME --host 127.0.0.1 2>/dev/null | jq '.players | length' 2>/dev/null || echo "0")

if [ "$PLAYER_COUNT" -gt 0 ]; then
    echo "[$(date)] $PLAYER_COUNT players online, skipping update"
    exit 0
fi

echo "[$(date)] No players online, updating $SERVER_NAME"
screen -S $SCREEN_NAME -X quit 2>/dev/null
sleep 10

/home/steam/steamcmd/steamcmd.sh \
    +force_install_dir "$SERVER_DIR" \
    +login anonymous \
    +app_update $APP_ID validate \
    +quit

screen -dmS $SCREEN_NAME "$SERVER_DIR/start.sh"
echo "[$(date)] Update complete, server restarted"
SCRIPT
sudo -u steam chmod +x /home/steam/scripts/safe-update.sh
```

## Systemd Service Templates

```ini
# /etc/systemd/system/steam-server@.service
[Unit]
Description=Steam Game Server: %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=steam
Group=steam
WorkingDirectory=/home/steam/servers/%i
ExecStart=/home/steam/servers/%i/start.sh
ExecStop=/bin/kill -SIGINT $MAINPID
Restart=on-failure
RestartSec=30
TimeoutStopSec=120

LimitNOFILE=100000
MemoryMax=12G

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable steam-server@cs2
sudo systemctl start steam-server@cs2
sudo systemctl status steam-server@cs2
```

## Troubleshooting

```bash
# SteamCMD fails to update
# Clear download cache
sudo -u steam rm -rf /home/steam/steamcmd/steamapps/downloading/*

# Missing shared libraries
ldd /home/steam/servers/<game>/<binary> 2>&1 | grep "not found"
sudo apt-get install -y lib32gcc-s1 lib32stdc++6

# Server not showing in browser
# Check firewall
sudo ufw status
# Check if query port is open
ss -tulnp | grep <query-port>
# Verify GSLT token (for Source games)

# Disk space issues
df -h /home/steam
du -sh /home/steam/servers/*

# Connection timeout
# Check if server is actually listening
ss -tulnp | grep <port>
# Check external connectivity
curl -s ifconfig.me  # Get public IP

# Steam authentication issues
# Delete cached credentials and re-login
sudo -u steam rm -rf /home/steam/Steam/config/
sudo -u steam /home/steam/steamcmd/steamcmd.sh +login YOUR_USERNAME +quit
```
