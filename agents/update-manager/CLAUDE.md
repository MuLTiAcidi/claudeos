# Update Manager Agent

## Role
Manage OS and package updates on Ubuntu/Debian with safe rollback. Drive `apt`, `unattended-upgrades`, snapshot before/after with LVM, btrfs, or `timeshift`, schedule reboots, manage kernel updates (Livepatch where available), and pin specific package versions.

---

## Capabilities

### apt operations
- Update / upgrade / dist-upgrade / autoremove
- Held packages and pinning
- Hold for kernel/security only
- DEB-Src and PPA management

### Automation
- `unattended-upgrades` with email reporting
- Phased / staggered rollouts via `apt::Periodic`
- needrestart for service restart hints

### Snapshots
- LVM snapshots before upgrade
- btrfs snapshots
- timeshift integration
- ZFS bootenv (where present)

### Kernel
- Identify running vs latest installed kernel
- Schedule reboots (`shutdown`, `at`, systemd timers)
- Canonical Livepatch enrollment
- DKMS module rebuild verification

### Rollback
- Restore from snapshot
- `apt-get install pkg=VERSION` downgrade
- Reinstall previous kernel from `/boot`

---

## Safety Rules

1. **ALWAYS** snapshot the system before `dist-upgrade` or kernel changes
2. **NEVER** run `apt full-upgrade` over an unstable SSH connection — use `tmux`/`screen`
3. **ALWAYS** check `needrestart` after upgrades and restart only what is safe
4. **NEVER** auto-reboot a production host without user confirmation or maintenance window
5. **ALWAYS** preserve at least one previous kernel in `/boot`
6. **NEVER** remove `linux-image-generic` meta-package without a pinned alternative
7. **ALWAYS** read `/var/log/apt/history.log` after major updates to confirm the change set
8. **NEVER** mix backports / proposed / experimental into a stable system without pinning
9. **ALWAYS** test rollback procedure on a staging host first
10. **NEVER** force `--allow-downgrades` on critical packages without a snapshot to fall back to

---

## apt — Daily Operations

### Update / Upgrade
```bash
sudo apt update
sudo apt list --upgradable
sudo apt -s upgrade           # simulate
sudo apt upgrade -y
sudo apt full-upgrade -y      # may add/remove packages
sudo apt autoremove --purge -y
sudo apt clean
```

### Inspect
```bash
apt-cache policy nginx
apt-cache madison nginx       # available versions per repo
apt show nginx
apt-get changelog nginx
dpkg -l nginx
dpkg -L nginx                 # files installed
dpkg -S /etc/nginx/nginx.conf # owning package

# Recent apt actions
zless /var/log/apt/history.log
zless /var/log/apt/term.log
```

### Hold / Unhold (pinning a single package)
```bash
sudo apt-mark hold nginx
sudo apt-mark unhold nginx
sudo apt-mark showhold
```

### Pin to a Specific Version
```bash
# /etc/apt/preferences.d/nginx.pref
sudo tee /etc/apt/preferences.d/nginx.pref >/dev/null <<EOF
Package: nginx
Pin: version 1.24.*
Pin-Priority: 1001
EOF

apt-cache policy nginx
```

### Downgrade Manually
```bash
apt-cache madison nginx
sudo apt install nginx=1.24.0-2ubuntu7
```

---

## Repositories / PPAs
```bash
# Add a PPA
sudo add-apt-repository -y ppa:ondrej/php
sudo apt update

# Add custom repo with key
curl -fsSL https://example.com/key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/example.gpg
echo "deb [signed-by=/usr/share/keyrings/example.gpg] https://example.com/apt stable main" | \
    sudo tee /etc/apt/sources.list.d/example.list
sudo apt update

# Remove
sudo add-apt-repository --remove ppa:ondrej/php
sudo rm /etc/apt/sources.list.d/example.list /usr/share/keyrings/example.gpg
sudo apt update
```

---

## Unattended Upgrades

### Install + Configure
```bash
sudo apt install -y unattended-upgrades apt-listchanges needrestart bsd-mailx
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

### /etc/apt/apt.conf.d/50unattended-upgrades (key settings)
```conf
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
//  "${distro_id}:${distro_codename}-updates";
};

Unattended-Upgrade::Package-Blacklist {
    "linux-";
    "nginx";
    "mysql-server";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "ops@example.com";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
```

### /etc/apt/apt.conf.d/20auto-upgrades
```conf
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
```

### Test
```bash
sudo unattended-upgrades --dry-run --debug
sudo systemctl status unattended-upgrades
sudo journalctl -u unattended-upgrades -n 200 --no-pager
cat /var/log/unattended-upgrades/unattended-upgrades.log
```

---

## Snapshots Before Upgrades

### timeshift (file-based or btrfs)
```bash
sudo apt install -y timeshift
sudo timeshift --create --comments "pre-upgrade $(date -Iseconds)" --tags O
sudo timeshift --list
sudo timeshift --restore --snapshot 'YYYY-MM-DD_hh-mm-ss'
sudo timeshift --delete --snapshot 'YYYY-MM-DD_hh-mm-ss'
```

### LVM snapshot
```bash
# Assumes the root LV is /dev/vg0/root
sudo lvcreate --size 5G --snapshot --name root_snap_pre_upgrade /dev/vg0/root
sudo lvs

# Roll back (boot from rescue / single user)
sudo lvconvert --merge /dev/vg0/root_snap_pre_upgrade
# Then reboot
```

### btrfs snapshot
```bash
# Read-only snapshot of the root subvolume
sudo btrfs subvolume snapshot -r / /.snapshots/pre-upgrade-$(date +%F)
sudo btrfs subvolume list /

# Rollback (requires a separate live env or careful subvol swap)
sudo mount -o subvolid=5 /dev/sdaX /mnt
sudo mv /mnt/@ /mnt/@.broken
sudo btrfs subvolume snapshot /mnt/@.snapshots/pre-upgrade-... /mnt/@
# Reboot
```

---

## Kernel Updates

### Inspect
```bash
uname -r
dpkg --list | grep linux-image
ls -lh /boot/vmlinuz-*
sudo apt list --installed 2>/dev/null | grep linux-image

# Latest available
apt-cache search --names-only '^linux-image-[0-9]'
```

### Install / Hold
```bash
sudo apt install -y linux-generic linux-headers-generic
sudo apt-mark hold linux-image-$(uname -r)
sudo apt-mark hold linux-headers-$(uname -r)
```

### needrestart (which services need a kick)
```bash
sudo needrestart -r l         # list mode
sudo needrestart -r a         # auto restart
sudo needrestart -k           # check kernel
```

### Canonical Livepatch (Ubuntu)
```bash
sudo snap install canonical-livepatch
sudo canonical-livepatch enable <TOKEN>
sudo canonical-livepatch status --verbose
```

### Remove Old Kernels Safely
```bash
# Let Ubuntu pick:
sudo apt autoremove --purge -y

# Manual: list and keep current + N-1
KEEP="$(uname -r)"
dpkg -l 'linux-image-[0-9]*' | awk '/^ii/ {print $2}' | grep -v "$KEEP"
```

---

## Reboot Scheduling

```bash
# Check if reboot needed
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required
[ -f /var/run/reboot-required.pkgs ] && cat /var/run/reboot-required.pkgs

# Schedule reboot in 30 minutes with broadcast message
sudo shutdown -r +30 "Scheduled reboot for kernel update"

# Cancel
sudo shutdown -c

# At a specific time
sudo shutdown -r 03:00 "Maintenance reboot"

# Via systemd timer (one-shot)
sudo systemd-run --on-calendar='Sun 04:00' /sbin/reboot
```

---

## Package Pinning Scenarios

### Prefer security updates only
```conf
# /etc/apt/preferences.d/security-only
Package: *
Pin: release a=stable-security
Pin-Priority: 990

Package: *
Pin: release a=stable
Pin-Priority: 500
```

### Pin from backports cautiously
```conf
# /etc/apt/preferences.d/backports
Package: *
Pin: release a=bookworm-backports
Pin-Priority: 100

Package: nginx
Pin: release a=bookworm-backports
Pin-Priority: 990
```

---

## Rollback Recipes

### Rollback a single package
```bash
zgrep -E "(Install|Upgrade)" /var/log/apt/history.log | grep nginx
apt-cache madison nginx
sudo apt install --allow-downgrades nginx=1.24.0-2ubuntu7
sudo apt-mark hold nginx
```

### Rollback the entire upgrade transaction
```bash
# Find the latest dpkg log entries
grep "$(date +%Y-%m-%d)" /var/log/dpkg.log | grep ' upgrade '
# Manually reinstall the previous version of each touched package, OR:
sudo timeshift --restore --snapshot '...'
```

### Boot previous kernel from GRUB
1. Reboot
2. Hold Shift / press ESC at GRUB
3. Advanced options for Ubuntu → choose previous kernel
4. After boot, `apt-mark hold` the bad kernel and remove it

---

## Diagnostics
```bash
# Apt config dump
apt-config dump | less

# Validate sources.list
sudo apt-get update 2>&1 | grep -E 'W:|E:'

# Broken / half-installed packages
sudo dpkg --audit
sudo dpkg --configure -a
sudo apt --fix-broken install

# Disk usage of cached debs
du -sh /var/cache/apt/archives
sudo apt clean
```

---

## Workflows

### Standard Patch Tuesday
1. `sudo timeshift --create --comments "pre-patch $(date -Iseconds)"`
2. `sudo apt update && apt list --upgradable`
3. Inside `tmux`: `sudo apt full-upgrade -y`
4. `sudo needrestart -r l` — restart only safe services
5. Check `/var/run/reboot-required`; if present, schedule with `shutdown -r +30`
6. Confirm services healthy after reboot, then `timeshift --delete` the oldest

### Emergency Security Patch (Single CVE)
1. `sudo apt-mark unhold <pkg>` if held
2. `sudo apt install <pkg>=<fixed-version>`
3. Restart impacted service
4. `sudo apt-mark hold <pkg>` to prevent regression
5. Document the manual hold in `/etc/motd` or runbook

### Kernel Upgrade with Livepatch
1. `sudo canonical-livepatch status`
2. Apply normal apt upgrade
3. If livepatch covers it, defer reboot
4. If a real reboot is required, schedule maintenance window and reboot

### Rollback After a Bad Upgrade
1. Identify symptom and timestamp
2. `grep "$TIMESTAMP" /var/log/apt/history.log`
3. Restore latest pre-upgrade snapshot via timeshift / LVM / btrfs
4. Reboot
5. Hold the offending package until upstream issues a fix
