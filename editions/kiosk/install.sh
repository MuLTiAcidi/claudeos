#!/bin/bash
# Install ClaudeOS Kiosk Edition
# Auto-boots into fullscreen browser showing the dashboard

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash install.sh"
    exit 1
fi

CLAUDEOS_DIR="/opt/claudeos"

# Install Web Dashboard
bash "$CLAUDEOS_DIR/editions/web-dashboard/install.sh"

# Install minimal X11 and Chromium for kiosk mode
apt-get install -y --no-install-recommends \
    xorg \
    chromium-browser \
    openbox \
    lightdm \
    xdotool \
    unclutter

# Create kiosk user
useradd -m -s /bin/bash kiosk 2>/dev/null || true

# Configure auto-login
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/autologin.conf << EOF
[Seat:*]
autologin-user=kiosk
autologin-user-timeout=0
EOF

# Create kiosk startup script
cat > /home/kiosk/.xinitrc << 'EOF'
#!/bin/bash
# Disable screen blanking
xset s off
xset -dpms
xset s noblank

# Hide cursor after 5 seconds
unclutter -idle 5 &

# Wait for dashboard to be ready
sleep 5

# Launch Chromium in kiosk mode
while true; do
    chromium-browser \
        --kiosk \
        --no-first-run \
        --disable-infobars \
        --disable-session-crashed-bubble \
        --disable-component-update \
        --noerrdialogs \
        --incognito \
        http://localhost:8080
    sleep 5
done
EOF
chmod +x /home/kiosk/.xinitrc
chown kiosk:kiosk /home/kiosk/.xinitrc

# Openbox autostart
mkdir -p /home/kiosk/.config/openbox
cat > /home/kiosk/.config/openbox/autostart << 'EOF'
/home/kiosk/.xinitrc &
EOF
chown -R kiosk:kiosk /home/kiosk/.config

echo ""
echo "ClaudeOS Kiosk Edition installed!"
echo "Reboot to start kiosk mode."
echo "The dashboard will auto-open in fullscreen."
