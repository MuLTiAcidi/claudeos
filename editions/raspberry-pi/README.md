# ClaudeOS Raspberry Pi Edition

Ultra-lightweight build optimized for ARM hardware.

## Requirements
- Raspberry Pi 3/4/5 (or any ARM64 board)
- 256MB RAM minimum (512MB recommended)
- Raspberry Pi OS Lite (64-bit) or Ubuntu Server ARM
- MicroSD card 8GB+

## Install
```bash
curl -fsSL https://raw.githubusercontent.com/herolind/claudeos/main/install.sh | sudo bash -s -- --pi
```

## Optimizations
- Reduced monitoring intervals (every 15 min instead of 5)
- Lightweight dashboard (no WebSocket, polling instead)
- Smaller log retention (7 days)
- Disabled heavy agents (Docker orchestrator, cost optimizer)
- Swap optimization for SD card longevity

## Use Cases
- Home server management
- NAS/file server
- Network monitoring
- IoT gateway
- Pi cluster orchestrator
- Development server
- VPN server
- DNS ad-blocker (Pi-hole companion)
