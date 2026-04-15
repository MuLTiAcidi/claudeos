#!/bin/bash
# ============================================
# ClaudeOS — New Engagement Setup
# ============================================
# Usage: ./new-engagement.sh <target-name> [platform]
# Example: ./new-engagement.sh bumba-exchange hackerone
#          ./new-engagement.sh shopify-app bugcrowd
# ============================================

TARGET="${1:?Usage: ./new-engagement.sh <target-name> [platform]}"
PLATFORM="${2:-hackerone}"
BASE_DIR="${CLAUDEOS_ENGAGEMENTS:-/Users/herolind/Desktop/Claude/engagements}"
ENGAGEMENT_DIR="${BASE_DIR}/${TARGET}-hunt"
DATE=$(date +%Y-%m-%d)
TIME=$(date +%H:%M)

if [ -d "$ENGAGEMENT_DIR" ]; then
    echo "[!] Engagement already exists: $ENGAGEMENT_DIR"
    echo "[*] Use it or remove it first."
    exit 1
fi

# Create structure
mkdir -p "$ENGAGEMENT_DIR"/{evidence/{video,screenshots,requests},reports,scripts,recon/{subdomains,js-bundles,tech-stack},notes}

# Create STATE.md
cat > "$ENGAGEMENT_DIR/STATE.md" << EOF
# ${TARGET} — Hunt State

**Created:** ${DATE} ${TIME}
**Platform:** ${PLATFORM}
**Status:** ACTIVE
**Alpha:** ClaudeOS

---

## Target Info

- **Program:**
- **Scope:**
- **Domains:**
- **Out of scope:**

---

## Hunt Progress

### Phase 0: Bounty Intel
- [ ] Checked resolved report count
- [ ] Read disclosed reports
- [ ] Calculated duplicate risk
- [ ] Freshness score:

### Phase 1: Ghost Request
- [ ] First request sent
- [ ] WAF identified:
- [ ] Framework identified:
- [ ] Security headers noted

### Phase 2: JS Extraction
- [ ] JS bundles downloaded
- [ ] Endpoints found:
- [ ] client_id found:
- [ ] API base URLs:
- [ ] Secrets/keys:

### Phase 3: Lead Chain
- [ ] Primary chain:
- [ ] Secondary angles:

### Phase 4: Full Pack
- [ ] Scouts deployed
- [ ] Infiltrators deployed
- [ ] Analysts deployed
- [ ] Infrastructure checked
- [ ] Strikers active

### Phase 5: Record & Report
- [ ] Evidence recorded
- [ ] Report written
- [ ] Report submitted
- [ ] Report URL:

---

## Findings

| # | Finding | Severity | Status | Evidence |
|---|---------|----------|--------|----------|
| 1 |         |          |        |          |

---

## Timeline

- ${DATE} ${TIME} — Engagement created

---

## Notes

EOF

# Create evidence metadata template
cat > "$ENGAGEMENT_DIR/evidence/template-metadata.json" << 'EOF'
{
    "finding": "",
    "target": "",
    "severity": "",
    "timestamp": "",
    "recorded_from": "mac|vps",
    "video_duration_seconds": 0,
    "attack_chain": []
}
EOF

# Create scripts template
cat > "$ENGAGEMENT_DIR/scripts/recon.sh" << 'EOF'
#!/bin/bash
# Quick recon script for this target
# Run: bash scripts/recon.sh <domain>
DOMAIN="${1:?Usage: bash recon.sh <domain>}"
echo "[*] Recon: $DOMAIN"
echo "[*] Tech stack..."
curl -sI "https://$DOMAIN" | grep -iE "server|x-powered|x-frame|content-security|set-cookie"
echo "[*] Done."
EOF
chmod +x "$ENGAGEMENT_DIR/scripts/recon.sh"

echo "[+] Engagement created: $ENGAGEMENT_DIR"
echo ""
echo "    evidence/          Video, screenshots, curl logs"
echo "    reports/           H1/Bugcrowd submissions"
echo "    scripts/           Custom scripts"
echo "    recon/             Subdomains, JS, tech stack"
echo "    STATE.md           Hunt progress tracker"
echo ""
echo "[*] Next: Update STATE.md with target info, then hunt."
