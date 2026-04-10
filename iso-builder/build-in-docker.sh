#!/bin/bash
# Build ClaudeOS ISO using Docker
# Run from Mac: bash build-in-docker.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDEOS_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$SCRIPT_DIR/output"

mkdir -p "$OUTPUT_DIR"

echo "=================================="
echo "  ClaudeOS ISO Builder (Docker)"
echo "=================================="
echo ""
echo "This will build a bootable ClaudeOS ISO"
echo "Output: $OUTPUT_DIR/claudeos.iso"
echo ""

# Check Docker
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running"
    echo "Start Colima: colima start --cpu 4 --memory 4 --disk 30"
    exit 1
fi

echo "[1/3] Preparing build context..."

# Create temp build context
TMPDIR=$(mktemp -d)
cp "$SCRIPT_DIR/build-iso.sh" "$TMPDIR/"
cp -r "$HOME/Desktop/Claude/claudeos" "$TMPDIR/claudeos-source"

# Create Dockerfile for the builder
cp "$SCRIPT_DIR/Dockerfile" "$TMPDIR/Dockerfile"

echo "[2/3] Building Docker image..."
docker build -t claudeos-builder "$TMPDIR"

echo "[3/3] Building ISO (this takes 15-30 minutes)..."
docker run --rm --privileged \
    -v "$OUTPUT_DIR:/output" \
    claudeos-builder

# Cleanup
rm -rf "$TMPDIR"
docker rmi claudeos-builder 2>/dev/null || true

if [ -f "$OUTPUT_DIR/claudeos.iso" ]; then
    SIZE=$(du -sh "$OUTPUT_DIR/claudeos.iso" | awk '{print $1}')
    echo ""
    echo "=================================="
    echo "  ClaudeOS ISO Ready!"
    echo "  File: $OUTPUT_DIR/claudeos.iso"
    echo "  Size: $SIZE"
    echo "=================================="
    echo ""
    echo "To install:"
    echo "  1. Flash to USB: dd if=$OUTPUT_DIR/claudeos.iso of=/dev/sdX bs=4M status=progress"
    echo "  2. Or use balenaEtcher"
    echo "  3. Boot from USB on your server hardware"
    echo "  4. Follow the installer"
    echo "  5. On first boot, ClaudeOS setup wizard runs automatically"
else
    echo "ERROR: ISO build failed!"
    exit 1
fi
