#!/bin/bash
# Daemon restart script - compiles, clears logs, restarts daemon
# Also builds macOS binaries for both Apple Silicon and Intel
set -e

cd /home/ubuntu/fcm

echo "==> Stopping daemon..."
sudo pkill -f 'fcm daemon' 2>/dev/null || true
sleep 1

echo "==> Building daemon (Linux)..."
cargo build --release 2>&1 | tail -5

echo "==> Building macOS binaries..."
cargo zigbuild --release --target aarch64-apple-darwin 2>&1 | grep -E "Compiling|Finished|error" | tail -3
cargo zigbuild --release --target x86_64-apple-darwin 2>&1 | grep -E "Compiling|Finished|error" | tail -3

echo "==> Installing binaries..."
sudo cp target/release/fcm /usr/local/bin/fcm
sudo cp target/aarch64-apple-darwin/release/fcm /var/lib/firecracker/releases/fcm-macos-arm64
sudo cp target/x86_64-apple-darwin/release/fcm /var/lib/firecracker/releases/fcm-macos-x64

# Update COMMIT file with current version
echo "$(git rev-parse --short HEAD) $(date '+%Y-%m-%d %H:%M %Z')" | sudo tee /var/lib/firecracker/releases/COMMIT > /dev/null

echo "==> Clearing logs..."
sudo rm -f /tmp/fcm-daemon.log /tmp/fcm-daemon2.log

echo "==> Starting daemon..."
sudo /usr/local/bin/fcm daemon > /tmp/fcm-daemon.log 2>&1 &

echo "==> Waiting for daemon to start..."
sleep 2

echo "==> Daemon status:"
ps aux | grep 'fcm daemon' | grep -v grep || echo "Daemon not running!"

echo ""
echo "==> Binaries:"
ls -lh /var/lib/firecracker/releases/fcm-macos-* 2>/dev/null
cat /var/lib/firecracker/releases/COMMIT

echo ""
echo "==> Recent logs:"
tail -15 /tmp/fcm-daemon.log 2>/dev/null || echo "(no logs yet)"

echo ""
echo "==> To download on Mac:"
echo "  Apple Silicon: curl -o fcm https://fcm.64-34-93-45.sslip.io/releases/fcm-macos-arm64 && chmod +x fcm"
echo "  Intel Mac:     curl -o fcm https://fcm.64-34-93-45.sslip.io/releases/fcm-macos-x64 && chmod +x fcm"
