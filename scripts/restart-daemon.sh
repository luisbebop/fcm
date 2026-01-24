#!/bin/bash
# Daemon restart script - compiles, clears logs, restarts daemon
# Also builds macOS binaries for both Apple Silicon and Intel
set -e

cd /home/ubuntu/fcm

# Ensure cargo/rustup environment is set up
export PATH="/home/ubuntu/.cargo/bin:$PATH"
export RUSTUP_HOME="/home/ubuntu/.rustup"
export CARGO_HOME="/home/ubuntu/.cargo"

echo "==> Stopping daemon..."
sudo pkill -f 'fcm daemon' 2>/dev/null || true
sleep 1

echo "==> Building daemon (Linux)..."
cargo build --release 2>&1 | tail -5

echo "==> Building macOS binaries..."
cargo zigbuild --release --target aarch64-apple-darwin 2>&1 | grep -E "Compiling|Finished|error" | tail -3
cargo zigbuild --release --target x86_64-apple-darwin 2>&1 | grep -E "Compiling|Finished|error" | tail -3

echo "==> Cleaning old releases..."
sudo rm -f /var/lib/firecracker/releases/fcm-*.tar.gz
sudo rm -f /var/lib/firecracker/releases/fcm-macos*

echo "==> Creating release archives..."
RELEASES_DIR=/var/lib/firecracker/releases
TEMP_DIR=$(mktemp -d)

# macOS ARM64 (Apple Silicon)
cp target/aarch64-apple-darwin/release/fcm "$TEMP_DIR/fcm"
chmod +x "$TEMP_DIR/fcm"
tar -czf "$TEMP_DIR/fcm-macos-arm64.tar.gz" -C "$TEMP_DIR" fcm
sudo mv "$TEMP_DIR/fcm-macos-arm64.tar.gz" "$RELEASES_DIR/"
rm "$TEMP_DIR/fcm"

# macOS x64 (Intel)
cp target/x86_64-apple-darwin/release/fcm "$TEMP_DIR/fcm"
chmod +x "$TEMP_DIR/fcm"
tar -czf "$TEMP_DIR/fcm-macos-x64.tar.gz" -C "$TEMP_DIR" fcm
sudo mv "$TEMP_DIR/fcm-macos-x64.tar.gz" "$RELEASES_DIR/"
rm "$TEMP_DIR/fcm"

# Linux x64
cp target/release/fcm "$TEMP_DIR/fcm"
chmod +x "$TEMP_DIR/fcm"
tar -czf "$TEMP_DIR/fcm-linux-x64.tar.gz" -C "$TEMP_DIR" fcm
sudo mv "$TEMP_DIR/fcm-linux-x64.tar.gz" "$RELEASES_DIR/"
rm "$TEMP_DIR/fcm"

rmdir "$TEMP_DIR"

echo "==> Installing daemon binary..."
sudo cp target/release/fcm /usr/local/bin/fcm

# Update COMMIT file with current version (BRT timezone)
echo "$(git rev-parse --short HEAD) $(TZ='America/Sao_Paulo' date '+%Y-%m-%d %H:%M BRT')" | sudo tee "$RELEASES_DIR/COMMIT" > /dev/null

echo "==> Clearing logs..."
sudo rm -f /tmp/fcm-daemon.log /tmp/fcm-daemon2.log

echo "==> Starting daemon..."
sudo /usr/local/bin/fcm daemon > /tmp/fcm-daemon.log 2>&1 &

echo "==> Waiting for daemon to start..."
sleep 2

echo "==> Daemon status:"
ps aux | grep 'fcm daemon' | grep -v grep || echo "Daemon not running!"

echo ""
echo "==> Releases:"
ls -lh "$RELEASES_DIR"/fcm-*.tar.gz 2>/dev/null
cat "$RELEASES_DIR/COMMIT"

echo ""
echo "==> Recent logs:"
tail -15 /tmp/fcm-daemon.log 2>/dev/null || echo "(no logs yet)"

echo ""
echo "==> To download on Mac:"
echo "  Apple Silicon: curl -sL https://fcm.64-34-93-45.sslip.io/releases/fcm-macos-arm64.tar.gz | tar xz && sudo mv fcm /usr/local/bin/"
echo "  Intel Mac:     curl -sL https://fcm.64-34-93-45.sslip.io/releases/fcm-macos-x64.tar.gz | tar xz && sudo mv fcm /usr/local/bin/"
