#!/bin/bash
# Build release binaries for all platforms and create download archives
set -e

cd /home/ubuntu/fcm

# Ensure cargo/rustup environment is set up
export PATH="/home/ubuntu/.cargo/bin:$PATH"
export RUSTUP_HOME="/home/ubuntu/.rustup"
export CARGO_HOME="/home/ubuntu/.cargo"

echo "==> Building Linux binary..."
cargo build --release 2>&1 | tail -5

echo "==> Building macOS binaries..."
cargo zigbuild --release --target aarch64-apple-darwin 2>&1 | grep -E "Compiling|Finished|error" | tail -3
cargo zigbuild --release --target x86_64-apple-darwin 2>&1 | grep -E "Compiling|Finished|error" | tail -3

echo "==> Cleaning old releases..."
RELEASES_DIR=/var/lib/firecracker/releases
sudo rm -f "$RELEASES_DIR"/fcm-*.tar.gz

echo "==> Creating release archives..."
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

# Update COMMIT file with current version (BRT timezone)
echo "$(git rev-parse --short HEAD) $(TZ='America/Sao_Paulo' date '+%Y-%m-%d %H:%M BRT')" | sudo tee "$RELEASES_DIR/COMMIT" > /dev/null

echo ""
echo "==> Releases created:"
ls -lh "$RELEASES_DIR"/fcm-*.tar.gz
cat "$RELEASES_DIR/COMMIT"

echo ""
echo "==> Download commands:"
echo "  Linux:         curl -sL https://fcm.64-34-93-45.sslip.io/releases/fcm-linux-x64.tar.gz | tar xz && sudo mv fcm /usr/local/bin/"
echo "  Apple Silicon: curl -sL https://fcm.64-34-93-45.sslip.io/releases/fcm-macos-arm64.tar.gz | tar xz && sudo mv fcm /usr/local/bin/"
echo "  Intel Mac:     curl -sL https://fcm.64-34-93-45.sslip.io/releases/fcm-macos-x64.tar.gz | tar xz && sudo mv fcm /usr/local/bin/"
