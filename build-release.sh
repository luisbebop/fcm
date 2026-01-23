#!/bin/bash
# Build release binaries and copy to releases directory
#
# Prerequisites:
#   - cargo install cargo-zigbuild
#   - zig (for cross-compilation)
#   - rustup target add x86_64-unknown-linux-gnu
#   - rustup target add aarch64-apple-darwin
#   - rustup target add x86_64-apple-darwin
#
# Usage: ./build-release.sh

set -e

RELEASES_DIR="/var/lib/firecracker/releases"
COMMIT=$(git rev-parse --short HEAD)

echo "Building fcm release binaries..."
echo "Commit: $COMMIT"
echo ""

# Create releases directory if it doesn't exist
sudo mkdir -p "$RELEASES_DIR"

# Write current commit
echo "$COMMIT" | sudo tee "$RELEASES_DIR/COMMIT" > /dev/null

# Build Linux x86_64 (native)
echo "Building linux-x86_64..."
cargo build --release --target x86_64-unknown-linux-gnu
LINUX_BIN="target/x86_64-unknown-linux-gnu/release/fcm"

# Package Linux binary
LINUX_PKG="fcm-${COMMIT}-linux-x86_64.tar.gz"
tar -czf "/tmp/$LINUX_PKG" -C "$(dirname $LINUX_BIN)" fcm
sudo mv "/tmp/$LINUX_PKG" "$RELEASES_DIR/"
echo "  -> $RELEASES_DIR/$LINUX_PKG"

# Build macOS ARM64 (Apple Silicon)
echo "Building darwin-arm64..."
if command -v cargo-zigbuild &> /dev/null; then
    cargo zigbuild --release --target aarch64-apple-darwin 2>/dev/null || {
        echo "  Warning: macOS ARM64 build failed (may need zig)"
    }
    if [ -f "target/aarch64-apple-darwin/release/fcm" ]; then
        DARWIN_ARM_PKG="fcm-${COMMIT}-darwin-arm64.tar.gz"
        tar -czf "/tmp/$DARWIN_ARM_PKG" -C "target/aarch64-apple-darwin/release" fcm
        sudo mv "/tmp/$DARWIN_ARM_PKG" "$RELEASES_DIR/"
        echo "  -> $RELEASES_DIR/$DARWIN_ARM_PKG"
    fi
else
    echo "  Skipping (cargo-zigbuild not installed)"
fi

# Build macOS x86_64 (Intel)
echo "Building darwin-x86_64..."
if command -v cargo-zigbuild &> /dev/null; then
    cargo zigbuild --release --target x86_64-apple-darwin 2>/dev/null || {
        echo "  Warning: macOS x86_64 build failed (may need zig)"
    }
    if [ -f "target/x86_64-apple-darwin/release/fcm" ]; then
        DARWIN_X86_PKG="fcm-${COMMIT}-darwin-x86_64.tar.gz"
        tar -czf "/tmp/$DARWIN_X86_PKG" -C "target/x86_64-apple-darwin/release" fcm
        sudo mv "/tmp/$DARWIN_X86_PKG" "$RELEASES_DIR/"
        echo "  -> $RELEASES_DIR/$DARWIN_X86_PKG"
    fi
else
    echo "  Skipping (cargo-zigbuild not installed)"
fi

echo ""
echo "Done! Releases available at: $RELEASES_DIR"
ls -la "$RELEASES_DIR"
