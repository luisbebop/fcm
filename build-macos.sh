#!/bin/bash
# Cross-compile fcm CLI to macOS using cargo-zigbuild
# Requires: cargo install cargo-zigbuild, zig installed
set -e

cd "$(dirname "$0")"

# Build for Apple Silicon (M1/M2/M3)
echo "Building for aarch64-apple-darwin (Apple Silicon)..."
cargo zigbuild --release --target aarch64-apple-darwin

# Build for Intel Macs
echo "Building for x86_64-apple-darwin (Intel)..."
cargo zigbuild --release --target x86_64-apple-darwin

echo ""
echo "Build complete!"
echo "  Apple Silicon: target/aarch64-apple-darwin/release/fcm ($(du -h target/aarch64-apple-darwin/release/fcm | cut -f1))"
echo "  Intel Mac:     target/x86_64-apple-darwin/release/fcm ($(du -h target/x86_64-apple-darwin/release/fcm | cut -f1))"
echo ""
echo "Copy to your Mac:"
echo "  scp $(hostname):$PWD/target/aarch64-apple-darwin/release/fcm ~/bin/fcm"
