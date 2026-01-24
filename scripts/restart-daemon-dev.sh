#!/bin/bash
# Development: rebuild daemon, clear logs, restart
# Use this for debugging and testing changes
set -e

cd /home/ubuntu/fcm

# Ensure cargo/rustup environment is set up
export PATH="/home/ubuntu/.cargo/bin:$PATH"
export RUSTUP_HOME="/home/ubuntu/.rustup"
export CARGO_HOME="/home/ubuntu/.cargo"

echo "==> Stopping daemon..."
sudo pkill -f 'fcm daemon' 2>/dev/null || true
sleep 1

echo "==> Building daemon (debug)..."
cargo build --release 2>&1 | tail -5

echo "==> Installing daemon binary..."
sudo cp target/release/fcm /usr/local/bin/fcm

echo "==> Clearing logs..."
sudo rm -f /tmp/fcm-daemon.log /tmp/fcm-daemon2.log

echo "==> Starting daemon..."
sudo /usr/local/bin/fcm daemon > /tmp/fcm-daemon.log 2>&1 &

echo "==> Waiting for daemon to start..."
sleep 2

echo "==> Daemon status:"
ps aux | grep 'fcm daemon' | grep -v grep || echo "Daemon not running!"

echo ""
echo "==> Recent logs:"
tail -20 /tmp/fcm-daemon.log 2>/dev/null || echo "(no logs yet)"

echo ""
echo "==> Follow logs with: tail -f /tmp/fcm-daemon.log"
