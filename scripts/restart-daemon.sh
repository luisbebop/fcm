#!/bin/bash
# Production: restart daemon without rebuilding or clearing logs
# Use build-releases.sh first if you need to update binaries
set -e

echo "==> Stopping daemon..."
sudo pkill -f 'fcm daemon' 2>/dev/null || true
sleep 1

echo "==> Starting daemon..."
sudo /usr/local/bin/fcm daemon >> /tmp/fcm-daemon.log 2>&1 &

echo "==> Waiting for daemon to start..."
sleep 2

echo "==> Daemon status:"
ps aux | grep 'fcm daemon' | grep -v grep || echo "Daemon not running!"

echo ""
echo "==> Recent logs:"
tail -15 /tmp/fcm-daemon.log 2>/dev/null || echo "(no logs yet)"
