#!/bin/bash
#
# Build script for fcm base rootfs image
# Creates an ext4 filesystem image from a Docker container
#
# Usage: ./build.sh [output_path]
#
# Output: base-rootfs.img (~400MB sparse ext4 image)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="${1:-/var/lib/firecracker/base-rootfs.img}"
IMAGE_NAME="fcm-rootfs"
CONTAINER_NAME="fcm-rootfs-builder"
IMAGE_SIZE_MB=1024  # 1GB filesystem, will be sparse

echo "==> Building fcm base rootfs image"
echo "    Output: $OUTPUT_PATH"

# Cleanup function
cleanup() {
    echo "==> Cleaning up..."
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    rm -f /tmp/rootfs.tar
}
trap cleanup EXIT

# Build Docker image
echo "==> Building Docker image..."
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

# Create and export container filesystem
echo "==> Exporting container filesystem..."
docker create --name "$CONTAINER_NAME" "$IMAGE_NAME"
docker export "$CONTAINER_NAME" > /tmp/rootfs.tar

# Create sparse ext4 image
echo "==> Creating ext4 filesystem image (${IMAGE_SIZE_MB}MB)..."
rm -f "$OUTPUT_PATH"
dd if=/dev/zero of="$OUTPUT_PATH" bs=1M count=0 seek=$IMAGE_SIZE_MB 2>/dev/null
mkfs.ext4 -F -q "$OUTPUT_PATH"

# Mount and extract
echo "==> Extracting rootfs to image..."
MOUNT_DIR=$(mktemp -d)
mount -o loop "$OUTPUT_PATH" "$MOUNT_DIR"
tar -xf /tmp/rootfs.tar -C "$MOUNT_DIR"
umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"

# Final size info
ACTUAL_SIZE=$(du -h "$OUTPUT_PATH" | cut -f1)
APPARENT_SIZE=$(du -h --apparent-size "$OUTPUT_PATH" | cut -f1)
echo "==> Build complete!"
echo "    Actual size: $ACTUAL_SIZE (sparse)"
echo "    Apparent size: $APPARENT_SIZE"
echo "    Output: $OUTPUT_PATH"
