#!/bin/bash
# Flash the socfpga_v2021.07 FORK native-boot test image to the SD card.
# Run with sudo (writes raw /dev/mmcblk0). Logs to /tmp/sockit-flash-fork.log.
set -u
LOG=/tmp/sockit-flash-fork.log
IMG=/home/dkc/sockit-netan/build/images/sdcard-fork.img
DEV=/dev/mmcblk0
exec > >(tee "$LOG") 2>&1
echo "=== sockit fork flash $(date) ==="

if [ ! -f "$IMG" ]; then echo "FAIL: image missing: $IMG"; exit 1; fi
echo "image: $IMG ($(stat -c%s "$IMG") bytes)"
if [ ! -b "$DEV" ]; then echo "FAIL: $DEV is not a block device (SD card in reader?)"; exit 1; fi
echo "target: $DEV ($(lsblk -ndo SIZE "$DEV"))"

echo "--- unmounting any $DEV partitions ---"
for p in ${DEV}p1 ${DEV}p2 ${DEV}p3; do
  if mount | grep -q "^$p "; then umount "$p" && echo "unmounted $p" || { echo "FAIL: could not unmount $p"; exit 1; }; fi
done

echo "--- writing image ---"
dd if="$IMG" of="$DEV" bs=4M conv=fsync status=progress || { echo "FAIL: dd error"; exit 1; }
sync
blockdev --flushbufs "$DEV" 2>/dev/null

echo "--- verifying fork SPL landed on the physical card ---"
HITS=$(dd if="$DEV" bs=512 skip=2 count=2046 2>/dev/null | strings | grep -c 'U-Boot SPL 2021.07')
echo "fork SPL banner copies found in card p1: $HITS"
dd if="$DEV" bs=512 skip=2 count=2046 2>/dev/null | strings | grep 'U-Boot SPL 2021.07' | head -1
if [ "$HITS" -ge 1 ]; then
  echo "=== FLASH OK — fork 2021.07 SPL is on the card ==="
else
  echo "=== FAIL — fork banner NOT found on card, do not proceed ==="
  exit 1
fi
