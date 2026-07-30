#!/bin/sh
# Stage the extlinux boot config where genimage's vfat step can pick it up.
set -eu
# Resolve the PHYSICAL board dir: BR2_EXTERNAL is normally a symlink
# (/home/dkc/sockit-netan/external -> .../net-mgr/utilities/sockit-netan/external),
# and the shared netan payload is found by walking up from the real location, so
# a naive $(dirname $0) with the symlink in it would traverse the wrong parent.
BOARD_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
cp -f "$BOARD_DIR/extlinux.conf" "$BINARIES_DIR/extlinux.conf"

# Assemble the board-agnostic netan core from the shared payload (single source
# of truth for net-analyzer / netan-iperf / netan-mode; netan-lcd is board-
# specific and ships in the overlay). Layout: BOARD_DIR is
# .../utilities/sockit-netan/external/board/sockit_netan, so the shared dir is
# four levels up. Fail loudly rather than let the chmod below emit a cryptic
# "No such file" under set -eu.
NETAN_SHARED="$BOARD_DIR/../../../../netan"
if [ ! -d "$NETAN_SHARED/bin" ]; then
    echo "post-build.sh: FATAL: shared netan payload not found at $NETAN_SHARED/bin" >&2
    echo "post-build.sh:        expected net-mgr/utilities/netan/ beside sockit-netan/" >&2
    exit 1
fi
mkdir -p "$TARGET_DIR/usr/bin"
cp -f "$NETAN_SHARED/bin/net-analyzer" "$NETAN_SHARED/bin/netan-iperf" \
      "$NETAN_SHARED/bin/netan-mode"   "$TARGET_DIR/usr/bin/"

# buildroot's overlay copy normalizes modes — re-tighten ssh material.
# overlay/root/.ssh/authorized_keys is deliberately NOT tracked in git (this
# repo is public); supply your own before building — see ../../README.md.
# Without it the image still boots, but root ssh to the appliance won't work.
if [ -f "$TARGET_DIR/root/.ssh/authorized_keys" ]; then
    chmod 700 "$TARGET_DIR/root/.ssh"
    chmod 600 "$TARGET_DIR/root/.ssh/authorized_keys"
else
    echo "post-build.sh: WARNING: no root authorized_keys in the overlay -" >&2
    echo "post-build.sh:          root ssh to the appliance will NOT work." >&2
    echo "post-build.sh:          see utilities/sockit-netan/README.md" >&2
fi

# ...and re-assert +x on the appliance scripts (overlay copy can drop it)
chmod 0755 "$TARGET_DIR"/usr/bin/net-analyzer "$TARGET_DIR"/usr/bin/netan-lcd \
           "$TARGET_DIR"/usr/bin/netan-iperf  "$TARGET_DIR"/usr/bin/netan-mode
chmod 0755 "$TARGET_DIR/etc/init.d/S45wlan"

# WiFi supplicant conf carries the PSK; the real file is NOT tracked (public repo).
if [ -f "$TARGET_DIR/etc/wpa_supplicant/wpa_supplicant-wlan0.conf" ]; then
    chmod 600 "$TARGET_DIR/etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
else
    echo "post-build.sh: WARNING: no wpa_supplicant-wlan0.conf in the overlay -" >&2
    echo "post-build.sh:          WiFi uplink will NOT come up (cp the .sample, set PSK)." >&2
fi

# Phase-2 VGA: stage the FPGA bitstream into $BINARIES_DIR for genimage's vfat step.
if [ -f "$BOARD_DIR/vga_hps.rbf" ]; then
    cp -f "$BOARD_DIR/vga_hps.rbf" "$BINARIES_DIR/vga_hps.rbf"
else
    echo "post-build.sh: note: no vga_hps.rbf (VGA gateware) in board dir - VGA off." >&2
fi

# evkeys: the one C helper (evdev buttons -> text lines for netan-lcd)
"$HOST_DIR/bin/arm-buildroot-linux-gnueabihf-gcc" -Os -Wall \
    -o "$TARGET_DIR/usr/bin/evkeys" "$BOARD_DIR/evkeys.c"

# netan-vga: mmap-writes the 80x30 FPGA VGA char buffer (the readable dashboard).
"$HOST_DIR/bin/arm-buildroot-linux-gnueabihf-gcc" -Os -Wall \
    -o "$TARGET_DIR/usr/bin/netan-vga" "$BOARD_DIR/netan-vga.c"
chmod 0755 "$TARGET_DIR/usr/bin/netan-vga-render" "$TARGET_DIR/etc/init.d/S97netanvga"
