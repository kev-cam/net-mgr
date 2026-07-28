#!/bin/sh
# Stage the extlinux boot config where genimage's vfat step can pick it up.
set -eu
BOARD_DIR="$(dirname "$0")"
cp -f "$BOARD_DIR/extlinux.conf" "$BINARIES_DIR/extlinux.conf"

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

# evkeys: the one C helper (evdev buttons -> text lines for netan-lcd)
"$HOST_DIR/bin/arm-buildroot-linux-gnueabihf-gcc" -Os -Wall \
    -o "$TARGET_DIR/usr/bin/evkeys" "$BOARD_DIR/evkeys.c"
