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

# evkeys: the one C helper (evdev buttons -> text lines for netan-lcd)
"$HOST_DIR/bin/arm-buildroot-linux-gnueabihf-gcc" -Os -Wall \
    -o "$TARGET_DIR/usr/bin/evkeys" "$BOARD_DIR/evkeys.c"
