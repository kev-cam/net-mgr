#!/bin/bash
# Capture SoCKit serial console (ttyUSB0, 115200 8N1) during a power-cycle.
# No sudo needed (ttyUSB0 is world-rw). Logs to /tmp/sockit-serial-fork.log.
# Run this, then power-cycle the board within the 90s window.
set -u
LOG=/tmp/sockit-serial-fork.log
PORT=/dev/ttyUSB0
WINDOW=90
: > "$LOG"
if [ ! -c "$PORT" ]; then echo "FAIL: $PORT not present (board USB-UART unplugged?)"; exit 1; fi
stty -F "$PORT" 115200 raw -echo -echoe -echok -echoctl -echoke 2>/dev/null || { echo "FAIL: stty on $PORT"; exit 1; }
echo ">>> Capturing $PORT for ${WINDOW}s -> $LOG"
echo ">>> POWER-CYCLE THE SOCKIT BOARD NOW (SD inserted, BSEL=SD)."
echo ">>> Watching for:  U-Boot SPL 2021.07   (= WIN: spl_early_init passed)"
echo "------------------------------------------------------------"
timeout "$WINDOW" cat "$PORT" | tee -a "$LOG"
echo "------------------------------------------------------------"
echo ">>> Capture window ended. $(wc -c < "$LOG") bytes captured to $LOG"
