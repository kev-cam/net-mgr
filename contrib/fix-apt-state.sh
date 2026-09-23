#!/bin/bash
#
# fix-apt-state.sh — diagnose, and optionally repair, a dpkg/apt database
# that is stuck part-way through a transaction.
#
#     ./fix-apt-state.sh                  # read-only: say what is wrong
#     ./fix-apt-state.sh --repair         # act, prompting before each stage
#     ./fix-apt-state.sh --repair --yes   # act without prompting
#
# Written for nas3, which stalled mid-way through an nvidia 535 -> 580
# migration: 117 packages unconfigured, 331 held back, and dpkg refusing to
# unpack nvidia-kernel-common-580 because nvidia-utils-535 already owns
# /usr/bin/nvidia-bug-report.sh. Nothing here is nvidia-specific though —
# the "trying to overwrite X, which is also in package Y" failure is a
# generic dpkg condition and is handled generically.
#
# ---------------------------------------------------------------------------
# What it will and will not do
#
#   WILL:  dpkg --configure -a, apt-get -f install, and — only when dpkg
#          reports a file-ownership clash — dpkg -i --force-overwrite on the
#          exact archive dpkg named, then carry on. That is the documented
#          resolution for two packages shipping one path, and it is applied
#          to one named .deb at a time, never as a blanket dpkg option.
#
#   WILL NOT: pick a driver branch, purge old series, run autoremove, or
#          pull the 331 pending upgrades. Those are judgement calls with a
#          reboot attached, and this script deliberately leaves them to you.
#          It prints what it would have suggested instead.
#
# Everything is logged to /var/log/fix-apt-state.<stamp>.log, and the package
# list is snapshotted before any change, so the diff is recoverable.
# ---------------------------------------------------------------------------

set -uo pipefail          # NOT -e: this script runs commands that are
                          # expected to fail and reads their output.

REPAIR=0; ASSUME_YES=0
for a in "$@"; do
    case "$a" in
        --repair) REPAIR=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --help|-h) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

STAMP=$(date +%Y%m%d-%H%M%S)
LOG=/var/log/fix-apt-state.$STAMP.log
SNAP=/var/backups/dpkg-list.$STAMP.txt
MAXPASS=25

say()  { printf '\n\033[1m== %s\033[0m\n' "$*" | tee -a "$LOG"; }
info() { printf '   %s\n' "$*" | tee -a "$LOG"; }
warn() { printf '   \033[33m!! %s\033[0m\n' "$*" | tee -a "$LOG"; }
die()  { printf '   \033[31m** %s\033[0m\n' "$*" | tee -a "$LOG" >&2; exit 1; }

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
touch "$LOG" 2>/dev/null || { echo "cannot write $LOG" >&2; exit 1; }

ask() {
    [ "$ASSUME_YES" = 1 ] && return 0
    printf '   \033[36m?? %s [y/N] \033[0m' "$1"
    read -r r </dev/tty || return 1
    case "$r" in y|Y|yes) return 0 ;; *) return 1 ;; esac
}

# dpkg's status field is desired-action + current-state. Only these current
# states mean "not fully installed or removed": U unpacked, F half-configured,
# H half-installed, W trigger-await, t trigger-pending. Note 'rc' (removed,
# config files kept) is ORDINARY — counting "second char != i" reports every
# healthy machine as broken, typically 150+ packages.
broken_list() { dpkg -l 2>/dev/null | awk 'substr($1,2,1) ~ /[UFHWt]/ {print $1, $2, $3}'; }
broken_count() { broken_list | wc -l; }

# ===========================================================================
say "diagnosis  ($(hostname -s), $STAMP)"
. /etc/os-release 2>/dev/null
info "$PRETTY_NAME"
info "running kernel: $(uname -r)"
info "log: $LOG"

n=$(broken_count)
say "packages not fully installed or removed: $n"
if [ "$n" -gt 0 ]; then
    broken_list | head -40 | sed 's/^/     /' | tee -a "$LOG"
    [ "$n" -gt 40 ] && info "... and $((n - 40)) more"
fi

say "apt-get check"
apt-get check 2>&1 | sed 's/^/     /' | tee -a "$LOG"

say "what apt wants to do to fix itself (simulated, no changes)"
apt-get -s -f install 2>&1 | grep -vE '^(Reading|Building|Correcting)' \
    | head -30 | sed 's/^/     /' | tee -a "$LOG"

say "nvidia packages by series (the usual cause of this shape of breakage)"
for s in 470 535 580; do
    c=$(dpkg -l 2>/dev/null | awk -v s="$s" '$2 ~ ("-" s "$") || $2 ~ ("-" s "-") {n++} END {print n+0}')
    [ "$c" -gt 0 ] && info "series $s: $c package(s) installed"
done
info "kernels installed: $(dpkg -l 'linux-image-*' 2>/dev/null | awk '$1=="ii"{print $2}' | tr '\n' ' ')"
if command -v nvidia-smi >/dev/null; then
    info "nvidia-smi: $(nvidia-smi --query-gpu=driver_version,name --format=csv,noheader 2>&1 | head -1)"
else
    info "nvidia-smi: not present"
fi

say "disk space (dpkg needs room in /var)"
df -h / /var 2>/dev/null | sed 's/^/     /' | tee -a "$LOG"

say "packages on hold"
h=$(apt-mark showhold 2>/dev/null); info "${h:-none}"

if [ "$REPAIR" != 1 ]; then
    say "read-only run — nothing changed"
    cat <<'NEXT' | tee -a "$LOG"
   To attempt the repair:   sudo ./fix-apt-state.sh --repair

   It will: snapshot the package list, then loop over
       dpkg --configure -a   /   apt-get -f install
   resolving any "trying to overwrite ... also in package ..." clash by
   force-overwriting the single archive dpkg names, until apt is consistent.

   It will NOT purge old driver series, autoremove, or apply the pending
   upgrades — do those deliberately afterwards, with a reboot available.
NEXT
    exit 0
fi

# ===========================================================================
say "repair"
[ "$n" -gt 0 ] || { info "nothing to repair"; exit 0; }

dpkg -l > "$SNAP" 2>/dev/null
info "package list snapshotted to $SNAP"
ask "proceed with repair on $(hostname -s)?" || die "aborted at your request"

pass=0
forced=()
while [ $pass -lt $MAXPASS ]; do
    pass=$((pass + 1))
    info "--- pass $pass ---"

    out=$(dpkg --configure -a 2>&1); rc=$?
    echo "$out" >> "$LOG"
    if [ $rc -eq 0 ]; then
        out=$(apt-get -f install -y 2>&1); rc=$?
        echo "$out" >> "$LOG"
    fi

    if [ $rc -eq 0 ] && [ "$(broken_count)" -eq 0 ]; then
        info "dpkg and apt both clean"
        break
    fi

    # The generic file-ownership clash. dpkg names the exact archive it
    # could not unpack; force-overwrite only that one, then go round again.
    deb=$(echo "$out" | grep -oE 'error processing archive [^ ]+\.deb' \
          | awk '{print $4}' | head -1)
    clash=$(echo "$out" | grep -oE "trying to overwrite '[^']+'" | head -1)

    if [ -n "$deb" ] && [ -n "$clash" ] && [ -f "$deb" ]; then
        warn "file clash: $clash"
        warn "in archive:  $(basename "$deb")"
        if ask "force-overwrite that one archive and continue?"; then
            dpkg -i --force-overwrite "$deb" >>"$LOG" 2>&1
            forced+=("$(basename "$deb")")
            continue
        fi
        die "stopped at your request — nothing further changed"
    fi

    warn "apt/dpkg failed with something this script will not guess at:"
    echo "$out" | tail -20 | sed 's/^/     /' | tee -a "$LOG"
    die "see $LOG — the snapshot of what was installed before is $SNAP"
done

[ $pass -lt $MAXPASS ] || die "gave up after $MAXPASS passes — see $LOG"

# ===========================================================================
say "result"
info "packages still not fully installed: $(broken_count)"
apt-get check 2>&1 | sed 's/^/     /' | tee -a "$LOG"
if [ ${#forced[@]} -gt 0 ]; then
    warn "force-overwrote ${#forced[@]} archive(s):"
    printf '     %s\n' "${forced[@]}" | tee -a "$LOG"
    warn "those paths are now owned by two packages; removing either one"
    warn "later will delete the file. Harmless here, worth remembering."
fi

say "deliberately NOT done"
cat <<'LEFT' | tee -a "$LOG"
   apt autoremove            — would drop the superseded driver series and
                               the cuda-*-13-2 set. Check that list by hand
                               first; autoremove has opinions about CUDA.
   apt upgrade               — 331 packages are pending. Separate job.
   reboot                    — if a driver or kernel module was rebuilt, the
                               running kernel is still using the old one.
                               Verify nvidia-smi AFTER the next boot, not now.
LEFT
info "full log: $LOG"
info "before-state: $SNAP"
