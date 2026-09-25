#!/bin/bash
#
# purge-bridge-markers.sh — delete the bitchat-bridge startup-marker rows that
# a crash-looping supervisor wrote into chat_messages, keeping the real traffic.
#
#   ./purge-bridge-markers.sh              # REPORT ONLY — counts, no changes
#   ./purge-bridge-markers.sh --delete     # back up, then delete in batches
#   ./purge-bridge-markers.sh --delete --no-backup --batch 10000
#
# Run as root ON THE AFFECTED NODE (nas3). Read-only by default.
#
# ---------------------------------------------------------------------------
# Why direct SQL, when net-mgr has chat verbs for everything else:
#
#   * There is no selective delete anywhere in the protocol. No CHAT_* verb,
#     no DB.pm helper and no net-chat subcommand removes individual messages
#     or messages matching a predicate.
#   * CHAT_CLOSE looks like the tool and is a trap: it ARCHIVES every message
#     to /var/lib/net-mgr/chat/<name>/ and restores the lot the moment the
#     session is reopened with zero live messages — which the bridge does on
#     its next launch. Close-then-reopen is not cleanup.
#   * CHAT_DELETE really does destroy the rows, and takes the session, its
#     archive and the ~26k legitimate messages with them.
#
# Safe to do locally because chat_messages is NOT replicated: it is absent
# from @REPLICATED in lib/NetMgr/Relay.pm and has no _apply_/_delete_ handler,
# so these rows never entered the replication path in either direction and
# deleting them cannot desync a peer. (Contrast the known relay DELETE gap,
# which applies to tables that ARE replicated — this is not one of them.)
#
# Known, harmless side effect: live SUBSCRIBE clients get no delete events,
# so an open net-chat window keeps a stale view until it resubscribes.
# ---------------------------------------------------------------------------

set -uo pipefail

DB=${DB:-netmgr}
SESSION='bitchat-bridge'
PATTERN='[bridge] online nick=%'
BATCH=5000
DO_DELETE=0
BACKUP=1
BACKUP_DIR=/var/backups

while [ $# -gt 0 ]; do
    case "$1" in
        --delete)     DO_DELETE=1 ;;
        --no-backup)  BACKUP=0 ;;
        --batch)      shift; BATCH=${1:-5000} ;;
        --session)    shift; SESSION=${1:-bitchat-bridge} ;;
        --db)         shift; DB=${1:-netmgr} ;;
        -h|--help)    sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '   \033[33m!! %s\033[0m\n' "$*"; }
die()  { printf '   \033[31m** %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (needs the DB credentials in /root/.my.cnf or /etc/net-mgr/root.conf)"

# net-mgr keeps root DB credentials in one of two places depending on how the
# node was provisioned; prefer an explicit defaults-file so this does not
# depend on $HOME being /root.
MYSQL=(mysql)
if   [ -r /root/.my.cnf ];            then MYSQL=(mysql --defaults-file=/root/.my.cnf)
elif [ -r /etc/net-mgr/root.conf ];   then MYSQL=(mysql --defaults-file=/etc/net-mgr/root.conf)
fi
q() { "${MYSQL[@]}" -N -B -D "$DB" -e "$1" 2>/dev/null; }

q "SELECT 1" >/dev/null || die "cannot reach the '$DB' database with ${MYSQL[*]}"

# SQL-escape the single quotes we are about to interpolate. The pattern has
# none today, but a --session from the command line is user input.
esc() { printf '%s' "$1" | sed "s/'/''/g"; }
S=$(esc "$SESSION")
P=$(esc "$PATTERN")

# NOTE on LIKE: '[' and ']' are NOT metacharacters in MySQL's LIKE (only % and
# _ are), so '[bridge] online nick=%' matches literally and needs no escaping.

say "survey"
TOTAL=$(q "SELECT COUNT(*) FROM chat_messages")
MARK=$(q  "SELECT COUNT(*) FROM chat_messages WHERE session='$S' AND body LIKE '$P'")
KEEP=$((TOTAL - MARK))
info "database        : $DB"
info "rows in total   : $TOTAL"
info "marker rows     : $MARK   (session='$SESSION', body LIKE '$PATTERN')"
info "rows kept       : $KEEP"

if [ "${MARK:-0}" -eq 0 ]; then
    info "nothing to do."
    exit 0
fi

say "where they are"
q "SELECT session, COUNT(*) FROM chat_messages WHERE body LIKE '$P'
   GROUP BY session ORDER BY COUNT(*) DESC" |
  while IFS=$'\t' read -r sess cnt; do printf '   %-24s %s\n' "$sess" "$cnt"; done
info ""
info "oldest marker   : $(q "SELECT MIN(ts) FROM chat_messages WHERE session='$S' AND body LIKE '$P'")"
info "newest marker   : $(q "SELECT MAX(ts) FROM chat_messages WHERE session='$S' AND body LIKE '$P'")"

say "what survives in this session"
q "SELECT COUNT(*) FROM chat_messages WHERE session='$S' AND body NOT LIKE '$P'" |
  while read -r c; do info "non-marker rows in '$SESSION': $c"; done
info "sample of what is KEPT (newest 3):"
q "SELECT CONCAT(ts,'  ',sender,'  ',LEFT(body,70))
     FROM chat_messages WHERE session='$S' AND body NOT LIKE '$P'
    ORDER BY id DESC LIMIT 3" | sed 's/^/     /'

# A pattern that matches everything in the session would mean the predicate is
# wrong, not that every row is junk. Refuse rather than empty the session.
INSESSION=$(q "SELECT COUNT(*) FROM chat_messages WHERE session='$S'")
NONMARK=$((INSESSION - MARK))
if [ "$NONMARK" -le 0 ]; then
    warn "the pattern matches EVERY row in session '$SESSION'."
    warn "that is more likely a bad predicate than a session of pure junk."
    die "refusing to proceed"
fi

if [ "$DO_DELETE" != 1 ]; then
    say "report only — nothing changed"
    info "to delete:  $0 --delete"
    info "it will back up chat_messages to $BACKUP_DIR first, then remove"
    info "$MARK row(s) in batches of $BATCH, keeping $KEEP."
    exit 0
fi

# ---------------------------------------------------------------------------
say "backup"
if [ "$BACKUP" = 1 ]; then
    command -v mysqldump >/dev/null || die "mysqldump not found; use --no-backup only if you mean it"
    mkdir -p "$BACKUP_DIR"
    STAMP=$(date +%Y%m%d-%H%M%S)
    OUT="$BACKUP_DIR/chat_messages-$STAMP.sql.gz"
    DUMP=(mysqldump); [ "${#MYSQL[@]}" -gt 1 ] && DUMP=(mysqldump "${MYSQL[1]}")
    if "${DUMP[@]}" "$DB" chat_messages 2>/dev/null | gzip > "$OUT"; then
        info "wrote $OUT ($(du -h "$OUT" | cut -f1))"
    else
        rm -f "$OUT"
        die "mysqldump failed — not deleting anything"
    fi
else
    warn "--no-backup given; proceeding without a copy"
fi

say "deleting in batches of $BATCH"
# Batched on purpose: one DELETE over ~115k rows holds locks long enough to
# stall the daemon's own writes, and this table is on a box that is already
# mid-upgrade. Small transactions, with a breath between them.
DELETED=0
while :; do
    n=$(q "DELETE FROM chat_messages
            WHERE session='$S' AND body LIKE '$P' LIMIT $BATCH;
           SELECT ROW_COUNT();")
    n=${n:-0}
    [ "$n" -gt 0 ] || break
    DELETED=$((DELETED + n))
    printf '\r   removed %s / %s' "$DELETED" "$MARK"
    sleep 0.3
done
echo

say "result"
T2=$(q "SELECT COUNT(*) FROM chat_messages")
M2=$(q "SELECT COUNT(*) FROM chat_messages WHERE session='$S' AND body LIKE '$P'")
info "deleted         : $DELETED"
info "markers left    : $M2   (expect 0, or a few if the bridge posted meanwhile)"
info "rows in total   : $T2   (was $TOTAL, expected $KEEP)"
if [ "$T2" -ne "$KEEP" ]; then
    warn "total is not exactly the predicted $KEEP — harmless if the difference is"
    warn "small and positive: the bridge and other sessions keep writing."
fi
info ""
info "Space is not returned to the filesystem until the table is rebuilt."
info "Optional, takes a write lock for its duration:  OPTIMIZE TABLE chat_messages;"
