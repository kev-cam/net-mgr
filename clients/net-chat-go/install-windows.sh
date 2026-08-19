#!/bin/bash
# Install net-chat.exe on Windows WITHOUT privilege, from GitHub.
#
# Written for Cygwin because that is what the mobile laptop has (no WSL there -
# WSL2's Hyper-V clashes with VirtualBox). Nothing here needs admin: the client
# is a single self-contained .exe importing only Windows system DLLs
# (KERNEL32/USER32/GDI32/SHELL32/OPENGL32/msvcrt), so "installing" it means
# putting one file somewhere on PATH.
#
#   ./install-windows.sh              # latest release
#   ./install-windows.sh net-chat-v3  # a specific tag
#
# Deliberately NOT writing to Program Files, the registry, or a service: all of
# those need elevation, and a laptop that travels should not need an admin
# prompt to update a chat client.
set -euo pipefail

REPO="${NETCHAT_REPO:-kev-cam/net-mgr}"
TAG="${1:-latest}"
DEST="${NETCHAT_DEST:-$HOME/bin}"
EXE="$DEST/net-chat.exe"

mkdir -p "$DEST"

if [ "$TAG" = latest ]; then
  API="https://api.github.com/repos/$REPO/releases/latest"
else
  API="https://api.github.com/repos/$REPO/releases/tags/$TAG"
fi

echo "==> looking up $TAG in $REPO"

# `|| true` matters: under `set -e` a 404 would abort right here and the
# operator would see a bare "curl: (22) error 404" instead of the explanation
# below - which is the message that actually resolves it, because a PRIVATE
# repo returns 404 (not 401) when you are unauthenticated.
JSON=$(curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} "$API" 2>/dev/null || true)
URL=$(printf '%s' "$JSON" \
      | grep -oE '"browser_download_url": *"[^"]*net-chat\.exe"' \
      | head -1 | cut -d'"' -f4 || true)

if [ -z "${URL:-}" ]; then
  if [ -z "$JSON" ]; then
    echo "could not read $API" >&2
    echo "  A 404 here is what a PRIVATE repo returns when unauthenticated -" >&2
    echo "  it does not necessarily mean the release is missing." >&2
    echo "  Set a token with 'repo' scope:  export GITHUB_TOKEN=ghp_..." >&2
  else
    echo "release '$TAG' exists but carries no net-chat.exe asset." >&2
    echo "  Build one by pushing a tag matching net-chat-v* (see" >&2
    echo "  .github/workflows/net-chat-windows.yml), or run it by hand from" >&2
    echo "  the Actions tab (workflow_dispatch)." >&2
  fi
  exit 1
fi

echo "==> downloading $URL"
# Download to a temp file first: a half-written binary left at the destination
# is worse than none, because it still runs and fails confusingly.
TMP=$(mktemp "$DEST/.net-chat.XXXXXX") || exit 1
trap 'rm -f "$TMP"' EXIT
curl -fL --progress-bar ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} -o "$TMP" "$URL"
chmod +x "$TMP"
mv -f "$TMP" "$EXE"
trap - EXIT

echo "==> installed: $EXE ($(stat -c%s "$EXE" 2>/dev/null || echo '?') bytes)"

case ":$PATH:" in
  *":$DEST:"*) ;;
  *) echo
     echo "    $DEST is not on your PATH. Either add it:"
     echo "      echo 'export PATH=\"\$HOME/bin:\$PATH\"' >> ~/.bash_profile"
     echo "    or run it by full path: $EXE" ;;
esac

echo
echo "    check:    $EXE --help | head -3"
echo "    gui:      $EXE -as \$USER-win -gui"
echo "    headless: $EXE -as \$USER-win        # protocol only, no window"
