#!/usr/bin/env bash
# Install this skill into an OpenCode skills directory.
# Canonical source: ./php2shell-audit
# Default target:   ./.opencode/skills/php2shell-audit
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

usage() {
  cat <<'EOF'
Usage: install.sh [TARGET]

TARGET may be:
  (omitted)                 ./.opencode/skills/php2shell-audit
  --global                  ~/.config/opencode/skills/php2shell-audit
  /path/to/skills/name      explicit destination

The destination is replaced with a fresh copy of this directory.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  --global) DEST="$HOME/.config/opencode/skills/php2shell-audit" ;;
  "") DEST="$HERE/../.opencode/skills/php2shell-audit" ;;
  *) DEST="$1" ;;
esac

mkdir -p "$(dirname "$DEST")"
rm -rf "$DEST"
cp -a "$HERE" "$DEST"
rm -rf "$DEST/scripts/__pycache__"
chmod +x "$DEST"/scripts/*.sh "$DEST"/scripts/report.py
printf 'installed %s -> %s\n' "$HERE" "$DEST"
