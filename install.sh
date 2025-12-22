#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/deauther.sh"
DEST="/usr/local/bin/deauther"

if [[ ! -f "$SRC" ]]; then
  echo "Error: ${SRC} not found." >&2
  exit 1
fi

run_root() {
  if [[ $EUID -ne 0 ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

run_root rm -f "$DEST"
run_root install -m 755 "$SRC" "$DEST"

echo "Installed to ${DEST}"
