#!/bin/sh
# mac-audit installer — DRY-RUN BY DEFAULT.
#
# Transparency rules:
# - With no arguments (or --dry-run) this script writes NOTHING.
#   It builds the binary if needed and prints exactly what an
#   install would do, including every permission requested.
# - It never grants a permission for any user. Full Disk Access is
#   granted by each user themselves, in their own session, in
#   System Settings. There is no flag that changes that.
# - --apply is intentionally NOT implemented in v0: review the
#   dry-run output, then place the plists manually if you agree.
set -eu

cd "$(dirname "$0")"

case "${1:-}" in
  --apply)
    echo "install.sh: --apply is not implemented in v0 (fail closed)." >&2
    echo "Run ./install.sh --dry-run, review it, and install manually." >&2
    exit 1
    ;;
  ""|--dry-run)
    echo "mac-audit install — DRY RUN, nothing will be written."
    echo
    if command -v cargo >/dev/null 2>&1; then
      cargo run --quiet -- install --dry-run
    else
      echo "(cargo not found — showing the permission summary only)"
      echo "Labels: dev.ademr.macaudit.daemon / dev.ademr.macaudit.agent"
      echo "Full Disk Access: requested per user, status-only in v0;"
      echo "the logic using it is deferred to the next update."
      echo "Camera/Mic/Screen/Input Monitoring/Accessibility: NOT requested."
    fi
    ;;
  *)
    echo "usage: ./install.sh [--dry-run]" >&2
    exit 2
    ;;
esac
