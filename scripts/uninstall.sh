#!/usr/bin/env bash
# OneMachine Licensing POC — Linux/macOS Uninstall Script
# Clears all license state so a fresh activate can run cleanly.
# Usage: bash scripts/uninstall.sh [--dir <license-dir>] [--quiet]

set -euo pipefail

LICENSE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
QUIET=0

while [[ $# -gt 0 ]]; do
  case $1 in
    --dir)    LICENSE_DIR="$2"; shift 2 ;;
    --quiet)  QUIET=1; shift ;;
    *)        echo "Unknown argument: $1"; exit 1 ;;
  esac
done

rm_if_exists() {
  local p="$1"
  if [ -e "$p" ]; then
    rm -rf "$p"
    [ $QUIET -eq 0 ] && echo "  removed: $p"
  fi
}

echo ""
echo "OneMachine — clearing license state ($(uname -s))"
echo ""

# 1. Local working-directory files
rm_if_exists "$LICENSE_DIR/license.json"
rm_if_exists "$LICENSE_DIR/last_seen.json"
rm_if_exists "$LICENSE_DIR/public_key.pem"
rm_if_exists "$LICENSE_DIR/fingerprint.txt"

OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
  # 2. macOS — Application Support mirror
  rm_if_exists "$HOME/Library/Application Support/OneMachine"

  # 3. macOS Keychain entries (via keyring; ignore if not installed)
  python3 -c "
import sys
try:
    import keyring
    keyring.delete_password('com.onemachine.licensepoc', 'last_seen_sig')
    keyring.delete_password('com.onemachine.licensepoc', 'last_seen_anchor')
    print('  removed: Keychain entries (com.onemachine.licensepoc)')
except Exception as e:
    print(f'  keychain: {e} (skipped)')
" 2>/dev/null || true

elif [ "$OS" = "Linux" ]; then
  # 2. Linux — XDG data mirror
  XDG_DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
  rm_if_exists "$XDG_DATA/onemachine"

  # 3a. Linux dotfile anchor
  rm_if_exists "$HOME/.config/.onemachine"

  # 3b. libsecret entries (via secretstorage; ignore if not installed)
  python3 -c "
import sys
try:
    import secretstorage
    conn = secretstorage.dbus_init()
    coll = secretstorage.get_default_collection(conn)
    if coll.is_locked(): coll.unlock()
    for attr in [
        {'app': 'onemachine', 'type': 'last_seen_sig'},
        {'app': 'onemachine', 'type': 'last_seen_anchor'},
    ]:
        for item in coll.search_items(attr):
            item.delete()
    print('  removed: secretstorage entries')
except Exception as e:
    print(f'  secretstorage: {e} (skipped)')
" 2>/dev/null || true

  # 3c. xattr on last_seen.json if it still exists (belt-and-suspenders)
  if command -v attr &>/dev/null && [ -f "$LICENSE_DIR/last_seen.json" ]; then
    attr -r user.onemachine_sig    "$LICENSE_DIR/last_seen.json" 2>/dev/null || true
    attr -r user.onemachine_anchor "$LICENSE_DIR/last_seen.json" 2>/dev/null || true
  fi
fi

echo ""
echo "Done. Run 'onemachine-license activate --activation-key YOUR-KEY' to re-activate."
