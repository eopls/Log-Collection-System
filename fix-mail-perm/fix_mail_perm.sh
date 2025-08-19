#!/bin/bash
set -euo pipefail
BASE="/opt/mail/Maildir"

/usr/bin/inotifywait -m -r -e create -e moved_to -e close_write \
  --format '%w%f' "$BASE" \
| while IFS= read -r f; do
  case "$f" in
    */new/*)
      [ -f "$f" ] && chmod 0644 "$f" || true
      ;;
  esac
done

