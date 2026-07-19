#!/usr/bin/env bash
# wp2shell-watch.sh — watches a directory for new .txt files,
# runs wp2shell-check.sh on each domain, saves results.

set -euo pipefail

WATCH_DIR="${1:-/home/ahmex/test/us_senior_web_research/output}"
RESULTS_DIR="/home/ahmex/WP2Shell/results"
SCRIPT="/home/ahmex/WP2Shell/wp2shell-check.sh"
PROCESSED_LOG="$RESULTS_DIR/.processed"
SCANNED_DOMAINS="$RESULTS_DIR/.scanned_domains"
POLL_INTERVAL=10  # seconds

# Telegram (set these or export as env vars)
# TG_CHAT_ID can be multiple IDs separated by spaces
TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"

tg_send() {
  [[ -z "$TG_TOKEN" || -z "$TG_CHAT_ID" ]] && return
  for chat_id in $TG_CHAT_ID; do
    curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
      -d chat_id="$chat_id" \
      -d text="$1" \
      -d parse_mode="HTML" > /dev/null 2>&1
  done
}

mkdir -p "$RESULTS_DIR"
touch "$PROCESSED_LOG"
touch "$SCANNED_DOMAINS"

echo "[*] Watching $WATCH_DIR for new .txt files (poll every ${POLL_INTERVAL}s)"

while true; do
  for txt in "$WATCH_DIR"/*.txt; do
    [ -f "$txt" ] || continue

    # skip already processed
    if grep -qFx "$txt" "$PROCESSED_LOG" 2>/dev/null; then
      continue
    fi

    basename="${txt##*/}"
    timestamp=$(date +%Y%m%d_%H%M%S)
    result_file="$RESULTS_DIR/${basename%.txt}_${timestamp}.json"
    text_file="$RESULTS_DIR/${basename%.txt}_${timestamp}.txt"

    echo "[+] New file detected: $basename"
    echo "[+] Scanning domains..."
    tg_send "🔍 <b>New scan started:</b> <code>$basename</code>"

    # filter out already-scanned domains
    new_domains=$(mktemp)
    while IFS= read -r domain; do
      domain="${domain%%#*}"
      domain="${domain#"${domain%%[![:space:]]*}"}"
      domain="${domain%"${domain##*[![:space:]]}"}"
      [[ -z "$domain" ]] && continue
      if ! grep -qFx "$domain" "$SCANNED_DOMAINS" 2>/dev/null; then
        echo "$domain" >> "$new_domains"
      fi
    done < "$txt"

    new_count=$(wc -l < "$new_domains" | tr -d ' ')
    if [[ "$new_count" -eq 0 ]]; then
      echo "[+] All domains already scanned, skipping"
      echo "$txt" >> "$PROCESSED_LOG"
      rm -f "$new_domains"
      continue
    fi

    echo "[+] $new_count new domains to scan (skipping already-scanned)"

    # mark domains as scanned BEFORE scanning (so killed runs don't lose progress)
    cat "$new_domains" >> "$SCANNED_DOMAINS"

    # scan only new domains, print line by line AND save to file
    "$SCRIPT" -f "$new_domains" --simple --no-color 2>/dev/null | while IFS= read -r line; do
      echo "$line"
      echo "$line" >> "$result_file"

      # send only vulnerable/likely to telegram, skip clean/inconclusive
      if echo "$line" | grep -qE '\| (VULNERABLE|LIKELY_VULNERABLE)$'; then
        tg_send "⚠️ <code>$line</code>"
      fi
    done || true

    rm -f "$new_domains"

    echo "[+] Done: $basename — $new_count new domains scanned"
    tg_send "✅ <b>Scan complete:</b> <code>$basename</code> ($new_count new domains)"
    echo "$txt" >> "$PROCESSED_LOG"
  done

  sleep "$POLL_INTERVAL"
done
