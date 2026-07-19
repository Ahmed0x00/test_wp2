#!/usr/bin/env bash
# wp2shell-watch.sh — scans domains.txt and sends results to Telegram

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOMAINS_FILE="${1:-$SCRIPT_DIR/domains.txt}"
RESULTS_DIR="$SCRIPT_DIR/results"
SCRIPT="$SCRIPT_DIR/wp2shell-check.sh"
SCANNED_DOMAINS="$RESULTS_DIR/.scanned_domains"

# Telegram (set these or export as env vars)
TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"

if [[ -z "$TG_TOKEN" || -z "$TG_CHAT_ID" ]]; then
  echo "Error: set TG_TOKEN and TG_CHAT_ID" >&2
  echo "Usage: TG_TOKEN=... TG_CHAT_ID=... ./wp2shell-watch.sh [domains.txt]" >&2
  exit 1
fi

if [[ ! -f "$DOMAINS_FILE" ]]; then
  echo "Error: domains file not found: $DOMAINS_FILE" >&2
  exit 1
fi

mkdir -p "$RESULTS_DIR"
touch "$SCANNED_DOMAINS"

tg_send() {
  for chat_id in $TG_CHAT_ID; do
    curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
      -d chat_id="$chat_id" \
      -d text="$1" \
      -d parse_mode="HTML" > /dev/null 2>&1
  done
}

# filter already-scanned domains
new_domains=$(mktemp)
while IFS= read -r domain; do
  domain="${domain%%#*}"
  domain="${domain#"${domain%%[![:space:]]*}"}"
  domain="${domain%"${domain##*[![:space:]]}"}"
  [[ -z "$domain" ]] && continue
  if ! grep -qFx "$domain" "$SCANNED_DOMAINS" 2>/dev/null; then
    echo "$domain" >> "$new_domains"
  fi
done < "$DOMAINS_FILE"

new_count=$(wc -l < "$new_domains" | tr -d ' ')
total_count=$(grep -c '[^ ]' "$DOMAINS_FILE" 2>/dev/null || echo 0)
already=$((total_count - new_count))

echo "[*] Total domains: $total_count"
echo "[*] Already scanned: $already"
echo "[*] New to scan: $new_count"

if [[ "$new_count" -eq 0 ]]; then
  echo "[+] Nothing to scan"
  rm -f "$new_domains"
  exit 0
fi

tg_send "🔍 <b>Starting scan</b> — <code>$new_count</code> new domains (<code>$already</code> already done)"

# mark before scanning
cat "$new_domains" >> "$SCANNED_DOMAINS"

# scan and send results
vuln_count=0
likely_count=0
total_scanned=0

"$SCRIPT" -f "$new_domains" --simple --no-color 2>/dev/null | while IFS= read -r line; do
  echo "$line"
  echo "$line" >> "$RESULTS_DIR/results.txt"
  total_scanned=$((total_scanned + 1))

  if echo "$line" | grep -qE '\| VULNERABLE$'; then
    vuln_count=$((vuln_count + 1))
    tg_send "🔴 <code>$line</code>"
  elif echo "$line" | grep -qE '\| LIKELY_VULNERABLE$'; then
    likely_count=$((likely_count + 1))
    tg_send "🟡 <code>$line</code>"
  fi
done || true

rm -f "$new_domains"

echo "[+] Done — scanned $new_count domains"
tg_send "✅ <b>Scan complete</b> — <code>$new_count</code> domains scanned"
