#!/usr/bin/env bash
# batch-scan.sh — run wp2shell check on multiple domains in parallel

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

check_domain() {
  local domain="$1"
  local result
  result=$(python3 "$SCRIPT_DIR/wp2shell.py" check "https://$domain" 2>&1)
  local rc=$?

  if echo "$result" | grep -q "CONFIRMED\|VULNERABLE"; then
    echo "🔴 $domain"
    echo "$domain | CONFIRMED | $result" >> "$RESULTS_DIR/confirmed.txt"
    tg_send "🔴 <b>CONFIRMED</b> <code>$domain</code>"
  else
    echo "⚪ $domain (not vulnerable)"
    echo "$domain | NOT VULNERABLE" >> "$RESULTS_DIR/not-vuln.txt"
  fi
}

export -f check_domain
export -f tg_send
export SCRIPT_DIR RESULTS_DIR TG_TOKEN TG_CHAT_ID

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 domains.txt [workers]"
  exit 1
fi

echo "[*] Scanning with $WORKERS parallel workers..."

cat "$1" | xargs -P "$WORKERS" -I {} bash -c 'check_domain "$@"' _ {}

echo "[+] Done. Results in $RESULTS_DIR/"
