#!/usr/bin/env bash
# batch-scan.sh — simple check + telegram

TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

> "$RESULTS_DIR/confirmed.txt"
> "$RESULTS_DIR/not-vuln.txt"

[[ $# -lt 1 ]] && { echo "Usage: $0 domains.txt"; exit 1; }

while IFS= read -r domain || [[ -n "$domain" ]]; do
  domain="${domain%%#*}"
  domain="${domain#"${domain%%[![:space:]]*}"}"
  domain="${domain%"${domain##*[![:space:]]}"}"
  [[ -z "$domain" ]] && continue

  result=$(python3 "$SCRIPT_DIR/wp2shell.py" check "https://$domain" 2>&1)

  if echo "$result" | grep -q "CONFIRMED\|VULNERABLE"; then
    echo "🔴 $domain"
    echo "$domain" >> "$RESULTS_DIR/confirmed.txt"
    curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
      -d chat_id="$TG_CHAT_ID" \
      -d text="🔴 VULNERABLE — $domain" > /dev/null 2>&1
  else
    echo "⚪ $domain"
    echo "$domain" >> "$RESULTS_DIR/not-vuln.txt"
  fi
done < "$1"

echo ""
echo "Confirmed: $(wc -l < "$RESULTS_DIR/confirmed.txt")"
echo "Not vulnerable: $(wc -l < "$RESULTS_DIR/not-vuln.txt")"
