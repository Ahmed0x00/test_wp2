#!/usr/bin/env bash
# wp2shell-check.sh v2.0.0 — Non-intrusive WordPress wp2shell vulnerability
# detector (CVE-2026-63030 + CVE-2026-60137). Detection only — never sends
# exploit payloads.
#
# Usage:
#   ./wp2shell-check.sh <url>                         Single target
#   ./wp2shell-check.sh -f targets.txt                 Scan list of URLs
#   ./wp2shell-check.sh <url> --json                   JSON output
#   ./wp2shell-check.sh -f targets.txt --csv           CSV output
#   ./wp2shell-check.sh -f sites.txt -o results.json   Save to file
#   ./wp2shell-check.sh -f sites.txt --simple          domain | verdict
#
# Options:
#   --json         JSON output (one object per line for multi-target)
#   --csv          CSV output
#   --simple       One line per target: domain | VERDICT
#   -o, --output   Save results to file (instead of stdout)
#   --verbose      Show every HTTP request and response detail
#   --no-color     Disable colored output
#   -f FILE        Read targets from file (one URL per line, # comments ok)
#   -h, --help     Show this help
#   -V, --version  Show version
#
# Exit codes:
#   0  not vulnerable (or not WordPress)
#   1  inconclusive / error
#   2  at least one target vulnerable or likely vulnerable

set -u

VERSION="2.0.0"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# ── colors ──────────────────────────────────────────────────────────
RED="" GRN="" YLW="" CYN="" BLD="" DIM="" RST=""
NO_COLOR_FLAG=0

setup_colors() {
  if [[ -t 2 ]] && [[ "${NO_COLOR:-}" != "1" ]] && [[ $NO_COLOR_FLAG -eq 0 ]]; then
    RED=$'\033[1;31m'  GRN=$'\033[1;32m'  YLW=$'\033[1;33m'
    CYN=$'\033[0;36m'  BLD=$'\033[1m'     DIM=$'\033[2m'  RST=$'\033[0m'
  fi
}

# ── argument parsing ────────────────────────────────────────────────
TARGET=""
TARGET_FILE=""
FORMAT="text"
VERBOSE=0
OUTPUT_FILE=""
SIMPLE=0

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)      FORMAT="json" ;;
      --csv)       FORMAT="csv" ;;
      --simple)    SIMPLE=1 ;;
      --verbose)   VERBOSE=1 ;;
      --no-color)  NO_COLOR_FLAG=1 ;;
      -o|--output)
        shift
        if [[ $# -eq 0 ]]; then echo "Error: -o requires a filename" >&2; exit 1; fi
        OUTPUT_FILE="$1"
        ;;
      -V|--version) echo "wp2shell-check v$VERSION"; exit 0 ;;
      -h|--help)   sed -n '2,24p' "$0" | sed 's/^# \?//'; exit 0 ;;
      -f)
        shift
        if [[ $# -eq 0 ]]; then echo "Error: -f requires a filename" >&2; exit 1; fi
        TARGET_FILE="$1"
        if [[ ! -f "$TARGET_FILE" ]]; then echo "Error: file not found: $TARGET_FILE" >&2; exit 1; fi
        ;;
      -*) echo "Unknown flag: $1" >&2; exit 1 ;;
      *)
        if [[ -z "$TARGET" ]]; then TARGET="$1"
        else echo "Unexpected argument: $1 (use -f for multi-target)" >&2; exit 1; fi
        ;;
    esac
    shift
  done
  if [[ -z "$TARGET" ]] && [[ -z "$TARGET_FILE" ]]; then
    echo "Usage: $0 <url> [--json|--csv] [-o output_file] [--verbose] [--no-color]" >&2
    echo "       $0 -f targets.txt [--json|--csv] [-o output_file] [--verbose]" >&2
    exit 1
  fi
}

# ── helpers ─────────────────────────────────────────────────────────
log()    { [[ "$FORMAT" == "text" ]] && printf '%s\n' "$*" >&2; return 0; }
log_v()  { [[ $VERBOSE -eq 1 ]] && printf '    %s%s%s\n' "$DIM" "$*" "$RST" >&2; return 0; }

fetch_url() {
  local url="$1" out="$2" code
  code=$(curl -sSL --max-time 15 -A "$UA" -D "$out.hdr" -o "$out.body" \
            -w "%{http_code}" "$url" 2>/dev/null) || code="000"
  HTTP_CODE="$code"
  log_v "GET $url → $code"
}

extract_wp_version() {
  local body="$1"
  grep -oiE 'name="generator" content="WordPress [0-9]+\.[0-9]+(\.[0-9]+)?(-(beta|alpha|rc)[0-9]*)?"' \
    "$body" 2>/dev/null | head -1 \
    | grep -oiE '[0-9]+\.[0-9]+(\.[0-9]+)?(-(beta|alpha|rc)[0-9]*)?' | head -1
}

get_header() {
  grep -i "^${2}:" "$1" 2>/dev/null | head -1 | sed 's/^[^:]*: *//' | tr -d '\r'
}

is_json_body() { [[ -s "$1" ]] && head -c 1 "$1" 2>/dev/null | grep -q '[{[]'; }

ver_ge()       { [[ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -1)" == "$2" ]]; }
ver_in_range() { ver_ge "$1" "$2" && ver_ge "$3" "$1"; }

is_71_beta_vulnerable() { [[ "$1" =~ ^7\.1(\.0)?-(beta1|alpha[0-9]*)$ ]]; }

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

detect_waf() {
  local hdr="$1"
  [[ -f "$hdr" ]] || return
  local server cf sucuri
  server=$(get_header "$hdr" "Server")
  cf=$(get_header "$hdr" "Cf-Ray")
  sucuri=$(get_header "$hdr" "X-Sucuri-ID")
  [[ -n "$cf" ]]      && { echo "cloudflare"; return; }
  [[ -n "$sucuri" ]]   && { echo "sucuri"; return; }
  echo "$server" | grep -qi "akamai"              && { echo "akamai"; return; }
  echo "$server" | grep -qi "imperva\|incapsula"  && { echo "imperva"; return; }
  local body="${hdr%.hdr}.body"
  [[ -s "$body" ]] && grep -qi "wordfence" "$body" 2>/dev/null && { echo "wordfence"; return; }
  echo "none"
}

# ── result variables (set by scan_target, read by output) ───────────
reset_results() {
  R_TARGET="" R_IS_WP="unknown" R_VER="" R_VER_SRC=""
  R_REST_CODE="000" R_REST_AVAILABLE="unknown"
  R_B1_CODE="000" R_B1_ALLOW="" R_B1_JSON="false"
  R_B2_CODE="000" R_B2_ALLOW="" R_B2_JSON="false"
  R_WAF="none" R_CACHE="none" R_CACHE_NOTE=""
  R_EP_NOTE="" R_VERDICT="INCONCLUSIVE" R_SEVERITY="UNKNOWN"
  R_REASON="could not determine WordPress version" R_FIX=""
}

# ── core scan ───────────────────────────────────────────────────────
scan_target() {
  local target="${1%/}"
  reset_results
  R_TARGET="$target"
  local td
  td=$(mktemp -d)

  # 1 ── Homepage: version + WP fingerprint
  log "  ${DIM}→${RST} Fetching homepage"
  fetch_url "$target/" "$td/home"
  local hp_code="$HTTP_CODE"
  if [[ -s "$td/home.body" ]]; then
    R_VER=$(extract_wp_version "$td/home.body")
    [[ -n "$R_VER" ]] && R_VER_SRC="meta generator tag"
  fi

  # 2 ── readme.html
  if [[ -z "$R_VER" ]]; then
    log "  ${DIM}→${RST} Trying /readme.html"
    fetch_url "$target/readme.html" "$td/readme"
    if [[ -s "$td/readme.body" ]]; then
      local v
      v=$(grep -oE 'Version [0-9]+\.[0-9]+(\.[0-9]+)?' "$td/readme.body" 2>/dev/null \
          | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
      [[ -n "$v" ]] && { R_VER="$v"; R_VER_SRC="readme.html"; }
    fi
  fi

  # 3 ── /wp-json/ (also saves REST API code for step 5)
  if [[ -z "$R_VER" ]]; then
    log "  ${DIM}→${RST} Trying /wp-json/"
    fetch_url "$target/wp-json/" "$td/json"
    R_REST_CODE="$HTTP_CODE"
    if [[ -s "$td/json.body" ]]; then
      local v
      v=$(grep -oE '"wp":"[0-9]+\.[0-9]+(\.[0-9]+)?"|"version":"[0-9]+\.[0-9]+(\.[0-9]+)?"' \
          "$td/json.body" 2>/dev/null | head -3 \
          | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
      [[ -n "$v" ]] && { R_VER="$v"; R_VER_SRC="/wp-json/ site_info"; }
    fi
  fi

  # 4 ── /wp-includes/version.php (misconfig fallback)
  if [[ -z "$R_VER" ]]; then
    log "  ${DIM}→${RST} Trying /wp-includes/version.php"
    fetch_url "$target/wp-includes/version.php" "$td/verphp"
    if [[ -s "$td/verphp.body" ]]; then
      local v
      v=$(grep -oE "\\\$wp_version *= *'[0-9]+\.[0-9]+(\.[0-9]+)?'" "$td/verphp.body" 2>/dev/null \
          | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
      [[ -n "$v" ]] && { R_VER="$v"; R_VER_SRC="wp-includes/version.php"; }
    fi
  fi

  # 5 ── REST API availability
  log "  ${DIM}→${RST} Checking REST API"
  if [[ ! -f "$td/json.body" ]]; then
    fetch_url "$target/wp-json/" "$td/json"
    R_REST_CODE="$HTTP_CODE"
  fi
  if [[ "$R_REST_CODE" == "200" ]] && is_json_body "$td/json.body"; then
    grep -q '"namespaces"' "$td/json.body" 2>/dev/null \
      && R_REST_AVAILABLE="yes" || R_REST_AVAILABLE="partial"
  elif [[ "$R_REST_CODE" == "200" ]]; then
    R_REST_AVAILABLE="hijacked"
  else
    R_REST_AVAILABLE="no"
  fi

  # 6 ── Batch endpoint (pretty permalink)
  log "  ${DIM}→${RST} Probing /wp-json/batch/v1"
  fetch_url "$target/wp-json/batch/v1" "$td/b1"
  R_B1_CODE="$HTTP_CODE"
  R_B1_ALLOW=$(get_header "$td/b1.hdr" "Allow")
  is_json_body "$td/b1.body" && R_B1_JSON="true"

  # 7 ── Batch endpoint (query-string — WAFs often miss this)
  log "  ${DIM}→${RST} Probing ?rest_route=/batch/v1"
  fetch_url "$target/?rest_route=/batch/v1" "$td/b2"
  R_B2_CODE="$HTTP_CODE"
  R_B2_ALLOW=$(get_header "$td/b2.hdr" "Allow")
  is_json_body "$td/b2.body" && R_B2_JSON="true"

  # 8 ── WAF fingerprint
  R_WAF=$(detect_waf "$td/home.hdr")
  [[ "$R_WAF" == "none" ]] && R_WAF=$(detect_waf "$td/b1.hdr")
  log_v "WAF detected: $R_WAF"

  # 9 ── Object-cache / CDN headers
  log "  ${DIM}→${RST} Checking cache indicators"
  for hf in "$td"/home.hdr "$td"/json.hdr; do
    [[ -f "$hf" ]] || continue
    local cf xc xwpc
    cf=$(get_header "$hf" "Cf-Cache-Status")
    xc=$(get_header "$hf" "X-Cache")
    xwpc=$(get_header "$hf" "X-WP-Cache")
    if   [[ -n "$cf" ]];   then R_CACHE="cloudflare ($cf)"; break
    elif [[ -n "$xwpc" ]]; then R_CACHE="wp-object-cache ($xwpc)"; break
    elif [[ -n "$xc" ]];   then R_CACHE="cdn/proxy ($xc)"; break
    fi
  done
  if [[ "$R_CACHE" == "none" ]] && [[ -s "$td/home.body" ]]; then
    grep -qi "object-cache\.php" "$td/home.body" 2>/dev/null && \
      R_CACHE="object-cache.php in source"
  fi
  [[ "$R_CACHE" != "none" ]] && \
    R_CACHE_NOTE="persistent cache detected — full RCE chain harder but SQLi still reachable"

  # 10 ── WordPress detection (fallback when version unknown)
  if [[ -z "$R_VER" ]]; then
    if [[ "$hp_code" == "200" ]] && [[ -s "$td/home.body" ]]; then
      if grep -qE "wordpress|wp-content/|wp-includes/" "$td/home.body" 2>/dev/null; then
        R_IS_WP="maybe"
      else
        log "  ${DIM}→${RST} Trying /wp-login.php"
        fetch_url "$target/wp-login.php" "$td/wplogin"
        if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "302" ]]; then
          R_IS_WP="maybe"
          log_v "wp-login.php → HTTP $HTTP_CODE — likely WordPress"
        else
          R_IS_WP="no"
        fi
      fi
    fi
  else
    R_IS_WP="yes"
  fi

  # ── verdict ──
  if [[ -n "$R_VER" ]]; then
    R_REASON=""
    if is_71_beta_vulnerable "$R_VER"; then
      R_VERDICT="VULNERABLE"; R_SEVERITY="CRITICAL"
      R_REASON="WP 7.1-beta1 — full pre-auth RCE chain reachable"
      R_FIX="Update to WordPress 7.1-beta2 or later"
    elif ver_in_range "$R_VER" "7.0.0" "7.0.1"; then
      R_VERDICT="VULNERABLE"; R_SEVERITY="CRITICAL"
      R_REASON="WP 7.0.0-7.0.1 — full pre-auth RCE chain reachable"
      R_FIX="Update to WordPress 7.0.2"
    elif ver_in_range "$R_VER" "6.9.0" "6.9.4"; then
      R_VERDICT="VULNERABLE"; R_SEVERITY="CRITICAL"
      R_REASON="WP 6.9.0-6.9.4 — full pre-auth RCE chain reachable"
      R_FIX="Update to WordPress 6.9.5"
    elif ver_in_range "$R_VER" "6.8.0" "6.8.5"; then
      R_VERDICT="LIKELY_VULNERABLE"; R_SEVERITY="HIGH"
      R_REASON="WP 6.8.0-6.8.5 — standalone SQLi (CVE-2026-60137), RCE chain not present"
      R_FIX="Update to WordPress 6.8.6"
    else
      R_VERDICT="NOT_VULNERABLE"; R_SEVERITY="INFO"
      R_REASON="version $R_VER is patched or predates vulnerable code"
    fi
  fi

  # Refine with endpoint reachability
  if [[ "$R_VERDICT" == "VULNERABLE" ]]; then
    if [[ "$R_B1_CODE" == "405" || "$R_B1_CODE" == "200" ]]; then
      R_EP_NOTE="batch endpoint reachable (HTTP $R_B1_CODE)"
    elif [[ "$R_B1_CODE" == "403" || "$R_B1_CODE" == "406" ]]; then
      R_EP_NOTE="pretty route WAF-blocked (HTTP $R_B1_CODE)"
      R_VERDICT="LIKELY_VULNERABLE"
      R_REASON="$R_REASON — WAF blocking pretty-permalink route"
    else
      R_EP_NOTE="batch endpoint unreachable (HTTP $R_B1_CODE)"
      R_VERDICT="LIKELY_VULNERABLE"
      R_REASON="$R_REASON — endpoint not directly observable"
    fi
    # Query-string bypass?
    if [[ "$R_VERDICT" == "LIKELY_VULNERABLE" ]]; then
      if [[ "$R_B2_CODE" == "405" || "$R_B2_CODE" == "200" ]]; then
        R_EP_NOTE="$R_EP_NOTE; query-string route BYPASSES WAF (HTTP $R_B2_CODE)"
        R_VERDICT="VULNERABLE"
        R_REASON="${R_REASON/ — WAF blocking pretty-permalink route/ — WAF bypassed via query-string route}"
        R_REASON="${R_REASON/ — endpoint not directly observable/ — query-string route bypasses restriction}"
      fi
    fi
  fi

  if [[ "$R_REST_AVAILABLE" == "no" ]] && \
     [[ "$R_VERDICT" == "VULNERABLE" || "$R_VERDICT" == "LIKELY_VULNERABLE" ]]; then
    R_EP_NOTE="${R_EP_NOTE:+$R_EP_NOTE; }REST API disabled (HTTP $R_REST_CODE)"
  fi

  rm -rf "$td"
}

# ── output: text ────────────────────────────────────────────────────
vc() {
  case "$1" in
    VULNERABLE)        printf '%s' "$RED" ;;
    LIKELY_VULNERABLE) printf '%s' "$YLW" ;;
    NOT_VULNERABLE)    printf '%s' "$GRN" ;;
    *)                 printf '%s' "$DIM" ;;
  esac
}

print_text() {
  local c; c=$(vc "$R_VERDICT")
  echo "" >&2
  printf '  %sTarget%s:           %s\n' "$BLD" "$RST" "$R_TARGET" >&2
  printf '  WordPress:        %s\n' "$R_IS_WP" >&2
  if [[ -n "$R_VER" ]]; then
    printf '  Detected version: %s%s%s (via %s)\n' "$BLD" "$R_VER" "$RST" "$R_VER_SRC" >&2
  else
    printf '  Detected version: %sUNKNOWN%s\n' "$DIM" "$RST" >&2
  fi
  printf '  REST API:         %s (HTTP %s)\n' "$R_REST_AVAILABLE" "$R_REST_CODE" >&2
  printf '  Batch endpoint:   pretty=%s  query-string=%s\n' "$R_B1_CODE" "$R_B2_CODE" >&2
  [[ -n "$R_B1_ALLOW" || -n "$R_B2_ALLOW" ]] && \
    printf '  Batch Allow:      pretty=[%s]  query-string=[%s]\n' "$R_B1_ALLOW" "$R_B2_ALLOW" >&2
  printf '  Batch response:   pretty=%s  query-string=%s\n' \
    "$([[ $R_B1_JSON == "true" ]] && echo "JSON" || echo "HTML/other")" \
    "$([[ $R_B2_JSON == "true" ]] && echo "JSON" || echo "HTML/other")" >&2
  [[ "$R_WAF" != "none" ]] && \
    printf '  WAF:              %s%s%s\n' "$YLW" "$R_WAF" "$RST" >&2
  printf '  Object cache:     %s\n' "$R_CACHE" >&2
  [[ -n "$R_EP_NOTE" ]]    && printf '  Endpoint note:    %s\n' "$R_EP_NOTE" >&2
  [[ -n "$R_CACHE_NOTE" ]] && printf '  Cache note:       %s\n' "$R_CACHE_NOTE" >&2
  echo "" >&2
  printf '  Verdict:  %s%s%s\n' "$c" "$R_VERDICT" "$RST" >&2
  printf '  Severity: %s%s%s\n' "$c" "$R_SEVERITY" "$RST" >&2
  [[ -n "$R_REASON" ]] && printf '  Reason:   %s\n' "$R_REASON" >&2
  [[ -n "$R_FIX" ]]    && printf '  Fix:      %s%s%s\n' "$GRN" "$R_FIX" "$RST" >&2
  echo "" >&2
}

# ── output: json ────────────────────────────────────────────────────
print_json() {
  printf '{"tool":"wp2shell-check","version":"%s",' "$VERSION"
  printf '"target":"%s",' "$(json_escape "$R_TARGET")"
  printf '"is_wordpress":"%s",' "$R_IS_WP"
  printf '"wp_version":"%s",' "$(json_escape "${R_VER:-}")"
  printf '"version_source":"%s",' "$(json_escape "$R_VER_SRC")"
  printf '"rest_api_status":%s,' "$R_REST_CODE"
  printf '"rest_api_available":"%s",' "$R_REST_AVAILABLE"
  printf '"batch_pretty_status":%s,' "$R_B1_CODE"
  printf '"batch_pretty_allow":"%s",' "$(json_escape "$R_B1_ALLOW")"
  printf '"batch_pretty_is_json":%s,' "$R_B1_JSON"
  printf '"batch_querystring_status":%s,' "$R_B2_CODE"
  printf '"batch_querystring_allow":"%s",' "$(json_escape "$R_B2_ALLOW")"
  printf '"batch_querystring_is_json":%s,' "$R_B2_JSON"
  printf '"waf":"%s",' "$R_WAF"
  printf '"object_cache":"%s",' "$(json_escape "$R_CACHE")"
  printf '"cache_note":"%s",' "$(json_escape "$R_CACHE_NOTE")"
  printf '"endpoint_note":"%s",' "$(json_escape "$R_EP_NOTE")"
  printf '"verdict":"%s",' "$R_VERDICT"
  printf '"severity":"%s",' "$R_SEVERITY"
  printf '"reason":"%s",' "$(json_escape "$R_REASON")"
  printf '"fix":"%s"}\n' "$(json_escape "$R_FIX")"
}

# ── output: csv ─────────────────────────────────────────────────────
CSV_HEADER=0
csve() { printf '"%s"' "${1//\"/\"\"}"; }

print_csv() {
  if [[ $CSV_HEADER -eq 0 ]]; then
    echo "target,is_wordpress,wp_version,version_source,rest_api,batch_pretty,batch_querystring,waf,object_cache,verdict,severity,reason,fix"
    CSV_HEADER=1
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csve "$R_TARGET")" "$R_IS_WP" "${R_VER:-}" "$(csve "$R_VER_SRC")" \
    "$R_REST_AVAILABLE" "$R_B1_CODE" "$R_B2_CODE" "$R_WAF" \
    "$(csve "$R_CACHE")" "$R_VERDICT" "$R_SEVERITY" \
    "$(csve "$R_REASON")" "$(csve "$R_FIX")"
}

# ── output: simple (domain | verdict) ────────────────────────────────
print_simple() {
  local domain="${R_TARGET#https://}"
  domain="${domain#http://}"
  domain="${domain%/}"
  printf '%s | %s\n' "$domain" "$R_VERDICT"
}

# ── output dispatcher ──────────────────────────────────────────────
emit() {
  if [[ $SIMPLE -eq 1 ]]; then
    print_simple
    return
  fi
  case "$FORMAT" in
    json) print_json ;;
    csv)  print_csv ;;
    *)    print_text ;;
  esac
}

# ── main ────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  setup_colors

  if ! command -v curl &>/dev/null; then
    echo "Error: curl is required" >&2; exit 1
  fi

  # redirect stdout to output file if -o was given
  if [[ -n "$OUTPUT_FILE" ]]; then
    exec > "$OUTPUT_FILE"
  fi

  local worst=0 total=0 nv=0 nl=0 nc=0 ni=0

  log ""
  log "  ${BLD}wp2shell-check${RST} v${VERSION}"
  log "  ${DIM}CVE-2026-63030 + CVE-2026-60137 detector${RST}"
  log ""

  do_scan() {
    local url="$1"
    url="${url%/}"
    [[ "$url" =~ ^https?:// ]] || url="https://$url"

    log "  ${BLD}Scanning${RST}: $url"
    scan_target "$url"
    emit

    total=$((total + 1))
    case "$R_VERDICT" in
      VULNERABLE)        nv=$((nv + 1)); [[ $worst -lt 2 ]] && worst=2 ;;
      LIKELY_VULNERABLE) nl=$((nl + 1)); [[ $worst -lt 2 ]] && worst=2 ;;
      NOT_VULNERABLE)    nc=$((nc + 1)) ;;
      *)                 ni=$((ni + 1)); [[ $worst -lt 1 ]] && worst=1 ;;
    esac
  }

  if [[ -n "$TARGET_FILE" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
      [[ -z "$line" ]] && continue
      do_scan "$line"
    done < "$TARGET_FILE"

    if [[ "$FORMAT" == "text" ]] && [[ $total -gt 1 ]]; then
      log "  ${BLD}━━ Summary ━━${RST}"
      log "  Scanned:            $total targets"
      [[ $nv -gt 0 ]] && log "  ${RED}Vulnerable:         $nv${RST}"
      [[ $nl -gt 0 ]] && log "  ${YLW}Likely vulnerable:  $nl${RST}"
      [[ $nc -gt 0 ]] && log "  ${GRN}Clean:              $nc${RST}"
      [[ $ni -gt 0 ]] && log "  ${DIM}Inconclusive:       $ni${RST}"
      log ""
    fi
  else
    do_scan "$TARGET"
  fi

  exit "$worst"
}

main "$@"
