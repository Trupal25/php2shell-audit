#!/usr/bin/env bash
# php2shell verify-hardening: check the directives that matter on the running SAPI.
# Usage: verify-hardening.sh [--php-bin php-fpm] [--from php-i.txt] [--json] [--strict]
set -uo pipefail

PHP_BIN="${PHP_BIN:-php}"
FROM=""
JSON=0
STRICT=0
RESULTS=""

usage() {
  cat <<'EOF'
Usage: verify-hardening.sh [options]

Checks the PHP2Shell interim directives. Read-only.

Options:
  --php-bin PATH   PHP/FPM binary to query (default: php, or $PHP_BIN)
  --from FILE      Parse a captured `php -i` output instead of running a binary
  --json           Emit one JSON object per check
  --strict         Treat WARN as failure
  -h, --help       Show this help

Exit codes: 0 pass (or warnings only), 1 failure, 2 cannot read PHP info.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --php-bin) PHP_BIN="${2:-php}"; shift 2 ;;
    --from) FROM="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    --strict) STRICT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

version_ge() {
  [[ -n "$1" && -n "$2" ]] || return 1
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]
}

get_field() {
  awk -F' => ' -v k="$1" '
    { sub(/^[[:space:]]+/, "") }
    $1 == k { print $2; exit }
  ' "$SOURCE"
}

to_bytes() {
  local v="$1" last num
  [[ -z "$v" || "$v" == "no value" ]] && { echo ""; return; }
  [[ "$v" == "-1" ]] && { echo "-1"; return; }
  last="${v: -1}"
  num="${v%?}"
  case "$last" in
    k|K) [[ "$num" =~ ^[0-9]+$ ]] && echo $((num * 1024)) || echo "" ;;
    m|M) [[ "$num" =~ ^[0-9]+$ ]] && echo $((num * 1024 * 1024)) || echo "" ;;
    g|G) [[ "$num" =~ ^[0-9]+$ ]] && echo $((num * 1024 * 1024 * 1024)) || echo "" ;;
    [0-9]) echo "$v" ;;
    *) echo "" ;;
  esac
}

tmp=""
cleanup() { [[ -n "$tmp" && -f "$tmp" ]] && rm -f "$tmp"; }
trap cleanup EXIT

if [[ -n "$FROM" ]]; then
  [[ -f "$FROM" ]] || { echo "file not found: $FROM" >&2; exit 2; }
  SOURCE="$FROM"
else
  tmp="$(mktemp)"
  timeout 20 "$PHP_BIN" -i > "$tmp" 2>/dev/null
  SOURCE="$tmp"
fi

if [[ ! -s "$SOURCE" ]]; then
  echo "cannot read PHP info from $PHP_BIN or $FROM" >&2
  exit 2
fi

VERSION="$(get_field 'PHP Version')"
SAPI="$(get_field 'Server API')"
BUILD="$(get_field 'Build Date')"
RESULTS="$(mktemp)"
trap 'cleanup; rm -f "$RESULTS"' EXIT

# Auto-detect whether this host is already above its branch gate. On a patched
# host the interim directives are defense-in-depth, not CVE failures.
PATCHED_MODE=0
PGATE=""
case "${VERSION%.*}" in
  8.5) PGATE=8.5.12 ;;
  8.4) PGATE=8.4.27 ;;
  8.3) PGATE=8.3.36 ;;
  8.2) PGATE=8.2.35 ;;
esac
if [[ -n "$PGATE" ]] && version_ge "$VERSION" "$PGATE"; then
  PATCHED_MODE=1
fi

fails=0
warns=0

add_check() {
  local status="$1" key="$2" observed="$3" expected="$4" note="$5"
  printf '%s|%s|%s|%s|%s\n' "$status" "$key" "$observed" "$expected" "$note" >> "$RESULTS"
  case "$status" in
    FAIL) fails=$((fails + 1)) ;;
    WARN) warns=$((warns + 1)) ;;
  esac
}

mem="$(get_field memory_limit)"
maxmem="$(get_field max_memory_limit)"
post="$(get_field post_max_size)"
upload="$(get_field upload_max_filesize)"
progress="$(get_field session.upload_progress.enabled)"
inputvars="$(get_field max_input_vars)"
nesting="$(get_field max_input_nesting_level)"
parts="$(get_field max_multipart_body_parts)"
fileuploads="$(get_field max_file_uploads)"
fatalbt="$(get_field fatal_error_backtraces)"
expose="$(get_field expose_php)"
logerrors="$(get_field log_errors)"
errorlog="$(get_field error_log)"
display="$(get_field display_errors)"
postreading="$(get_field enable_post_data_reading)"

# 1. Upload progress
if [[ "$progress" =~ ^(Off|0|)$ ]]; then
  add_check PASS session.upload_progress.enabled "$progress" "Off" "early consumer disabled"
elif [[ "$PATCHED_MODE" == 1 ]]; then
  add_check WARN session.upload_progress.enabled "$progress" "Off" "optional after patch; disable if unused"
else
  add_check FAIL session.upload_progress.enabled "$progress" "Off" "re-enable via startup config, then restart"
fi

# 2. memory_limit
if [[ "$mem" == "-1" ]]; then
  add_check PASS memory_limit "$mem" "-1" "interim control present; monitor host memory"
elif [[ "$PATCHED_MODE" == 1 ]]; then
  add_check INFO memory_limit "$mem" "-1 (interim)" "patched; a finite limit is normal"
else
  add_check FAIL memory_limit "$mem" "-1" "finite limit enables predictable OOM"
fi

# 3. max_memory_limit (8.5+)
if [[ -z "$maxmem" || "$maxmem" == "no value" ]]; then
  add_check N/A max_memory_limit "-" "-1" "directive not present on this build"
elif [[ "$maxmem" == "-1" ]]; then
  add_check PASS max_memory_limit "$maxmem" "-1" "does not cap memory_limit=-1"
elif [[ "$PATCHED_MODE" == 1 ]]; then
  add_check INFO max_memory_limit "$maxmem" "-1 (interim)" "patched; no need to cap memory_limit"
else
  add_check FAIL max_memory_limit "$maxmem" "-1" "finite value caps memory_limit=-1"
fi

# 4. post_max_size
post_b="$(to_bytes "$post")"
if [[ -z "$post_b" ]]; then
  add_check WARN post_max_size "$post" "<= 8M" "unparseable value"
elif [[ "$post_b" -le $((8 * 1024 * 1024)) ]]; then
  add_check PASS post_max_size "$post" "<= 8M" "conservative"
elif [[ "$post_b" -le $((64 * 1024 * 1024)) ]]; then
  add_check WARN post_max_size "$post" "<= 8M" "larger than recommended"
else
  add_check FAIL post_max_size "$post" "<= 8M" "large body budget"
fi

# 5. upload_max_filesize < post_max_size
upload_b="$(to_bytes "$upload")"
if [[ -z "$upload_b" || -z "$post_b" ]]; then
  add_check WARN upload_max_filesize "$upload" "< post_max_size" "unparseable value"
elif [[ "$upload_b" -lt "$post_b" ]]; then
  add_check PASS upload_max_filesize "$upload" "< post_max_size" "ok"
else
  add_check FAIL upload_max_filesize "$upload" "< post_max_size" "must be strictly smaller"
fi

# 6. max_input_vars
if [[ "$inputvars" =~ ^[0-9]+$ && "$inputvars" -le 1000 ]]; then
  add_check PASS max_input_vars "$inputvars" "<= 1000" "ok"
elif [[ "$inputvars" =~ ^[0-9]+$ && "$inputvars" -le 10000 ]]; then
  add_check WARN max_input_vars "$inputvars" "<= 1000" "raise only if a form needs it"
elif [[ "$inputvars" =~ ^[0-9]+$ ]]; then
  add_check FAIL max_input_vars "$inputvars" "<= 1000" "too many input variables"
else
  add_check WARN max_input_vars "$inputvars" "<= 1000" "unparseable value"
fi

# 7. max_input_nesting_level
if [[ "$nesting" =~ ^[0-9]+$ && "$nesting" -le 64 ]]; then
  add_check PASS max_input_nesting_level "$nesting" "<= 64" "ok"
elif [[ "$nesting" =~ ^[0-9]+$ && "$nesting" -le 128 ]]; then
  add_check WARN max_input_nesting_level "$nesting" "<= 64" "nested names multiply work"
elif [[ "$nesting" =~ ^[0-9]+$ ]]; then
  add_check FAIL max_input_nesting_level "$nesting" "<= 64" "deep nesting"
else
  add_check WARN max_input_nesting_level "$nesting" "<= 64" "unparseable value"
fi

# 8. max_multipart_body_parts
if [[ -z "$parts" || "$parts" == "no value" ]]; then
  add_check N/A max_multipart_body_parts "-" "<= 100" "directive not present on this build"
elif [[ "$parts" == "-1" ]]; then
  add_check WARN max_multipart_body_parts "$parts" "<= 100" "unlimited parts"
elif [[ "$parts" =~ ^[0-9]+$ && "$parts" -le 100 ]]; then
  add_check PASS max_multipart_body_parts "$parts" "<= 100" "ok"
elif [[ "$parts" =~ ^[0-9]+$ && "$parts" -le 1000 ]]; then
  add_check WARN max_multipart_body_parts "$parts" "<= 100" "higher than recommended"
elif [[ "$parts" =~ ^[0-9]+$ ]]; then
  add_check FAIL max_multipart_body_parts "$parts" "<= 100" "too many parts"
else
  add_check WARN max_multipart_body_parts "$parts" "<= 100" "unparseable value"
fi

# 9. max_file_uploads
if [[ "$fileuploads" =~ ^[0-9]+$ && "$fileuploads" -le 20 ]]; then
  add_check PASS max_file_uploads "$fileuploads" "<= 20" "ok"
elif [[ "$fileuploads" =~ ^[0-9]+$ && "$fileuploads" -le 100 ]]; then
  add_check WARN max_file_uploads "$fileuploads" "<= 20" "higher than recommended"
elif [[ "$fileuploads" =~ ^[0-9]+$ ]]; then
  add_check FAIL max_file_uploads "$fileuploads" "<= 20" "too many upload controls"
else
  add_check WARN max_file_uploads "$fileuploads" "<= 20" "unparseable value"
fi

# 10. fatal_error_backtraces (8.5+)
if version_ge "$VERSION" "8.5"; then
  if [[ "$fatalbt" =~ ^(0|Off|)$ ]]; then
    add_check PASS fatal_error_backtraces "$fatalbt" "0" "producer disabled"
  elif [[ "$PATCHED_MODE" == 1 ]]; then
    add_check WARN fatal_error_backtraces "$fatalbt" "0" "optional after patch; backtraces aid diagnostics"
  else
    add_check FAIL fatal_error_backtraces "$fatalbt" "0" "set 0 on 8.5 below the patch gate"
  fi
else
  add_check N/A fatal_error_backtraces "$fatalbt" "0 (8.5+)" "not applicable before 8.5"
fi

# 11-14. Hygiene and audit visibility
[[ "$expose" =~ ^(Off|0|)$ ]] && add_check PASS expose_php "$expose" "Off" "hides X-Powered-By" || add_check WARN expose_php "$expose" "Off" "information disclosure only"
[[ "$logerrors" =~ ^(On|1)$ ]] && add_check PASS log_errors "$logerrors" "On" "audit visibility" || add_check WARN log_errors "$logerrors" "On" "enable for the audit window"
[[ -n "$errorlog" && "$errorlog" != "no value" ]] && add_check PASS error_log "$errorlog" "set" "ok" || add_check WARN error_log "$errorlog" "set" "no functional error log"
[[ "$display" =~ ^(Off|0|)$ ]] && add_check PASS display_errors "$display" "Off" "production hygiene" || add_check WARN display_errors "$display" "Off" "not a CVE mitigation"

# 15. Optional strong control
if [[ "$postreading" =~ ^(0|Off)$ ]]; then
  add_check INFO enable_post_data_reading "$postreading" "0" "automatic body parsing disabled; verify the app does not need it"
else
  add_check INFO enable_post_data_reading "$postreading" "0" "optional; only if the app parses the body itself"
fi

if [[ "$JSON" == 1 ]]; then
  while IFS='|' read -r status key observed expected note; do
    printf '{"check":"%s","status":"%s","observed":"%s","expected":"%s","note":"%s","version":"%s","sapi":"%s","mode":"%s"}\n' \
      "$(printf '%s' "$key" | sed 's/"/\\"/g')" "$status" \
      "$(printf '%s' "$observed" | sed 's/"/\\"/g')" \
      "$(printf '%s' "$expected" | sed 's/"/\\"/g')" \
      "$(printf '%s' "$note" | sed 's/"/\\"/g')" \
      "$(printf '%s' "$VERSION" | sed 's/"/\\"/g')" \
      "$(printf '%s' "$SAPI" | sed 's/"/\\"/g')" \
      "$([[ "$PATCHED_MODE" == 1 ]] && echo patched || echo interim)"
  done < "$RESULTS"
else
  printf 'PHP %s (%s), built %s\n' "${VERSION:-unknown}" "${SAPI:-unknown}" "${BUILD:-unknown}"
  if [[ "$PATCHED_MODE" == 1 ]]; then
    printf 'Mode: patched — interim checks are defense-in-depth, not CVE failures\n\n'
  else
    printf 'Mode: interim — host is below the patch gate or version is unknown\n\n'
  fi
  printf '%-6s %-38s %-16s %-24s %s\n' "RESULT" "CHECK" "OBSERVED" "EXPECTED" "NOTE"
  printf '%-6s %-38s %-16s %-24s %s\n' "------" "-----" "--------" "--------" "----"
  while IFS='|' read -r status key observed expected note; do
    printf '%-6s %-38s %-16s %-24s %s\n' "$status" "$key" "${observed:-?}" "$expected" "$note"
  done < "$RESULTS"
  printf '\nSummary: %d fail, %d warn\n' "$fails" "$warns"
fi

[[ "$fails" -gt 0 ]] && exit 1
[[ "$STRICT" == 1 && "$warns" -gt 0 ]] && exit 1
exit 0
