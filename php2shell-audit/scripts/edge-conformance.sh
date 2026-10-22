#!/usr/bin/env bash
# php2shell edge-conformance: one bounded request to check long-key rejection.
# No exploit payloads. Private/loopback lab targets run without a scope file.
set -uo pipefail

URL=""
SCOPE_FILE=""
KEY_BYTES=2048
TIMEOUT=10
EXPECT="400,403,413,414"
JSON=0

usage() {
  cat <<'EOF'
Usage: edge-conformance.sh --url URL [options]

Sends ONE urlencoded POST with a long parameter key and reports the status.
Expected: 400/403/413/414. A 200 means the key-length control is absent.

Options:
  --url URL            Target endpoint (required)
  --scope-file FILE    Authorized host list; required only for public targets
  --key-bytes N        Key length, 64..8192 (default: 2048)
  --timeout SECS       Request timeout (default: 10)
  --expect CODES       Comma-separated pass codes (default: 400,403,413,414)
  --json               Emit one JSON object
  -h, --help           Show this help

Exit codes: 0 pass, 1 fail, 2 stop/error.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2 ;;
    --scope-file) SCOPE_FILE="${2:-}"; shift 2 ;;
    --key-bytes) KEY_BYTES="${2:-2048}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-10}"; shift 2 ;;
    --expect) EXPECT="${2:-400,403,413,414}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$URL" ]] || { echo "--url is required" >&2; usage; exit 2; }
[[ "$KEY_BYTES" =~ ^[0-9]+$ && "$KEY_BYTES" -ge 64 && "$KEY_BYTES" -le 8192 ]] \
  || { echo "--key-bytes must be 64..8192" >&2; exit 2; }

host_is_private() {
  local ip="$1"
  case "$ip" in
    10.*|127.*|192.168.*|169.254.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    ::1|fc*|fd*|fe80:*) return 0 ;;
    *) return 1 ;;
  esac
}

in_scope() {
  local h="$1" line suffix
  [[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]] || return 1
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(printf '%s' "$line" | xargs)"
    [[ -z "$line" ]] && continue
    [[ "$h" == "$line" ]] && return 0
    if [[ "$line" == \*.* ]]; then
      suffix="${line#\*}"
      [[ "$h" == *"$suffix" ]] && return 0
    fi
  done < "$SCOPE_FILE"
  return 1
}

rest="${URL#*://}"
authority="${rest%%/*}"
if [[ "$authority" == \[* ]]; then
  host="${authority%%]*}"; host="${host#\[}"
else
  host="${authority%%:*}"
fi
[[ -n "$host" ]] || { echo "cannot parse host from URL: $URL" >&2; exit 2; }

public=0
while IFS= read -r ip; do
  [[ -z "$ip" ]] && continue
  host_is_private "$ip" || public=1
done < <(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u)

if [[ "$public" == 1 ]] && ! in_scope "$host"; then
  echo "refusing public target '$host': add it to --scope-file" >&2
  exit 2
fi

# One baseline GET, then one POST. No retries, no concurrency.
baseline="$(curl -sS -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" --no-keepalive "$URL" 2>/dev/null || echo "000")"

body="$(head -c "$KEY_BYTES" /dev/zero | tr '\0' 'A')=1"
hdr="$(mktemp)"
trap 'rm -f "$hdr"' EXIT

resp="$(curl -sS --max-time "$TIMEOUT" --no-keepalive --max-redirs 0 \
  -o /dev/null -D "$hdr" -w '%{http_code}|%{time_total}|%{size_download}' \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'User-Agent: php2shell-audit/1.0' \
  -H 'X-Audit-Request: php2shell-conformance' \
  --data-binary "$body" "$URL" 2>/dev/null || echo "000|0|0")"

code="${resp%%|*}"
rest_resp="${resp#*|}"
time_total="${rest_resp%%|*}"
size="${rest_resp##*|}"

phpsessid=0
cookie_len=0
if grep -qi '^set-cookie:.*PHPSESSID' "$hdr"; then
  phpsessid=1
  cookie_line="$(grep -i '^set-cookie:.*PHPSESSID' "$hdr" | head -1)"
  cookie_len=${#cookie_line}
fi

result=""
note=""
case "$code" in
  000) result=STOP; note="no response; check connectivity or a crashed worker" ;;
  502|504) result=STOP; note="possible worker crash or upstream failure; inspect logs, do not retry" ;;
  3??) result=WARN; note="redirect; control was not evaluated at this layer" ;;
  *)
    if [[ ",$EXPECT," == *",$code,"* ]]; then
      result=PASS; note="edge rejected the oversized key"
    elif [[ "$code" == "200" ]]; then
      result=FAIL; note="edge forwarded the oversized key; key-length control absent"
    elif [[ "$code" =~ ^4[0-9][0-9]$ ]]; then
      result=WARN; note="4xx but not in the expected set; confirm the layer"
    else
      result=WARN; note="unexpected status; inspect the response"
    fi
    ;;
esac

if [[ "$JSON" == 1 ]]; then
  printf '{"url":"%s","host":"%s","status":"%s","baseline":"%s","result":"%s","key_bytes":%s,"phpsessid":%s,"cookie_len":%s,"time_s":"%s","note":"%s"}\n' \
    "$(printf '%s' "$URL" | sed 's/"/\\"/g')" \
    "$(printf '%s' "$host" | sed 's/"/\\"/g')" \
    "$code" "$baseline" "$result" "$KEY_BYTES" "$phpsessid" "$cookie_len" \
    "$(printf '%s' "$time_total" | sed 's/"/\\"/g')" \
    "$(printf '%s' "$note" | sed 's/"/\\"/g')"
else
  printf 'RESULT:   %s\n' "$result"
  printf 'URL:      %s\n' "$URL"
  printf 'HTTP:     %s (baseline %s, %.3fs, %s bytes)\n' "$code" "$baseline" "$time_total" "$size"
  printf 'KEY:      %s bytes\n' "$KEY_BYTES"
  printf 'PHPSESSID: %s (header length %s)\n' "$phpsessid" "$cookie_len"
  printf 'NOTE:     %s\n' "$note"
fi

case "$result" in
  PASS) exit 0 ;;
  FAIL) exit 1 ;;
  *) exit 2 ;;
esac
