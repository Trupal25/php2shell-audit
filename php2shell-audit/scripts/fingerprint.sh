#!/usr/bin/env bash
# php2shell fingerprint: passive HTTP classification for targets without SSH.
# One GET. No exploit payloads, no content discovery, no version proof.
set -uo pipefail

URL=""
SCOPE_FILE=""
TIMEOUT=10
JSON=0

usage() {
  cat <<'EOF'
Usage: fingerprint.sh --url URL [options]

One passive GET. Reports PHP presence, version hint, likely SAPI, and a triage
decision. Headers are hints, not proof; confirm with an authenticated php -v.

Options:
  --url URL            Target URL (required)
  --scope-file FILE    Authorized host list; required only for public targets
  --timeout SECS       Request timeout (default: 10)
  --json               Emit one JSON object
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2 ;;
    --scope-file) SCOPE_FILE="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-10}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$URL" ]] || { echo "--url is required" >&2; usage; exit 2; }

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
      suffix="${line#\*}"; [[ "$h" == *"$suffix" ]] && return 0
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

hdr="$(mktemp)"; body="$(mktemp)"
trap 'rm -f "$hdr" "$body"' EXIT

code="$(curl -sS -D "$hdr" -o "$body" --max-time "$TIMEOUT" --max-filesize 1048576 --no-keepalive \
  --max-redirs 0 -A 'php2shell-audit/1.0' -w '%{http_code}' "$URL" 2>/dev/null || echo 000)"

server="$(grep -i '^server:' "$hdr" 2>/dev/null | head -1 | cut -d' ' -f2- | tr -d '\r')"
xpb="$(grep -i '^x-powered-by:' "$hdr" 2>/dev/null | head -1 | cut -d' ' -f2- | tr -d '\r')"
location="$(grep -i '^location:' "$hdr" 2>/dev/null | head -1 | cut -d' ' -f2- | tr -d '\r')"
phpsessid=no
grep -qi 'PHPSESSID' "$hdr" 2>/dev/null && phpsessid=yes
php_links="$(grep -oE 'href="[^"]*\.php[^"]*"' "$body" 2>/dev/null | head -3 | tr '\n' ' ')"

php_hint="unknown"
[[ "$phpsessid" == yes ]] && php_hint="likely"
[[ -n "$php_links" ]] && php_hint="likely"
[[ -n "$xpb" ]] && php_hint="yes"

version=""
if [[ "$xpb" =~ PHP/([0-9]+\.[0-9]+\.[0-9]+) ]]; then
  version="${BASH_REMATCH[1]}"
elif [[ "$server" =~ PHP/([0-9]+\.[0-9]+\.[0-9]+) ]]; then
  version="${BASH_REMATCH[1]}"
fi

sapi="unknown"
confidence="low"
case "$server" in
  *[Aa]pache*)
    if [[ "$php_hint" != "unknown" ]]; then sapi="mod_php"; confidence="medium"; fi
    ;;
  *nginx*)
    if [[ "$php_hint" != "unknown" ]]; then sapi="fpm"; confidence="medium"; fi
    ;;
  *[Cc]addy*|*[Ff]ranken[Bb]PHP*)
    sapi="frankenphp"; confidence="medium"
    ;;
  *[Ll]ite[Ss]peed*)
    sapi="lsapi"; confidence="medium"
    ;;
esac

gate=""
case "${version%.*}" in
  8.5) gate=8.5.12 ;;
  8.4) gate=8.4.27 ;;
  8.3) gate=8.3.36 ;;
  8.2) gate=8.2.35 ;;
esac

decision="VERIFY"
reason=""
if [[ -n "$version" && -n "$gate" ]]; then
  if [[ "$(printf '%s\n%s\n' "$gate" "$version" | sort -V | head -1)" == "$gate" ]]; then
    decision="LIKELY-PATCHED"; reason="header hint $version >= $gate; verify with php -v"
  else
    decision="LIKELY-VULNERABLE"; reason="header hint $version < $gate"
  fi
elif [[ "$php_hint" != "unknown" ]]; then
  decision="ASSUME-AFFECTED"; reason="PHP detected but version is not exposed"
else
  decision="UNKNOWN"; reason="no PHP signal; do not conclude 'not PHP' from headers alone"
fi

if [[ "$decision" == "LIKELY-VULNERABLE" && "$sapi" == "mod_php" ]]; then
  decision="P0"
elif [[ "$decision" == "LIKELY-VULNERABLE" && ( "$sapi" == "fpm" || "$sapi" == "lsapi" ) ]]; then
  decision="P1"
elif [[ "$decision" == "ASSUME-AFFECTED" ]]; then
  decision="P1"
fi

if [[ "$JSON" == 1 ]]; then
  printf '{"url":"%s","host":"%s","http":"%s","php":"%s","version_hint":"%s","sapi_hint":"%s","confidence":"%s","decision":"%s","reason":"%s","server":"%s","x_powered_by":"%s","phpsessid":"%s","location":"%s"}\n' \
    "$(printf '%s' "$URL" | sed 's/"/\\"/g')" "$(printf '%s' "$host" | sed 's/"/\\"/g')" \
    "$code" "$php_hint" "$version" "$sapi" "$confidence" "$decision" \
    "$(printf '%s' "$reason" | sed 's/"/\\"/g')" \
    "$(printf '%s' "$server" | sed 's/"/\\"/g')" \
    "$(printf '%s' "$xpb" | sed 's/"/\\"/g')" "$phpsessid" \
    "$(printf '%s' "$location" | sed 's/"/\\"/g')"
else
  printf 'DECISION:  %s\n' "$decision"
  printf 'PHP:       %s\n' "$php_hint"
  printf 'VERSION:   %s\n' "${version:-not exposed}"
  printf 'SAPI HINT: %s (%s confidence)\n' "$sapi" "$confidence"
  printf 'HTTP:      %s\n' "$code"
  printf 'SERVER:    %s\n' "${server:-unknown}"
  printf 'X-POWERED: %s\n' "${xpb:-not set}"
  printf 'PHPSESSID: %s\n' "$phpsessid"
  printf 'REASON:    %s\n' "$reason"
  printf 'NEXT:      Get one authenticated php -v from the web SAPI; headers are not proof.\n'
  [[ -n "$location" ]] && printf 'REDIRECT:   %s (re-run on the final URL)\n' "$location"
fi

case "$decision" in
  P0|P1|LIKELY-VULNERABLE|ASSUME-AFFECTED) exit 1 ;;
  LIKELY-PATCHED) exit 0 ;;
  *) exit 2 ;;
esac
