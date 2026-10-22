#!/usr/bin/env bash
# php2shell inventory: read-only collection of PHP version, SAPI, ini, and overrides.
# Usage: inventory.sh [--local | --host user@host | --hosts FILE] [--fast] [--json]
set -uo pipefail

PHP_BIN="${PHP_BIN:-php}"
WEB_ROOT="${WEB_ROOT:-/var/www}"
TIMEOUT="${TIMEOUT:-20}"
FAST=0
JSON=0
SSH_HOST=""
HOSTS_FILE=""
SCOPE_FILE=""
export PHP_BIN

usage() {
  cat <<'EOF'
Usage: inventory.sh [--local | --host user@host | --hosts FILE] [options]

Read-only PHP2Shell inventory. Emits version, SAPI, ini, and config overrides.

Options:
  --local                 Check this host (default)
  --host user@host        Check one host over SSH
  --hosts FILE            Check each host in FILE (one per line, # comments ok)
  --scope-file FILE       Authorized host list; required only for public targets
  --php-bin PATH          PHP CLI binary (default: php, or $PHP_BIN)
  --web-root DIR          Scan this tree for ini_set/.user.ini (default: /var/www)
  --fast                  Version/SAPI/ini only; skip config and app scans
  --json                  Emit one JSON object per asset
  --timeout SECS          Per-host timeout (default: 20)
  -h, --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local) SSH_HOST=""; shift ;;
    --host) SSH_HOST="${2:-}"; shift 2 ;;
    --hosts) HOSTS_FILE="${2:-}"; shift 2 ;;
    --scope-file) SCOPE_FILE="${2:-}"; shift 2 ;;
    --php-bin) PHP_BIN="${2:-php}"; export PHP_BIN; shift 2 ;;
    --web-root) WEB_ROOT="${2:-/var/www}"; shift 2 ;;
    --fast) FAST=1; shift ;;
    --json) JSON=1; shift ;;
    --timeout) TIMEOUT="${2:-20}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

host_is_private() {
  local ip="$1"
  case "$ip" in
    10.*|127.*|192.168.*|169.254.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    ::1|fc*|fd*|fe80:*) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_ips() { getent ahosts "$1" 2>/dev/null | awk '{print $1}' | sort -u; }

in_scope() {
  local h="$1" line suffix
  [[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]] || return 1
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(printf '%s' "$line" | xargs)"
    [[ -z "$line" ]] && continue
    [[ "$h" == "$line" || "$SSH_HOST" == "$line" ]] && return 0
    if [[ "$line" == \*.* ]]; then
      suffix="${line#\*}"
      [[ "$h" == *"$suffix" ]] && return 0
    fi
  done < "$SCOPE_FILE"
  return 1
}

check_scope() {
  local h="$1" ip
  [[ -z "$h" ]] && return 0
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    if ! host_is_private "$ip"; then
      in_scope "$h" && return 0
      echo "refusing public target '$h' ($ip): add it to --scope-file" >&2
      return 1
    fi
  done < <(resolve_ips "$h")
  return 0
}

# Collection payload. Quoted heredoc; placeholders substituted below.
COLLECT=$(cat <<'EOS'
PHP_BIN='__PHP_BIN__'
WEB_ROOT='__WEB_ROOT__'
FAST='__FAST__'
"$PHP_BIN" -r '
$keys = ["memory_limit","max_memory_limit","post_max_size","upload_max_filesize",
         "session.upload_progress.enabled","max_input_vars","max_input_nesting_level",
         "max_multipart_body_parts","max_file_uploads","fatal_error_backtraces",
         "expose_php","log_errors","error_log","display_errors","enable_post_data_reading"];
echo "version=", PHP_VERSION, "\n";
echo "sapi_cli=", PHP_SAPI, "\n";
foreach ($keys as $k) { echo "ini.", $k, "=", ini_get($k), "\n"; }
' 2>/dev/null
"$PHP_BIN" -i 2>/dev/null | sed -n 's/^Build Date => /build_date=/p' | head -1
"$PHP_BIN" -i 2>/dev/null | sed -n 's/^Loaded Configuration File => /ini_file=/p' | head -1
"$PHP_BIN" -i 2>/dev/null | sed -n 's/^Scan this dir for additional .ini files => /scan_dir=/p' | head -1

if command -v apachectl >/dev/null 2>&1; then
  apachectl -M 2>/dev/null | grep -qi 'php_module' && echo "marker_apache_php=yes"
fi
if command -v frankenphp >/dev/null 2>&1 || pgrep -x frankenphp >/dev/null 2>&1; then
  echo "marker_frankenphp=yes"
fi
if command -v php-fpm >/dev/null 2>&1 || pgrep -x php-fpm >/dev/null 2>&1; then
  echo "marker_fpm=yes"
fi
if command -v php-cgi >/dev/null 2>&1; then
  echo "marker_cgi=yes"
fi
if command -v lsphp >/dev/null 2>&1 || pgrep -x lsphp >/dev/null 2>&1; then
  echo "marker_lsapi=yes"
fi

if [ "$FAST" = "0" ]; then
  if command -v php-fpm >/dev/null 2>&1; then
    php-fpm -tt 2>&1 | grep -E 'php_admin_(value|flag)|pm\.max_requests' | sed 's/^/override=fpm:/' | head -40
  fi
  for d in /etc/apache2 /etc/httpd; do
    [ -d "$d" ] && grep -RhsE 'php_admin_(value|flag)' "$d" 2>/dev/null | sed 's/^/override=apache:/' | head -20
  done
  if [ -d "$WEB_ROOT" ]; then
    grep -RhsE "ini_set.*(memory_limit|max_memory_limit|post_max_size|upload_max_filesize|session\.upload_progress)" "$WEB_ROOT" 2>/dev/null | sed 's/^/override=app:/' | head -40
    find "$WEB_ROOT" -maxdepth 8 -name '.user.ini' -print 2>/dev/null | sed 's/^/override=userini:/' | head -20
  fi
  if command -v docker >/dev/null 2>&1; then
    docker ps --format '{{.Names}}|{{.Image}}' 2>/dev/null | sed 's/^/override=docker:/' | head -20
    docker ps -q 2>/dev/null | head -20 | xargs -r docker inspect --format 'override=docker_digest:{{.Name}}|{{.Config.Image}}|{{.Image}}' 2>/dev/null | head -20
  fi
fi
EOS
)

RUN="${COLLECT//__PHP_BIN__/$PHP_BIN}"
RUN="${RUN//__WEB_ROOT__/$WEB_ROOT}"
RUN="${RUN//__FAST__/$FAST}"

run_remote() {
  local host="$1" b64
  check_scope "$host" || { echo "error=scope-refused"; return 2; }
  b64="$(printf '%s' "$RUN" | base64 -w0 2>/dev/null || printf '%s' "$RUN" | base64 | tr -d '\n')"
  timeout "$TIMEOUT" ssh -o BatchMode=yes -o ConnectTimeout="$TIMEOUT" \
    -o StrictHostKeyChecking=accept-new "$host" \
    "printf '%s' '$b64' | base64 -d | bash" 2>/dev/null
}

emit_json() {
  local asset="$1" source="$2" file="$3"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$asset" "$source" "$file" <<'PY'
import json, sys
asset, source, path = sys.argv[1:4]
out = {"asset": asset, "source": source, "ini": {}, "overrides": []}
try:
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
except OSError:
    lines = []
for line in lines:
    if "=" not in line:
        continue
    k, v = line.split("=", 1)
    if k.startswith("ini."):
        out["ini"][k[4:]] = v
    elif k == "override":
        out["overrides"].append(v)
    else:
        out[k] = v
print(json.dumps(out, ensure_ascii=False))
PY
  else
    printf '{"asset":"%s","source":"%s","raw":"%s"}\n' \
      "$(json_escape "$asset")" "$(json_escape "$source")" \
      "$(json_escape "$(tr '\n' '|' < "$file")")"
  fi
}

print_human() {
  local asset="$1" source="$2" file="$3"
  printf '\n== %s (%s) ==\n' "$asset" "$source"
  grep -E '^(version|sapi_cli|build_date|ini_file|scan_dir)=' "$file" 2>/dev/null | sed 's/^/  /'
  grep -E '^marker_' "$file" 2>/dev/null | sed 's/^/  /'
  grep -E '^ini\.' "$file" 2>/dev/null | sed 's/^ini\./  /'
  if grep -q '^override=' "$file" 2>/dev/null; then
    echo "  -- overrides --"
    sed -n 's/^override=/  /p' "$file" | head -60
  fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

rc=0
if [[ -n "$HOSTS_FILE" ]]; then
  [[ -f "$HOSTS_FILE" ]] || { echo "hosts file not found: $HOSTS_FILE" >&2; exit 2; }
  declare -a hosts=() files=()
  i=0
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(printf '%s' "$line" | xargs)"
    [[ -z "$line" ]] && continue
    i=$((i + 1))
    f="$tmpdir/$i"
    hosts+=("$line"); files+=("$f")
    ( run_remote "$line" > "$f" 2>/dev/null ) &
  done < "$HOSTS_FILE"
  wait || true
  for idx in "${!files[@]}"; do
    if [[ "$JSON" == 1 ]]; then emit_json "${hosts[$idx]}" "ssh" "${files[$idx]}"; else print_human "${hosts[$idx]}" "ssh" "${files[$idx]}"; fi
  done
elif [[ -n "$SSH_HOST" ]]; then
  f="$tmpdir/one"
  run_remote "$SSH_HOST" > "$f" 2>/dev/null || rc=$?
  if [[ "$JSON" == 1 ]]; then emit_json "$SSH_HOST" "ssh" "$f"; else print_human "$SSH_HOST" "ssh" "$f"; fi
else
  f="$tmpdir/local"
  timeout "$TIMEOUT" bash -c "$RUN" > "$f" 2>/dev/null || rc=$?
  if [[ "$JSON" == 1 ]]; then emit_json "local" "local" "$f"; else print_human "local" "local" "$f"; fi
fi

exit "$rc"
