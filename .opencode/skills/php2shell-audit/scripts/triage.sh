#!/usr/bin/env bash
# php2shell triage: one fast decision per host.
# Read-only. No exploit payloads. Private/loopback lab targets need no setup.
set -uo pipefail

PHP_BIN="${PHP_BIN:-php}"
TIMEOUT="${TIMEOUT:-15}"
SSH_HOST=""
LOCAL=1
JSON=0
EXPOSURE="unknown"
SCOPE_FILE=""
HOSTS_FILE=""
export PHP_BIN

version_ge() {
  [[ -n "$1" && -n "$2" ]] || return 1
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]
}

usage() {
  cat <<'EOF'
Usage: triage.sh [--local | --host user@host | --hosts FILE] [options]

Fast PHP2Shell triage. Prints P0/P1/P2/P3/PATCHED and the next action.

Options:
  --local                 Check this host (default)
  --host user@host        Check one host over SSH
  --hosts FILE            Check each host in FILE (one per line, # comments ok)
  --php-bin PATH          PHP CLI binary (default: php, or $PHP_BIN)
  --exposure MODE         internet | partner | internal | local (default: unknown)
  --scope-file FILE       Authorized host list; required only for public targets
  --json                  Emit one JSON object per host
  --timeout SECS          Per-host timeout (default: 15)
  -h, --help              Show this help

Exit codes: 0 patched/P3, 1 P0-P2, 2 unable to determine.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local) LOCAL=1; SSH_HOST=""; shift ;;
    --host) LOCAL=0; SSH_HOST="${2:-}"; shift 2 ;;
    --hosts) LOCAL=0; HOSTS_FILE="${2:-}"; shift 2 ;;
    --php-bin) PHP_BIN="${2:-php}"; shift 2 ;;
    --exposure) EXPOSURE="${2:-unknown}"; shift 2 ;;
    --scope-file) SCOPE_FILE="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    --timeout) TIMEOUT="${2:-15}"; shift 2 ;;
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

resolve_ips() {
  local h="$1"
  getent ahosts "$h" 2>/dev/null | awk '{print $1}' | sort -u
}

in_scope() {
  local h="$1" line cleansuffix
  [[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]] || return 1
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | xargs)"
    [[ -z "$line" ]] && continue
    [[ "$h" == "$line" || "$SSH_HOST" == "$line" ]] && return 0
    if [[ "$line" == \*.* ]]; then
      cleansuffix="${line#\*}"
      [[ "$h" == *"$cleansuffix" ]] && return 0
    fi
  done < "$SCOPE_FILE"
  return 1
}

# Public targets must appear in the scope file. Private/loopback targets are
# already isolated lab resources and run without extra setup.
check_scope() {
  local h="$1" ip
  [[ -z "$h" ]] && return 0
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    if ! host_is_private "$ip"; then
      if in_scope "$h"; then return 0; fi
      echo "refusing public target '$h' ($ip): add it to --scope-file" >&2
      return 1
    fi
  done < <(resolve_ips "$h")
  return 0
}

# Shell payload executed locally or over SSH. Quoted heredoc: no local expansion.
read -r -d '' RUN <<'EOS'
PHP_BIN="${PHP_BIN:-php}"
"$PHP_BIN" -r '
$keys = ["memory_limit","max_memory_limit","post_max_size","upload_max_filesize",
         "session.upload_progress.enabled","max_input_vars","max_input_nesting_level",
         "max_multipart_body_parts","max_file_uploads","fatal_error_backtraces"];
echo "VERSION=", PHP_VERSION, "\n";
echo "SAPI_CLI=", PHP_SAPI, "\n";
foreach ($keys as $k) { echo "INI[", $k, "]=", ini_get($k), "\n"; }
' 2>/dev/null
echo "---MARKERS---"
if command -v apachectl >/dev/null 2>&1; then
  apachectl -M 2>/dev/null | grep -qi 'php_module' && echo "APACHE_PHP=yes"
fi
if command -v frankenphp >/dev/null 2>&1 || pgrep -x frankenphp >/dev/null 2>&1; then
  echo "FRANKENPHP=yes"
fi
if command -v php-fpm >/dev/null 2>&1 || pgrep -x php-fpm >/dev/null 2>&1; then
  echo "FPM=yes"
fi
if command -v php-cgi >/dev/null 2>&1; then
  echo "CGI=yes"
fi
if command -v lsphp >/dev/null 2>&1 || pgrep -x lsphp >/dev/null 2>&1; then
  echo "LSAPI=yes"
fi
EOS

run_one() {
  local host="$1" out
  if [[ -n "$host" ]]; then
    if ! check_scope "$host"; then
      if [[ "$JSON" == 1 ]]; then
        printf '{"asset":"%s","decision":"ERROR","reason":"scope refused; add host to --scope-file"}\n' \
          "$(json_escape "$host")"
      else
        printf 'DECISION: ERROR\nASSET:    %s\nREASON:   scope refused; add host to --scope-file\n' "$host" >&2
      fi
      return 2
    fi
    local b64
    b64="$(printf '%s' "$RUN" | base64 -w0 2>/dev/null || printf '%s' "$RUN" | base64 | tr -d '\n')"
    out="$(timeout "$TIMEOUT" ssh -o BatchMode=yes -o ConnectTimeout="$TIMEOUT" \
      -o StrictHostKeyChecking=accept-new "$host" \
      "printf '%s' '$b64' | base64 -d | bash" 2>/dev/null)"
  else
    out="$(timeout "$TIMEOUT" bash -c "$RUN" 2>/dev/null)"
  fi

  local version sapi_cli apache_php franken fpm cgi lsapi
  version="$(printf '%s\n' "$out" | sed -n 's/^VERSION=//p' | head -1)"
  sapi_cli="$(printf '%s\n' "$out" | sed -n 's/^SAPI_CLI=//p' | head -1)"
  apache_php="$(printf '%s\n' "$out" | grep -q '^APACHE_PHP=yes$' && echo yes || echo no)"
  franken="$(printf '%s\n' "$out" | grep -q '^FRANKENPHP=yes$' && echo yes || echo no)"
  fpm="$(printf '%s\n' "$out" | grep -q '^FPM=yes$' && echo yes || echo no)"
  cgi="$(printf '%s\n' "$out" | grep -q '^CGI=yes$' && echo yes || echo no)"
  lsapi="$(printf '%s\n' "$out" | grep -q '^LSAPI=yes$' && echo yes || echo no)"

  get_ini() {
    printf '%s\n' "$out" | awk -v k="INI[$1]" 'index($0,k"=")==1 {print substr($0,length(k)+2); exit}'
  }

  local sapi
  if [[ "$apache_php" == yes ]]; then sapi=mod_php
  elif [[ "$franken" == yes ]]; then sapi=frankenphp
  elif [[ "$lsapi" == yes ]]; then sapi=lsapi
  elif [[ "$fpm" == yes ]]; then sapi=fpm
  elif [[ "$cgi" == yes ]]; then sapi=cgi
  elif [[ "$sapi_cli" == cli ]]; then sapi=cli
  else sapi="unknown(${sapi_cli:-no-php})"; fi

  local gate="" mm status priority reason next
  mm="${version%.*}"
  case "$mm" in
    8.5) gate=8.5.12 ;;
    8.4) gate=8.4.27 ;;
    8.3) gate=8.3.36 ;;
    8.2) gate=8.2.35 ;;
    *) gate="" ;;
  esac

  if [[ -z "$version" ]]; then
    status=unknown
    if [[ "$sapi" == mod_php || "$sapi" == frankenphp ]]; then
      priority=P0; reason="$sapi present but version unreadable; assume affected and application-independent"
      next="Get one authenticated php -v from the web SAPI, then patch or isolate now."
    else
      priority=P1; reason="PHP version unreadable; assume affected"
      next="Get one authenticated php -v from the web SAPI; do not wait for full inventory."
    fi
  elif [[ -z "$gate" ]]; then
    status=eol
    if [[ "$sapi" == mod_php || "$sapi" == frankenphp ]]; then
      priority=P0; reason="PHP $version is EOL with no listed patch on $sapi"
      next="Upgrade to a supported branch or isolate now; no official patch exists for this branch."
    else
      priority=P1; reason="PHP $version is on an EOL branch with no listed patch"
      next="Upgrade to a supported branch; patch or isolate now."
    fi
  elif version_ge "$version" "$gate"; then
    status=patched
    if [[ "$(get_ini session.upload_progress.enabled)" =~ ^(On|1)$ ]]; then
      priority=P3; reason="patched at $version; upload-progress still enabled (optional hardening)"
      next="Optional: disable session.upload_progress; keep monitoring."
    else
      priority=PATCHED; reason="version $version meets gate $gate"
      next="No action; keep monitoring and keep the CI gate."
    fi
  else
    status=vulnerable
    if [[ "$sapi" == mod_php || "$sapi" == frankenphp ]]; then
      priority=P0; reason="$sapi on $version < $gate (application-independent path)"
      next="Capture php -v + SAPI + pool config, then patch or isolate now."
    elif [[ "$sapi" == fpm || "$sapi" == lsapi || "$sapi" == cgi || "$sapi" == unknown* ]]; then
      priority=P1; reason="$sapi on $version < $gate (application-specific or unknown web path)"
      next="Capture evidence and patch now; interim controls are not a fix."
    else
      priority=P2; reason="$sapi on $version < $gate (no web SAPI detected)"
      next="Patch in the next window; confirm whether a web SAPI is reachable."
    fi
  fi

  if [[ "$EXPOSURE" == local && "$priority" =~ ^P[01]$ ]]; then
    priority=P2; reason="$reason; exposure=local"
  elif [[ "$EXPOSURE" == internal && "$priority" == P0 ]]; then
    priority=P1; reason="$reason; exposure=internal"
  fi

  local mem maxmem upload fatal interim
  mem="$(get_ini memory_limit)"
  maxmem="$(get_ini max_memory_limit)"
  upload="$(get_ini session.upload_progress.enabled)"
  fatal="$(get_ini fatal_error_backtraces)"
  if [[ "$mem" == "-1" && "$upload" =~ ^(Off|0|)$ ]]; then
    interim="present"
  else
    interim="partial"
  fi

  local label="${host:-local}"
  if [[ "$JSON" == 1 ]]; then
    printf '{"asset":"%s","decision":"%s","status":"%s","sapi":"%s","version":"%s","gate":"%s","exposure":"%s","reason":"%s","interim":"%s","memory_limit":"%s","max_memory_limit":"%s","upload_progress":"%s","fatal_error_backtraces":"%s","evidence":[{"type":"version","version":"%s","sapi":"%s","gate":"%s"}],"remediation":"%s","next":"%s"}\n' \
      "$(json_escape "$label")" "$priority" "$status" "$(json_escape "$sapi")" \
      "$(json_escape "$version")" "$(json_escape "$gate")" "$(json_escape "$EXPOSURE")" \
      "$(json_escape "$reason")" "$interim" "$(json_escape "$mem")" \
      "$(json_escape "$maxmem")" "$(json_escape "$upload")" "$(json_escape "$fatal")" \
      "$(json_escape "$version")" "$(json_escape "$sapi")" "$(json_escape "$gate")" \
      "$(json_escape "$next")" "$(json_escape "$next")"
  else
    printf 'DECISION: %s\n' "$priority"
    printf 'SAPI:     %s\n' "$sapi"
    printf 'VERSION:  %s\n' "${version:-unknown}"
    printf 'GATE:     %s\n' "${gate:-none}"
    printf 'STATUS:   %s\n' "$status"
    printf 'REASON:   %s\n' "$reason"
    printf 'INTERIM:  %s (memory_limit=%s, max_memory_limit=%s, upload_progress=%s, fatal_backtraces=%s)\n' \
      "$interim" "${mem:-?}" "${maxmem:-?}" "${upload:-?}" "${fatal:-?}"
    printf 'NEXT:     %s\n' "$next"
  fi

  case "$priority" in
    PATCHED|P3) return 0 ;;
    P0|P1|P2) return 1 ;;
    *) return 2 ;;
  esac
}

rc=0
if [[ -n "$HOSTS_FILE" ]]; then
  [[ -f "$HOSTS_FILE" ]] || { echo "hosts file not found: $HOSTS_FILE" >&2; exit 2; }
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | xargs)"
    [[ -z "$line" ]] && continue
    run_one "$line" || rc=$?
  done < "$HOSTS_FILE"
elif [[ -n "$SSH_HOST" ]]; then
  run_one "$SSH_HOST" || rc=$?
else
  run_one "" || rc=$?
fi
exit "$rc"
