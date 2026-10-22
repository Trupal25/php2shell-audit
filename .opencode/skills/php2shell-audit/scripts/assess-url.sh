#!/usr/bin/env bash
# php2shell assess-url: full URL-based remote assessment workflow.
#
# One authorized URL in -> one evidence-backed assessment report out:
#   1. SSRF-safe target authorization (URL parsing, scope check, DNS locality
#      check, one pinned address per request) via scripts/url_guard.py.
#   2. Bounded redirect-authorized GET collection (raw headers/body per hop).
#   3. One bounded long-key edge-conformance POST on the final URL.
#   4. Derived fingerprint/edge artifacts -> chain verdict -> optional RCE
#      evidence validation -> assessment.json + findings.jsonl + report.md
#      + findings.csv.
#
# Safety model (safe by default):
#   - HTTP/HTTPS only; userinfo/credentials refused; malformed URLs refused.
#   - Every resolved address must be globally routable unless --lab is given
#     (loopback/private/link-local/unique-local/metadata all require --lab).
#   - Public targets must appear in --scope-file; --lab never waives the
#     scope requirement for a public host.
#   - DNS is resolved once by the guard and pinned with curl --resolve so the
#     actual request cannot silently change destination (DNS rebinding).
#   - Redirect targets are re-authorized before use; https->http downgrades
#     are refused and never followed.
#   - TLS certificate verification is never disabled.
#   - No credentials, cookies, session tokens, or exploit payloads are sent.
#   - Response sizes, connection time, total request time, and redirect count
#     are bounded.
#
# Remote assessment is deliberately separate from the Docker lab reproduction
# (lab-repro.sh): a URL-only run sends no execution trigger and can never
# produce RCE-CONFIRMED on its own.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL_VERSION="$(cat "$HERE/../VERSION" 2>/dev/null || echo 0)"

URL=""
SCOPE_FILE=""
OUT=""
ASSET=""
EXPOSURE="unknown"
CONNECT_TIMEOUT=5
TIMEOUT=15
MAX_REDIRS=5
MAX_BYTES=1048576
LAB=0
JSON=0
RCE_EVIDENCE=""
MARKERS=""
VERIFY_DIR=""

usage() {
  cat <<EOF
Usage: assess-url.sh [--url] URL [options]

Full URL-based remote assessment: safe HTTP collection + derived
fingerprint/edge evidence + chain verdict + a structured report.

Options:
  URL                   Target URL (positional) — http/https only
  --url URL             Same as positional; one of the two is required
  --out DIR             Output directory (default: url-audit-<timestamp>)
  --asset NAME          Asset name (default: target host)
  --scope-file FILE     Authorized host list; required for public targets
                        (one host per line, '*.suffix' wildcards, '#' comments)
  --lab                 Permit non-global lab addresses (loopback/private/
                        link-local/metadata); never waives the scope-file
                        requirement for a public host
  --exposure VALUE      internet | partner | internal | local | unknown
  --connect-timeout S   curl connect timeout per request (default: 5)
  --timeout S           Total time per request (default: 15)
  --max-redirects N     Redirects followed, each re-authorized (default: 5)
  --max-bytes N         Max response body bytes per request (default: 1048576)
  --rce-evidence FILE   Optional RCE evidence artifact for rce-validate.sh
  --markers FILE        Optional marker file for RCE validation
  --verify DIR          Verify a previous run's artifact hashes and
                        consistency; exit 5 on tampering or contradiction
  --json                Print assessment.json to stdout
  -h, --help            Show this help

Exit codes:
  0  report generated
  2  invalid input, unauthorized or unsafe target (no request sent)
  3  collection did not complete (unreachable, timeout, refused redirect,
     oversized response, or redirect limit) — a failure report is written
  4  internal error
  5  (--verify only) artifact tampering or contradiction detected

Artifacts (inside --out DIR):
  assessment.json      machine-readable evidence artifact (schema 1)
  report.md            human-readable report
  findings.jsonl       one normalized record compatible with report.py
  findings.csv         rendered by scripts/report.py
  fingerprint.json     derived passive-fingerprint artifact (pinned GET)
  edge.json            derived edge-conformance artifact (bounded POST)
  chain.json           precondition-chain verdict from scripts/chain.sh
  rce.json             optional validated RCE evidence state
  raw/                 raw per-request evidence (headers/body/curl stderr)
EOF
}

log() { printf '[assess-url] %s\n' "$*" >&2; }
usage_exit() { echo "assess-url: $1" >&2; usage >&2; exit 2; }
is_uint() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) [[ $# -lt 2 ]] && usage_exit "--url needs a value"; URL="$2"; shift 2 ;;
    --out) [[ $# -lt 2 ]] && usage_exit "--out needs a value"; OUT="$2"; shift 2 ;;
    --asset) [[ $# -lt 2 ]] && usage_exit "--asset needs a value"; ASSET="$2"; shift 2 ;;
    --scope-file) [[ $# -lt 2 ]] && usage_exit "--scope-file needs a value"; SCOPE_FILE="$2"; shift 2 ;;
    --exposure) [[ $# -lt 2 ]] && usage_exit "--exposure needs a value"; EXPOSURE="$2"; shift 2 ;;
    --connect-timeout) [[ $# -lt 2 ]] && usage_exit "--connect-timeout needs a value"; CONNECT_TIMEOUT="$2"; shift 2 ;;
    --timeout|--max-time) [[ $# -lt 2 ]] && usage_exit "--timeout needs a value"; TIMEOUT="$2"; shift 2 ;;
    --max-redirects|--max-redirs) [[ $# -lt 2 ]] && usage_exit "--max-redirects needs a value"; MAX_REDIRS="$2"; shift 2 ;;
    --max-bytes) [[ $# -lt 2 ]] && usage_exit "--max-bytes needs a value"; MAX_BYTES="$2"; shift 2 ;;
    --rce-evidence) [[ $# -lt 2 ]] && usage_exit "--rce-evidence needs a value"; RCE_EVIDENCE="$2"; shift 2 ;;
    --markers) [[ $# -lt 2 ]] && usage_exit "--markers needs a value"; MARKERS="$2"; shift 2 ;;
    --verify) [[ $# -lt 2 ]] && usage_exit "--verify needs a value"; VERIFY_DIR="$2"; shift 2 ;;
    --lab) LAB=1; shift ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; while [[ $# -gt 0 ]]; do
          [[ -z "$URL" ]] || usage_exit "unexpected extra positional argument: $1"
          URL="$1"; shift
        done ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)  [[ -z "$URL" ]] || usage_exit "unexpected extra positional argument: $1"; URL="$1"; shift ;;
  esac
done

# ---- artifact verification mode ------------------------------------------------
if [[ -n "$VERIFY_DIR" ]]; then
  [[ -d "$VERIFY_DIR" ]] || { echo "assess-url: no such directory: $VERIFY_DIR" >&2; exit 4; }
  python3 - "$VERIFY_DIR" <<'PY'
import hashlib, json, os, sys

d = sys.argv[1]
apath = os.path.join(d, "assessment.json")
if not os.path.isfile(apath):
    print(f"assess-url: no assessment.json in {d}", file=sys.stderr)
    raise SystemExit(4)
try:
    with open(apath, encoding="utf-8", errors="replace") as fh:
        assessment = json.load(fh)
except (OSError, json.JSONDecodeError) as exc:
    print(f"assess-url: unreadable assessment.json: {exc}", file=sys.stderr)
    raise SystemExit(4)

sha = assessment.get("artifact_hashes", {}).get("sha256", {})
gen = assessment.get("generated_sha256", {})
problems = []
checked = 0

def match(rel, expected):
    global checked
    path = os.path.join(d, rel)
    if not os.path.isfile(path):
        problems.append(f"missing: {rel}")
        return
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    checked += 1
    if digest != expected:
        problems.append(f"tampered: {rel}")

for rel, expected in sorted(sha.items()):
    if not isinstance(expected, str) or len(expected) != 64:
        problems.append(f"invalid hash entry for {rel}")
        continue
    match(rel, expected)
for rel, expected in sorted(gen.items()):
    if isinstance(expected, dict) and "sha256" in expected:
        expected = expected["sha256"]
    if not isinstance(expected, str) or len(expected) != 64:
        problems.append(f"invalid generated hash entry for {rel}")
        continue
    match(rel, expected)

if not sha and not gen:
    problems.append("assessment records no artifact hashes")
consistency = assessment.get("consistency", {})
if consistency.get("ok") is False:
    for reason in consistency.get("reasons", []):
        problems.append(f"contradiction: {reason}")
if problems:
    print(f"VERIFY: TAMPERED ({checked} artifacts checked)")
    for p in problems:
        print(f"  - {p}")
    raise SystemExit(5)
print(f"VERIFY: OK ({checked} artifacts match)")
raise SystemExit(0)
PY
  exit $?
fi

# ---- argument validation --------------------------------------------------------
[[ -n "$URL" ]] || usage_exit "a target URL is required (positional or --url)"

is_uint "$CONNECT_TIMEOUT" && (( CONNECT_TIMEOUT >= 1 && CONNECT_TIMEOUT <= 3600 )) \
  || usage_exit "--connect-timeout must be an integer 1..3600 (got '$CONNECT_TIMEOUT')"
is_uint "$TIMEOUT" && (( TIMEOUT >= 1 && TIMEOUT <= 3600 )) \
  || usage_exit "--timeout must be an integer 1..3600 (got '$TIMEOUT')"
is_uint "$MAX_REDIRS" && (( MAX_REDIRS <= 10 )) \
  || usage_exit "--max-redirects must be an integer 0..10 (got '$MAX_REDIRS')"
is_uint "$MAX_BYTES" && (( MAX_BYTES >= 1024 && MAX_BYTES <= 16777216 )) \
  || usage_exit "--max-bytes must be an integer 1024..16777216 (got '$MAX_BYTES')"
case "$EXPOSURE" in
  internet|partner|internal|local|unknown) ;;
  *) usage_exit "--exposure must be one of: internet, partner, internal, local, unknown (got '$EXPOSURE')" ;;
esac
if [[ -n "$RCE_EVIDENCE" && ! -f "$RCE_EVIDENCE" ]]; then
  usage_exit "--rce-evidence not found: $RCE_EVIDENCE"
fi
if [[ -n "$MARKERS" && -z "$RCE_EVIDENCE" ]]; then
  usage_exit "--markers requires --rce-evidence"
fi
if [[ -n "$MARKERS" && ! -f "$MARKERS" ]]; then
  usage_exit "--markers not found: $MARKERS"
fi
if command -v curl >/dev/null 2>&1; then :; else
  echo "assess-url: curl is required" >&2; exit 4
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "assess-url: python3 is required" >&2; exit 4
fi
if [[ -n "$SCOPE_FILE" && ! -f "$SCOPE_FILE" ]]; then
  usage_exit "--scope-file not found: $SCOPE_FILE"
fi

[[ -n "$ASSET" ]] || ASSET="$(printf '%s' "$URL" | sed -E 's#^[a-zA-Z]+://##; s#[/?].*$##; s#:[0-9]+$##')"
[[ -n "$OUT" ]] || OUT="url-audit-$(date +%Y%m%d-%H%M%S)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log "target=$URL asset=$ASSET out=$OUT lab=$LAB scope_file=${SCOPE_FILE:-none}"

# ---- pre-flight authorization (url_guard.py) ------------------------------------
mkdir -p "$OUT/raw"
GUARD_JSON="$OUT/raw/guard-hop-00.json"
guard_args=(--url "$URL")
[[ -n "$SCOPE_FILE" ]] && guard_args+=(--scope-file "$SCOPE_FILE")
[[ "$LAB" == 1 ]] && guard_args+=(--lab)

if ! python3 "$HERE/url_guard.py" "${guard_args[@]}" > "$GUARD_JSON" 2>"$OUT/raw/guard-hop-00.err"; then
  echo "assess-url: refused target:" >&2
  python3 - "$GUARD_JSON" <<'PY' >&2
import json, sys
for reason in json.load(open(sys.argv[1])).get("reasons", []):
    print(f"  - {reason}")
PY
  rm -f "$OUT/raw/guard-hop-00.json" "$OUT/raw/guard-hop-00.err" "$OUT/raw/hops.tsv"
  rmdir "$OUT/raw" "$OUT" 2>/dev/null
  exit 2
fi

guard_get() {
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("'"$2"'", ""))' "$1"
}

ORIGIN="$(python3 - "$GUARD_JSON" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
scheme, host, port = d.get("scheme", ""), d.get("host", ""), d.get("port", 0)
print(f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}")
PY
)"
log "authorized origin=$ORIGIN"

# ---- bounded, redirect-authorized GET collection ---------------------------------
hops_tsv="$OUT/raw/hops.tsv"
: > "$hops_tsv"

append_hop() { # hop method url pin rc status time size oversized
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" >> "$hops_tsv"
}

h_url="$(guard_get "$GUARD_JSON" url)"
h_pin="$(guard_get "$GUARD_JSON" pin)"
h_host="$(guard_get "$GUARD_JSON" host)"
h_port="$(guard_get "$GUARD_JSON" port)"

STATE=""
REASONS_NOTE=""
FOLLOWED=0
hop_idx=0
h_rc=0

while :; do
  seq="$(printf 'hop-%02d' "$hop_idx")"
  hfile="$OUT/raw/$seq.headers"
  bfile="$OUT/raw/$seq.body"
  efile="$OUT/raw/$seq.curl-err"

  meta="$(curl -sS -D "$hfile" -o "$bfile" \
    --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
    --max-filesize "$MAX_BYTES" --max-redirs 0 --no-keepalive \
    --noproxy '*' --netrc-file /dev/null \
    -A "php2shell-audit/${TOOL_VERSION}" -H 'Accept: text/html,text/plain,*/*' \
    --resolve "$h_host:$h_port:$h_pin" \
    -w '%{http_code}|%{time_total}|%{size_download}' \
    "$h_url" 2>"$efile")"
  h_rc=$?
  code="${meta%%|*}"
  rest="${meta#*|}"
  ttime="${rest%%|*}"
  dsize="${rest##*|}"
  [[ "$code" =~ ^[0-9]+$ ]] || code="000"

  bytes="$(wc -c <"$bfile" 2>/dev/null || echo 0)"
  oversized=0
  if (( bytes > MAX_BYTES )); then
    oversized=1
    truncate -s "$MAX_BYTES" "$bfile" 2>/dev/null || true
  fi
  if [[ "$h_rc" == "63" ]]; then
    oversized=1
  fi
  append_hop "$seq" GET "$h_url" "$h_pin" "$h_rc" "$code" "$ttime" "$bytes" "$oversized"

  case "$h_rc" in
    0) : ;;
    63)
      if [[ -f "$bfile" ]]; then
        STATE="aborted-oversized-response"
        REASONS_NOTE="response body exceeded --max-bytes=$MAX_BYTES at $seq (received $bytes bytes; artifact truncated)"
      else
        STATE="aborted-oversized-response"
        REASONS_NOTE="response body exceeds --max-bytes=$MAX_BYTES at $seq (curl code 63: transfer aborted before the body was written)"
      fi
      break
      ;;
    28)
      STATE="unreachable"
      REASONS_NOTE="curl exit 28 at $seq: request timed out after ${TIMEOUT}s"
      break
      ;;
    59|60)
      STATE="unreachable"
      REASONS_NOTE="curl exit $h_rc at $seq: TLS certificate verification failed (verification is never disabled)"
      break
      ;;
    6|7|35|52|55|56)
      STATE="unreachable"
      REASONS_NOTE="curl exit $h_rc at $seq: connection/transfer failed"
      break
      ;;
    *)
      STATE="collection-failed"
      REASONS_NOTE="curl exit $h_rc at $seq: unexpected failure"
      break
      ;;
  esac

  if (( code >= 300 && code < 400 )); then
    location="$(grep -i '^location:' "$hfile" 2>/dev/null | head -1 | cut -d' ' -f2- | tr -d '\r')"
    if [[ -z "$location" ]]; then
      break  # 3xx without Location: keep as final observation
    fi
    if (( FOLLOWED >= MAX_REDIRS )); then
      STATE="aborted-redirect-limit"
      REASONS_NOTE="redirect budget reached (--max-redirects=$MAX_REDIRS) at $seq; refused target: $location"
      break
    fi
    next_idx=$(( hop_idx + 1 ))
    gseq="guard-hop-$(printf '%02d' "$next_idx")"
    redir_args=(--base "$h_url" --location "$location")
    [[ -n "$SCOPE_FILE" ]] && redir_args+=(--scope-file "$SCOPE_FILE")
    [[ "$LAB" == 1 ]] && redir_args+=(--lab)
    if ! python3 "$HERE/url_guard.py" "${redir_args[@]}" > "$OUT/raw/$gseq.json" 2>"$OUT/raw/$gseq.err"; then
      STATE="aborted-unsafe-redirect"
      REASONS_NOTE="redirect target refused by url_guard.py: $location (see raw/$gseq.json)"
      break
    fi
    h_url="$(guard_get "$OUT/raw/$gseq.json" url)"
    h_pin="$(guard_get "$OUT/raw/$gseq.json" pin)"
    h_host="$(guard_get "$OUT/raw/$gseq.json" host)"
    h_port="$(guard_get "$OUT/raw/$gseq.json" port)"
    FOLLOWED=$(( FOLLOWED + 1 ))
    hop_idx=$next_idx
    continue
  fi
  break
done

if [[ -z "$STATE" && "$h_rc" == 0 ]]; then
  STATE="ok"
fi
[[ -z "$STATE" ]] && STATE="collection-failed"
[[ -z "$REASONS_NOTE" ]] && REASONS_NOTE="none"

printf '%s\n' "$REASONS_NOTE" > "$OUT/raw/collection-notes.txt"
python3 - "$OUT/raw/collection-state.json" "$STATE" "$REASONS_NOTE" "$FOLLOWED" <<'PY'
import json, sys
path, state, reason, followed = sys.argv[1:5]
json.dump(
    {"state": state, "reason": reason, "redirects_followed": int(followed)},
    open(path, "w"), indent=2, sort_keys=True,
)
with open(path, "a") as fh:
    fh.write("\n")
PY

# ---- one bounded edge-conformance POST on the final URL ---------------------------
if [[ "$STATE" == "ok" ]]; then
  edge_key="$(head -c 2048 /dev/zero | tr '\0' 'A')"
  edge_meta="$(curl -sS -D "$OUT/raw/edge-probe.headers" -o "$OUT/raw/edge-probe.body" \
    --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
    --max-filesize "$MAX_BYTES" --max-redirs 0 --no-keepalive \
    --noproxy '*' --netrc-file /dev/null \
    -A "php2shell-audit/${TOOL_VERSION}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'X-Audit-Request: php2shell-conformance' \
    --resolve "$h_host:$h_port:$h_pin" \
    -X POST --data-binary "${edge_key}=1" \
    -w '%{http_code}|%{time_total}|%{size_download}' \
    "$h_url" 2>"$OUT/raw/edge-probe.curl-err")"
  e_rc=$?
  e_code="${edge_meta%%|*}"
  e_rest="${edge_meta#*|}"
  e_time="${e_rest%%|*}"
  e_size="${e_rest##*|}"
  [[ "$e_code" =~ ^[0-9]+$ ]] || e_code="000"
  e_bytes="$(wc -c <"$OUT/raw/edge-probe.body" 2>/dev/null || echo 0)"
  if (( e_bytes > MAX_BYTES )); then
    truncate -s "$MAX_BYTES" "$OUT/raw/edge-probe.body" 2>/dev/null || true
  fi
  append_hop "edge" POST "$h_url" "$h_pin" "$e_rc" "$e_code" "$e_time" "$e_bytes" 0
fi

# ---- derive fingerprint.json / edge.json from the pinned captures ------------------
python3 - "$OUT" <<'PY'
import json, os, re, sys
from urllib.parse import urlsplit

out = sys.argv[1]

hops = []
with open(os.path.join(out, "raw", "hops.tsv"), encoding="utf-8", errors="replace") as fh:
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 9:
            continue
        hops.append({
            "hop": parts[0], "method": parts[1], "url": parts[2], "pin": parts[3],
            "rc": int(parts[4]), "status": parts[5], "time_s": parts[6],
            "size": parts[7], "oversized": parts[8] == "1",
        })

get_hops = [h for h in hops if h["method"] == "GET" and h["rc"] == 0 and not h["oversized"]]

def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")

def header(headers, name):
    m = re.search(rf"(?im)^\s*{re.escape(name)}\s*:\s*[ \t]*(.*)$", headers)
    return m.group(1).strip() if m else ""

def vt(v):
    parts = []
    for piece in str(v or "").split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)

fp_written = False
if get_hops:
    last = get_hops[-1]
    hdr_path = os.path.join(out, "raw", f"{last['hop']}.headers")
    body_path = os.path.join(out, "raw", f"{last['hop']}.body")
    headers = open(hdr_path, encoding="utf-8", errors="replace").read() if os.path.exists(hdr_path) else ""
    body = open(body_path, encoding="utf-8", errors="replace").read() if os.path.exists(body_path) else ""
    server = header(headers, "Server")
    xpb = header(headers, "X-Powered-By")
    location = header(headers, "Location")
    phpsessid = "yes" if re.search(r"PHPSESSID", headers, re.I) else "no"
    php_links = re.findall(r'href="[^"]*\.php[^"]*"', body)[:3]

    php_hint = "unknown"
    if phpsessid == "yes":
        php_hint = "likely"
    if php_links:
        php_hint = "likely"
    if xpb:
        php_hint = "yes"

    m = re.search(r"PHP/([0-9]+\.[0-9]+\.[0-9]+)", xpb) or re.search(r"PHP/([0-9]+\.[0-9]+\.[0-9]+)", server)
    version = m.group(1) if m else ""
    sapi, confidence = "unknown", "low"
    if re.search(r"apache", server, re.I) and php_hint != "unknown":
        sapi, confidence = "mod_php", "medium"
    elif re.search(r"nginx", server, re.I) and php_hint != "unknown":
        sapi, confidence = "fpm", "medium"
    elif re.search(r"caddy|frankenphp", server, re.I):
        sapi, confidence = "frankenphp", "medium"
    elif re.search(r"litespeed", server, re.I):
        sapi, confidence = "lsapi", "medium"

    GATES = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
    branch = ".".join(version.split(".")[:2]) if version else ""
    gate = GATES.get(branch, "")
    decision, reason = "UNKNOWN", "no PHP signal; do not conclude 'not PHP' from headers alone"
    if version and gate:
        if vt(version) >= vt(gate):
            decision, reason = "LIKELY-PATCHED", f"header hint {version} >= gate {gate}; confirm with one authenticated php -v"
        else:
            decision, reason = "LIKELY-VULNERABLE", f"header hint {version} < gate {gate}"
    elif php_hint != "unknown":
        decision, reason = "ASSUME-AFFECTED", "PHP detected but version is not exposed"
    if decision == "LIKELY-VULNERABLE" and sapi == "mod_php":
        decision = "P0"
    elif decision == "LIKELY-VULNERABLE" and sapi in ("fpm", "lsapi"):
        decision = "P1"
    elif decision == "ASSUME-AFFECTED":
        decision = "P1"

    host = ""
    try:
        host = (urlsplit(last["url"]).hostname or "").lower()
    except ValueError:
        pass

    fp = {
        "url": last["url"], "host": host, "http": last["status"],
        "php": php_hint, "version_hint": version, "sapi_hint": sapi,
        "confidence": confidence, "decision": decision, "reason": reason,
        "server": server, "x_powered_by": xpb, "phpsessid": phpsessid,
        "location": location,
        "derivation": "pinned-GET; same decision rules as fingerprint.sh; collected by assess-url.sh",
    }
    write_json(os.path.join(out, "fingerprint.json"), fp)
    fp_written = True

edge_hops = [h for h in hops if h["method"] == "POST"]
if edge_hops:
    e = edge_hops[-1]
    e_hdrs_path = os.path.join(out, "raw", "edge-probe.headers")
    e_hdrs = open(e_hdrs_path, encoding="utf-8", errors="replace").read() if os.path.exists(e_hdrs_path) else ""
    code = e["status"]
    baseline = get_hops[-1]["status"] if get_hops else ""
    phpsessid = 0
    cookie_len = 0
    m = re.search(r"(?im)^\s*set-cookie\s*:.*PHPSESSID.*$", e_hdrs)
    if m:
        phpsessid = 1
        cookie_len = len(m.group(0))
    if code == "000":
        result, note = "STOP", "no response; check connectivity or a crashed worker"
    elif code in ("502", "504"):
        result, note = "STOP", "possible worker crash or upstream failure; inspect logs, do not retry"
    elif code.startswith("3"):
        result, note = "WARN", "redirect; control was not evaluated at this layer"
    elif code == "200":
        result, note = "FAIL", "edge forwarded the oversized key; key-length control absent"
    elif code in ("400", "403", "413", "414"):
        result, note = "PASS", "edge rejected the oversized key"
    elif code.startswith("4"):
        result, note = "WARN", "4xx but not in the expected set; confirm the layer"
    else:
        result, note = "WARN", "unexpected status; inspect the response"
    edge = {
        "url": e["url"], "host": (urlsplit(e["url"]).hostname or ""), "status": code,
        "baseline": baseline, "result": result, "key_bytes": 2048,
        "phpsessid": phpsessid, "cookie_len": cookie_len,
        "time_s": e["time_s"], "note": note, "curl_exit": e["rc"],
        "derivation": "pinned-POST; same decision rules as edge-conformance.sh; collected by assess-url.sh",
    }
    write_json(os.path.join(out, "edge.json"), edge)

decision_echo = ""
if os.path.isfile(os.path.join(out, "fingerprint.json")):
    decision_echo = json.load(open(os.path.join(out, "fingerprint.json"))).get("decision", "")
print(f"derive: fingerprint={fp_written} decision={decision_echo}", file=sys.stderr)
PY

# ---- chain verdict from the derived artifacts --------------------------------------
chain_args=()
[[ -s "$OUT/fingerprint.json" ]] && chain_args+=(--fingerprint "$OUT/fingerprint.json")
[[ -s "$OUT/edge.json" ]] && chain_args+=(--edge "$OUT/edge.json")
"$HERE/chain.sh" "${chain_args[@]}" --asset "$ASSET" --json > "$OUT/chain.json" 2> "$OUT/chain.err" || true
CHAIN_DECISION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("decision","UNKNOWN"))' "$OUT/chain.json" 2>/dev/null || echo UNKNOWN)"
log "chain=$CHAIN_DECISION"

# ---- optional RCE evidence validation (existing validator, never weakened) ----------
if [[ -n "$RCE_EVIDENCE" ]]; then
  rce_args=(--evidence "$RCE_EVIDENCE" --asset "$ASSET" --seen-file "$OUT/.rce-seen.json" --json)
  [[ -n "$MARKERS" ]] && rce_args+=(--markers "$MARKERS")
  "$HERE/rce-validate.sh" "${rce_args[@]}" > "$OUT/rce.json" 2> "$OUT/rce.err" || true
  log "rce=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("state","?"))' "$OUT/rce.json" 2>/dev/null || echo ERROR)"
fi

# ---- build assessment.json + findings.jsonl ----------------------------------------
python3 - "$OUT" "$URL" "$ASSET" "$TOOL_VERSION" "$LAB" "$SCOPE_FILE" "$EXPOSURE" \
  "$CONNECT_TIMEOUT" "$TIMEOUT" "$MAX_REDIRS" "$MAX_BYTES" "$HERE" "$STARTED_AT" <<'PY'
import hashlib, json, os, sys
from datetime import datetime, timezone

(out, target_url, asset, tool_version, lab, scope_file, exposure,
 connect_timeout, request_timeout, max_redirects, max_bytes, here_dir, started_at) = sys.argv[1:14]

def load_json(name):
    path = os.path.join(out, name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"skip {name}: {exc}", file=sys.stderr)
        return None

def vt(v):
    parts = []
    for piece in str(v or "").split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)

guard = load_json("raw/guard-hop-00.json") or {}
colstate = load_json("raw/collection-state.json") or {}
fp = load_json("fingerprint.json") or {}
edge = load_json("edge.json") or {}
chain = load_json("chain.json") or {}
rce = load_json("rce.json")

hops = []
try:
    with open(os.path.join(out, "raw", "hops.tsv"), encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            p = line.split("\t")
            if len(p) >= 9:
                hops.append({"hop": p[0], "method": p[1], "url": p[2], "pin": p[3],
                             "curl_exit": int(p[4]), "status": p[5], "time_s": p[6],
                             "bytes": int(p[7] or 0), "oversized": p[8] == "1"})
except OSError as exc:
    print(f"skip hops.tsv: {exc}", file=sys.stderr)

state = colstate.get("state", "collection-failed")
state_reason = colstate.get("reason", "") if colstate.get("reason") != "none" else ""
get_hops = [h for h in hops if h["method"] == "GET"]
edge_hop = next((h for h in hops if h["method"] == "POST"), None)
followed = int(colstate.get("redirects_followed", max(0, len(get_hops) - 1)))

# ---- version evidence (never definitive) --------------------------------------------
version_hint = fp.get("version_hint") or ""
version_src = "http-header-hint" if version_hint else "none"
claim = {
    "version": version_hint or None,
    "definitive": False,
    "source": version_src,
    "note": (
        "HTTP banner/headers are hints, not proof; a version number is only established "
        "by an authenticated php -v / web-SAPI php -i on the host."
        if version_hint else
        "No PHP version evidence was observable over HTTP; this is not evidence that "
        "the host is not PHP."
    ),
    "server_header": fp.get("server") or None,
    "x_powered_by": fp.get("x_powered_by") or None,
}

# ---- limits --------------------------------------------------------------------------
limits = []
if any(h["oversized"] or h["curl_exit"] == 63 for h in hops):
    limited = [h for h in hops if h["oversized"] or h["curl_exit"] == 63][-1]
    limits.append({"type": "response-size", "max_bytes": int(max_bytes), "hop": limited["hop"],
                   "note": f"body capped/truncated at {int(max_bytes)} bytes for safety"})
if edge_hop and edge_hop["status"] in ("000", "502", "504"):
    limits.append({"type": "edge-probe-unreachable", "hop": edge_hop["hop"],
                   "note": f"edge probe curl_exit={edge_hop['curl_exit']}"})
if followed >= int(max_redirects) and state in ("ok", "aborted-redirect-limit"):
    limits.append({"type": "redirect-limit", "max_redirects": int(max_redirects),
                   "note": "redirect budget used or exceeded"})

# ---- RCE state notes ------------------------------------------------------------------
rce_state = (rce or {}).get("state") or ""
rce_artifact = "rce.json" if isinstance(rce, dict) and rce else ""
if rce_state:
    rce_note = {
        "RCE-CONFIRMED": "Execution evidence validated by scripts/rce-validate.sh.",
        "RCE-BLOCKED": "Validator established a decisive blocking condition (patch gate or control).",
        "RCE-NOT-REPRODUCED": "Trigger attempted in the supplied artifact as defined there; no execution effects recorded.",
        "RCE-INCONCLUSIVE": "Validator could not establish the result from the supplied artifact.",
    }.get(rce_state, "State from scripts/rce-validate.sh.")
    rce_note = f"{rce_note} The URL-only collection itself sent no exploit payload."
else:
    rce_note = (
        "RCE not established: this URL-only assessment sent no execution trigger and "
        "collected no execution evidence. Confirming RCE requires a separate, authorized "
        "validation module (see references/rce-validation.md)."
    )

# ---- limitations / not tested / next steps --------------------------------------------
limitation_common = [
    "Remote evidence is limited to what one bounded GET (with re-authorized redirects) "
    "plus one bounded long-key POST can observe; HTTP headers may be absent, misleading, "
    "or spoofed.",
    "No server-side php -v, php -i, or filesystem evidence was collected; any version "
    "number or SAPI label here is an unverified hint.",
    "A passing edge probe is a defense-in-depth control check, not a fix; the patch "
    "gate is the fix.",
    "No credentials, cookies, session tokens, or exploit payload were sent by this run.",
]
if state != "ok":
    limitations = [
        f"The target could not be assessed: {state_reason or state}. Exposure conclusions "
        "are not supported by this run.",
    ] + limitation_common
else:
    limitations = limitation_common
if limits:
    limitations.append(
        "Collection limits were reached: " + "; ".join(l["type"] for l in limits) + ". "
        "These boundaries bound what this run can claim."
    )

not_tested = [
    "No RCE/execution trigger was sent and the heap-grooming/exploitation chain is not "
    "implemented in this skill.",
    "No authenticated php -v or web-SAPI ini evidence was collected; the chain verdict "
    "relies on header hints only.",
    "No Docker lab reproduction (lab-repro.sh OOM differential) was run as part of this "
    "URL assessment; that evidence is separate and must be collected independently.",
    "No content discovery, authentication change, or destructive request was attempted.",
]

next_steps = []
if state != "ok":
    next_steps.append("Re-run assess-url.sh once the target is reachable with the same authorization flags.")
if edge.get("result") == "FAIL":
    next_steps.append("Patch the PHP runtimes to the branch gate; treat the failed edge probe as a control gap, not a fix.")
if edge.get("result") == "PASS":
    next_steps.append("Keep the edge key-length control in force and monitor; it is defense-in-depth only.")
next_steps += [
    "Confirm the PHP version with one authenticated php -v / web-SAPI php -i and record "
    "version_proof before closing or escalating.",
    "For local servers, run triage.sh / inventory.sh for authoritative evidence; for a "
    "full pipeline use run-audit.sh with the same scope authorization.",
]

# ---- chain decision / priority / status -------------------------------------------------
def verdict_from_chain(decision, gate, version, sapi_value, chain_obj):
    priority, status, remediation = "UNKNOWN", "unknown", "Confirm with an authenticated php -v before closing."
    if decision == "CHAIN-OPEN":
        s = sapi_value.lower()
        priority = "P0" if ("mod_php" in s or "frankenphp" in s) else "P1"
        status = "vulnerable"
        remediation = "Patch to the branch gate; edge controls are defense-in-depth, not a fix."
    elif decision == "CHAIN-PARTIAL":
        priority, status = "P1", "inconclusive"
        remediation = "Collect one authenticated php -v and web-SAPI ini evidence, then re-run."
    elif decision == "CHAIN-BLOCKED":
        if gate != "none" and version != "unknown" and vt(version) >= vt(gate):
            priority, status = "PATCHED", "patched"
            remediation = "No action; keep the CI gate and monitoring."
        else:
            priority, status = "P3", "blocked"
            remediation = "A decisive control is in force; keep it and monitor."
    else:
        fpd = (chain_obj.get("fingerprint") or {}).get("decision") or "UNKNOWN"
        priority = {"P0": "P0", "P1": "P1", "LIKELY-VULNERABLE": "P1", "ASSUME-AFFECTED": "P1"}.get(fpd, "UNKNOWN")
        status = "unknown" if fpd == "UNKNOWN" else ("vulnerable" if fpd != "LIKELY-PATCHED" else "patched")
        if fpd == "LIKELY-PATCHED":
            priority = "PATCHED"
        remediation = "Confirm with an authenticated php -v before closing."
    return priority, status, remediation

chain_decision = chain.get("decision", "UNKNOWN")
gate = chain.get("gate") or "none"
version = chain.get("version") or version_hint or "unknown"
sapi_value = chain.get("sapi") or fp.get("sapi_hint") or "unknown"
priority, status, remediation = verdict_from_chain(chain_decision, gate, version, sapi_value, chain)

if rce_state == "RCE-CONFIRMED":
    remediation = "RCE evidence validated. Patch immediately; preserve the evidence bundle."
elif rce_state == "RCE-BLOCKED":
    remediation = "Validation blocked by patch or a decisive control; maintain it."

# ---- consistency check ------------------------------------------------------------------
contradictions = []
if state == "ok":
    if not get_hops:
        contradictions.append("state=ok but no successful GET recorded")
    elif get_hops[-1]["curl_exit"] != 0:
        contradictions.append(f"state=ok but last GET curl_exit={get_hops[-1]['curl_exit']}")
if rce_state == "RCE-CONFIRMED" and not (isinstance(rce, dict) and rce.get("state") == "RCE-CONFIRMED"):
    contradictions.append("RCE-CONFIRMED reported without a matching validated rce.json artifact")
if claim["version"] and version_src != "http-header-hint":
    contradictions.append("version recorded without a recognized source")
if claim["definitive"]:
    contradictions.append("HTTP header evidence must never be marked definitive for a version")

finished_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ---- evidence list ------------------------------------------------------------------------
req_summary = {
    "requests": len(hops),
    "redirects_followed": followed,
    "state": state,
    "state_reason": state_reason or None,
    "edge_result": edge.get("result", "SKIPPED"),
    "baseline_status": get_hops[0]["status"] if get_hops else "",
    "final_status": get_hops[-1]["status"] if get_hops else "",
}
evidence = [{"type": "url-collection", "output": req_summary}]
if fp:
    evidence.append({"type": "fingerprint", "output": fp})
if edge:
    evidence.append({"type": "edge-conformance", "output": edge})
if chain is not None and chain:
    evidence.append({"type": "chain", "output": chain})
if rce is not None and rce:
    evidence.append({"type": "rce-validation", "output": rce})

# ---- findings record (report.py-compatible) ------------------------------------------------
record = {
    "asset": asset,
    "priority": priority,
    "status": status,
    "sapi": sapi_value,
    "version": version,
    "gate": gate,
    "exposure": exposure,
    "owner": "",
    "evidence": evidence,
    "remediation": remediation.strip(),
    "repro_state": "",
    "repro_summary": "URL-only assessment; no Docker lab reproduction was part of this run",
    "rce_state": rce_state,
    "verified_at": finished_at,
}
with open(os.path.join(out, "findings.jsonl"), "w", encoding="utf-8") as fh:
    fh.write(json.dumps(record, ensure_ascii=False) + "\n")

# ---- artifact digests ----------------------------------------------------------------------
digests = {}
def add(rel):
    path = os.path.join(out, rel)
    if os.path.isfile(path):
        digests[rel] = hashlib.sha256(open(path, "rb").read()).hexdigest()

raw_dir = os.path.join(out, "raw")
if os.path.isdir(raw_dir):
    for name in sorted(os.listdir(raw_dir)):
        full = os.path.join(raw_dir, name)
        if os.path.isfile(full):
            digests[os.path.join("raw", name)] = hashlib.sha256(open(full, "rb").read()).hexdigest()
for name in ("fingerprint.json", "edge.json", "chain.json", "rce.json"):
    add(name)
digests["findings.jsonl"] = hashlib.sha256(open(os.path.join(out, "findings.jsonl"), "rb").read()).hexdigest()

# ---- assessment artifact ---------------------------------------------------------------------
scope_mode = (guard.get("scope") or {}).get("mode") or ("lab" if lab == "1" else "none")
origin_bits = []
if guard.get("scheme"):
    origin_bits.append(guard["scheme"] + "://")
if guard.get("host"):
    origin_bits.append(guard["host"])
if guard.get("port"):
    origin_bits.append(f":{guard['port']}")
origin = "".join(origin_bits)

chain_compact = {
    "asset": chain.get("asset", asset),
    "decision": chain_decision,
    "version": version,
    "gate": gate,
    "sapi": sapi_value,
    "version_proof": chain.get("version_proof", "none"),
    "proof_note": chain.get("proof_note", ""),
    "preconditions": chain.get("preconditions", {}),
}

fingerprint_compact = {
    "decision": fp.get("decision", "UNKNOWN"),
    "reason": fp.get("reason", ""),
    "php": fp.get("php", "unknown"),
    "sapi_hint": fp.get("sapi_hint", "unknown"),
    "confidence": fp.get("confidence", "low"),
    "server": fp.get("server", ""),
    "x_powered_by": fp.get("x_powered_by", ""),
    "phpsessid": fp.get("phpsessid", "no"),
}

assessment = {
    "schema": 1,
    "kind": "url-assessment",
    "tool": {"name": "php2shell-audit", "version": tool_version, "script": "scripts/assess-url.sh"},
    "target": {
        "url": target_url,
        "origin": origin,
        "host": guard.get("host", ""),
        "port": guard.get("port", 0),
        "asset": asset,
        "scope": {
            "mode": scope_mode,
            "entry": (guard.get("scope") or {}).get("entry", ""),
            "scope_file": scope_file or "",
        },
        "exposure": exposure,
    },
    "safety": {
        "lab_mode": lab == "1",
        "tls_verify": "on",
        "credentials_sent": "none",
        "cookies_sent": "none",
        "payload_sent": "none",
        "pinned_dns": True,
        "redirect_policy": "each redirect target re-authorized before use; TLS downgrades refused",
        "max_redirects": int(max_redirects),
        "max_bytes": int(max_bytes),
        "connect_timeout_s": int(connect_timeout),
        "request_timeout_s": int(request_timeout),
    },
    "timestamps": {"started_at": started_at, "finished_at": finished_at},
    "state": state,
    "state_reason": state_reason or None,
    "collection": {
        "requests": hops,
        "requests_made": len(hops),
        "redirects_followed": followed,
        "edge_result": edge.get("result", "SKIPPED"),
        "baseline_status": get_hops[0]["status"] if get_hops else "",
        "final_status": get_hops[-1]["status"] if get_hops else "",
    },
    "version_evidence": claim,
    "fingerprint": fingerprint_compact,
    "chain": chain_compact,
    "rce": {
        "state": rce_state,
        "note": rce_note,
        "validator_artifact": rce_artifact,
        "allowed_states": ["RCE-CONFIRMED", "RCE-NOT-REPRODUCED", "RCE-INCONCLUSIVE", "RCE-BLOCKED"],
    },
    "limits": limits,
    "limitations": limitations,
    "not_tested": not_tested,
    "next_steps": next_steps,
    "consistency": {"ok": not contradictions, "reasons": contradictions},
    "artifact_hashes": {"sha256": digests},
}
with open(os.path.join(out, "assessment.json"), "w", encoding="utf-8") as fh:
    json.dump(assessment, fh, ensure_ascii=False, indent=2, sort_keys=True)
    fh.write("\n")
PY

if [[ ! -s "$OUT/assessment.json" ]]; then
  echo "assess-url: internal error: assessment.json was not built" >&2
  exit 4
fi

# ---- report steps ------------------------------------------------------------------------------
python3 "$HERE/report.py" --input "$OUT/findings.jsonl" \
  --md "$OUT/findings.md" --csv "$OUT/findings.csv" \
  --title "PHP2Shell URL assessment — $ASSET" > "$OUT/report.log" 2>&1 || true

python3 "$HERE/url-report.py" --assessment "$OUT/assessment.json" \
  --findings "$OUT/findings.jsonl" --out "$OUT/report.md" 2> "$OUT/url-report.err"
url_report_rc=$?
if [[ "$url_report_rc" != 0 ]]; then
  echo "assess-url: internal error: url-report.py failed (exit $url_report_rc); see $OUT/url-report.err" >&2
  exit 4
fi

# ---- summary ------------------------------------------------------------------------------------
if [[ "$JSON" == 1 ]]; then
  cat "$OUT/assessment.json"
else
  python3 - "$OUT/assessment.json" "$OUT" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))
out_dir = sys.argv[2]
c = a["collection"]
v = a["version_evidence"]
r = a["rce"]
f = a["fingerprint"]
print(f"ASSESSMENT: {a['chain']['decision']}  (asset={a['target']['asset']})")
print(f"TARGET:     {a['target']['url']}")
print(f"STATE:      {a['state']}" + (f" ({a['state_reason']})" if a.get("state_reason") else ""))
print(f"PHP:        {f['php']}  ({f['sapi_hint']}, {f['confidence']} confidence)")
print(f"VERSION:    {v['version'] or 'not exposed'}  [header hint; not proof; confirm with an authenticated php -v]")
print(f"HTTP:       baseline={c['baseline_status'] or '-'}  final={c['final_status'] or '-'}  redirects={c['redirects_followed']}")
print(f"EDGE:       {c['edge_result']}")
print(f"CHAIN:      {a['chain']['decision']}")
rc = r["state"] or "not established (URL-only assessment; no execution trigger sent)"
print(f"RCE:        {rc}")
print(f"LIMITS:     " + (", ".join(l["type"] for l in a["limits"]) if a["limits"] else "none"))
print(f"REPORT:     {out_dir}/report.md")
PY
fi

if [[ "$STATE" == "ok" ]]; then
  exit 0
fi
exit 3
