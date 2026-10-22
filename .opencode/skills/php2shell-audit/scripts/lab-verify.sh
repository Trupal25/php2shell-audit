#!/usr/bin/env bash
# php2shell lab-verify: offline self-tests for every script in this skill.
#
# Builds stub PHP binaries + local HTTP fixtures, then asserts each script's
# decision logic. No real PHP install, no Docker, no internet, no exploit.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0

expect() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    PASS=$((PASS + 1)); echo "ok      $name"
  else
    FAIL=$((FAIL + 1)); echo "FAIL    $name: expected='$expected' actual='$actual'"
  fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# ---- stub PHP ----------------------------------------------------------------
mkdir -p "$tmpdir/bin"
cat > "$tmpdir/bin/php" <<'STUB'
#!/usr/bin/env bash
V="${FAKE_PHP_VERSION:-8.4.26}"
PG="${FAKE_UPLOAD_PROGRESS:-On}"
if [[ "$1" == "-r" ]]; then
  if [[ "$2" == *'VERSION='* ]]; then
    cat <<EOT
VERSION=$V
SAPI_CLI=cli
INI[memory_limit]=8M
INI[max_memory_limit]=256M
INI[post_max_size]=12M
INI[upload_max_filesize]=8M
INI[session.upload_progress.enabled]=$PG
INI[max_input_vars]=5000
INI[max_input_nesting_level]=64
INI[max_multipart_body_parts]=-1
INI[max_file_uploads]=20
INI[fatal_error_backtraces]=1
INI[expose_php]=On
INI[log_errors]=On
INI[error_log]=/var/log/php/error.log
INI[display_errors]=Off
INI[enable_post_data_reading]=On
EOT
  else
    cat <<EOT
version=$V
sapi_cli=cli
ini.memory_limit=8M
ini.max_memory_limit=256M
ini.post_max_size=12M
ini.upload_max_filesize=8M
ini.session.upload_progress.enabled=$PG
ini.max_input_vars=5000
ini.max_input_nesting_level=64
ini.max_multipart_body_parts=-1
ini.max_file_uploads=20
ini.fatal_error_backtraces=1
ini.expose_php=On
ini.log_errors=On
ini.error_log=/var/log/php/error.log
ini.display_errors=Off
ini.enable_post_data_reading=On
EOT
  fi
elif [[ "$1" == "-i" ]]; then
  echo "PHP Version => $V"
  echo "Server API => FPM/FastCGI"
  echo "Build Date => Jan  1 2026"
  echo "memory_limit => 8M => 8M"
  echo "max_memory_limit => 256M => 256M"
  echo "post_max_size => 12M => 12M"
  echo "upload_max_filesize => 8M => 8M"
  echo "session.upload_progress.enabled => $PG => $PG"
  echo "max_input_vars => 5000 => 5000"
  echo "max_input_nesting_level => 64 => 64"
  echo "max_multipart_body_parts => -1 => -1"
  echo "max_file_uploads => 20 => 20"
  echo "fatal_error_backtraces => 1 => 1"
  echo "expose_php => On => On"
  echo "log_errors => On => On"
  echo "error_log => /var/log/php/error.log => /var/log/php/error.log"
  echo "display_errors => Off => Off"
  echo "enable_post_data_reading => On => On"
fi
STUB
cat > "$tmpdir/bin/apachectl" <<'STUB'
#!/usr/bin/env bash
echo " php_module (shared)"
STUB
chmod +x "$tmpdir/bin/php" "$tmpdir/bin/apachectl"

export PATH="$tmpdir/bin:$PATH"

# ---- triage decisions --------------------------------------------------------
triage_decision() {
  local v="${1:-8.4.26}" pg="${2:-On}"
  FAKE_PHP_VERSION="$v" FAKE_UPLOAD_PROGRESS="$pg" "$HERE/triage.sh" --local --json \
    --php-bin "$tmpdir/bin/php" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["decision"])'
}

expect "triage 8.4.26 mod_php -> P0" "P0" "$(triage_decision 8.4.26)"
expect "triage 8.4.27 mod_php progress-on -> P3" "P3"  "$(triage_decision 8.4.27 On)"
expect "triage 8.4.27 mod_php progress-off -> PATCHED" "PATCHED" "$(triage_decision 8.4.27 Off)"
expect "triage 8.5.11 mod_php -> P0" "P0" "$(triage_decision 8.5.11)"
expect "triage 8.5.12 mod_php -> PATCHED" "PATCHED" "$(triage_decision 8.5.12 Off)"
expect "triage 8.1.33 mod_php eol -> P0" "P0" "$(triage_decision 8.1.33)"
expect "triage 8.2.35 mod_php -> PATCHED" "PATCHED" "$(triage_decision 8.2.35 Off)"

# cli SAPI (no apachectl in PATH)
cli_cli() {
  mv "$tmpdir/bin/apachectl" "$tmpdir/bin/apachectl.off"
  local out
  out="$(FAKE_PHP_VERSION="$1" "$HERE/triage.sh" --local --json \
    --php-bin "$tmpdir/bin/php" 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["decision"])')"
  mv "$tmpdir/bin/apachectl.off" "$tmpdir/bin/apachectl"
  printf '%s' "$out"
}
expect "triage 8.4.26 cli -> P2" "P2" "$(cli_cli 8.4.26)"

# unknown version + mod_php
expect "triage unknown-version mod_php -> P0" "P0" "$(
  FAKE_PHP_VERSION="" "$HERE/triage.sh" --local --json \
    --php-bin /bin/false 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["decision"])'
)"

# ---- verify-hardening fixtures -------------------------------------------------
cat > "$tmpdir/php-i-good.txt" <<'EOF'
PHP Version => 8.4.26
Server API => FPM/FastCGI
memory_limit => -1 => -1
max_memory_limit => no value => no value
post_max_size => 8M => 8M
upload_max_filesize => 2M => 2M
session.upload_progress.enabled => Off => Off
max_input_vars => 1000 => 1000
max_input_nesting_level => 64 => 64
max_multipart_body_parts => 100 => 100
max_file_uploads => 20 => 20
fatal_error_backtraces => no value => no value
EOF
cat > "$tmpdir/php-i-bad.txt" <<'EOF'
PHP Version => 8.4.26
Server API => FPM/FastCGI
memory_limit => 128M => 128M
max_memory_limit => 256M => 256M
post_max_size => 12M => 12M
upload_max_filesize => 8M => 8M
session.upload_progress.enabled => On => On
max_input_vars => 5000 => 5000
max_input_nesting_level => 64 => 64
max_multipart_body_parts => -1 => -1
max_file_uploads => 20 => 20
fatal_error_backtraces => no value => no value
EOF

"$HERE/verify-hardening.sh" --from "$tmpdir/php-i-good.txt" >/dev/null 2>&1
expect "verify-hardening good -> exit 0" "0" "$?"
"$HERE/verify-hardening.sh" --from "$tmpdir/php-i-bad.txt" >/dev/null 2>&1
expect "verify-hardening bad -> exit 1" "1" "$?"

# ---- fingerprint + edge fixtures -------------------------------------------------
HTTP_SERVER_PY="$tmpdir/server.py"
cat > "$HTTP_SERVER_PY" <<'PY'
import os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

powered = os.environ["FAKE_X_POWERED_BY"]
origin = os.environ["FAKE_SERVER"]
post_code = int(os.environ.get("FAKE_POST_STATUS", "413"))
port = int(sys.argv[1])

class H(BaseHTTPRequestHandler):
    server_version = origin
    sys_version = ""
    def do_GET(self):
        self.send_response(200)
        if powered and powered != "-":
            self.send_header("X-Powered-By", powered)
        self.send_header("Set-Cookie", "PHPSESSID=labverify; path=/")
        self.end_headers()
        self.wfile.write(b'<html><a href="index.php">home</a></html>')
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(n)
        self.send_response(post_code)
        self.end_headers()
        self.wfile.write(b"no")
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", port), H).serve_forever()
PY

if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  run_server() { # run_server PORT X_POWERED_BY POST_STATUS
    local port="$1" powered="$2" post="$3"
    FAKE_X_POWERED_BY="$powered" FAKE_SERVER="Apache/2.4.54 (Debian)" \
      FAKE_POST_STATUS="$post" python3 "$HTTP_SERVER_PY" "$port" >/dev/null 2>&1 &
    echo $!
  }
  stop_server() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }

  S1="$(run_server 18091 "PHP/8.4.26" 200)"
  sleep 1
  FP_JSON="$tmpdir/fp.json"
  "$HERE/fingerprint.sh" --url http://127.0.0.1:18091/ --json > "$FP_JSON" 2>/dev/null
  fpv="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version_hint",""))' "$FP_JSON")"
  fps="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("sapi_hint",""))' "$FP_JSON")"
  expect "fingerprint version hint" "8.4.26" "$fpv"
  expect "fingerprint sapi hint" "mod_php" "$fps"

  EDGE_JSON="$tmpdir/edge-fail.json"
  "$HERE/edge-conformance.sh" --url http://127.0.0.1:18091/ --json > "$EDGE_JSON" 2>/dev/null
  edge_r="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("result",""))' "$EDGE_JSON")"
  # POST -> baseline 200 (no edge busy); expect FAIL
  expect "edge-conformance 200 -> FAIL" "FAIL" "$edge_r"
  stop_server "$S1"

  S2="$(run_server 18092 "PHP/8.4.26" 413)"
  sleep 1
  EDGE2_JSON="$tmpdir/edge-pass.json"
  "$HERE/edge-conformance.sh" --url http://127.0.0.1:18092/ --json > "$EDGE2_JSON" 2>/dev/null
  edge2_r="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("result",""))' "$EDGE2_JSON")"
  expect "edge-conformance 413 -> PASS" "PASS" "$edge2_r"
  stop_server "$S2"
else
  echo "skip    fingerprint/edge tests (curl or python3 missing)"
fi

# ---- chain ---------------------------------------------------------------------
CHAIN_OUT="$tmpdir/chain.json"
"$HERE/chain.sh" --fingerprint "$FP_JSON" --edge "$EDGE_JSON" --json > "$CHAIN_OUT" 2>/dev/null
chain_d="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("decision",""))' "$CHAIN_OUT")"
expect "chain hint-behind-gate + edge-fail -> CHAIN-OPEN" "CHAIN-OPEN" "$chain_d"

"$HERE/chain.sh" --fingerprint "$FP_JSON" --edge "$EDGE2_JSON" --json > "$tmpdir/chain2.json" 2>/dev/null
chain2_d="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("decision",""))' "$tmpdir/chain2.json")"
expect "chain edge-pass (control active) -> CHAIN-BLOCKED" "CHAIN-BLOCKED" "$chain2_d"

"$HERE/chain.sh" --asset lab-empty > /dev/null 2>&1
expect "chain no evidence -> exit 2 (partial)" "2" "$?"

# local triage with no PHP binary must not turn a header hint into BLOCKED
cat > "$tmpdir/tri-unknown.jsonl" <<'EOF'
{"asset":"lab","decision":"P1","status":"unknown","sapi":"unknown(no-php)","version":"","gate":""}
EOF
"$HERE/chain.sh" --triage "$tmpdir/tri-unknown.jsonl" --fingerprint "$FP_JSON" --edge "$EDGE_JSON" --json > "$tmpdir/chain-unknown.json" 2>/dev/null
chain_unknown_d="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("decision",""))' "$tmpdir/chain-unknown.json")"
expect "chain no-php triage + header hint -> CHAIN-PARTIAL" "CHAIN-PARTIAL" "$chain_unknown_d"

# triage patched 8.4.27 + edge FAIL, still blocked by version
TRI_JSON="$tmpdir/tri-patched.jsonl"
FAKE_PHP_VERSION=8.4.27 "$HERE/triage.sh" --local --json --php-bin "$tmpdir/bin/php" > "$TRI_JSON" 2>/dev/null
"$HERE/chain.sh" --triage "$TRI_JSON" --edge "$EDGE_JSON" --json > "$tmpdir/chain3.json" 2>/dev/null
chain3_d="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("decision",""))' "$tmpdir/chain3.json")"
expect "chain triage-patched + edge-fail -> CHAIN-BLOCKED" "CHAIN-BLOCKED" "$chain3_d"

# ---- RCE evidence validator -------------------------------------------------
RCE="$tmpdir/rce"; mkdir -p "$RCE"
python3 - "$RCE" <<'PY'
import hashlib, json, sys
base = sys.argv[1]
nonce = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
marker = f"PHP2SHELL-LAB-PROOF nonce={nonce}\nroot-check=passed\n"
open(f"{base}/marker.txt", "w").write(marker)
marker_sha = hashlib.sha256(marker.encode()).hexdigest()
request_sha = "f" * 64
base_ev = {
    "kind": "rce-validation", "schema": 1, "asset": "lab-01",
    "surface": "session.upload_progress",
    "preconditions": {
        "php_version": "8.4.26", "web_sapi": "mod_php",
        "upload_progress_enabled": True,
    },
    "validation": {
        "nonce": nonce, "triggered_at": "2026-10-22T10:00:00Z",
        "request_sha256": request_sha, "execution_effects": ["file_write"],
        "marker_sha256": marker_sha,
    },
}
variants = {
    "confirm": {},
    "blocked": {"preconditions": {"php_version": "8.4.27"}},
    "control-off": {"preconditions": {"upload_progress_enabled": False}},
    "not-repro": {"validation": {"execution_effects": []}},
    "tamper": {"validation": {"marker_sha256": "b" * 64}},
}
for name, override in variants.items():
    ev = json.loads(json.dumps(base_ev))
    for section, values in override.items():
        ev[section].update(values)
    json.dump(ev, open(f"{base}/{name}.json", "w"), indent=2)
PY

run_rce() { # evidence expected-state seen extra...
  local ev="$1" expected="$2" seen="$3"
  shift 3
  local out state
  out="$("$HERE/rce-validate.sh" --evidence "$ev" --asset lab-01 --seen-file "$seen" --json "$@" 2>/dev/null)"
  state="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))' 2>/dev/null)"
  expect "rce $(basename "$ev") -> $expected" "$expected" "$state"
}

run_rce "$RCE/confirm.json"       "RCE-CONFIRMED"      "$RCE/seen-confirm.json" --markers "$RCE/marker.txt"
run_rce "$RCE/confirm.json"       "RCE-INCONCLUSIVE"   "$RCE/seen-confirm.json" --markers "$RCE/marker.txt"
run_rce "$RCE/blocked.json"       "RCE-BLOCKED"        "$RCE/seen-blocked.json" --markers "$RCE/marker.txt"
run_rce "$RCE/control-off.json"   "RCE-BLOCKED"        "$RCE/seen-control.json" --markers "$RCE/marker.txt"
run_rce "$RCE/not-repro.json"     "RCE-NOT-REPRODUCED" "$RCE/seen-notrepro.json" --markers "$RCE/marker.txt"
run_rce "$RCE/tamper.json"        "RCE-INCONCLUSIVE"   "$RCE/seen-tamper.json" --markers "$RCE/marker.txt"
run_rce "$RCE/confirm.json"       "RCE-INCONCLUSIVE"   "$RCE/seen-nomarker.json"

# evidence for a different asset must not confirm this audit
rce_asset_out="$("$HERE/rce-validate.sh" --evidence "$RCE/confirm.json" --markers "$RCE/marker.txt" \
  --asset lab-other --seen-file "$RCE/seen-asset.json" --json 2>/dev/null)"
rce_asset_state="$(printf '%s' "$rce_asset_out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))' 2>/dev/null)"
expect "rce asset mismatch -> RCE-INCONCLUSIVE" "RCE-INCONCLUSIVE" "$rce_asset_state"

"$HERE/rce-validate.sh" --evidence "$RCE/confirm.json" --markers "$RCE/marker.txt" \
  --asset lab-01 --seen-file "$RCE/seen-human.json" > "$RCE/human.out" 2>/dev/null
expect "rce human mode prints state" "yes" "$(grep -q 'RCE STATE: RCE-CONFIRMED' "$RCE/human.out" && echo yes || echo no)"

# ---- reproduction report integration (offline pipeline fixture) --------------
# This fixture tests report rendering only. It is not a real lab result and
# must not be presented as exploitation evidence.
cat > "$tmpdir/repro-findings.jsonl" <<'EOF'
{"asset":"lab-repro","priority":"P0","status":"vulnerable","sapi":"mod_php","version":"8.4.26","gate":"8.4.27","notes":"offline report fixture only","evidence":[{"type":"lab-reproduction","output":{"state":"REPRO-OOM-DIFFERENTIAL","observations":{"vulnerable":{"oom_detected":true,"normal_detected":false},"patched":{"oom_detected":false,"normal_detected":true},"execution_effects":[],"rce_observed":false}}}],"repro_state":"REPRO-OOM-DIFFERENTIAL","rce_state":""}
EOF
python3 "$HERE/report.py" --input "$tmpdir/repro-findings.jsonl" \
  --md "$tmpdir/repro-report.md" --csv "$tmpdir/repro-findings.csv" >/dev/null 2>&1
expect "report includes reproduction state" "yes" \
  "$(grep -q 'REPRO-OOM-DIFFERENTIAL' "$tmpdir/repro-report.md" && echo yes || echo no)"
expect "report includes reproduction section" "yes" \
  "$(grep -q '## Reproduction evidence' "$tmpdir/repro-report.md" && echo yes || echo no)"
expect "reproduction report does not claim RCE" "yes" \
  "$(grep -q '| RCE-CONFIRMED |' "$tmpdir/repro-report.md" && echo no || echo yes)"
expect "CSV includes repro_state" "yes" \
  "$(head -1 "$tmpdir/repro-findings.csv" | grep -q 'repro_state' && echo yes || echo no)"

cat > "$tmpdir/repro-noevidence.jsonl" <<'EOF'
{"asset":"lab-repro-noev","priority":"P0","status":"vulnerable","repro_state":"REPRO-OOM-DIFFERENTIAL"}
EOF
python3 "$HERE/report.py" --input "$tmpdir/repro-noevidence.jsonl" \
  --md "$tmpdir/repro-noevidence.md" >/dev/null 2>&1
expect "report flags reproduction state without evidence" "yes" \
  "$(grep -q 'reproduction state without evidence' "$tmpdir/repro-noevidence.md" && echo yes || echo no)"

# ---- end-to-end orchestration ------------------------------------------------
if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  S3="$(run_server 18093 "PHP/8.4.26" 200)"
  sleep 1
  "$HERE/run-audit.sh" --url http://127.0.0.1:18093/ --out "$tmpdir/audit" \
    --asset lab-01 --rce-evidence "$RCE/confirm.json" --markers "$RCE/marker.txt" \
    > "$tmpdir/audit.log" 2>&1
  expect "run-audit exit 0" "0" "$?"
  expect "run-audit report includes RCE-CONFIRMED" "yes" \
    "$(grep -q 'RCE-CONFIRMED' "$tmpdir/audit/report.md" 2>/dev/null && echo yes || echo no)"
  expect "run-audit CSV produced" "yes" \
    "$([[ -s "$tmpdir/audit/findings.csv" ]] && echo yes || echo no)"

  # A reproduction state that contradicts its own observations must not be
  # trusted. This is an offline rejection fixture, not a real lab result.
  cat > "$tmpdir/repro-inconsistent.json" <<'EOF'
{"kind":"lab-reproduction","schema":1,"asset":"lab-01","state":"REPRO-OOM-DIFFERENTIAL","request":{"method":"POST"},"images":{"vulnerable":{"ref":"fixture"},"patched":{"ref":"fixture"}},"observations":{"vulnerable":{"oom_detected":false},"patched":{"oom_detected":false},"execution_effects":[],"rce_observed":false}}
EOF
  "$HERE/run-audit.sh" --url http://127.0.0.1:18093/ --out "$tmpdir/audit-repro-bad" \
    --asset lab-01 --repro-evidence "$tmpdir/repro-inconsistent.json" \
    > "$tmpdir/audit-repro-bad.log" 2>&1
  expect "run-audit rejects inconsistent repro state" "REPRO-INCONCLUSIVE" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["repro_state"])' "$tmpdir/audit-repro-bad/findings.jsonl" 2>/dev/null)"
  stop_server "$S3"
fi

# ---- url workflow (offline + local mock server) --------------------------------
URL_SERVER_PY="$tmpdir/url_server.py"
cat > "$URL_SERVER_PY" <<'PY'
import os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

powered = os.environ.get("FAKE_X_POWERED_BY", "-")
origin = os.environ.get("FAKE_SERVER", "Apache/2.4.54 (Debian)")
post_code = int(os.environ.get("FAKE_POST_STATUS", "200"))
mode = os.environ.get("FAKE_MODE", "ok")
big_kb = int(os.environ.get("FAKE_BIG_KB", "3072"))
sleep_s = float(os.environ.get("FAKE_SLEEP", "6"))
port = int(sys.argv[1])

class H(BaseHTTPRequestHandler):
    server_version = origin
    sys_version = ""
    def do_GET(self):
        if mode == "redirect-good" and self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        if mode == "redirect-loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
            return
        if mode == "redirect-evil":
            self.send_response(302)
            self.send_header("Location", "http://user:pass@127.0.0.1:1/")
            self.end_headers()
            return
        if mode == "big":
            self.send_response(200)
            self.send_header("Content-Length", str(big_kb * 1024))
            if powered and powered != "-":
                self.send_header("X-Powered-By", powered)
            self.end_headers()
            chunk = b"x" * 65536
            for _ in range(big_kb * 1024 // 65536 + 1):
                self.wfile.write(chunk)
            return
        if mode == "slow":
            time.sleep(sleep_s)
        self.send_response(200)
        if powered and powered != "-":
            self.send_header("X-Powered-By", powered)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b'<html><a href="index.php">home</a></html>')
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(n)
        self.send_response(post_code)
        self.end_headers()
        self.wfile.write(b"no")
    def log_message(self, *a):
        pass

ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY

start_url_server() { # start_url_server PORT MODE X_POWERED_BY SLEEP_S POST_STATUS
  local port="$1" m="$2" pw="$3" sl="${4:-0}" pc="${5:-200}"
  FAKE_MODE="$m" FAKE_X_POWERED_BY="$pw" FAKE_SLEEP="$sl" FAKE_POST_STATUS="$pc" \
    python3 "$URL_SERVER_PY" "$port" >/dev/null 2>&1 &
  local pid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/" 2>/dev/null && break
    sleep 0.3
  done
  echo "$pid"
}

# guard-only (offline, no server): authorization decisions
python3 "$HERE/url_guard.py" --url http://127.0.0.1:19001/ >/dev/null 2>&1
expect "url_guard loopback without --lab -> refused" "2" "$?"
python3 "$HERE/url_guard.py" --url http://127.0.0.1:19001/ --lab >/dev/null 2>&1
expect "url_guard loopback with --lab -> authorized" "0" "$?"
python3 "$HERE/url_guard.py" --url http://user:pass@127.0.0.1:19001/ --lab >/dev/null 2>&1
expect "url_guard embedded credentials -> refused" "2" "$?"
python3 "$HERE/url_guard.py" --url ftp://127.0.0.1/ --lab >/dev/null 2>&1
expect "url_guard unsupported scheme -> refused" "2" "$?"
python3 "$HERE/url_guard.py" --url http://169.254.169.254/latest/ >/dev/null 2>&1
expect "url_guard metadata endpoint without --lab -> refused" "2" "$?"
python3 "$HERE/url_guard.py" --url http://169.254.169.254/latest/ --lab >/dev/null 2>&1
expect "url_guard metadata endpoint with --lab -> authorized" "0" "$?"
printf 'other.example\n' > "$tmpdir/scope-miss.txt"
python3 "$HERE/url_guard.py" --url http://8.8.8.8/ --scope-file "$tmpdir/scope-miss.txt" >/dev/null 2>&1
expect "url_guard public IP not in scope -> refused" "2" "$?"
printf '8.8.8.8\n' > "$tmpdir/scope-hit.txt"
python3 "$HERE/url_guard.py" --url http://8.8.8.8/ --scope-file "$tmpdir/scope-hit.txt" >/dev/null 2>&1
expect "url_guard public IP in scope -> authorized (no contact)" "0" "$?"
python3 "$HERE/url_guard.py" --base https://a.example/ --location http://a.example/ok --scope-file "$tmpdir/scope-hit.txt" >/dev/null 2>&1
expect "url_guard https->http redirect downgrade -> refused" "2" "$?"
python3 "$HERE/url_guard.py" --url 'http://[fe80::1%25eth0]/' --lab >/dev/null 2>&1
expect "url_guard scoped IPv6 zone id -> refused" "2" "$?"
python3 "$HERE/url_guard.py" --url 'http://127.0.0.1/\evil' --lab >/dev/null 2>&1
expect "url_guard backslash in URL -> refused" "2" "$?"
python3 "$HERE/url_guard.py" --url http://127.0.0.1:port/ --lab >/dev/null 2>&1
expect "url_guard malformed port -> refused" "2" "$?"
python3 "$HERE/url_guard.py" --url http://no-such-host-4671.example/ --scope-file "$tmpdir/scope-hit.txt" >/dev/null 2>&1
expect "url_guard unresolvable public host -> refused" "2" "$?"

if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  # scenario 1: valid authorized URL -> structured report
  SP="$(start_url_server 18291 ok "PHP/8.4.26")"
  bash "$HERE/assess-url.sh" http://127.0.0.1:18291/ --lab --out "$tmpdir/url-ok" --json \
    > "$tmpdir/url-ok.json" 2>/dev/null
  rc_ok=$?
  expect "assess-url valid run exit 0" "0" "$rc_ok"
  expect "assess-url report exists" "yes" "$([[ -s "$tmpdir/url-ok/report.md" ]] && echo yes || echo no)"
  expect "assess-url assessment schema/kind" "1 url-assessment" \
    "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["schema"], d["kind"])' "$tmpdir/url-ok/assessment.json")"
  expect "assess-url state ok" "ok" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$tmpdir/url-ok.json")"
  expect "assess-url finds version hint" "8.4.26" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version_evidence"]["version"])' "$tmpdir/url-ok.json")"
  expect "assess-url pin recorded per request" "127.0.0.1" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["collection"]["requests"][0]["pin"])' "$tmpdir/url-ok.json")"
  expect "assess-url report says version is not proof" "yes" \
    "$(grep -q 'not proof' "$tmpdir/url-ok/report.md" && echo yes || echo no)"
  expect "assess-url findings.csv produced" "yes" \
    "$([[ -s "$tmpdir/url-ok/findings.csv" ]] && echo yes || echo no)"
  "$HERE/assess-url.sh" --verify "$tmpdir/url-ok" >/dev/null 2>&1
  expect "assess-url verify ok" "0" "$?"

  # scenario 5: insufficient evidence never produces RCE-CONFIRMED
  expect "assess-url URL-only rce_state never confirmed" "yes" \
    "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("yes" if d["rce"]["state"] != "RCE-CONFIRMED" else "no")' "$tmpdir/url-ok.json")"
  expect "assess-url report says RCE not established" "yes" \
    "$(grep -q 'not established' "$tmpdir/url-ok/report.md" && echo yes || echo no)"

  # edge probe FAIL (POST returns 200) -> P0 exposure in findings
  expect "assess-url edge probe FAIL honored" "FAIL" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["collection"]["edge_result"])' "$tmpdir/url-ok.json")"
  expect "assess-url edge-fail -> findings P0" "P0" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("priority"))' "$tmpdir/url-ok/findings.jsonl")"

  # edge probe PASS (POST returns 413) -> decisive control recognized
  SEDGE="$(start_url_server 18292 ok "PHP/8.4.26" 0 413)"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:18292/ --lab --out "$tmpdir/url-pass" --json \
    > "$tmpdir/url-pass.json" 2>/dev/null
  expect "assess-url edge-pass exit 0" "0" "$?"
  expect "assess-url edge PASS honored" "PASS" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["collection"]["edge_result"])' "$tmpdir/url-pass.json")"
  expect "assess-url edge-pass -> findings blocked not P0" "P3" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("priority"))' "$tmpdir/url-pass/findings.jsonl")"
  stop_server "$SEDGE"
  stop_server "$SP"

  # scenario 2: unreachable target -> useful failure report
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:9/ --lab --out "$tmpdir/url-unreach" --json > "$tmpdir/url-unreach.json" 2>/dev/null
  expect "assess-url unreachable exit 3" "3" "$?"
  expect "assess-url unreachable state" "unreachable" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$tmpdir/url-unreach.json")"
  expect "assess-url unreachable still writes a failure report" "yes" \
    "$([[ -s "$tmpdir/url-unreach/report.md" ]] && grep -q 'not supported by this run' "$tmpdir/url-unreach/report.md" && echo yes || echo no)"

  # scenario 3: redirect to prohibited destination refused without contacting it
  SEV="$(start_url_server 18293 redirect-evil "-")"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:18293/ --lab --out "$tmpdir/url-evil" --json > "$tmpdir/url-evil.json" 2>/dev/null
  expect "assess-url unsafe redirect exit 3" "3" "$?"
  expect "assess-url unsafe redirect state" "aborted-unsafe-redirect" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$tmpdir/url-evil.json")"
  expect "assess-url unsafe redirect sent only one request" "1" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["collection"]["requests_made"])' "$tmpdir/url-evil.json")"
  expect "assess-url unsafe redirect reason names credentials" "yes" \
    "$(grep -q 'credentials' "$tmpdir/url-evil/raw/guard-hop-01.json" && echo yes || echo no)"
  stop_server "$SEV"

  # valid redirect must be followed and re-authorized
  SGO="$(start_url_server 18294 redirect-good "PHP/8.4.26")"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:18294/ --lab --out "$tmpdir/url-redir" --json > "$tmpdir/url-redir.json" 2>/dev/null
  expect "assess-url valid redirect exit 0" "0" "$?"
  expect "assess-url valid redirect followed" "1" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["collection"]["redirects_followed"])' "$tmpdir/url-redir.json")"
  expect "assess-url valid redirect finds version at final URL" "8.4.26" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version_evidence"]["version"])' "$tmpdir/url-redir.json")"
  stop_server "$SGO"

  # redirect budget honored
  SLP="$(start_url_server 18295 redirect-loop "-")"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:18295/ --lab --max-redirects 2 \
    --out "$tmpdir/url-loop" --json > "$tmpdir/url-loop.json" 2>/dev/null
  expect "assess-url redirect budget exit 3" "3" "$?"
  expect "assess-url redirect budget state" "aborted-redirect-limit" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$tmpdir/url-loop.json")"
  stop_server "$SLP"

  # oversized response bounded
  SBG="$(start_url_server 18296 big "PHP/8.4.26")"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:18296/ --lab --out "$tmpdir/url-big" --json > "$tmpdir/url-big.json" 2>/dev/null
  expect "assess-url oversized response exit 3" "3" "$?"
  expect "assess-url oversized state" "aborted-oversized-response" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$tmpdir/url-big.json")"
  expect "assess-url oversized limit recorded" "yes" \
    "$(grep -q 'response-size' "$tmpdir/url-big/assessment.json" && echo yes || echo no)"
  stop_server "$SBG"

  # total request timeout bounded
  SSL="$(start_url_server 18297 slow "PHP/8.4.26" 6)"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:18297/ --lab --timeout 1 \
    --out "$tmpdir/url-slow" --json > "$tmpdir/url-slow.json" 2>/dev/null
  expect "assess-url timeout exit 3" "3" "$?"
  expect "assess-url timeout state" "unreachable" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$tmpdir/url-slow.json")"
  stop_server "$SSL"

  # scenario 4: missing/spoofed version headers must stay hints
  SNV="$(start_url_server 18298 ok "-")"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:18298/ --lab --out "$tmpdir/url-nover" --json > "$tmpdir/url-nover.json" 2>/dev/null
  expect "assess-url missing version -> no version claim" "yes" \
    "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("yes" if not d["version_evidence"]["version"] and not d["version_evidence"]["definitive"] else "no")' "$tmpdir/url-nover.json")"
  expect "assess-url missing-version report honest" "yes" \
    "$(grep -q 'no PHP signal' "$tmpdir/url-nover/report.md" && echo yes || echo no)"
  stop_server "$SNV"

  SSF="$(start_url_server 18299 ok "PHP/9.9.9")"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:18299/ --lab --out "$tmpdir/url-spoof" --json > "$tmpdir/url-spoof.json" 2>/dev/null
  expect "assess-url spoofed hint recorded without definitive flag" "9.9.9 False" \
    "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); v=d["version_evidence"]; print(v["version"], v["definitive"])' "$tmpdir/url-spoof.json")"
  stop_server "$SSF"

  # option 6: artifact tampering detection
  cp -r "$tmpdir/url-ok" "$tmpdir/url-tamper"
  echo "tampered" >> "$tmpdir/url-tamper/raw/hop-00.headers"
  "$HERE/assess-url.sh" --verify "$tmpdir/url-tamper" >/dev/null 2>&1
  expect "assess-url verify detects tampering" "5" "$?"

  # optional RCE evidence must go through the existing validator, unchanged
  SRCE="$(start_url_server 18301 ok "PHP/8.4.26")"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:18301/ --lab --asset lab-01 \
    --rce-evidence "$RCE/confirm.json" --markers "$RCE/marker.txt" \
    --out "$tmpdir/url-rce" --json > "$tmpdir/url-rce.json" 2>/dev/null
  expect "assess-url rce-evidence run exit 0" "0" "$?"
  expect "assess-url rce_state from validator" "RCE-CONFIRMED" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["rce"]["state"])' "$tmpdir/url-rce.json")"
  expect "assess-url rce report keeps validator state" "yes" \
    "$(grep -q 'RCE-CONFIRMED' "$tmpdir/url-rce/report.md" && echo yes || echo no)"
  stop_server "$SRCE"

  # CLI validation failures (no request may leave the machine)
  bash "$HERE/assess-url.sh" https://198.51.100.7/ >/dev/null 2>&1
  expect "assess-url public target without scope -> exit 2" "2" "$?"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:1/ --out "$tmpdir/url-nolab" >/dev/null 2>&1
  expect "assess-url loopback without --lab -> exit 2" "2" "$?"
  bash "$HERE/assess-url.sh" --url ftp://127.0.0.1/ --lab >/dev/null 2>&1
  expect "assess-url ftp scheme -> exit 2" "2" "$?"
  bash "$HERE/assess-url.sh" --url 'http://user:pass@127.0.0.1:1/' --lab >/dev/null 2>&1
  expect "assess-url embedded credentials -> exit 2" "2" "$?"
  bash "$HERE/assess-url.sh" >/dev/null 2>&1
  expect "assess-url missing URL -> exit 2" "2" "$?"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:1/ --lab --timeout bogus >/dev/null 2>&1
  expect "assess-url invalid --timeout -> exit 2" "2" "$?"
  bash "$HERE/assess-url.sh" --url http://127.0.0.1:1/ --lab --exposure banana >/dev/null 2>&1
  expect "assess-url invalid --exposure -> exit 2" "2" "$?"
else
  echo "skip    url workflow tests (curl or python3 missing)"
fi

echo
echo "----"
if [[ "$FAIL" -eq 0 ]]; then
  echo "ALL $PASS TESTS PASSED"
  exit 0
else
  echo "$FAIL TEST(S) FAILED out of $((PASS + FAIL))"
  exit 1
fi
