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

echo
echo "----"
if [[ "$FAIL" -eq 0 ]]; then
  echo "ALL $PASS TESTS PASSED"
  exit 0
else
  echo "$FAIL TEST(S) FAILED out of $((PASS + FAIL))"
  exit 1
fi
