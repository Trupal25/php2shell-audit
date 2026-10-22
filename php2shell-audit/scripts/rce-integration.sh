#!/usr/bin/env bash
# php2shell rce-integration: opt-in, repeatable end-to-end check for the
# external-trigger RCE validation module.
#
# This is deliberately separate from scripts/lab-verify.sh and
# scripts/lab-integration.sh. It requires:
#   - Docker and the php:8.4.26-apache / php:8.4.27-apache images;
#   - python:3.12-slim (or the module runtime image);
#   - an authorized copy of the public php2shell upstream trigger, supplied
#     by the operator. The trigger is not bundled and is not redistributed.
#
# It runs modules/rce-modphp twice against fresh disposable vulnerable/patched
# labs, then asserts the corroborated result, marker binding, patched control,
# and cleanup. It never targets an arbitrary URL.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
EXPLOIT_DIR="${P2S_EXPLOIT_DIR:-}"
OUT=""
ASSET="lab-rce-integration"
TIMEOUT=180
PASS=0
FAIL=0

usage() {
  cat <<'EOF'
Usage: rce-integration.sh --exploit-dir DIR [options]

The directory must contain an authorized php2shell upstream exploit.py. The
trigger source is not included in this repository.

Options:
  --exploit-dir DIR   External trigger directory (or set P2S_EXPLOIT_DIR)
  --out DIR           Artifact directory (default: rce-integration-<timestamp>)
  --asset NAME        Asset name (default: lab-rce-integration)
  --timeout SEC       Per-run module timeout (default: 180)
  -h, --help          Show this help

Exit codes: 0 all assertions passed; 1 assertion or trigger run failed;
            2 missing Docker/image/tool/trigger.
EOF
}

expect() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    PASS=$((PASS + 1)); echo "ok      $name"
  else
    FAIL=$((FAIL + 1)); echo "FAIL    $name: expected='$expected' actual='$actual'"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exploit-dir) EXPLOIT_DIR="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --asset) ASSET="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[[ -n "$EXPLOIT_DIR" ]] || { echo "missing --exploit-dir (or P2S_EXPLOIT_DIR)" >&2; usage >&2; exit 2; }
[[ -d "$EXPLOIT_DIR" ]] || { echo "trigger directory not found: $EXPLOIT_DIR" >&2; exit 2; }
[[ -f "$EXPLOIT_DIR/exploit.py" ]] || { echo "trigger directory has no exploit.py: $EXPLOIT_DIR" >&2; exit 2; }
EXPLOIT_DIR="$(cd "$EXPLOIT_DIR" && pwd)"
[[ -n "$OUT" ]] || OUT="rce-integration-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT" || { echo "cannot create $OUT" >&2; exit 2; }

for tool in docker python3 sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing dependency: $tool" >&2; exit 2; }
done
docker info >/dev/null 2>&1 || { echo "missing dependency: running Docker daemon" >&2; exit 2; }
for image in php:8.4.26-apache php:8.4.27-apache python:3.12-slim; do
  docker image inspect "$image" >/dev/null 2>&1 || {
    echo "missing dependency: image $image (pull it first)" >&2
    exit 2
  }
done

TRIGGER_SHA="$(sha256sum "$EXPLOIT_DIR/exploit.py" | awk '{print $1}')"
echo "[rce-integration] out=$OUT asset=$ASSET"
echo "[rce-integration] external trigger sha256=$TRIGGER_SHA"
echo "[rce-integration] note: the trigger is not bundled; this script only executes the operator-supplied copy in the disposable lab"

get() {
  local file="$1" key="$2"
  python3 - "$file" "$key" <<'PY'
import json, sys
try:
    current = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("missing")
    raise SystemExit
for part in sys.argv[2].split("."):
    if isinstance(current, dict) and part in current:
        current = current[part]
    else:
        print("missing")
        raise SystemExit
if isinstance(current, bool):
    print("true" if current else "false")
elif current is None:
    print("null")
elif isinstance(current, (dict, list)):
    print(json.dumps(current, sort_keys=True))
else:
    print(current)
PY
}

run_case() {
  local label="$1" dest="$2"
  local run_out="$OUT/$dest"
  "$HERE/module-run.sh" --module "$ROOT/modules/rce-modphp" \
    --exploit-dir "$EXPLOIT_DIR" --asset "$ASSET" --out "$run_out" \
    --timeout "$TIMEOUT" --json \
    > "$OUT/$dest.stdout.json" 2> "$OUT/$dest.stderr.log"
  local rc=$?
  expect "$label exit 0" "0" "$rc"
  if [[ "$rc" -ne 0 ]]; then
    sed -n '1,200p' "$OUT/$dest.stderr.log" >&2
  fi
  local json="$run_out/module-run.json"
  [[ -s "$json" ]] || { echo "missing module-run.json for $label" >&2; return 0; }
  expect "$label state completed" "completed" "$(get "$json" state)"
  expect "$label impact" "demonstrated-code-execution" "$(get "$json" classification.impact)"
  expect "$label confidence" "corroborated" "$(get "$json" classification.confidence)"
  expect "$label RCE validator" "RCE-CONFIRMED" "$(get "$json" rce_validation.state)"
  expect "$label target marker" "true" "$(get "$json" corroboration.marker_in_target)"
  expect "$label patched control marker" "false" "$(get "$json" corroboration.control_marker_in_target)"
  expect "$label containers removed" "true" "$(get "$json" cleanup.containers_removed)"
  expect "$label network removed" "true" "$(get "$json" cleanup.network_removed)"
  local nonce marker sha
  nonce="$(get "$json" result.nonce)"
  marker="$run_out/raw/target-marker.bin"
  sha="$(get "$json" corroboration.marker_sha256)"
  expect "$label marker file present" "True" "$([[ -s "$marker" ]] && echo True || echo False)"
  expect "$label marker contains nonce" "True" "$([[ -f "$marker" ]] && grep -a -q "$nonce" "$marker" && echo True || echo False)"
  expect "$label marker hash matches" "True" "$([[ -f "$marker" ]] && [[ "$(sha256sum "$marker" | awk '{print $1}')" == "$sha" ]] && echo True || echo False)"
  local art_ok
  art_ok="$(python3 - "$json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    c = ((d.get("classification") or {}).get("checks") or {}).get("artifacts_verified") or {}
    print("True" if int(c.get("declared") or 0) > 0 and int(c.get("declared") or 0) == int(c.get("verified") or 0) else "False")
except Exception:
    print("False")
PY
)"
  expect "$label artifacts verified" "True" "$art_ok"
  expect "$label vulnerable container removed from Docker" "False" \
    "$(docker inspect "$(get "$json" targets.vulnerable.container)" >/dev/null 2>&1 && echo True || echo False)"
  expect "$label patched container removed from Docker" "False" \
    "$(docker inspect "$(get "$json" targets.patched.container)" >/dev/null 2>&1 && echo True || echo False)"
  expect "$label module container removed from Docker" "False" \
    "$(docker inspect "$(get "$json" module_container.name)" >/dev/null 2>&1 && echo True || echo False)"
  expect "$label network removed from Docker" "False" \
    "$(docker network inspect "$(get "$json" network.name)" >/dev/null 2>&1 && echo True || echo False)"
  echo "[rce-integration] $label marker: $(tr -d '\n' < "$marker" 2>/dev/null || echo missing)"
}

echo "[rce-integration] run 1/2: fresh lab"
run_case "run 1" "run-1"
echo "[rce-integration] run 2/2: fresh lab, fresh nonce"
run_case "run 2" "run-2"

echo
echo "----"
if [[ "$FAIL" -eq 0 ]]; then
  echo "ALL $PASS RCE INTEGRATION TESTS PASSED"
  echo "artifacts: $OUT"
  exit 0
else
  echo "$FAIL RCE INTEGRATION TEST(S) FAILED out of $((PASS + FAIL))"
  exit 1
fi
