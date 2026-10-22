#!/usr/bin/env bash
# php2shell lab-integration: Docker-gated integration test.
#
# This is deliberately separate from scripts/lab-verify.sh. It requires a real
# Docker daemon and the two Apache/mod_php images, runs scripts/lab-repro.sh as
# an independent evidence producer, then feeds that evidence into
# scripts/run-audit.sh and asserts that the report shows the observed
# reproduction state. It must never turn the reproduction into RCE-CONFIRMED.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ASSET="lab-repro-integration"
OUT=""
PULL=0
KEEP=0
TIMEOUT=30
V_C=""
P_C=""
PASS=0
FAIL=0

usage() {
  cat <<'EOF'
Usage: lab-integration.sh [options]

Requires Docker and:
  php:8.4.26-apache   vulnerable
  php:8.4.27-apache   patched

Options:
  --out DIR       Artifact directory (default: lab-integration-<timestamp>)
  --asset NAME    Asset name (default: lab-repro-integration)
  --pull          Pull missing images first
  --keep          Keep the lab containers after the test
  --timeout SEC   curl max time per probe (default: 30)
  -h, --help      Show this help

Exit codes: 0 all integration assertions passed; 1 assertion failed;
            2 missing Docker, image, or required tool.
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

cleanup() {
  if [[ "$KEEP" != 1 ]]; then
    [[ -n "$V_C" ]] && docker rm -f "$V_C" >/dev/null 2>&1 || true
    [[ -n "$P_C" ]] && docker rm -f "$P_C" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:-}"; shift 2 ;;
    --asset) ASSET="${2:-}"; shift 2 ;;
    --pull) PULL=1; shift ;;
    --keep) KEEP=1; shift ;;
    --timeout) TIMEOUT="${2:-30}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "$OUT" ]] || OUT="lab-integration-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

for tool in docker curl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing dependency: $tool" >&2; exit 2; }
done
docker info >/dev/null 2>&1 || { echo "missing dependency: running Docker daemon" >&2; exit 2; }
for image in php:8.4.26-apache php:8.4.27-apache; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    if [[ "$PULL" == 1 ]]; then
      docker pull "$image" >/dev/null 2>&1 || { echo "could not pull $image" >&2; exit 2; }
    else
      echo "missing dependency: image $image (rerun with --pull)" >&2
      exit 2
    fi
  fi
done

echo "[lab-integration] out=$OUT asset=$ASSET"
echo "[lab-integration] stage 1: independent reproduction"
"$HERE/lab-repro.sh" --out "$OUT/repro" --asset "$ASSET" --keep --timeout "$TIMEOUT" --json \
  > "$OUT/repro.stdout.json" 2> "$OUT/repro.log"
REPRO_RC=$?
expect "lab-repro exit 0" "0" "$REPRO_RC"

# Parse the independently produced evidence before deciding whether the run
# succeeded, so the cleanup trap can remove containers from a failed run too.
if [[ -s "$OUT/repro/repro-evidence.json" ]]; then
  read -r V_URL V_C P_C <<EOF
$(python3 - "$OUT/repro/repro-evidence.json" <<'PY'
import json, sys
ev = json.load(open(sys.argv[1], encoding="utf-8"))
v = (ev.get("containers") or {}).get("vulnerable") or {}
p = (ev.get("containers") or {}).get("patched") or {}
print(v.get("url", ""), v.get("name", ""), p.get("name", ""), sep="\t")
PY
)
EOF
fi

if [[ "$REPRO_RC" -ne 0 ]]; then
  sed -n '1,120p' "$OUT/repro.log" >&2
  echo
  echo "No report integration attempted: the real reproduction did not produce a differential." >&2
  exit 1
fi

STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$OUT/repro/repro-evidence.json")"
V_OOM="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["observations"]["vulnerable"]["oom_detected"])' "$OUT/repro/repro-evidence.json")"
P_OOM="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["observations"]["patched"]["oom_detected"])' "$OUT/repro/repro-evidence.json")"
P_NORMAL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["observations"]["patched"]["normal_detected"])' "$OUT/repro/repro-evidence.json")"
EXEC_EFFECTS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["observations"]["execution_effects"])' "$OUT/repro/repro-evidence.json")"
RCE_OBSERVED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["observations"]["rce_observed"])' "$OUT/repro/repro-evidence.json")"

expect "reproduction state REPRO-OOM-DIFFERENTIAL" "True" "$([[ "$STATE" == "REPRO-OOM-DIFFERENTIAL" ]] && echo True || echo False)"
expect "vulnerable build OOM observed" "True" "$([[ "$V_OOM" == "True" ]] && echo True || echo False)"
expect "patched build no OOM" "False" "$P_OOM"
expect "patched build returned normal probe JSON" "True" "$([[ "$P_NORMAL" == "True" ]] && echo True || echo False)"
expect "reproduction has no execution effects" "[]" "$EXEC_EFFECTS"
expect "reproduction does not assert RCE" "False" "$RCE_OBSERVED"

echo "[lab-integration] stage 2: report consumes the independent evidence"
"$HERE/run-audit.sh" --url "$V_URL" --asset "$ASSET" \
  --out "$OUT/audit" --repro-evidence "$OUT/repro/repro-evidence.json" \
  > "$OUT/audit.log" 2>&1
AUDIT_RC=$?
expect "run-audit exit 0" "0" "$AUDIT_RC"
if [[ "$AUDIT_RC" -ne 0 ]]; then
  sed -n '1,160p' "$OUT/audit.log" >&2
fi

FIND="$OUT/audit/findings.jsonl"
REPORT="$OUT/audit/report.md"
CSV="$OUT/audit/findings.csv"
if [[ -s "$FIND" ]]; then
  FIND_REPRO="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline()).get("repro_state",""))' "$FIND")"
  FIND_RCE="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline()).get("rce_state",""))' "$FIND")"
else
  FIND_REPRO="missing"
  FIND_RCE="missing"
fi
expect "findings repro_state recorded" "REPRO-OOM-DIFFERENTIAL" "$FIND_REPRO"
expect "findings rce_state not RCE-CONFIRMED" "True" "$([[ "$FIND_RCE" != "RCE-CONFIRMED" ]] && echo True || echo False)"
expect "report contains reproduction state" "True" "$(grep -q 'REPRO-OOM-DIFFERENTIAL' "$REPORT" 2>/dev/null && echo True || echo False)"
expect "report contains reproduction section" "True" "$(grep -q '## Reproduction evidence' "$REPORT" 2>/dev/null && echo True || echo False)"
expect "report does not claim RCE-CONFIRMED" "True" "$([[ "$(grep -c '| RCE-CONFIRMED |' "$REPORT" 2>/dev/null || true)" == "0" ]] && echo True || echo False)"
expect "CSV has repro_state column" "True" "$(head -1 "$CSV" 2>/dev/null | grep -q 'repro_state' && echo True || echo False)"

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "ALL $PASS INTEGRATION TESTS PASSED"
  echo "evidence: $OUT/repro/repro-evidence.json"
  echo "report:   $OUT/audit/report.md"
  exit 0
fi
echo "$FAIL INTEGRATION TEST(S) FAILED out of $((PASS + FAIL))"
echo "artifacts: $OUT"
exit 1
