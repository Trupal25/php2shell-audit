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

echo "[lab-integration] stage 3: validation-module harness (real OOM differential)"
MOD_OUT="$OUT/module"
"$HERE/module-run.sh" --module "$HERE/../modules/oom-differential" \
  --asset "$ASSET" --out "$MOD_OUT" --json \
  > "$OUT/module.stdout.json" 2> "$OUT/module.log"
MOD_RC=$?
expect "module-run exit 0" "0" "$MOD_RC"
if [[ "$MOD_RC" -ne 0 ]]; then
  sed -n '1,200p' "$OUT/module.log" >&2
fi

MOD_JSON="$MOD_OUT/module-run.json"
mod_get() {
  python3 - "$MOD_JSON" "$1" <<'PY'
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

expect "module evidence file present" "True" "$([[ -s "$MOD_JSON" ]] && echo True || echo False)"
expect "module state completed" "completed" "$(mod_get state)"
expect "module target impact crash-oom" "crash-oom" "$(mod_get classification.impact)"
expect "module confidence observed" "observed" "$(mod_get classification.confidence)"
expect "module is not synthetic" "false" "$(mod_get synthetic)"
expect "vulnerable build OOM corroborated" "true" "$(mod_get harness_observations.vulnerable.oom_in_log)"
expect "patched build no OOM corroborated" "false" "$(mod_get harness_observations.patched.oom_in_log)"
expect "patched build normal-response control" "true" "$(mod_get classification.checks.normal_response.patched)"
expect "module has no execution effects" "[]" "$(mod_get classification.checks.execution.execution_effects)"
expect "module did not retrieve target marker" "false" "$(mod_get corroboration.marker_in_target)"
expect "module has no RCE validator result" "null" "$(mod_get rce_validation)"
expect "module network is internal" "true" "$(mod_get network.internal)"
expect "module network publishes no ports" "[]" "$(mod_get network.published_ports)"
expect "vulnerable target publishes no ports" "[]" "$(mod_get targets.vulnerable.published_ports)"
expect "patched target publishes no ports" "[]" "$(mod_get targets.patched.published_ports)"
expect "module resource memory limit" "512m" "$(mod_get invocation.resource_limits.memory)"
expect "module resource cpu limit" "1" "$(mod_get invocation.resource_limits.cpus)"
expect "module resource pid limit" "128" "$(mod_get invocation.resource_limits.pids_limit)"
expect "module container exited 0" "0" "$(mod_get module_container.exit_code)"
expect "module container did not time out" "false" "$(mod_get module_container.timed_out)"
expect "module containers removed" "true" "$(mod_get cleanup.containers_removed)"
expect "module network removed" "true" "$(mod_get cleanup.network_removed)"
expect "module artifacts independently verified" "True" "$(python3 - "$MOD_JSON" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    arts = (((data.get("classification") or {}).get("checks") or {}).get("artifacts_verified") or {})
    declared = int(arts.get("declared") or 0)
    verified = int(arts.get("verified") or 0)
    print("True" if declared > 0 and declared == verified else "False")
except Exception:
    print("False")
PY
)"
expect "module provenance hash present" "True" "$([[ "$(mod_get module.sha256)" =~ ^[0-9a-f]{64}$ ]] && echo True || echo False)"
expect "module result sha256 present" "True" "$([[ "$(mod_get result_sha256)" =~ ^[0-9a-f]{64}$ ]] && echo True || echo False)"
expect "module log sha256 present" "True" "$([[ "$(mod_get module_container.logs_sha256)" =~ ^[0-9a-f]{64}$ ]] && echo True || echo False)"
expect "module impact is not code execution" "True" "$([[ "$(mod_get classification.impact)" != "demonstrated-code-execution" ]] && echo True || echo False)"

V_MOD_C="$(mod_get targets.vulnerable.container)"
P_MOD_C="$(mod_get targets.patched.container)"
M_MOD_C="$(mod_get module_container.name)"
MOD_NET="$(mod_get network.name)"
expect "vulnerable module container removed from Docker" "False" "$(docker inspect "$V_MOD_C" >/dev/null 2>&1 && echo True || echo False)"
expect "patched module container removed from Docker" "False" "$(docker inspect "$P_MOD_C" >/dev/null 2>&1 && echo True || echo False)"
expect "module container removed from Docker" "False" "$(docker inspect "$M_MOD_C" >/dev/null 2>&1 && echo True || echo False)"
expect "module network removed from Docker" "False" "$(docker network inspect "$MOD_NET" >/dev/null 2>&1 && echo True || echo False)"

echo "[lab-integration] stage 3b: harness repeatability"
MOD2_OUT="$OUT/module-repeat"
"$HERE/module-run.sh" --module "$HERE/../modules/oom-differential" \
  --asset "$ASSET" --out "$MOD2_OUT" --json \
  > "$OUT/module-repeat.stdout.json" 2> "$OUT/module-repeat.log"
MOD2_RC=$?
expect "repeat module-run exit 0" "0" "$MOD2_RC"
MOD2_JSON="$MOD2_OUT/module-run.json"
if [[ -s "$MOD2_JSON" ]]; then
  MOD2_IMPACT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["classification"]["impact"])' "$MOD2_JSON" 2>/dev/null)"
  MOD2_STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$MOD2_JSON" 2>/dev/null)"
  MOD2_EXEC="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["classification"]["checks"]["execution"]["execution_effects"])' "$MOD2_JSON" 2>/dev/null)"
else
  MOD2_IMPACT="missing"; MOD2_STATE="missing"; MOD2_EXEC="missing"
fi
expect "repeat module state completed" "completed" "$MOD2_STATE"
expect "repeat module classification stable" "$(mod_get classification.impact)" "$MOD2_IMPACT"
expect "repeat module has no execution effects" "[]" "$MOD2_EXEC"
V_MOD2_C="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["targets"]["vulnerable"]["container"])' "$MOD2_JSON" 2>/dev/null)"
P_MOD2_C="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["targets"]["patched"]["container"])' "$MOD2_JSON" 2>/dev/null)"
MOD2_NET="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["network"]["name"])' "$MOD2_JSON" 2>/dev/null)"
expect "repeat vulnerable container removed" "False" "$(docker inspect "$V_MOD2_C" >/dev/null 2>&1 && echo True || echo False)"
expect "repeat patched container removed" "False" "$(docker inspect "$P_MOD2_C" >/dev/null 2>&1 && echo True || echo False)"
expect "repeat network removed" "False" "$(docker network inspect "$MOD2_NET" >/dev/null 2>&1 && echo True || echo False)"

echo "[lab-integration] stage 4: audit consumes the real module evidence"
"$HERE/run-audit.sh" --url "$V_URL" --asset "$ASSET" \
  --out "$OUT/audit-module" --module-run "$MOD_JSON" \
  --repro-evidence "$OUT/repro/repro-evidence.json" \
  > "$OUT/audit-module.log" 2>&1
AUDIT_MOD_RC=$?
expect "run-audit module exit 0" "0" "$AUDIT_MOD_RC"
if [[ "$AUDIT_MOD_RC" -ne 0 ]]; then
  sed -n '1,200p' "$OUT/audit-module.log" >&2
fi
FIND_MOD="$OUT/audit-module/findings.jsonl"
REPORT_MOD="$OUT/audit-module/report.md"
CSV_MOD="$OUT/audit-module/findings.csv"
if [[ -s "$FIND_MOD" ]]; then
  MOD_REC_IMPACT="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline()).get("impact",""))' "$FIND_MOD")"
  MOD_REC_VALIDATION="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline()).get("validation_impact",""))' "$FIND_MOD")"
  MOD_REC_SUMMARY="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline()).get("validation_summary",""))' "$FIND_MOD")"
  MOD_REC_RCE="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline()).get("rce_state",""))' "$FIND_MOD")"
else
  MOD_REC_IMPACT="missing"; MOD_REC_VALIDATION="missing"; MOD_REC_SUMMARY="missing"; MOD_REC_RCE="missing"
fi
expect "audit target impact from real module" "crash-oom" "$MOD_REC_IMPACT"
expect "audit validation impact recorded" "crash-oom" "$MOD_REC_VALIDATION"
expect "audit validation artifacts verified" "True" "$([[ "$MOD_REC_SUMMARY" != *"artifacts unverified"* ]] && echo True || echo False)"
expect "audit does not claim RCE-CONFIRMED" "True" "$([[ "$MOD_REC_RCE" != "RCE-CONFIRMED" ]] && echo True || echo False)"
expect "audit report has validation section" "True" "$(grep -q '## Validation and impact' "$REPORT_MOD" 2>/dev/null && echo True || echo False)"
expect "audit report shows crash-oom impact" "True" "$(grep -q '| crash-oom |' "$REPORT_MOD" 2>/dev/null && echo True || echo False)"
expect "audit report does not claim code execution" "True" "$([[ "$(grep -c '| demonstrated-code-execution |' "$REPORT_MOD" 2>/dev/null || true)" == "0" ]] && echo True || echo False)"
expect "audit CSV has validation_impact column" "True" "$(head -1 "$CSV_MOD" 2>/dev/null | grep -q 'validation_impact' && echo True || echo False)"

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "ALL $PASS INTEGRATION TESTS PASSED"
  echo "reproduction evidence: $OUT/repro/repro-evidence.json"
  echo "module evidence:       $MOD_JSON"
  echo "report:                $OUT/audit/report.md"
  echo "module report:         $REPORT_MOD"
  exit 0
fi
echo "$FAIL INTEGRATION TEST(S) FAILED out of $((PASS + FAIL))"
echo "artifacts: $OUT"
exit 1
