#!/usr/bin/env bash
# php2shell run-audit: one invocation from a target URL to an evidence report.
#
# Pipeline:
#   fingerprint -> edge conformance -> optional host triage/hardening
#   -> chain verdict -> optional lab-reproduction evidence
#   -> optional RCE evidence validation -> report
#
# The reproduction stage consumes evidence from scripts/lab-repro.sh (a real,
# bounded OOM/crash differential). The RCE stage validates an artifact from an
# authorized validation module. Neither stage generates or sends an exploit
# payload.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
URL=""
SCOPE_FILE=""
ASSET=""
OUT=""
LOCAL=0
SSH_HOST=""
DEEP=0
RCE_EVIDENCE=""
REPRO_EVIDENCE=""
MARKERS=""
MODULE=""
MODULE_RUN=""
MODULE_TIMEOUT=120
EXPOSURE="unknown"

usage() {
  cat <<'EOF'
Usage: run-audit.sh --url URL [options]

One invocation from a target URL to report.md + findings.csv.

Options:
  --url URL             Target URL (required)
  --scope-file FILE     Authorized host list; public targets only
  --asset NAME          Asset name (default: URL host)
  --out DIR             Evidence directory (default: audit-<timestamp>)
  --exposure VALUE      internet | partner | internal | local | unknown
  --local               Also collect local triage/hardening evidence
  --host user@host      Also collect triage evidence over SSH
  --deep                With --local/--host, run inventory as well
  --repro-evidence FILE Optional lab-reproduction evidence (see references/lab-reproduction.md)
  --rce-evidence FILE   Optional RCE evidence artifact (see references/rce-validation.md)
  --markers FILE        Optional marker file for RCE validation
  --module DIR          Execute a validation module in the disposable lab
                        (see references/module-interface.md)
  --module-run FILE     Consume an existing module-run.json (or its directory)
  --module-timeout SEC  Module hard timeout (default: 120)
  -h, --help            Show this help

Artifacts:
  fingerprint.json  edge.json  chain.json  triage.jsonl  hardening.jsonl
  repro.json  rce.json  module-run.json  impact.json  findings.jsonl
  report.md  findings.csv

Exit codes: 0 report generated, 2 setup/stage failure.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2 ;;
    --scope-file) SCOPE_FILE="${2:-}"; shift 2 ;;
    --asset) ASSET="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --exposure) EXPOSURE="${2:-unknown}"; shift 2 ;;
    --local) LOCAL=1; shift ;;
    --host) SSH_HOST="${2:-}"; shift 2 ;;
    --deep) DEEP=1; shift ;;
    --repro-evidence) REPRO_EVIDENCE="${2:-}"; shift 2 ;;
    --rce-evidence) RCE_EVIDENCE="${2:-}"; shift 2 ;;
    --markers) MARKERS="${2:-}"; shift 2 ;;
    --module) MODULE="${2:-}"; shift 2 ;;
    --module-run) MODULE_RUN="${2:-}"; shift 2 ;;
    --module-timeout) MODULE_TIMEOUT="${2:-120}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$URL" ]] || { echo "--url is required" >&2; usage; exit 2; }
[[ -n "$ASSET" ]] || ASSET="$(printf '%s' "$URL" | sed -E 's#^[a-z]+://##; s#/.*$##; s#:[0-9]+$##')"
[[ -n "$OUT" ]] || OUT="audit-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

log() { printf '[run-audit] %s\n' "$*" >&2; }

log "asset=$ASSET out=$OUT"

# 1. Passive fingerprint.
fp_args=(--url "$URL" --json)
[[ -n "$SCOPE_FILE" ]] && fp_args+=(--scope-file "$SCOPE_FILE")
"$HERE/fingerprint.sh" "${fp_args[@]}" > "$OUT/fingerprint.json" 2> "$OUT/fingerprint.err" || true
log "fingerprint: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("decision","?"), d.get("version_hint","no-version"))' "$OUT/fingerprint.json" 2>/dev/null || echo failed)"

# 2. Edge conformance (one bounded request).
edge_args=(--url "$URL" --json)
[[ -n "$SCOPE_FILE" ]] && edge_args+=(--scope-file "$SCOPE_FILE")
"$HERE/edge-conformance.sh" "${edge_args[@]}" > "$OUT/edge.json" 2> "$OUT/edge.err" || true
log "edge: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("result","?"), d.get("status","?"))' "$OUT/edge.json" 2>/dev/null || echo failed)"

# 3. Host evidence (optional).
if [[ "$LOCAL" == 1 ]]; then
  "$HERE/triage.sh" --local --json > "$OUT/triage.jsonl" 2> "$OUT/triage.err" || true
  "$HERE/verify-hardening.sh" --json > "$OUT/hardening.jsonl" 2> "$OUT/hardening.err" || true
  if [[ "$DEEP" == 1 ]]; then
    "$HERE/inventory.sh" --local --fast --json > "$OUT/inventory.jsonl" 2> "$OUT/inventory.err" || true
  fi
  log "local host evidence collected"
elif [[ -n "$SSH_HOST" ]]; then
  "$HERE/triage.sh" --host "$SSH_HOST" --json > "$OUT/triage.jsonl" 2> "$OUT/triage.err" || true
  if [[ "$DEEP" == 1 ]]; then
    "$HERE/inventory.sh" --host "$SSH_HOST" --fast --json > "$OUT/inventory.jsonl" 2> "$OUT/inventory.err" || true
  fi
  log "ssh host evidence collected from $SSH_HOST"
fi

# 4. Chain verdict.
chain_args=()
[[ -s "$OUT/triage.jsonl" ]] && chain_args+=(--triage "$OUT/triage.jsonl")
[[ -s "$OUT/fingerprint.json" ]] && chain_args+=(--fingerprint "$OUT/fingerprint.json")
[[ -s "$OUT/hardening.jsonl" ]] && chain_args+=(--hardening "$OUT/hardening.jsonl")
[[ -s "$OUT/edge.json" ]] && chain_args+=(--edge "$OUT/edge.json")
"$HERE/chain.sh" "${chain_args[@]}" --asset "$ASSET" --json > "$OUT/chain.json" 2> "$OUT/chain.err" || true
log "chain: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("decision","?"))' "$OUT/chain.json" 2>/dev/null || echo failed)"

# 5. Lab reproduction evidence (optional).
if [[ -n "$REPRO_EVIDENCE" ]]; then
  if [[ ! -f "$REPRO_EVIDENCE" ]]; then
    echo "reproduction evidence not found: $REPRO_EVIDENCE" >&2
    exit 2
  fi
  python3 - "$REPRO_EVIDENCE" "$OUT/repro.json" "$ASSET" <<'PY'
import json, os, sys

source, dest, audit_asset = sys.argv[1:4]
ALLOWED = {
    "REPRO-OOM-DIFFERENTIAL", "REPRO-FATAL-BOTH", "REPRO-NO-EFFECT",
    "REPRO-CRASH-OBSERVED", "REPRO-UNAVAILABLE", "REPRO-INCONCLUSIVE",
}
reasons = []
try:
    with open(source, encoding="utf-8", errors="replace") as fh:
        ev = json.load(fh)
except (OSError, json.JSONDecodeError) as exc:
    ev = {}
    reasons.append(f"cannot read reproduction evidence: {exc}")
if not isinstance(ev, dict):
    ev = {}
    reasons.append("reproduction evidence root is not a JSON object")

state = str(ev.get("state", "")).strip().upper()
if ev.get("kind") != "lab-reproduction":
    reasons.append("kind must be 'lab-reproduction'")
if ev.get("schema") != 1:
    reasons.append("schema must be 1")
if state not in ALLOWED:
    reasons.append(f"state is {state or 'missing'}; expected one of {sorted(ALLOWED)}")
if state != "REPRO-UNAVAILABLE":
    if not isinstance(ev.get("request"), dict) or not ev.get("request"):
        reasons.append("request metadata is missing")
    if not isinstance(ev.get("images"), dict) or not ev.get("images"):
        reasons.append("image provenance is missing")
obs = ev.get("observations") if isinstance(ev.get("observations"), dict) else {}
if not obs:
    if state != "REPRO-UNAVAILABLE":
        reasons.append("observations are missing")
else:
    if "execution_effects" not in obs or obs.get("execution_effects") != []:
        reasons.append("lab-reproduction evidence must have empty execution_effects")
    if obs.get("rce_observed") is not False:
        reasons.append("lab-reproduction evidence must set rce_observed=false")
    v = obs.get("vulnerable") if isinstance(obs.get("vulnerable"), dict) else {}
    p = obs.get("patched") if isinstance(obs.get("patched"), dict) else {}
    if state in {"REPRO-OOM-DIFFERENTIAL", "REPRO-FATAL-BOTH", "REPRO-NO-EFFECT", "REPRO-CRASH-OBSERVED"}:
        if not v or not p:
            reasons.append("vulnerable and patched observations are required for this state")
        v_oom = bool(v.get("oom_detected"))
        p_oom = bool(p.get("oom_detected"))
        p_normal = bool(p.get("normal_detected"))
        crash = bool(v.get("crash_signal") or p.get("crash_signal"))
        expected = (
            "REPRO-CRASH-OBSERVED" if crash else
            "REPRO-OOM-DIFFERENTIAL" if v_oom and not p_oom and p_normal else
            "REPRO-FATAL-BOTH" if v_oom and p_oom else
            "REPRO-NO-EFFECT" if not v_oom and not p_oom else
            "REPRO-INCONCLUSIVE"
        )
        if state != expected:
            reasons.append(f"state {state} does not match observations (expected {expected})")
ev_asset = str(ev.get("asset") or "").strip()
if ev_asset and ev_asset != audit_asset:
    reasons.append(f"evidence asset '{ev_asset}' does not match audit asset '{audit_asset}'")

out = dict(ev)
out["state"] = state if not reasons else "REPRO-INCONCLUSIVE"
out["source"] = source
out["validation"] = {"consistent": not reasons, "reasons": reasons}
with open(dest, "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
PY
  log "repro: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("state","?"))' "$OUT/repro.json" 2>/dev/null || echo failed)"
fi

# 6. RCE evidence validation (optional).
if [[ -n "$RCE_EVIDENCE" ]]; then
  rce_args=(--evidence "$RCE_EVIDENCE" --asset "$ASSET" --seen-file "$OUT/.rce-seen.json" --json)
  [[ -n "$MARKERS" ]] && rce_args+=(--markers "$MARKERS")
  "$HERE/rce-validate.sh" "${rce_args[@]}" > "$OUT/rce.json" 2> "$OUT/rce.err" || true
  log "rce: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("state","?"))' "$OUT/rce.json" 2>/dev/null || echo failed)"
fi

# 6b. Validation-module execution or consumption (optional).
MODULE_RC=0
if [[ -n "$MODULE" ]]; then
  log "module: executing $MODULE in the disposable lab"
  mkdir -p "$OUT/module-run"
  "$HERE/module-run.sh" --module "$MODULE" --asset "$ASSET" --out "$OUT/module-run" \
    --timeout "$MODULE_TIMEOUT" --json \
    > "$OUT/module-run/stdout.json" 2> "$OUT/module-run/stderr.log" || MODULE_RC=$?
  if [[ -f "$OUT/module-run/module-run.json" ]]; then
    cp "$OUT/module-run/module-run.json" "$OUT/module-run.json"
    if [[ -f "$OUT/module-run/classification.json" ]]; then
      cp "$OUT/module-run/classification.json" "$OUT/impact.json"
    fi
    log "module: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("state","?"), d.get("classification",{}).get("impact","?"))' "$OUT/module-run.json" 2>/dev/null || echo failed)"
  else
    log "module: no artifact (exit $MODULE_RC)"
  fi
elif [[ -n "$MODULE_RUN" ]]; then
  module_src="$MODULE_RUN"
  [[ -d "$module_src" ]] && module_src="$module_src/module-run.json"
  if [[ -f "$module_src" ]]; then
    module_src_dir="$(cd "$(dirname "$module_src")" && pwd)"
    rm -rf "$OUT/module-run"
    cp -a "$module_src_dir" "$OUT/module-run"
    cp "$module_src_dir/$(basename "$module_src")" "$OUT/module-run.json"
    log "module: consumed $module_src"
  else
    log "module: artifact not found: $module_src"
  fi
fi

if [[ -f "$OUT/module-run.json" ]]; then
  if [[ ! -f "$OUT/impact.json" ]]; then
    python3 "$HERE/impact-classify.py" --run "$OUT/module-run.json" --result-dir "$OUT/module-run" \
      --out "$OUT/impact.json" --json > "$OUT/impact.stdout.json" 2> "$OUT/impact.err" || true
  fi
elif [[ -n "$MODULE" || -n "$MODULE_RUN" ]]; then
  # Keep an explicit unavailable artifact instead of silently dropping the
  # stage. The report shows inconclusive impact, not a fabricated result.
  python3 - "$OUT/module-run.json" "$OUT/impact.json" "$ASSET" "$MODULE_RC" <<'PY'
import json, sys
run_path, impact_path, asset, rc = sys.argv[1:5]
reason = f"validation module unavailable (exit {rc}); no experiment completed"
classification = {
    "kind": "impact-classification", "schema": 1, "asset": asset,
    "module_id": "none", "synthetic": False,
    "impact": "inconclusive", "confidence": "insufficient", "applicable": True,
    "basis": [reason], "reasons": [reason], "checks": {},
    "negative_controls": {},
    "corroboration": {"execution_corroborated": False, "marker_in_target": False, "canary_supplied": False},
    "reproduction_steps": [], "environment_dependencies": ["module execution unavailable"],
    "evidence_refs": [], "limitations": [reason],
    "remediation": "Run the validation module in the disposable lab when Docker and both images are available.",
}
run = {
    "kind": "validation-module-run", "schema": 1, "asset": asset,
    "module": {"id": "none"}, "synthetic": False, "state": "unavailable",
    "result": None, "classification": classification,
    "harness_observations": {}, "corroboration": {}, "cleanup": {},
    "limitations": [reason],
}
with open(run_path, "w", encoding="utf-8") as fh:
    json.dump(run, fh, indent=2, sort_keys=True)
    fh.write("\n")
with open(impact_path, "w", encoding="utf-8") as fh:
    json.dump(classification, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
fi

if [[ -f "$OUT/impact.json" ]]; then
  log "impact: $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("impact","?"), "("+str(d.get("confidence","?"))+")")' "$OUT/impact.json" 2>/dev/null || echo inconclusive)"
fi

# 7. Normalize into one finding record.
python3 - "$OUT" "$ASSET" "$EXPOSURE" <<'PY'
import json, os, sys
from datetime import datetime, timezone

out, asset, exposure = sys.argv[1:4]

def load(name):
    path = os.path.join(out, name)
    if not os.path.isfile(path):
        return None
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

chain = load("chain.json") or {}
fp = load("fingerprint.json") or {}
edge = load("edge.json") or {}
repro = load("repro.json") or {}
rce = load("rce.json") or {}
inventory = load("inventory.jsonl") or None

def vt(value):
    parts = []
    for piece in str(value or "").split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)

version = chain.get("version") or fp.get("version_hint") or "unknown"
gate = chain.get("gate") or "none"
sapi = chain.get("sapi") or fp.get("sapi_hint") or "unknown"
decision = chain.get("decision", "UNKNOWN")

priority = "UNKNOWN"
status = "unknown"
remediation = ""
if decision == "CHAIN-OPEN":
    priority = "P0" if sapi in ("mod_php", "frankenphp") else "P1"
    status = "vulnerable"
    remediation = "Patch to the branch gate; edge controls are defense-in-depth, not a fix."
elif decision == "CHAIN-PARTIAL":
    priority = "P1"
    status = "inconclusive"
    remediation = "Collect one authenticated php -v and web-SAPI ini evidence, then re-run."
elif decision == "CHAIN-BLOCKED":
    if gate != "none" and version != "unknown" and vt(version) >= vt(gate):
        priority = "PATCHED"
        status = "patched"
        remediation = "No action; keep the CI gate and monitoring."
    else:
        priority = "P3"
        status = "blocked"
        remediation = "A decisive control is in force; keep it and monitor."
else:
    fpd = fp.get("decision", "UNKNOWN")
    priority = {"P0": "P0", "P1": "P1", "LIKELY-VULNERABLE": "P1", "ASSUME-AFFECTED": "P1"}.get(fpd, "UNKNOWN")
    status = "unknown" if fpd == "UNKNOWN" else ("vulnerable" if fpd != "LIKELY-PATCHED" else "patched")
    if fpd == "LIKELY-PATCHED":
        priority = "PATCHED"
    remediation = "Confirm with an authenticated php -v before closing."

rce_state = rce.get("state", "")
if rce_state == "RCE-CONFIRMED":
    remediation = "RCE evidence validated. Patch immediately; preserve the evidence bundle."
elif rce_state == "RCE-BLOCKED":
    remediation = "Validation blocked by patch or a decisive control; maintain it."

repro_state = repro.get("state", "")
repro_summary = ""
if repro_state:
    repro_obs = repro.get("observations") if isinstance(repro.get("observations"), dict) else {}
    rv = repro_obs.get("vulnerable") if isinstance(repro_obs.get("vulnerable"), dict) else {}
    rp = repro_obs.get("patched") if isinstance(repro_obs.get("patched"), dict) else {}
    def obs_label(item):
        if item.get("oom_detected"):
            return "OOM"
        if item.get("normal_detected"):
            return "normal"
        if item.get("crash_signal"):
            return "crash"
        return "unknown"
    if repro_state == "REPRO-UNAVAILABLE":
        repro_summary = "runtime unavailable; no request sent; no execution effects"
    else:
        repro_summary = f"vulnerable={obs_label(rv)}; patched={obs_label(rp)}; no execution effects"
    if repro_state == "REPRO-OOM-DIFFERENTIAL":
        remediation += " Request-parsing OOM differential reproduced; patch is still required."

module_run = load("module-run.json") or {}
if not isinstance(module_run, dict):
    module_run = {}
impact_cls = load("impact.json") or {}
if not isinstance(impact_cls, dict) or not impact_cls:
    embedded = module_run.get("classification")
    impact_cls = embedded if isinstance(embedded, dict) else {}
module_id = str(impact_cls.get("module_id") or ((module_run.get("module") or {}) if isinstance(module_run.get("module"), dict) else {}).get("id") or "")
module_synthetic = bool(module_run.get("synthetic") or impact_cls.get("synthetic"))
validation_impact = str(impact_cls.get("impact") or "inconclusive")
validation_confidence = str(impact_cls.get("confidence") or "insufficient")
checks = impact_cls.get("checks") if isinstance(impact_cls.get("checks"), dict) else {}
arts = checks.get("artifacts_verified") if isinstance(checks.get("artifacts_verified"), dict) else {}
def as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
declared_arts = as_int(arts.get("declared"))
verified_arts = as_int(arts.get("verified"))
module_verified = declared_arts > 0 and verified_arts == declared_arts
corr = impact_cls.get("corroboration") if isinstance(impact_cls.get("corroboration"), dict) else {}
if corr.get("execution_corroborated"):
    module_verified = True

target_meets_gate = bool(version != "unknown" and gate != "none" and vt(version) >= vt(gate))
target_applicable = priority != "PATCHED" and not target_meets_gate

impact_rank = {
    "inconclusive": 0,
    "suspected-exposure": 1,
    "crash-oom": 2,
    "memory-safety-failure": 3,
    "memory-disclosure": 4,
    "demonstrated-code-execution": 5,
}
candidates = []
impact_basis = []
impact_confidence = "insufficient"
if target_applicable:
    if impact_cls and not module_synthetic and module_verified:
        candidates.append(validation_impact)
        impact_basis.extend([str(item) for item in (impact_cls.get("basis") or [])])
        impact_confidence = validation_confidence
    elif impact_cls and module_synthetic:
        impact_basis.append("synthetic validation module ignored as evidence")
    elif impact_cls and not module_verified and validation_impact not in ("", "inconclusive"):
        impact_basis.append("validation module artifacts were not independently verified; claim not promoted")
    if repro_state in ("REPRO-OOM-DIFFERENTIAL", "REPRO-CRASH-OBSERVED"):
        candidates.append("crash-oom")
        impact_basis.append(f"lab reproduction state: {repro_state}")
        if impact_confidence == "insufficient":
            impact_confidence = "observed"
    if rce_state == "RCE-CONFIRMED":
        candidates.append("demonstrated-code-execution")
        impact_basis.append("rce-validate.sh returned RCE-CONFIRMED")
        impact_confidence = "corroborated"
    if not candidates and decision == "CHAIN-OPEN":
        candidates.append("suspected-exposure")
        impact_basis.append("below-gate web SAPI reachable; no validation module executed")
        impact_confidence = "exposure-only"
    target_impact = max(candidates, key=lambda item: impact_rank.get(item, 0)) if candidates else "inconclusive"
else:
    target_impact = "inconclusive"
    impact_basis.append("target meets the patch gate or is marked patched; lab validation is not target impact")
    impact_confidence = "insufficient"

if module_id:
    validation_summary = f"{module_id}: {validation_impact} ({validation_confidence})"
    if module_synthetic:
        validation_summary += " [synthetic, not evidence]"
    elif not module_verified:
        validation_summary += " [artifacts unverified]"
else:
    validation_summary = "no validation module executed"

if target_impact == "demonstrated-code-execution":
    remediation = "RCE evidence validated. Patch immediately; preserve the evidence bundle."
elif target_impact in ("memory-disclosure", "memory-safety-failure"):
    remediation = "Memory-safety/disclosure evidence validated. Patch immediately; preserve the evidence bundle."
elif target_impact == "crash-oom":
    remediation += " Lab validation observed an OOM/crash differential; patch is still required."

# Deduplicate while preserving order.
seen_basis = set()
impact_basis = [item for item in impact_basis if not (item in seen_basis or seen_basis.add(item))]

evidence = []
if fp:
    evidence.append({"type": "fingerprint", "output": fp})
if edge:
    evidence.append({"type": "edge-conformance", "output": edge})
if chain:
    evidence.append({"type": "chain", "output": chain})
if inventory:
    evidence.append({"type": "inventory", "output": inventory})
if repro:
    evidence.append({"type": "lab-reproduction", "output": repro})
if rce:
    evidence.append({"type": "rce-validation", "output": rce})
if module_run:
    evidence.append({"type": "validation-module-run", "output": module_run})

record = {
    "asset": asset,
    "priority": priority,
    "status": status,
    "sapi": sapi,
    "version": version,
    "gate": gate,
    "exposure": exposure,
    "owner": "",
    "impact": target_impact,
    "impact_confidence": impact_confidence,
    "impact_applicable": target_applicable,
    "impact_basis": impact_basis,
    "validation_impact": validation_impact,
    "validation_confidence": validation_confidence,
    "validation_synthetic": module_synthetic,
    "validation_summary": validation_summary,
    "module_id": module_id,
    "module_state": module_run.get("state", "") if isinstance(module_run, dict) else "",
    "evidence": evidence,
    "remediation": remediation.strip(),
    "repro_state": repro_state,
    "repro_summary": repro_summary,
    "rce_state": rce_state,
    "verified_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(os.path.join(out, "findings.jsonl"), "w", encoding="utf-8") as fh:
    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
PY

# 8. Report.
python3 "$HERE/report.py" --input "$OUT/findings.jsonl" \
  --md "$OUT/report.md" --csv "$OUT/findings.csv" \
  --title "PHP2Shell audit — $ASSET" 2> "$OUT/report.log" || {
  echo "report generation failed; see $OUT/report.log" >&2
  exit 2
}
cat "$OUT/report.md"
printf '\nArtifacts: %s\n' "$OUT"
