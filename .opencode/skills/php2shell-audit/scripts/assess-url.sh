#!/usr/bin/env bash
# php2shell assess-url: one URL in, one exposure decision out.
# Chains passive fingerprinting with a single bounded edge-conformance request.
# It does not generate or send an exploit payload, and it does not prove RCE.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
URL=""
SCOPE_FILE=""
JSON=0

usage() {
  cat <<'EOF'
Usage: assess-url.sh --url URL [options]

One URL in, one exposure decision out:
  1. passive fingerprint (PHP, version hint, likely SAPI)
  2. one bounded long-key POST to check edge rejection
  3. combined decision and next action

Options:
  --url URL            Target URL (required)
  --scope-file FILE    Authorized host list; required only for public targets
  --json               Emit one JSON object
  -h, --help           Show this help

Decisions:
  LIKELY-PATCHED / P0-EXPOSED / P1-EXPOSED
  P0-EDGE-MITIGATED / P1-EDGE-MITIGATED
  P0-UNVERIFIED / P1-UNVERIFIED / UNKNOWN

Exit codes: 0 likely patched, 1 action needed, 2 unknown/error.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2 ;;
    --scope-file) SCOPE_FILE="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$URL" ]] || { echo "--url is required" >&2; usage; exit 2; }

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fp_args=(--url "$URL" --json)
edge_args=(--url "$URL" --json)
[[ -n "$SCOPE_FILE" ]] && fp_args+=(--scope-file "$SCOPE_FILE") && edge_args+=(--scope-file "$SCOPE_FILE")

"$HERE/fingerprint.sh" "${fp_args[@]}" > "$tmpdir/fp.json" 2>"$tmpdir/fp.err"
fp_rc=$?
if [[ ! -s "$tmpdir/fp.json" ]]; then
  cat "$tmpdir/fp.err" >&2
  echo "fingerprint failed (exit $fp_rc)" >&2
  exit 2
fi

fp_decision="$(python3 - "$tmpdir/fp.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1])).get("decision", "UNKNOWN"))
PY
)"

run_edge=0
case "$fp_decision" in
  P0|P1|LIKELY-VULNERABLE|ASSUME-AFFECTED) run_edge=1 ;;
esac

edge_json="null"
edge_result="SKIPPED"
if [[ "$run_edge" == 1 ]]; then
  "$HERE/edge-conformance.sh" "${edge_args[@]}" > "$tmpdir/edge.json" 2>"$tmpdir/edge.err"
  edge_rc=$?
  if [[ -s "$tmpdir/edge.json" ]]; then
    edge_json="$(cat "$tmpdir/edge.json")"
    edge_result="$(python3 - "$tmpdir/edge.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1])).get("result", "ERROR"))
PY
)"
  else
    edge_result="ERROR"
  fi
fi

python3 - "$tmpdir/fp.json" "$tmpdir/edge.json" "$edge_json" "$edge_result" "$JSON" <<'PY'
import json, sys

fp_path, edge_path, edge_raw, edge_result, as_json = sys.argv[1:6]
fp = json.load(open(fp_path))
edge = None
if edge_raw != "null":
    try:
        edge = json.loads(edge_raw)
    except json.JSONDecodeError:
        edge = None

fp_decision = fp.get("decision", "UNKNOWN")
priority = ""
if fp_decision == "P0":
    priority = "P0"
elif fp_decision == "P1":
    priority = "P1"
elif fp_decision == "ASSUME-AFFECTED":
    priority = "P1"
elif fp_decision == "LIKELY-VULNERABLE":
    priority = "P0" if fp.get("sapi_hint") == "mod_php" else "P1"

if fp_decision == "LIKELY-PATCHED":
    decision = "LIKELY-PATCHED"
    action = "Header hint meets the branch gate. Confirm with one authenticated php -v; do not treat headers as proof."
elif fp_decision == "UNKNOWN":
    decision = "UNKNOWN"
    action = "No PHP signal. Do not conclude 'not PHP' from headers alone; get host/registry evidence."
elif edge_result == "PASS":
    decision = f"{priority}-EDGE-MITIGATED"
    action = "The edge rejected the long-key probe. This is not a fix: patch to the branch gate and keep the rule."
elif edge_result == "FAIL":
    decision = f"{priority}-EXPOSED"
    action = "The edge forwarded the oversized key. Patch to the branch gate now; add the edge rule only as defense-in-depth."
else:
    decision = f"{priority}-UNVERIFIED"
    action = "Exposure is indicated but the edge probe was inconclusive. Patch or isolate, then re-check."

out = {
    "url": fp.get("url", ""),
    "decision": decision,
    "action": action,
    "fingerprint": fp,
    "edge": edge,
}
if as_json == "1":
    print(json.dumps(out, ensure_ascii=False))
else:
    print(f"ASSESSMENT: {decision}")
    print(f"URL:        {fp.get('url','')}")
    print(f"PHP:        {fp.get('php','unknown')}")
    print(f"VERSION:    {fp.get('version_hint') or 'not exposed'}")
    print(f"SAPI HINT:  {fp.get('sapi_hint','unknown')} ({fp.get('confidence','low')} confidence)")
    print(f"HTTP:       {fp.get('http','?')}")
    if edge:
        print(f"EDGE:       {edge.get('result','ERROR')} ({edge.get('status','?')}) — {edge.get('note','')}")
    else:
        print(f"EDGE:       {edge_result}")
    print(f"ACTION:     {action}")

sys.exit(0 if decision == "LIKELY-PATCHED" else (2 if decision == "UNKNOWN" else 1))
PY
