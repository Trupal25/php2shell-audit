#!/usr/bin/env bash
# php2shell chain: precondition-chain assessment.
#
# Aggregates version/SAPI/config/edge evidence and outputs:
#   CHAIN-OPEN     attack path preconditions present (audit-only; no exploit is sent)
#   CHAIN-PARTIAL  decisive preconditions are unknown
#   CHAIN-BLOCKED  patch gate met, or all controls in force
#
# Evidence comes from other scripts in this skill:
#   triage.sh --json          -> one line of JSONL per host   (--triage FILE)
#   fingerprint.sh --json     -> one JSON object             (--fingerprint FILE)
#   verify-hardening.sh --json-> one JSON line per check      (--hardening FILE)
#   edge-conformance.sh --json-> one JSON object             (--edge FILE)
set -uo pipefail

TRIAGE_FILE=""
FP_FILE=""
HARDENING_FILE=""
EDGE_FILE=""
ASSET="unknown"
JSON=0

usage() {
  cat <<'EOF'
Usage: chain.sh [--triage FILE] [--fingerprint FILE] [--hardening FILE] [--edge FILE] [--asset NAME] [--json]

Aggregates evidence about the exploit precondition chain. Advisory-only.

Preconditions considered:
  version_below_gate   exact PHP version below its branch gate (or unknown/open)
  web_sapi             mod_php / frankenphp / fpm / lsapi / cgi
  upload_progress_on   session.upload_progress.enabled is On
  memory_limit_finite  memory_limit is not -1 (predictable OOM window)
  multipart_unlimited  max_multipart_body_parts is absent or -1
  backtraces_on        PHP 8.5+ with fatal_error_backtraces=1
  edge_accepts_key     edge does NOT reject oversized keys
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --triage) TRIAGE_FILE="${2:-}"; shift 2 ;;
    --fingerprint) FP_FILE="${2:-}"; shift 2 ;;
    --hardening) HARDENING_FILE="${2:-}"; shift 2 ;;
    --edge) EDGE_FILE="${2:-}"; shift 2 ;;
    --asset) ASSET="${2:-$ASSET}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

python3 - "$TRIAGE_FILE" "$FP_FILE" "$HARDENING_FILE" "$EDGE_FILE" "$ASSET" "$JSON" "$tmpdir" <<'PY'
import json, os, sys

triage_path, fp_path, hr_path, edge_path, asset, as_json, tmpdir = sys.argv[1:8]

def read_json_file(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"skip {path}: {exc}", file=sys.stderr)
        return None

def read_jsonl(path):
    if not path or not os.path.isfile(path):
        return []
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    out.append(obj)
            return out
    except OSError as exc:
        print(f"skip {path}: {exc}", file=sys.stderr)
        return []

triage = read_json_file(triage_path) if triage_path and os.path.isfile(triage_path) else None
if triage is None:
    triage_list = read_jsonl(triage_path)
    triage = triage_list[0] if triage_list else {}
fp = read_json_file(fp_path)
edge = read_json_file(edge_path)
hardening = read_jsonl(hr_path)

def hard_value(check):
    for rec in hardening:
        for key in ("check", "key"):
            if rec.get(key) == check:
                return rec.get("observed", "")
    return ""

def hard_version():
    for rec in hardening:
        if rec.get("version"):
            return rec["version"]
    return ""

def hard_sapi():
    for rec in hardening:
        if rec.get("sapi"):
            return rec["sapi"]
    return ""

def version_tuple(value):
    parts = []
    for piece in str(value or "").split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)

GATES = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}

# ---- collect facts -----------------------------------------------------------
version = ""
sapi = ""
version_proof = ""
gate = ""

if triage:
    version = triage.get("version") or triage.get("php_version") or ""
    sapi = triage.get("sapi") or ""
    version_proof = triage.get("version_proof") or ""
    gate = triage.get("gate") or ""
if not version and fp:
    version = fp.get("version_hint") or ""
    if version and not version_proof:
        version_proof = "http-hint"
if not sapi and fp:
    sapi = fp.get("sapi_hint") or ""

hr_ver = hard_version()
if hr_ver and not version:
    version = hr_ver
if hard_sapi() and not sapi:
    sapi = hard_sapi()

def branch_of(ver):
    pieces = str(ver).split(".")
    return ".".join(pieces[:2]) if len(pieces) >= 2 else ""

if not gate and version:
    gate = GATES.get(branch_of(version), "")

# ---- preconditions -----------------------------------------------------------
pre = {}

# version_below_gate
if triage and triage.get("status") in ("patched", "PATCHED"):
    pre["version_below_gate"] = "absent"
elif not version:
    pre["version_below_gate"] = "unknown"
elif not gate:
    pre["version_below_gate"] = "open"          # EOL branch, no listed patch
elif version_tuple(version) < version_tuple(gate):
    pre["version_below_gate"] = "present"
else:
    pre["version_below_gate"] = "absent"

# web_sapi
WEB_SAPIS = ("mod_php", "frankenphp", "fpm", "lsapi", "cgi", "FastCGI")
if not sapi or sapi.lower().startswith("unknown"):
    pre["web_sapi"] = "unknown"
elif any(s.lower() in sapi.lower() for s in WEB_SAPIS):
    pre["web_sapi"] = "present"
else:
    pre["web_sapi"] = "absent"

# upload_progress_on
up = hard_value("session.upload_progress.enabled")
if not up:
    pre["upload_progress_on"] = "unknown"
else:
    pre["upload_progress_on"] = "present" if up.lower() in ("on", "1") else "absent"

# memory_limit_finite
mem = hard_value("memory_limit")
if not mem:
    pre["memory_limit_finite"] = "unknown"
else:
    pre["memory_limit_finite"] = "absent" if mem == "-1" else "present"

# multipart_unlimited
parts = hard_value("max_multipart_body_parts")
if not parts or parts == "no value":
    pre["multipart_unlimited"] = "unknown"
elif parts == "-1":
    pre["multipart_unlimited"] = "present"
else:
    pre["multipart_unlimited"] = "absent"

# backtraces_on
if version and version >= "8.5" and branch_of(version) == "8.5":
    bt = hard_value("fatal_error_backtraces")
    if not bt:
        pre["backtraces_on"] = "unknown"
    else:
        pre["backtraces_on"] = "present" if bt == "1" else "absent"
else:
    pre["backtraces_on"] = "n/a"

# edge_accepts_key
if edge is None:
    pre["edge_accepts_key"] = "unknown"
else:
    result = str(edge.get("result", "")).upper()
    pre["edge_accepts_key"] = "present" if result == "FAIL" else (
        "absent" if result == "PASS" else "unknown")

# ---- decision ----------------------------------------------------------------
critical_block = [
    pre["version_below_gate"] == "absent",
    pre["web_sapi"] == "absent",
    pre["edge_accepts_key"] == "absent",
    pre["upload_progress_on"] == "absent",
    pre["memory_limit_finite"] == "absent",
]
if any(critical_block):
    decision = "CHAIN-BLOCKED"
else:
    decisive_unknown = pre["version_below_gate"] == "unknown" or pre["web_sapi"] == "unknown"
    if decisive_unknown:
        decision = "CHAIN-PARTIAL"
    else:
        decision = "CHAIN-OPEN"

proof_note = (
    "version proven by authenticated web-SAPI evidence"
    if version_proof != "http-hint" and version
    else "~ version is a header hint (X-Powered-By); not a fix-quality proof"
    if version
    else "~ no version evidence collected"
)

labels = {
    "version_below_gate": "PHP below patch gate",
    "web_sapi": "Web SAPI reachable",
    "upload_progress_on": "session.upload_progress enabled",
    "memory_limit_finite": "finite memory_limit (OOM window)",
    "multipart_unlimited": "multipart parts unlimited",
    "backtraces_on": "8.5 fatal_error_backtraces=1",
    "edge_accepts_key": "edge accepts oversized key",
}
friendly = {
    "present": "CONFIRMED PRESENT",
    "absent": "confirmed absent",
    "unknown": "unknown",
    "open": "open (no patch gate)",
    "n/a": "n/a",
}

out = {
    "asset": asset,
    "decision": decision,
    "version": version or "unknown",
    "gate": gate or "none",
    "sapi": sapi or "unknown",
    "version_proof": version_proof or "none",
    "preconditions": pre,
}
if as_json == "1":
    out["proof_note"] = proof_note
    out["triage"] = triage or {}
    out["fingerprint"] = fp or {}
    out["edge"] = edge or {}
    print(json.dumps(out, ensure_ascii=False))
    sys.exit(0 if decision == "CHAIN-BLOCKED" else (2 if decision == "CHAIN-PARTIAL" else 1))

print(f"ASSESSMENT: {decision}")
print(f"ASSET:      {asset}")
print(f"VERSION:    {version or 'unknown'}  gate={gate or 'none'}  [{proof_note}]")
print(f"SAPI:       {sapi or 'unknown'}")
print()
print("Preconditions:")
for key, status in pre.items():
    print(f"  {str(labels[key]):<42} {friendly.get(status, status)}")
print()
if decision == "CHAIN-OPEN":
    print("Path: patch-gate not met and web SAPI confirmed reachable.")
    print("      The exploit stage is NOT part of this skill; hand the finding to the owner.")
elif decision == "CHAIN-PARTIAL":
    print("Path: decisive preconditions unknown. Collect php -v / web-SAPI ini before acting.")
else:
    print("Path: patch gate met, not a web SAPI, or every control is in force.")

sys.exit(0 if decision == "CHAIN-BLOCKED" else (2 if decision == "CHAIN-PARTIAL" else 1))
PY
