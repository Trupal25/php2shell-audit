#!/usr/bin/env bash
# php2shell rce-validate: four-state RCE evidence validator.
#
# This stage does NOT generate or send an exploit payload. It validates an
# execution-evidence artifact produced by an authorized validation module and
# refuses to confirm RCE unless the evidence is internally consistent,
# reproducible, and attributable to the vulnerability's preconditions.
#
# States:
#   RCE-CONFIRMED        execution evidence is consistent and reproducible
#   RCE-NOT-REPRODUCED   trigger attempted, no execution effects recorded
#   RCE-INCONCLUSIVE     evidence incomplete, inconsistent, or tampered
#   RCE-BLOCKED          patch gate met or a decisive control is in force
set -uo pipefail

EVIDENCE=""
MARKERS=""
ASSET=""
SEEN_FILE=".rce-nonces.json"
JSON=0

usage() {
  cat <<'EOF'
Usage: rce-validate.sh --evidence FILE [options]

Validates an RCE evidence artifact for CVE-2026-109618/109619.

Options:
  --evidence FILE    Evidence JSON (required)
  --markers FILE     Marker file written by the execution proof
  --asset NAME       Asset name (default: evidence asset)
  --seen-file FILE   Nonce ledger for replay detection (default: .rce-nonces.json)
  --json             Emit one JSON object
  -h, --help         Show this help

Exit codes:
  0 RCE-CONFIRMED
  1 RCE-BLOCKED
  2 RCE-NOT-REPRODUCED
  3 RCE-INCONCLUSIVE
  4 usage/input error

Evidence schema: references/rce-validation.md
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence) EVIDENCE="${2:-}"; shift 2 ;;
    --markers) MARKERS="${2:-}"; shift 2 ;;
    --asset) ASSET="${2:-}"; shift 2 ;;
    --seen-file) SEEN_FILE="${2:-.rce-nonces.json}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 4 ;;
  esac
done

[[ -n "$EVIDENCE" ]] || { echo "--evidence is required" >&2; usage; exit 4; }
[[ -f "$EVIDENCE" ]] || { echo "evidence file not found: $EVIDENCE" >&2; exit 4; }

python3 - "$EVIDENCE" "$MARKERS" "$ASSET" "$SEEN_FILE" "$JSON" <<'PY'
import hashlib, json, os, re, sys
from datetime import datetime

evidence_path, markers_path, asset_arg, seen_path, as_json = sys.argv[1:6]

def fail(code, reasons):
    if as_json == "1":
        print(json.dumps({"state": "RCE-INCONCLUSIVE", "reasons": reasons}, ensure_ascii=False))
    else:
        print("RCE STATE: RCE-INCONCLUSIVE")
        for reason in reasons:
            print(f"REASON:    {reason}")
    sys.exit(code)

try:
    with open(evidence_path, encoding="utf-8", errors="replace") as fh:
        ev = json.load(fh)
except (OSError, json.JSONDecodeError) as exc:
    print(f"cannot read evidence: {exc}", file=sys.stderr)
    sys.exit(4)

reasons = []
checks = {}

def gate_for(version):
    branch = ".".join(str(version).split(".")[:2])
    return {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}.get(branch)

def vtuple(value):
    parts = []
    for piece in str(value).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)

def vge(a, b):
    return vtuple(a) >= vtuple(b)

if not isinstance(ev, dict):
    fail(4, ["evidence root is not a JSON object"])
if ev.get("kind") != "rce-validation":
    fail(4, ["kind must be 'rce-validation'"])
if ev.get("schema") != 1:
    fail(4, ["schema must be 1"])

surface = str(ev.get("surface", ""))
if surface != "session.upload_progress":
    reasons.append(f"surface is {surface or 'missing'}; expected session.upload_progress")

# Attribute the evidence to this audit's asset; a mismatch is not a confirmation.
ev_asset = str(ev.get("asset") or "").strip()
if asset_arg and ev_asset and ev_asset != asset_arg:
    reasons.append(f"evidence asset '{ev_asset}' does not match audit asset '{asset_arg}'")
asset = asset_arg or ev_asset or "unknown"

pre = ev.get("preconditions") if isinstance(ev.get("preconditions"), dict) else {}
version = str(pre.get("php_version", "")).strip()
sapi = str(pre.get("web_sapi", "")).strip().lower()
upload = pre.get("upload_progress_enabled")

if not version:
    reasons.append("preconditions.php_version is missing")
gate = gate_for(version) if version else None
checks["version"] = version or None
checks["gate"] = gate

# Recheck the patch gate from the version. Never trust a claimed "below_gate".
if version and gate and vge(version, gate):
    out = {
        "state": "RCE-BLOCKED",
        "asset": ev.get("asset") or asset_arg,
        "version": version,
        "gate": gate,
        "reasons": [f"PHP {version} meets gate {gate}; exploitation path is not applicable"],
        "checks": checks,
        "evidence": evidence_path,
    }
    print(json.dumps(out, ensure_ascii=False) if as_json == "1" else (
        "RCE STATE: RCE-BLOCKED\n"
        f"ASSET:     {out['asset']}\n"
        f"VERSION:   {version} (gate {gate})\n"
        f"REASON:    {out['reasons'][0]}"))
    sys.exit(1)

WEB_SAPIS = ("mod_php", "frankenphp", "fpm", "lsapi", "cgi", "fastcgi")
if sapi in ("", "unknown"):
    reasons.append("preconditions.web_sapi is missing or unknown")
elif not any(s in sapi for s in WEB_SAPIS):
    out = {
        "state": "RCE-BLOCKED",
        "asset": ev.get("asset") or asset_arg,
        "version": version,
        "gate": gate,
        "reasons": [f"SAPI '{sapi}' is not a web SAPI; no remote path"],
        "checks": checks,
        "evidence": evidence_path,
    }
    print(json.dumps(out, ensure_ascii=False) if as_json == "1" else (
        "RCE STATE: RCE-BLOCKED\n"
        f"ASSET:     {out['asset']}\n"
        f"SAPI:      {sapi} (not web-reachable)\n"
        f"REASON:    {out['reasons'][0]}"))
    sys.exit(1)

# upload_progress is the early-consumer prerequisite.
if upload is None:
    reasons.append("preconditions.upload_progress_enabled is missing")
elif isinstance(upload, str):
    upload_bool = upload.strip().lower() in ("on", "1", "true", "yes")
else:
    upload_bool = bool(upload)
checks["upload_progress_enabled"] = upload_bool
if upload is not None and not upload_bool:
    out = {
        "state": "RCE-BLOCKED",
        "asset": ev.get("asset") or asset_arg,
        "version": version,
        "gate": gate,
        "reasons": ["session.upload_progress is disabled; decisive control in force"],
        "checks": checks,
        "evidence": evidence_path,
    }
    print(json.dumps(out, ensure_ascii=False) if as_json == "1" else (
        "RCE STATE: RCE-BLOCKED\n"
        f"ASSET:     {out['asset']}\n"
        f"CONTROL:   session.upload_progress=Off\n"
        f"REASON:    {out['reasons'][0]}"))
    sys.exit(1)

val = ev.get("validation") if isinstance(ev.get("validation"), dict) else {}
effects = val.get("execution_effects")
effects_bad = False
if not isinstance(effects, list):
    reasons.append("validation.execution_effects must be a list")
    effects_bad = True
    effects = []
elif not effects:
    reasons.append("no execution effects recorded; trigger attempted but not reproduced")
nonce = str(val.get("nonce", "")).strip()
triggered_at = str(val.get("triggered_at", "")).strip()
request_sha = str(val.get("request_sha256", "")).strip()
marker_sha = str(val.get("marker_sha256", "")).strip()

checks["nonce_present"] = bool(nonce)
checks["request_sha256_present"] = bool(request_sha)
checks["marker_sha256_present"] = bool(marker_sha)

if not nonce:
    reasons.append("validation.nonce is missing")
elif not re.fullmatch(r"[A-Fa-f0-9]{16,128}", nonce):
    reasons.append("validation.nonce is not 16-128 hex characters")
if not triggered_at:
    reasons.append("validation.triggered_at is missing")
else:
    try:
        datetime.fromisoformat(triggered_at.replace("Z", "+00:00"))
    except ValueError:
        reasons.append("validation.triggered_at is not ISO-8601")
if not re.fullmatch(r"[A-Fa-f0-9]{64}", request_sha):
    reasons.append("validation.request_sha256 is not a 64-hex digest")
if not re.fullmatch(r"[A-Fa-f0-9]{64}", marker_sha):
    reasons.append("validation.marker_sha256 is not a 64-hex digest")

# Marker-file integrity and nonce binding.
marker_nonce_ok = None
if markers_path:
    if not os.path.isfile(markers_path):
        reasons.append(f"marker file not found: {markers_path}")
        marker_nonce_ok = False
    else:
        data = open(markers_path, "rb").read()
        actual = hashlib.sha256(data).hexdigest()
        checks["marker_sha256_actual"] = actual
        if marker_sha and actual.lower() != marker_sha.lower():
            reasons.append("marker file hash does not match validation.marker_sha256")
            marker_nonce_ok = False
        else:
            marker_nonce_ok = bool(nonce) and nonce.encode() in data
            checks["marker_contains_nonce"] = marker_nonce_ok
            if not marker_nonce_ok:
                reasons.append("marker file does not contain the validation nonce")
else:
    reasons.append("no --markers file supplied; marker integrity cannot be verified")

# Replay detection.
seen = {}
if os.path.isfile(seen_path):
    try:
        seen = json.load(open(seen_path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        reasons.append(f"nonce ledger is unreadable: {seen_path}")
        seen = {}
    if not isinstance(seen, dict):
        reasons.append(f"nonce ledger is not a JSON object: {seen_path}")
        seen = {}
prior = seen.get(asset, [])
if nonce and nonce in prior:
    reasons.append("nonce was already used for this asset; evidence is a replay")

# Decide.
if any("no execution effects" in r for r in reasons):
    state = "RCE-NOT-REPRODUCED"
    code = 2
elif reasons:
    state = "RCE-INCONCLUSIVE"
    code = 3
else:
    state = "RCE-CONFIRMED"
    code = 0
    seen.setdefault(asset, []).append(nonce)
    try:
        with open(seen_path, "w", encoding="utf-8") as fh:
            json.dump(seen, fh, indent=2)
    except OSError as exc:
        reasons.append(f"nonce ledger is not writable; replay protection not persisted: {exc}")
        state = "RCE-INCONCLUSIVE"
        code = 3

out = {
    "state": state,
    "asset": asset,
    "version": version,
    "gate": gate,
    "sapi": sapi or "unknown",
    "reasons": reasons,
    "checks": checks,
    "evidence": evidence_path,
}
if as_json == "1":
    print(json.dumps(out, ensure_ascii=False))
else:
    print(f"RCE STATE: {state}")
    print(f"ASSET:     {asset}")
    print(f"VERSION:   {version or 'unknown'} (gate {gate or 'none'})")
    print(f"SAPI:      {sapi or 'unknown'}")
    if effects:
        print(f"EFFECTS:   {', '.join(str(e) for e in effects)}")
    else:
        print("EFFECTS:   none recorded")
    if reasons:
        print("REASONS:")
        for reason in reasons:
            print(f"  - {reason}")
    else:
        print("REASONS:   none; evidence is consistent and reproducible")
sys.exit(code)
PY
