#!/usr/bin/env bash
# php2shell module-run: execute one authorized validation module in a disposable
# internal lab and capture corroborated provenance.
#
# The harness:
#   1. validates the module contract (module.json),
#   2. starts vulnerable + patched Apache/mod_php containers on a dedicated
#      --internal Docker network with no published ports and resource limits,
#   3. runs the module container on the same network with no host mounts except
#      the read-only module directory and the output directory,
#   4. captures module stdout/stderr, target logs, image IDs/digests, timings,
#      request/response artifact hashes, container state, and cleanup,
#   5. classifies the result with scripts/impact-classify.py, which treats the
#      module JSON as claims until independently corroborated.
#
# It does not generate or embed an exploit trigger. The module supplies the
# experiment; the harness supplies isolation, provenance, and conservative
# classification.
#
# Exit codes:
#   0  run completed and classification written
#   2  Docker/image/tool/readiness unavailable (no result)
#   3  module failed, timed out, or produced an invalid result (partial evidence kept)
#   4  usage or module-contract error
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
ORIGINAL_ARGV=("$0" "$@")

MODULE_DIR=""
OUT=""
ASSET=""
V_IMAGE="php:8.4.26-apache"
P_IMAGE="php:8.4.27-apache"
MODULE_IMAGE=""
TIMEOUT=90
MEMORY="512m"
CPUS="1"
PIDS=128
KEEP=0
PULL=0
JSON=0
DRY_RUN=0
ALLOW_SYNTHETIC=0
CLEANED=0

V_NAME=""; P_NAME=""; M_NAME=""; NET=""
MODULE_ID=""; MODULE_VERSION=""; SYNTHETIC=0; MODULE_SHA=""
MODULE_OUTPUT="module-result.json"
ENTRY=()
TARGET_MOUNTS=()
INI_PATH=""
RESULT_PATH=""
RCE_JSON=""
CANARY=""
RUN_ID=""
NONCE=""
STARTED_AT=""
FINISHED_AT=""
V_IMAGE_ID=""; P_IMAGE_ID=""; M_IMAGE_ID=""
V_DIGESTS="[]"; P_DIGESTS="[]"
V_VERSION=""; P_VERSION=""
V_URL=""; P_URL=""
V_BEFORE_LINES=0; P_BEFORE_LINES=0
MODULE_EXIT=1; MODULE_TIMED_OUT=0
MARKER_IN_TARGET=0; MARKER_SHA=""
CONTAINERS_REMOVED=0; NETWORK_REMOVED=0

usage() {
  cat <<'EOF'
Usage: module-run.sh --module DIR [options]

Runs one validation module against a disposable vulnerable/patched lab pair on
an internal Docker network, then classifies the observed impact.

Options:
  --module DIR            Module directory containing module.json (required)
  --out DIR               Evidence directory (default: module-run-<timestamp>)
  --asset NAME            Asset name (default: lab-php2shell-module)
  --vulnerable-image IMG  Default: php:8.4.26-apache
  --patched-image IMG     Default: php:8.4.27-apache
  --module-image IMG      Override the manifest runtime image
  --timeout SEC           Hard module timeout (default: 90)
  --memory SIZE           Per-container memory limit (default: 512m)
  --cpus N                Per-container CPU limit (default: 1)
  --pids-limit N          Per-container PID limit (default: 128)
  --pull                  Pull missing images first
  --keep                  Keep containers/network after the run
  --allow-synthetic       Permit a manifest with claims.synthetic=true
                          (its classification is always inconclusive)
  --dry-run               Validate the contract and print the plan; no Docker
  --json                  Print module-run.json to stdout
  -h, --help              Show this help

Contract: references/module-interface.md
Impact taxonomy: suspected-exposure, crash-oom, memory-safety-failure,
memory-disclosure, demonstrated-code-execution, inconclusive.
EOF
}

log() { printf '[module-run] %s\n' "$*" >&2; }

cleanup() {
  if [[ "$CLEANED" == 1 || "$KEEP" == 1 ]]; then
    return 0
  fi
  [[ -n "$M_NAME" ]] && docker rm -f "$M_NAME" >/dev/null 2>&1 || true
  [[ -n "$V_NAME" ]] && docker rm -f "$V_NAME" >/dev/null 2>&1 || true
  [[ -n "$P_NAME" ]] && docker rm -f "$P_NAME" >/dev/null 2>&1 || true
  [[ -n "$NET" ]] && docker network rm "$NET" >/dev/null 2>&1 || true
  CLEANED=1
}
trap cleanup EXIT INT TERM

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    python3 - "$1" <<'PY'
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())
PY
  fi
}

json_array_from_docker() {
  docker image inspect --format '{{json .RepoDigests}}' "$1" 2>/dev/null || printf '[]'
}

version_from_image() {
  python3 - "$1" <<'PY'
import re, sys
match = re.search(r"(\d+\.\d+\.\d+)", sys.argv[1])
print(match.group(1) if match else "unknown")
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --module) MODULE_DIR="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --asset) ASSET="${2:-}"; shift 2 ;;
    --vulnerable-image) V_IMAGE="${2:-}"; shift 2 ;;
    --patched-image) P_IMAGE="${2:-}"; shift 2 ;;
    --module-image) MODULE_IMAGE="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-90}"; shift 2 ;;
    --memory) MEMORY="${2:-512m}"; shift 2 ;;
    --cpus) CPUS="${2:-1}"; shift 2 ;;
    --pids-limit) PIDS="${2:-128}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --pull) PULL=1; shift ;;
    --allow-synthetic) ALLOW_SYNTHETIC=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 4 ;;
  esac
done

[[ -n "$MODULE_DIR" ]] || { echo "--module is required" >&2; usage >&2; exit 4; }
[[ -d "$MODULE_DIR" ]] || { echo "module directory not found: $MODULE_DIR" >&2; exit 4; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] && (( TIMEOUT > 0 )) || { echo "--timeout must be a positive integer" >&2; exit 4; }
[[ "$PIDS" =~ ^[0-9]+$ ]] && (( PIDS > 0 )) || { echo "--pids-limit must be a positive integer" >&2; exit 4; }

MODULE_DIR="$(cd "$MODULE_DIR" && pwd)"
[[ -n "$ASSET" ]] || ASSET="lab-php2shell-module"
[[ -n "$OUT" ]] || OUT="module-run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/raw" || { echo "cannot create $OUT" >&2; exit 4; }
OUT="$(cd "$OUT" && pwd)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}"
NONCE="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
CANARY="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"

# ---- 1. contract validation (no Docker) -------------------------------------
VALIDATE_ARGS=(--validate-manifest "$MODULE_DIR" --json)
[[ "$ALLOW_SYNTHETIC" == 1 ]] && VALIDATE_ARGS+=(--allow-synthetic)
MANIFEST_VALIDATION="$(python3 "$HERE/impact-classify.py" "${VALIDATE_ARGS[@]}" 2>"$OUT/raw/manifest.err")"
MANIFEST_RC=$?
printf '%s\n' "$MANIFEST_VALIDATION" > "$OUT/manifest-validation.json"
if [[ "$MANIFEST_RC" -ne 0 ]]; then
  echo "invalid validation-module contract: $MODULE_DIR" >&2
  printf '%s' "$MANIFEST_VALIDATION" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for reason in d.get("reasons") or ["invalid manifest"]:
    print(f"  - {reason}", file=sys.stderr)
' || true
  exit 4
fi

manifest_get() {
  printf '%s' "$MANIFEST_VALIDATION" | python3 -c '
import json, sys
args = sys.argv[1:]
d = json.load(sys.stdin)
m = d.get("manifest") or {}
cur = m
for key in args:
    if isinstance(cur, dict):
        cur = cur.get(key)
    else:
        cur = None
        break
if cur is None:
    print("")
elif isinstance(cur, bool):
    print("1" if cur else "0")
else:
    print(cur)
' "$@"
}

MODULE_ID="$(manifest_get id)"
MODULE_VERSION="$(manifest_get version)"
SYNTHETIC="$(manifest_get claims synthetic)"
MODULE_OUTPUT="$(manifest_get output)"
[[ -n "$MODULE_OUTPUT" ]] || MODULE_OUTPUT="module-result.json"
[[ -n "$MODULE_IMAGE" ]] || MODULE_IMAGE="$(manifest_get runtime image)"
[[ -n "$MODULE_IMAGE" ]] || MODULE_IMAGE="php:8.4.27-apache"
mapfile -t ENTRY < <(printf '%s' "$MANIFEST_VALIDATION" | python3 -c '
import json, sys
d = json.load(sys.stdin)
m = (d.get("manifest") or {}).get("runtime") or {}
for part in m.get("entrypoint") or []:
    print(part)
')

MODULE_SHA="$(python3 - "$MODULE_DIR" <<'PY'
import hashlib, os, sys
root = sys.argv[1]
h = hashlib.sha256()
for dirpath, dirnames, filenames in os.walk(root):
    dirnames.sort()
    for name in sorted(filenames):
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        h.update(rel.encode("utf-8", "replace") + b"\0")
        try:
            with open(path, "rb") as fh:
                h.update(fh.read())
        except OSError:
            h.update(b"<unreadable>")
        h.update(b"\0")
print(h.hexdigest())
PY
)"

# Target ini/files. Defaults are the lab reproduction assets.
INI_REL="$(manifest_get target ini)"
if [[ -n "$INI_REL" ]]; then
  if [[ -f "$REPO_ROOT/$INI_REL" ]]; then
    INI_PATH="$REPO_ROOT/$INI_REL"
  else
    INI_PATH="$MODULE_DIR/$INI_REL"
  fi
else
  INI_PATH="$REPO_ROOT/assets/lab/repro.ini"
fi
[[ -f "$INI_PATH" ]] || { echo "target ini not found: $INI_PATH" >&2; exit 4; }

TARGET_FILES_TSV="$(printf '%s' "$MANIFEST_VALIDATION" | python3 -c '
import json, sys
d = json.load(sys.stdin)
files = ((d.get("manifest") or {}).get("target") or {}).get("files")
if not isinstance(files, dict) or not files:
    print("repro.php\trepro.php")
    print("index.php\tindex.php")
else:
    for key, value in files.items():
        print(f"{key}\t{value}")
')"
while IFS=$'\t' read -r container_path host_rel; do
  [[ -z "$container_path" ]] && continue
  if [[ -f "$REPO_ROOT/assets/lab/$host_rel" ]]; then
    host_abs="$REPO_ROOT/assets/lab/$host_rel"
  elif [[ -f "$MODULE_DIR/$host_rel" ]]; then
    host_abs="$MODULE_DIR/$host_rel"
  else
    echo "target file not found: $host_rel" >&2
    exit 4
  fi
  TARGET_MOUNTS+=("$host_abs:/var/www/html/$container_path:ro")
done <<< "$TARGET_FILES_TSV"

V_VERSION="$(version_from_image "$V_IMAGE")"
P_VERSION="$(version_from_image "$P_IMAGE")"
V_URL="http://vulnerable/repro.php"
P_URL="http://patched/repro.php"
# A module may mount a different endpoint; the default remains repro.php.
if [[ "$TARGET_FILES_TSV" != *$'repro.php\t'* ]]; then
  V_URL="http://vulnerable/"
  P_URL="http://patched/"
fi

if [[ "$DRY_RUN" == 1 ]]; then
  P2S_PLAN_OUT="$OUT/plan.json" P2S_PLAN_MODULE_ID="$MODULE_ID" \
  P2S_PLAN_MODULE_VERSION="$MODULE_VERSION" P2S_PLAN_SYNTHETIC="$SYNTHETIC" \
  P2S_PLAN_MODULE_SHA="$MODULE_SHA" P2S_PLAN_MODULE_IMAGE="$MODULE_IMAGE" \
  P2S_PLAN_V_IMAGE="$V_IMAGE" P2S_PLAN_P_IMAGE="$P_IMAGE" \
  P2S_PLAN_V_VERSION="$V_VERSION" P2S_PLAN_P_VERSION="$P_VERSION" \
  P2S_PLAN_TIMEOUT="$TIMEOUT" P2S_PLAN_MEMORY="$MEMORY" P2S_PLAN_CPUS="$CPUS" \
  P2S_PLAN_PIDS="$PIDS" P2S_PLAN_INI="$INI_PATH" python3 - <<'PY'
import json, os, shlex
plan = {
    "kind": "validation-module-plan",
    "schema": 1,
    "module": {
        "id": os.environ["P2S_PLAN_MODULE_ID"],
        "version": os.environ["P2S_PLAN_MODULE_VERSION"],
        "sha256": os.environ["P2S_PLAN_MODULE_SHA"],
        "synthetic": os.environ["P2S_PLAN_SYNTHETIC"] == "1",
        "image": os.environ["P2S_PLAN_MODULE_IMAGE"],
    },
    "targets": {
        "vulnerable": {"image": os.environ["P2S_PLAN_V_IMAGE"], "version": os.environ["P2S_PLAN_V_VERSION"]},
        "patched": {"image": os.environ["P2S_PLAN_P_IMAGE"], "version": os.environ["P2S_PLAN_P_VERSION"]},
    },
    "network": {"internal": True, "published_ports": []},
    "resource_limits": {
        "memory": os.environ["P2S_PLAN_MEMORY"],
        "cpus": os.environ["P2S_PLAN_CPUS"],
        "pids_limit": int(os.environ["P2S_PLAN_PIDS"]),
    },
    "timeout_seconds": int(os.environ["P2S_PLAN_TIMEOUT"]),
    "target_ini": os.environ["P2S_PLAN_INI"],
    "would_run": True,
}
with open(os.environ["P2S_PLAN_OUT"], "w", encoding="utf-8") as fh:
    json.dump(plan, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  if [[ "$JSON" == 1 ]]; then
    cat "$OUT/plan.json"
  else
    log "dry run: module=$MODULE_ID synthetic=$SYNTHETIC image=$MODULE_IMAGE"
    log "targets: vulnerable=$V_IMAGE patched=$P_IMAGE"
    log "network: internal, no published ports; limits memory=$MEMORY cpus=$CPUS pids=$PIDS"
    log "plan: $OUT/plan.json"
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d, indent=2))' "$OUT/plan.json"
  fi
  exit 0
fi

if [[ "$SYNTHETIC" == 1 && "$ALLOW_SYNTHETIC" != 1 ]]; then
  echo "refusing synthetic module without --allow-synthetic" >&2
  exit 4
fi
if [[ "${#ENTRY[@]}" -eq 0 ]]; then
  echo "manifest runtime.entrypoint is empty" >&2
  exit 4
fi

# ---- 2. runtime dependencies ------------------------------------------------
for tool in docker python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "missing dependency: $tool" >&2
    exit 2
  }
done
docker info >/dev/null 2>&1 || { echo "Docker daemon is not available" >&2; exit 2; }

for image in "$V_IMAGE" "$P_IMAGE" "$MODULE_IMAGE"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    if [[ "$PULL" == 1 ]]; then
      log "pulling $image"
      docker pull "$image" >/dev/null 2>&1 || { echo "could not pull $image" >&2; exit 2; }
    else
      echo "image not present: $image (rerun with --pull)" >&2
      exit 2
    fi
  fi
done

V_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$V_IMAGE")"
P_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$P_IMAGE")"
M_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$MODULE_IMAGE")"
V_DIGESTS="$(json_array_from_docker "$V_IMAGE")"
P_DIGESTS="$(json_array_from_docker "$P_IMAGE")"
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
HOST_NAME="$(hostname 2>/dev/null || echo unknown)"
INI_SHA="$(sha256_file "$INI_PATH")"
PROBE_SHA=""
for mount in "${TARGET_MOUNTS[@]}"; do
  if [[ "$mount" == *":/var/www/html/repro.php:ro" ]]; then
    PROBE_SHA="$(sha256_file "${mount%%:*}")"
  fi
done

# ---- 3. internal network ----------------------------------------------------
NET="p2s-${RUN_ID}"
V_NAME="p2s-${RUN_ID}-vuln"
P_NAME="p2s-${RUN_ID}-patched"
M_NAME="p2s-${RUN_ID}-module"

docker network create --internal --label "p2s.run=${RUN_ID}" "$NET" >/dev/null || {
  echo "could not create the internal lab network" >&2
  exit 2
}

start_target() {
  local role="$1" name="$2" image="$3" mount
  local args=(
    -d --name "$name" --hostname "$role"
    --network "$NET" --network-alias "$role"
    --memory "$MEMORY" --memory-swap "$MEMORY" --cpus "$CPUS" --pids-limit "$PIDS"
    --security-opt no-new-privileges --restart no
    -e "P2S_CANARY=$CANARY"
    -v "$INI_PATH:/usr/local/etc/php/conf.d/zz-p2s.ini:ro"
  )
  for mount in "${TARGET_MOUNTS[@]}"; do
    args+=(-v "$mount")
  done
  docker run "${args[@]}" "$image" >/dev/null
}

start_target vulnerable "$V_NAME" "$V_IMAGE" || { echo "could not start vulnerable target" >&2; exit 2; }
start_target patched "$P_NAME" "$P_IMAGE" || { echo "could not start patched target" >&2; exit 2; }

wait_ready() {
  local name="$1" i
  for i in $(seq 1 80); do
    if docker exec "$name" php -r '
$s = @fsockopen("127.0.0.1", 80, $errno, $errstr, 2);
if (!$s) { exit(1); }
fwrite($s, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n");
$r = stream_get_contents($s);
fclose($s);
exit(strpos($r, "HTTP/") !== false ? 0 : 1);
' >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != "true" ]]; then
      return 1
    fi
    sleep 0.5
  done
  return 1
}

wait_ready "$V_NAME" || { echo "vulnerable target did not become ready" >&2; exit 2; }
wait_ready "$P_NAME" || { echo "patched target did not become ready" >&2; exit 2; }

for spec in "vulnerable:$V_NAME:$V_URL" "patched:$P_NAME:$P_URL"; do
  IFS=: read -r role name url <<< "$spec"
  docker logs "$name" > "$OUT/raw/$role.before.log" 2>&1 || true
  lines="$(wc -l < "$OUT/raw/$role.before.log" | tr -d ' ')"
  if [[ "$role" == "vulnerable" ]]; then V_BEFORE_LINES="$lines"; else P_BEFORE_LINES="$lines"; fi
done

# ---- 4. module container ----------------------------------------------------
MODULE_TIMEOUT="$((TIMEOUT > 10 ? TIMEOUT - 10 : 5))"
MODULE_ARGS=(
  -d --name "$M_NAME" --hostname module
  --network "$NET"
  --memory "$MEMORY" --memory-swap "$MEMORY" --cpus "$CPUS" --pids-limit "$PIDS"
  --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp
  --user "$(id -u):$(id -g)"
  -v "$MODULE_DIR:/module:ro"
  -v "$OUT:/out"
  -e "P2S_SCHEMA=1"
  -e "P2S_ASSET=$ASSET"
  -e "P2S_RUN_ID=$RUN_ID"
  -e "P2S_NONCE=$NONCE"
  -e "P2S_TARGET_URL=$V_URL"
  -e "P2S_CONTROL_URL=$P_URL"
  -e "P2S_TARGET_VERSION=$V_VERSION"
  -e "P2S_CONTROL_VERSION=$P_VERSION"
  -e "P2S_OUTPUT_DIR=/out"
  -e "P2S_TIMEOUT_SECONDS=$MODULE_TIMEOUT"
  -e "P2S_MODULE_DIR=/module"
)
docker run "${MODULE_ARGS[@]}" "$MODULE_IMAGE" "${ENTRY[@]}" >/dev/null || {
  echo "could not start the module container" >&2
  exit 2
}

DEADLINE=$((SECONDS + TIMEOUT))
while :; do
  status="$(docker inspect -f '{{.State.Status}}' "$M_NAME" 2>/dev/null || echo missing)"
  if [[ "$status" != "running" ]]; then
    break
  fi
  if (( SECONDS >= DEADLINE )); then
    MODULE_TIMED_OUT=1
    docker kill "$M_NAME" >/dev/null 2>&1 || true
    break
  fi
  sleep 0.5
done
MODULE_EXIT="$(docker inspect -f '{{.State.ExitCode}}' "$M_NAME" 2>/dev/null || echo 1)"
[[ "$MODULE_EXIT" =~ ^[0-9]+$ ]] || MODULE_EXIT=1
docker logs "$M_NAME" > "$OUT/raw/module.log" 2>&1 || true
MODULE_LOG_SHA="$(sha256_file "$OUT/raw/module.log")"

RESULT_PATH="$OUT/$MODULE_OUTPUT"
if [[ ! -f "$RESULT_PATH" ]]; then
  RESULT_PATH=""
fi

# ---- 5. independent target observations -------------------------------------
for spec in "vulnerable:$V_NAME" "patched:$P_NAME"; do
  IFS=: read -r role name <<< "$spec"
  docker logs "$name" > "$OUT/raw/$role.after.log" 2>&1 || true
done

docker inspect "$V_NAME" > "$OUT/raw/vulnerable.inspect.json" 2>/dev/null || true
docker inspect "$P_NAME" > "$OUT/raw/patched.inspect.json" 2>/dev/null || true
docker inspect "$M_NAME" > "$OUT/raw/module.inspect.json" 2>/dev/null || true

# Marker retrieval: a module that claims execution must have written the marker
# inside the target. The copy is independent of the module's JSON.
MARKER_TARGET_PATH=""
MARKER_DECLARED_SHA=""
if [[ -n "$RESULT_PATH" && -f "$RESULT_PATH" ]]; then
  IFS=$'\t' read -r MARKER_TARGET_PATH MARKER_DECLARED_SHA < <(python3 - "$RESULT_PATH" <<'PY'
import json, sys
try:
    result = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
path = str(evidence.get("marker_path_in_target") or "")
sha = str(evidence.get("marker_sha256") or "")
if path and sha:
    print(path, sha, sep="\t")
PY
)
fi
if [[ -n "$MARKER_TARGET_PATH" ]]; then
  if docker exec "$V_NAME" cat "$MARKER_TARGET_PATH" > "$OUT/raw/target-marker.bin" 2>/dev/null; then
    ACTUAL_MARKER_SHA="$(sha256_file "$OUT/raw/target-marker.bin")"
    if [[ -n "$MARKER_DECLARED_SHA" && "$ACTUAL_MARKER_SHA" == "$MARKER_DECLARED_SHA" ]]; then
      MARKER_IN_TARGET=1
      MARKER_SHA="$ACTUAL_MARKER_SHA"
    fi
  else
    rm -f "$OUT/raw/target-marker.bin"
  fi
fi

# Optional RCE validator bridge: the module supplies an rce-validation artifact
# and the harness supplies the marker it retrieved from the target.
if [[ -n "$RESULT_PATH" && -f "$RESULT_PATH" ]]; then
  RCE_REL="$(python3 - "$RESULT_PATH" <<'PY'
import json, sys
try:
    result = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
print(evidence.get("rce_evidence_path") or "")
PY
)"
  if [[ -n "$RCE_REL" && -f "$OUT/$RCE_REL" ]]; then
    RCE_MARKERS="$OUT/raw/target-marker.bin"
    if [[ ! -f "$RCE_MARKERS" ]]; then
      RCE_MARKERS="$(dirname "$OUT/$RCE_REL")/marker.txt"
    fi
    "$HERE/rce-validate.sh" --evidence "$OUT/$RCE_REL" --markers "$RCE_MARKERS" \
      --asset "$ASSET" --seen-file "$OUT/.rce-seen.json" --json \
      > "$OUT/rce.json" 2> "$OUT/rce.err" || true
    RCE_JSON="$OUT/rce.json"
  fi
fi

# ---- 6. provenance + classification ----------------------------------------
if [[ -z "$RESULT_PATH" ]]; then
  cat > "$OUT/raw/missing-result.json" <<'JSON'
{"kind":"validation-module-result","schema":1,"status":"failed","claims":{},"artifacts":[],"limitations":["The module did not write a result file."]}
JSON
  RESULT_PATH="$OUT/raw/missing-result.json"
fi
RESULT_SHA="$(sha256_file "$RESULT_PATH")"

export P2S_OUT="$OUT" P2S_RUN_ID="$RUN_ID" P2S_ASSET="$ASSET" P2S_NONCE="$NONCE" \
  P2S_SYNTHETIC="$SYNTHETIC" P2S_MODULE_ID="$MODULE_ID" P2S_MODULE_VERSION="$MODULE_VERSION" \
  P2S_MODULE_SHA="$MODULE_SHA" P2S_MODULE_IMAGE="$MODULE_IMAGE" P2S_MODULE_IMAGE_ID="$M_IMAGE_ID" \
  P2S_MODULE_EXIT="$MODULE_EXIT" P2S_MODULE_TIMED_OUT="$MODULE_TIMED_OUT" \
  P2S_MODULE_LOG_SHA="$MODULE_LOG_SHA" P2S_STARTED_AT="$STARTED_AT" P2S_FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  P2S_DOCKER_VERSION="$DOCKER_VERSION" P2S_HOST="$HOST_NAME" P2S_TIMEOUT="$TIMEOUT" \
  P2S_MEMORY="$MEMORY" P2S_CPUS="$CPUS" P2S_PIDS="$PIDS" P2S_NET="$NET" \
  P2S_V_NAME="$V_NAME" P2S_P_NAME="$P_NAME" P2S_M_NAME="$M_NAME" \
  P2S_V_IMAGE="$V_IMAGE" P2S_P_IMAGE="$P_IMAGE" P2S_V_IMAGE_ID="$V_IMAGE_ID" \
  P2S_P_IMAGE_ID="$P_IMAGE_ID" P2S_V_DIGESTS="$V_DIGESTS" P2S_P_DIGESTS="$P_DIGESTS" \
  P2S_V_VERSION="$V_VERSION" P2S_P_VERSION="$P_VERSION" P2S_V_URL="$V_URL" P2S_P_URL="$P_URL" \
  P2S_V_BEFORE_LINES="$V_BEFORE_LINES" P2S_P_BEFORE_LINES="$P_BEFORE_LINES" \
  P2S_KEEP="$KEEP" P2S_CANARY_SHA="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$CANARY")" \
  P2S_INI_SHA="$INI_SHA" P2S_PROBE_SHA="$PROBE_SHA" \
  P2S_MARKER_IN_TARGET="$MARKER_IN_TARGET" P2S_MARKER_SHA="$MARKER_SHA" \
  P2S_RESULT_PATH="$RESULT_PATH" P2S_RESULT_SHA="$RESULT_SHA" \
  P2S_CONTAINERS_REMOVED="$CONTAINERS_REMOVED" \
  P2S_NETWORK_REMOVED="$NETWORK_REMOVED" P2S_ARGV="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${ORIGINAL_ARGV[@]}")"

python3 - <<'PY'
import hashlib, json, os, re, sys
out = os.environ["P2S_OUT"]

def read(path):
    try:
        return open(path, "rb").read()
    except OSError:
        return b""

def sha(path):
    data = read(path)
    return hashlib.sha256(data).hexdigest() if data else ""

def new_log(role, before):
    data = read(os.path.join(out, "raw", f"{role}.after.log")).decode("utf-8", "replace")
    lines = data.splitlines()
    try:
        start = int(before)
    except ValueError:
        start = 0
    new = lines[start:] if start < len(lines) else []
    return data, new

def observe(role, before, running, oom_killed, restart_count):
    text, new = new_log(role, before)
    return {
        "apache_log_sha256": sha(os.path.join(out, "raw", f"{role}.after.log")),
        "apache_log_new": new[-80:],
        "oom_in_log": bool(re.search(r"Allowed memory size of \d+ bytes exhausted", text)),
        "crash_signal_in_log": bool(re.search(
            r"exit signal|segmentation fault|zend_mm_heap corrupted|core dumped|AH00051",
            text, re.IGNORECASE)),
        "running_after": running,
        "oom_killed": oom_killed,
        "restart_count": restart_count,
    }

def inspect_field(path, expr, default):
    try:
        data = json.load(open(path, encoding="utf-8"))
        item = data[0] if isinstance(data, list) and data else data
        cur = item
        for part in expr.split("."):
            cur = cur[int(part)] if isinstance(cur, list) else cur.get(part)
            if cur is None:
                return default
        return cur
    except Exception:
        return default

v_running = bool(inspect_field(os.path.join(out, "raw", "vulnerable.inspect.json"), "State.Running", True))
p_running = bool(inspect_field(os.path.join(out, "raw", "patched.inspect.json"), "State.Running", True))
v_oomk = bool(inspect_field(os.path.join(out, "raw", "vulnerable.inspect.json"), "State.OOMKilled", False))
p_oomk = bool(inspect_field(os.path.join(out, "raw", "patched.inspect.json"), "State.OOMKilled", False))
v_restart = int(inspect_field(os.path.join(out, "raw", "vulnerable.inspect.json"), "RestartCount", 0) or 0)
p_restart = int(inspect_field(os.path.join(out, "raw", "patched.inspect.json"), "RestartCount", 0) or 0)

v_obs = observe("vulnerable", os.environ["P2S_V_BEFORE_LINES"], v_running, v_oomk, v_restart)
p_obs = observe("patched", os.environ["P2S_P_BEFORE_LINES"], p_running, p_oomk, p_restart)

try:
    argv = json.loads(os.environ.get("P2S_ARGV") or "[]")
except ValueError:
    argv = []
try:
    v_digests = json.loads(os.environ.get("P2S_V_DIGESTS") or "[]")
except ValueError:
    v_digests = []
try:
    p_digests = json.loads(os.environ.get("P2S_P_DIGESTS") or "[]")
except ValueError:
    p_digests = []

provenance = {
    "kind": "validation-module-run-provenance",
    "schema": 1,
    "run_id": os.environ["P2S_RUN_ID"],
    "asset": os.environ["P2S_ASSET"],
    "nonce": os.environ["P2S_NONCE"],
    "synthetic": os.environ["P2S_SYNTHETIC"] == "1",
    "module": {
        "id": os.environ["P2S_MODULE_ID"],
        "version": os.environ["P2S_MODULE_VERSION"],
        "sha256": os.environ["P2S_MODULE_SHA"],
        "image": os.environ["P2S_MODULE_IMAGE"],
        "image_id": os.environ["P2S_MODULE_IMAGE_ID"],
    },
    "module_sha256": os.environ["P2S_MODULE_SHA"],
    "started_at": os.environ["P2S_STARTED_AT"],
    "finished_at": os.environ["P2S_FINISHED_AT"],
    "invocation": {
        "argv": argv,
        "host": os.environ["P2S_HOST"],
        "docker_version": os.environ["P2S_DOCKER_VERSION"],
        "timeout_seconds": int(os.environ["P2S_TIMEOUT"]),
        "resource_limits": {
            "memory": os.environ["P2S_MEMORY"],
            "cpus": os.environ["P2S_CPUS"],
            "pids_limit": int(os.environ["P2S_PIDS"]),
        },
    },
    "network": {
        "name": os.environ["P2S_NET"],
        "internal": True,
        "published_ports": [],
    },
    "targets": {
        "vulnerable": {
            "image": os.environ["P2S_V_IMAGE"],
            "image_id": os.environ["P2S_V_IMAGE_ID"],
            "repo_digests": v_digests,
            "container": os.environ["P2S_V_NAME"],
            "url": os.environ["P2S_V_URL"],
            "version": os.environ["P2S_V_VERSION"],
            "sapi": "mod_php",
            "published_ports": [],
        },
        "patched": {
            "image": os.environ["P2S_P_IMAGE"],
            "image_id": os.environ["P2S_P_IMAGE_ID"],
            "repo_digests": p_digests,
            "container": os.environ["P2S_P_NAME"],
            "url": os.environ["P2S_P_URL"],
            "version": os.environ["P2S_P_VERSION"],
            "sapi": "mod_php",
            "published_ports": [],
        },
    },
    "module_container": {
        "name": os.environ["P2S_M_NAME"],
        "image": os.environ["P2S_MODULE_IMAGE"],
        "image_id": os.environ["P2S_MODULE_IMAGE_ID"],
        "exit_code": int(os.environ["P2S_MODULE_EXIT"]),
        "timed_out": os.environ["P2S_MODULE_TIMED_OUT"] == "1",
        "logs": "raw/module.log",
        "logs_sha256": os.environ["P2S_MODULE_LOG_SHA"],
    },
    "harness_observations": {
        "vulnerable": v_obs,
        "patched": p_obs,
    },
    "corroboration": {
        "marker_in_target": os.environ["P2S_MARKER_IN_TARGET"] == "1",
        "marker_sha256": os.environ["P2S_MARKER_SHA"],
        "canary_sha256": os.environ["P2S_CANARY_SHA"],
    },
    "php_ini_sha256": os.environ["P2S_INI_SHA"],
    "probe_sha256": os.environ["P2S_PROBE_SHA"],
    "result": os.path.basename(os.environ.get("P2S_RESULT_PATH", "module-result.json")),
    "result_sha256": os.environ["P2S_RESULT_SHA"],
    "cleanup": {
        "kept": os.environ["P2S_KEEP"] == "1",
        "containers_removed": os.environ["P2S_CONTAINERS_REMOVED"] == "1",
        "network_removed": os.environ["P2S_NETWORK_REMOVED"] == "1",
    },
    "state": (
        "timeout" if os.environ["P2S_MODULE_TIMED_OUT"] == "1"
        else ("completed" if os.environ["P2S_MODULE_EXIT"] == "0" else "failed")
    ),
    "limitations": [
        "The harness records what the disposable lab did; it does not prove exploitability beyond the classified impact.",
        "The heap-grooming/execution trigger is supplied by the module and is not included in this repository.",
    ],
}
with open(os.path.join(out, "provenance.json"), "w", encoding="utf-8") as fh:
    json.dump(provenance, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

# The result path was exported after the provenance block above; export it now
# for the classifier and merge steps.
export P2S_RESULT_PATH="$RESULT_PATH"

CLASSIFY_ARGS=(--result "$RESULT_PATH" --provenance "$OUT/provenance.json" --result-dir "$OUT" \
  --out "$OUT/classification.json" --json)
[[ -n "$RCE_JSON" ]] && CLASSIFY_ARGS+=(--rce "$RCE_JSON")
[[ -f "$OUT/raw/target-marker.bin" ]] && CLASSIFY_ARGS+=(--marker "$OUT/raw/target-marker.bin")
CLASSIFY_ARGS+=(--canary "$CANARY")
python3 "$HERE/impact-classify.py" "${CLASSIFY_ARGS[@]}" \
  > "$OUT/classification.stdout.json" 2> "$OUT/classification.err" || true

# ---- 7. cleanup and final artifact -----------------------------------------
if [[ "$KEEP" != 1 ]]; then
  cleanup
fi
if [[ "$KEEP" == 1 ]]; then
  CONTAINERS_REMOVED=0
  NETWORK_REMOVED=0
else
  CONTAINERS_REMOVED=1
  for name in "$M_NAME" "$V_NAME" "$P_NAME"; do
    if docker inspect "$name" >/dev/null 2>&1; then
      CONTAINERS_REMOVED=0
    fi
  done
  NETWORK_REMOVED=1
  if docker network inspect "$NET" >/dev/null 2>&1; then
    NETWORK_REMOVED=0
  fi
fi

export P2S_CONTAINERS_REMOVED="$CONTAINERS_REMOVED" P2S_NETWORK_REMOVED="$NETWORK_REMOVED" \
  P2S_RESULT_PATH="$RESULT_PATH" P2S_RCE_JSON="$RCE_JSON"

python3 - "$OUT" <<'PY'
import hashlib, json, os, sys
out = sys.argv[1]

def load(name, default=None):
    path = os.path.join(out, name)
    if not os.path.isfile(path):
        return default
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default

provenance = load("provenance.json", {}) or {}
result = None
result_path = os.environ.get("P2S_RESULT_PATH", "")
if result_path and os.path.isfile(result_path):
    result = load(os.path.relpath(result_path, out) if result_path.startswith(out) else result_path)
classification = load("classification.json", {}) or {}
rce = load("rce.json", None)

run = {
    "kind": "validation-module-run",
    "schema": 1,
    "run_id": provenance.get("run_id", ""),
    "asset": provenance.get("asset", ""),
    "module": provenance.get("module", {}),
    "synthetic": bool(provenance.get("synthetic")),
    "started_at": provenance.get("started_at", ""),
    "finished_at": provenance.get("finished_at", ""),
    "invocation": provenance.get("invocation", {}),
    "network": provenance.get("network", {}),
    "targets": provenance.get("targets", {}),
    "module_container": provenance.get("module_container", {}),
    "harness_observations": provenance.get("harness_observations", {}),
    "corroboration": provenance.get("corroboration", {}),
    "cleanup": {
        "kept": bool(provenance.get("cleanup", {}).get("kept")),
        "containers_removed": os.environ.get("P2S_CONTAINERS_REMOVED") == "1",
        "network_removed": os.environ.get("P2S_NETWORK_REMOVED") == "1",
    },
    "state": provenance.get("state", "failed"),
    "result": result,
    "result_sha256": provenance.get("result_sha256", ""),
    "classification": classification,
    "rce_validation": rce,
    "limitations": classification.get("limitations", provenance.get("limitations", [])),
}
with open(os.path.join(out, "module-run.json"), "w", encoding="utf-8") as fh:
    json.dump(run, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("state","?"))' "$OUT/module-run.json" 2>/dev/null || echo failed)"
IMPACT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("classification",{}).get("impact","?"))' "$OUT/module-run.json" 2>/dev/null || echo inconclusive)"

if [[ "$KEEP" == 1 ]]; then
  log "containers kept: $V_NAME, $P_NAME, $M_NAME; network $NET"
  log "cleanup: docker rm -f $M_NAME $V_NAME $P_NAME && docker network rm $NET"
fi
log "state=$STATE impact=$IMPACT"
log "artifact: $OUT/module-run.json"

if [[ "$JSON" == 1 ]]; then
  cat "$OUT/module-run.json"
else
  python3 - "$OUT/module-run.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
c = d.get("classification", {})
print(f"MODULE:     {d.get('module', {}).get('id', '?')} (synthetic={d.get('synthetic')})")
print(f"STATE:      {d.get('state', '?')}")
print(f"IMPACT:     {c.get('impact', '?')}")
print(f"CONFIDENCE: {c.get('confidence', '?')}")
for item in c.get("basis") or []:
    print(f"BASIS:      {item}")
print(f"ARTIFACT:   {sys.argv[1]}")
PY
fi

if [[ "$STATE" == "completed" ]]; then
  exit 0
fi
exit 3
