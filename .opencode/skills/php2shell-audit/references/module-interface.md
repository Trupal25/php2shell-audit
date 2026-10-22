# Validation module interface

This reference defines the stable contract between the PHP2Shell framework and a
**vulnerability-specific validation module**. A module is separately supplied,
explicitly authorized code that runs one bounded experiment against a disposable
vulnerable/patched lab pair. The framework never fabricates a trigger; it runs a
supplied module, records provenance, and classifies the observed result.

The bundled modules are examples of the contract:

| Module | Purpose | Synthetic? |
|---|---|---|
| `modules/oom-differential` | Bounded multipart request-parsing OOM differential (CVE-2026-109618 surface). | No |
| `modules/rce-modphp` | Opt-in RCE adapter for the calibrated 8.4.26/mod_php lab; requires an operator-supplied external trigger. | No |
| `modules/synthetic-fixture` | Contract and classifier test only; never evidence. | **Yes** |

The heap-grooming/execution trigger is **not** included. The `rce-modphp` adapter
contains no exploit: it executes an authorized, operator-supplied upstream
trigger mounted read-only with `--exploit-dir`. A separately supplied module can
also implement the trigger and plug into this interface. Without a trigger, the
framework cannot demonstrate code execution.

## 1. Trust model

- The module is authorized but **untrusted code**. Run it only in the disposable
  lab container, never on a production host or an unrelated target.
- The module runs in its own container on a dedicated, `--internal` Docker
  network with the vulnerable and patched targets. It has no host network, no
  Docker socket, no published ports, no credentials, and cannot reach the
  internet.
- The module receives only its own directory (read-only), its output directory
  (read-write), and — when the manifest declares `requires.external_exploit` — a
  read-only operator-supplied trigger directory. The output directory is mounted
  only into the module container. The external trigger is never copied into this
  repository.
- Self-reported fields are **claims**. The framework independently checks request
  and artifact hashes, target logs, container state, and marker files before an
  impact is promoted. A claim with no corroboration stays `inconclusive`.
- A module marked `synthetic` can never produce an impact above `inconclusive`,
  even if it claims code execution, writes a marker, or looks internally
  consistent. Synthetic results are interface tests, not vulnerability research.

## 2. Module directory

A module is a directory containing `module.json` and its entrypoint and support
files. Example:

```text
modules/oom-differential/
├── module.json
└── run.php
```

### `module.json`

```json
{
  "kind": "php2shell-validation-module",
  "schema": 1,
  "id": "oom-differential",
  "version": "1.0.0",
  "description": "Bounded multipart OOM differential; never claims execution.",
  "authorized_use": "isolated lab only; no production targets",
  "runtime": {
    "image": "php:8.4.27-apache",
    "entrypoint": ["php", "-d", "memory_limit=-1", "/module/run.php"]
  },
  "target": {
    "ini": "assets/lab/repro.ini",
    "apache_conf": "assets/lab/apache-single.conf",
    "files": {
      "repro.php": "assets/lab/repro.php",
      "index.php": "assets/lab/index.php"
    }
  },
  "output": "module-result.json",
  "claims": {
    "synthetic": false,
    "max_impact": "crash-oom",
    "surface": "multipart request parsing"
  }
}
```

Field rules:

| Field | Rule |
|---|---|
| `kind` | Must be `php2shell-validation-module`. |
| `schema` | Must be `1`. |
| `id` | Lowercase `[a-z0-9-]`, 2-64 characters. |
| `version` | Non-empty string; recorded in every artifact. |
| `runtime.image` | Container image used to execute the module. Defaults to `php:8.4.27-apache` if omitted. |
| `runtime.entrypoint` | Non-empty array; first token is an interpreter/binary (`php`, `python3`, `sh`, `bash`, `node`); no `..` path segments. |
| `target.ini` | Optional PHP ini file relative to the repository root; defaults to `assets/lab/repro.ini`. |
| `target.apache_conf` | Optional Apache config mounted read-only at `/etc/apache2/conf-enabled/zz-p2s.conf`; used for the single-worker RCE lab profile. |
| `target.files` | Optional map of container path under `/var/www/html/` to a file relative to the module directory. Defaults to the lab reproduction files. |
| `requires.external_exploit` | Optional boolean. When `true`, `module-run.sh` refuses an actual run without `--exploit-dir` and mounts that directory read-only at `/opt/php2shell-upstream`. |
| `output` | Relative path; must stay inside the output directory; defaults to `module-result.json`. |
| `claims.synthetic` | Required boolean. `true` modules are test fixtures and can never demonstrate impact. |
| `claims.max_impact` | One of the taxonomy values in section 5. The module may not claim more than this in its result. |
| `claims.surface` | Short label recorded in provenance. |

A module directory is validated before any container is started:

```bash
python3 scripts/impact-classify.py --validate-manifest modules/oom-differential --json
```

## 3. Runtime inputs

The harness passes these environment variables:

| Variable | Meaning |
|---|---|
| `P2S_SCHEMA` | `1`. |
| `P2S_ASSET` | Asset name from the audit. |
| `P2S_RUN_ID` | Unique run identifier. |
| `P2S_NONCE` | 16-128 hex, fresh per run; use it in any marker/effect proof. |
| `P2S_TARGET_URL` | Vulnerable target URL on the internal network. |
| `P2S_CONTROL_URL` | Patched control URL on the internal network. |
| `P2S_TARGET_VERSION` | Version hint from the vulnerable image reference. |
| `P2S_CONTROL_VERSION` | Version hint from the patched image reference. |
| `P2S_OUTPUT_DIR` | Writable output directory (`/out`). |
| `P2S_TIMEOUT_SECONDS` | Module budget; stop before the harness hard timeout. |
| `P2S_MODULE_DIR` | Read-only module directory (`/module`). |
| `P2S_EXPLOIT_DIR` | Read-only external trigger directory (`/opt/php2shell-upstream`) when `--exploit-dir` is supplied. |

The harness does **not** pass the disclosure canary to the module. The canary is
present in the target environment and is used by the classifier to corroborate a
claimed memory disclosure. The target containers also receive `N=<fresh harness
nonce>` for the short marker command used by the RCE adapter; the module cannot
read the target filesystem and must let the harness retrieve the marker.

## 4. Module result

The module writes `$P2S_OUTPUT_DIR/<output>` (default `module-result.json`):

```json
{
  "kind": "validation-module-result",
  "schema": 1,
  "module": {"id": "oom-differential", "version": "1.0.0", "synthetic": false},
  "status": "completed",
  "asset": "lab-vulnerable",
  "nonce": "9f2c...",
  "started_at": "2026-10-22T10:00:00Z",
  "finished_at": "2026-10-22T10:00:04Z",
  "targets": {
    "vulnerable": {"url": "http://vulnerable/repro.php", "php_version": "8.4.26"},
    "patched": {"url": "http://patched/repro.php", "php_version": "8.4.27"}
  },
  "claims": {
    "impact": "crash-oom",
    "execution_effects": [],
    "oom_observed": true,
    "control_oom_observed": false,
    "normal_observed": false,
    "control_normal_observed": true,
    "differential": true
  },
  "requests": [
    {
      "role": "vulnerable",
      "method": "POST",
      "url": "http://vulnerable/repro.php",
      "body_sha256": "…64 hex…",
      "body_bytes": 1839274,
      "response_status": 200,
      "response_sha256": "…64 hex…",
      "response_bytes": 512,
      "response_excerpt": "Allowed memory size of 8388608 bytes exhausted …"
    }
  ],
  "artifacts": [
    {"path": "raw/request.multipart", "sha256": "…", "bytes": 1839274, "kind": "request-body"},
    {"path": "raw/vulnerable.response", "sha256": "…", "bytes": 512, "kind": "response"}
  ],
  "observed_effects": {},
  "limitations": ["This module measures OOM behavior only; it does not implement heap grooming or code execution."]
}
```

Field rules:

| Field | Rule |
|---|---|
| `kind` / `schema` | Must be `validation-module-result` / `1`. |
| `module.id` / `module.version` | Must match the manifest. |
| `module.synthetic` | Must match the manifest; a mismatch is `inconclusive`. |
| `status` | `completed` \| `failed` \| `blocked` \| `timeout`. Only `completed` can support an impact above `suspected-exposure`. |
| `asset` / `nonce` | Must match the harness inputs exactly. |
| `requests[]` | Each request has a method, URL, 64-hex body digest, body byte count, HTTP status, and 64-hex response digest. The digest must match the artifact file when the artifact is present. |
| `artifacts[]` | Paths are relative to the output directory, contain no `..`, and each SHA-256 must match. |
| `claims.execution_effects` | A list of effect labels. Non-empty is a claim, not proof. |
| `claims.impact` | The module's claimed impact; the classifier may only downgrade, never upgrade beyond corroboration. |
| `limitations` | Required honest limitations; copied into the report. |

### Execution-proof extension

A module that intends to demonstrate code execution must also produce:

1. An `rce-validation` artifact in the output directory, conforming to
   `references/rce-validation.md`, with a fresh nonce, request digest, and marker
   SHA-256.
2. A marker file written by the target process, with a path reported as
   `evidence.marker_path_in_target` (absolute inside the target container) and
   `evidence.marker_sha256`.
3. `claims.execution_effects` non-empty.
4. For differential validation, a control marker path/hash reported as
   `evidence.control_marker_path_in_target` / `evidence.control_marker_sha256`.
   The harness retrieves it from the patched container as well.

The harness independently retrieves the marker from both target containers,
hashes them, and records `corroboration.marker_in_target` and
`corroboration.control_marker_in_target` only when the retrieved hashes match. The
classifier requires a separate `RCE-CONFIRMED` validator result, a vulnerable
marker, and no matching patched-control marker. A crash, OOM, worker restart, or
synthetic marker is never enough.

The bundled `rce-modphp` adapter uses the target environment variable
`N=<harness nonce>` and the 14-byte command `echo $N>/tmp/m`. The harness then
retrieves `/tmp/m` from both containers. The module cannot see the target
filesystem; the marker and validator result are independent evidence.

### Disclosure-proof extension

A module that intends to demonstrate memory disclosure must write the disclosed
bytes to an artifact with `"kind": "memory-dump"`. The classifier searches the
bytes for the harness canary (a random value present in the target environment,
not passed to the module). If the canary is absent, or the patched control also
discloses it, the result is not `memory-disclosure`.

## 5. Impact taxonomy

The classifier emits exactly one of:

| Impact | Meaning | Minimum corroboration |
|---|---|---|
| `suspected-exposure` | Below-gate web SAPI and reachable, but no module test was run. | Version/SAPI/chain evidence; never an execution claim. |
| `crash-oom` | The vulnerable target exhausted memory, aborted a worker, or restarted while the patched control did not. | Harness log/response artifact, not just the module's JSON. |
| `memory-safety-failure` | A sanitizer, heap-corruption, or segmentation signal in the vulnerable target and not the control. | Harness log or artifact containing the signal. |
| `memory-disclosure` | Bytes from the target contain the harness canary and the control does not. | Canary match in the disclosed artifact. |
| `demonstrated-code-execution` | Execution effects are corroborated by a marker retrieved from the target and an `RCE-CONFIRMED` validator result. | Validator + independent marker retrieval; never synthetic. |
| `inconclusive` | Missing, failed, synthetic, uncorroborated, or contradictory evidence. | None. |

Rules that are enforced, not advisory:

- A `crash-oom` result is **not** a memory-safety failure unless a sanitizer or
  heap-corruption signal is present.
- A crash or OOM is **never** promoted to `demonstrated-code-execution`.
- A synthetic module result is **always** `inconclusive`.
- A self-reported `RCE-CONFIRMED` string in the module JSON is ignored; only the
  separate `rce-validate.sh` result counts.
- If the vulnerable and patched targets both show the effect, the result is
  `inconclusive` (no differential), with the observation recorded.
- A module that times out or exits non-zero yields `inconclusive`, even if it
  wrote a partial result.

## 6. Harness artifact (`module-run.json`)

`scripts/module-run.sh` wraps the module and writes `module-run.json`:

```json
{
  "kind": "validation-module-run",
  "schema": 1,
  "run_id": "20261022T100000Z-1234-5678",
  "asset": "lab-vulnerable",
  "module": {"id": "oom-differential", "version": "1.0.0", "sha256": "…", "synthetic": false},
  "started_at": "…",
  "finished_at": "…",
  "invocation": {
    "argv": ["bash", "scripts/module-run.sh", "--module", "modules/oom-differential", "…"],
    "host": "lab-host",
    "docker_version": "29.9.2",
    "timeout_seconds": 90,
    "resource_limits": {"memory": "512m", "cpus": "1", "pids_limit": 128}
  },
  "network": {"name": "p2s-…", "internal": true},
  "targets": {
    "vulnerable": {
      "image": "php:8.4.26-apache",
      "image_id": "sha256:…",
      "repo_digests": ["php@sha256:…"],
      "container": "…",
      "url": "http://vulnerable/repro.php",
      "version": "8.4.26",
      "published_ports": [],
      "running_after": true,
      "oom_killed": false,
      "restart_count": 0,
      "apache_log_sha256": "…",
      "apache_log_new": ["Allowed memory size of 8388608 bytes exhausted …"]
    },
    "patched": {"…": "…"}
  },
  "module_container": {
    "name": "…",
    "image": "php:8.4.27-apache",
    "image_id": "sha256:…",
    "exit_code": 0,
    "timed_out": false,
    "logs": "raw/module.log",
    "logs_sha256": "…"
  },
  "result": {"…": "the validated module result"},
  "result_sha256": "…",
  "classification": {"…": "the impact-classification object"},
  "harness_observations": {
    "vulnerable": {"oom_in_log": true, "crash_signal_in_log": false, "running_after": true},
    "patched": {"oom_in_log": false, "crash_signal_in_log": false, "running_after": true}
  },
  "corroboration": {
    "marker_in_target": false,
    "marker_sha256": "",
    "control_marker_in_target": false,
    "control_marker_sha256": ""
  },
  "cleanup": {"kept": false, "containers_removed": true, "network_removed": true},
  "limitations": ["…"]
}
```

The harness records the **actual invocation**, image IDs/digests, timestamps,
resource limits, internal network, module/result/log hashes, target container
state, and cleanup. `harness_observations` are independent of the module's JSON.

## 7. Running a module

```bash
# Validate the contract only; no Docker, no request.
bash scripts/module-run.sh --module modules/oom-differential --dry-run

# Real disposable lab run (requires Docker + both images).
bash scripts/module-run.sh \
  --module modules/oom-differential \
  --asset lab-vulnerable \
  --out module-runs/oom-1 \
  --timeout 90 \
  --json

# Classify an externally produced run artifact without re-running it.
python3 scripts/impact-classify.py \
  --run module-runs/oom-1/module-run.json \
  --out module-runs/oom-1/classification.json \
  --json

# Opt-in RCE adapter with an operator-supplied external trigger.
bash scripts/module-run.sh \
  --module modules/rce-modphp \
  --exploit-dir /authorized/path/php2shell-upstream \
  --asset lab-rce --out module-runs/rce-1 --timeout 180 --json

# Two-run repeatability check (34 assertions).
bash scripts/rce-integration.sh \
  --exploit-dir /authorized/path/php2shell-upstream \
  --out rce-integration-1
```

Exit codes for `module-run.sh`: `0` run and classification produced, `2`
Docker/image/tool/readiness unavailable, `3` module failed or timed out (partial
evidence is kept), `4` usage or module-contract error.

### Supplying the authorized exploit module

A separately supplied module only needs to follow this contract. Do not place a
production exploit in this repository. Keep it in an access-controlled location,
give it a manifest with `"synthetic": false`, and run it against the disposable
lab pair:

```bash
bash scripts/module-run.sh --module /authorized/path/php2shell-module \
  --exploit-dir /authorized/path/php2shell-upstream \
  --asset lab-vulnerable --out module-runs/authorized-1 --timeout 300
```

The harness does not generate a trigger, does not embed an exploit, and does not
claim success on the module's behalf. If the module produces no corroborated
marker, the classifier will return `crash-oom`, `memory-safety-failure`,
`memory-disclosure`, or `inconclusive` — never `demonstrated-code-execution`.

## 8. Boundary and external trigger

The following remain outside this repository and are the external dependency:

- The heap layout/grooming sequence that turns the OOM-corrupted request state
  into a controlled write.
- A reliable pre-auth trigger against a specific build, SAPI, extension set, and
  allocator layout.
- An execution-effect proof (marker/command output) with a fresh nonce.

The interface, disposable lab, provenance, negative controls, and impact
classification are implemented. The `rce-modphp` adapter implements the
execution-proof bridge for one calibrated profile, but the trigger itself is
supplied by the operator and is not redistributed. The upstream trigger has no
explicit license; review and authorization are the operator's responsibility.
The adapter is never exposed through `assess-url.sh`.
