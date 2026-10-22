# `rce-modphp` — opt-in RCE validation module

This module is the controlled execution path for `demonstrated-code-execution`.
It is **not** an exploit and does **not** contain one.

It expects an operator-supplied, authorized copy of the public php2shell upstream
trigger. The upstream source has no explicit license, so it is not vendored or
redistributed here. The module mounts that directory read-only, instruments a
temporary copy only to capture the final trigger request/response, and runs it
against the disposable vulnerable/patched lab pair created by
`scripts/module-run.sh`.

## Calibration

The profile is deliberately narrow:

- target: `php:8.4.26-apache` (Debian bookworm, amd64), `mod_php`
- patched control: `php:8.4.27-apache`
- `memory_limit=8M`, `display_errors=On`, `session.upload_progress=On`
- one prefork worker, keep-alive off (`assets/lab/apache-single.conf`)
- verified upstream trigger: the pinned 9bie `exploit.py` at commit `4586f5c`,
  SHA-256 `331789f087d79aaf60ecd71380d7e70b25adc4d8ff1bf8115e1866cfdd2aaaf8`

The module refuses to run if the preflight does not match the calibrated
version/SAPI/INI/architecture. A different PHP build needs a different offset
profile and is out of scope for this module.

## Run it

```bash
# One disposable lab run. The trigger directory must contain exploit.py.
bash scripts/module-run.sh \
  --module modules/rce-modphp \
  --exploit-dir /authorized/path/php2shell-upstream \
  --asset lab-rce \
  --out module-runs/rce-1 \
  --timeout 180 \
  --json

# Repeatability check: two fresh labs, fresh nonces, 34 assertions.
bash scripts/rce-integration.sh \
  --exploit-dir /authorized/path/php2shell-upstream \
  --out rce-integration-1
```

The module always starts its own calibrated disposable pair. When it is invoked
through `run-audit.sh`, the `--url` is only the audit context; it is never the
exploit target.

`--exploit-dir` is mounted at `/opt/php2shell-upstream:ro`; the host directory is
never modified. The module container runs on the internal Docker network with no
published ports, no Docker socket, a read-only root, and the harness resource
limits.

## How the marker is bound

The target containers receive `N=<harness nonce>`. The module runs the trigger
with the 14-byte command:

```sh
echo $N>/tmp/m
```

The target writes its own nonce-bound marker. The module cannot read the target
filesystem. The harness retrieves `/tmp/m` from the vulnerable and patched
containers independently, checks the SHA-256 declared by the module, and runs
`scripts/rce-validate.sh`. A patched-control marker downgrades the result to
`inconclusive`.

`demonstrated-code-execution` therefore requires all of:

- `RCE-CONFIRMED` from the validator;
- a non-empty execution-effect list;
- a marker independently retrieved from the vulnerable target with a matching
  hash and a fresh nonce;
- no matching marker on the patched control;
- verified module artifacts and a completed run.

## Evidence

A successful run writes:

- `module-result.json` — the module's claim and raw request/artifact hashes;
- `rce-evidence.json` — the four-state validator input;
- `raw/trigger-vulnerable.request` / `.response` — final stage-3 POST;
- `raw/trigger-patched.*` — the control attempt when it reaches stage 3;
- `raw/exploit-*.log` — trigger output;
- `raw/preflight-*.json` — target version/SAPI/INI observations.

`module-run.json` adds image IDs/digests, logs, resource limits, cleanup, marker
retrieval, the validator result, and the conservative classification.

## Boundary and licensing

- Only use this against the disposable lab pair, with explicit authorization.
- The module is never invoked by `assess-url.sh`; no arbitrary URL can trigger
  execution. The URL workflow remains non-exploitative.
- Do not commit, redistribute, or publish the upstream trigger with this module.
  Keep it in an access-controlled location and inspect it before use.
- The trigger is probabilistic and build-specific. A failed run is evidence of
  failure for that run, not a claim of safety; a success is evidence only for the
  calibrated build/configuration.
- A crash or OOM signal is not execution. Only the corroborated marker path above
  can produce `demonstrated-code-execution`.

## Verified result

On 2026-10-22, with the pinned trigger and the profile above, two consecutive
fresh-lab runs produced `demonstrated-code-execution` with
`RCE-CONFIRMED`; the retrieved marker contained the run nonce, and the patched
8.4.27 control produced no marker. The same result was produced when the run was
consumed by `run-audit.sh` and rendered into `report.md`/`findings.csv`.
