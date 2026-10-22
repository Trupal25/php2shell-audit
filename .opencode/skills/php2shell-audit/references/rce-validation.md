# RCE evidence validation

This reference defines the four-state RCE validator (`scripts/rce-validate.sh`) and the
evidence artifact it accepts. It is the last stage of the audit-to-report pipeline.

## 1. Boundary: what is and is not implemented

**Implemented in this repository:**

- Patch-gate and SAPI rechecks from the evidence's own preconditions.
- Control recheck for `session.upload_progress.enabled`.
- Nonce freshness (replay ledger) and nonce-to-marker binding.
- Marker-file SHA-256 integrity.
- Request digest shape, execution-effect presence, timestamp parsing.
- Four-state decision, exit codes, human and JSON output.
- Orchestration (`run-audit.sh`) and report/CSV integration.
- Offline tests for all four states plus tamper and replay cases.

**Not implemented: the heap-overflow trigger and heap-grooming/exploitation chain.**

That is the missing technical dependency. The CVE's execution path requires a
working trigger against a specific PHP build and SAPI, plus a heap layout that
survives the target's allocator behavior. A reliable trigger is exploit code. This
repository does not contain one, does not generate one, and does not send one.

A separate, non-RCE reproduction is available in `scripts/lab-repro.sh` and
`references/lab-reproduction.md`. It runs the real vulnerable/patched Apache pair
and records a request-parsing OOM differential. That artifact is for the
`repro_state` field, **not** for `rce_state`; it always has empty execution
effects and cannot reach `RCE-CONFIRMED`.

Consequences:

- The pipeline **cannot** reach `RCE-CONFIRMED` on its own. It reaches
  `RCE-NOT-REPRODUCED` when a trigger was attempted without effects, and
  `RCE-INCONCLUSIVE` when the artifact is incomplete or inconsistent.
- `RCE-CONFIRMED` requires an artifact produced by a separate, authorized
  validation module that actually executed code on the isolated lab target.
- A version/header finding is **suspected exposure**, never proof of RCE.

If the instructor supplies a trigger or a recorded execution artifact, this
validator is the acceptance gate for it. It does not replace the trigger.

## 2. Evidence schema

One JSON object per validation attempt:

```json
{
  "kind": "rce-validation",
  "schema": 1,
  "asset": "lab-web-01",
  "surface": "session.upload_progress",
  "preconditions": {
    "php_version": "8.4.26",
    "web_sapi": "mod_php",
    "upload_progress_enabled": true
  },
  "validation": {
    "nonce": "9f2c4a7b1e8d3056c2a4f6b8d0e1f3a5",
    "triggered_at": "2026-10-22T10:00:00Z",
    "request_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "execution_effects": ["file_write"],
    "marker_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
}
```

The example above is **shape only**. The digests are placeholders; the validator
will reject it until the real marker and request digests are supplied.

### Field rules

| Field | Rule |
|---|---|
| `kind` | Must be `rce-validation`. |
| `schema` | Must be `1`. |
| `asset` | Non-empty asset ID. Must match the audit's asset for report attribution. |
| `surface` | Must be `session.upload_progress`. Other surfaces are inconclusive for this CVE. |
| `preconditions.php_version` | Exact web-SAPI version, not a CLI version. Must map to a branch gate. |
| `preconditions.web_sapi` | `mod_php`, `frankenphp`, `fpm`, `lsapi`, `cgi`, or `fastcgi` (case-insensitive substring). CLI/unknown blocks confirmation. |
| `preconditions.upload_progress_enabled` | Boolean (or `On`/`Off` string). `false` is a decisive control. |
| `validation.nonce` | 16–128 hex characters. Unique per asset. Bound into the marker file. |
| `validation.triggered_at` | ISO-8601 timestamp with timezone (`Z` or offset). |
| `validation.request_sha256` | 64-hex SHA-256 of the exact trigger request bytes. |
| `validation.execution_effects` | Non-empty list, e.g. `["file_write", "command_output"]`. Empty means trigger attempted, not reproduced. |
| `validation.marker_sha256` | 64-hex SHA-256 of the marker file. Required; checked against `--markers`. |

Do not put secrets, credentials, or full payloads in the artifact. The request
digest is enough to bind the evidence without storing the request.

## 3. States

| State | Meaning | Exit |
|---|---|---|
| `RCE-CONFIRMED` | Execution effects recorded; version below gate; web SAPI; upload progress enabled; nonce fresh; marker hash and nonce match; request digest valid. | 0 |
| `RCE-NOT-REPRODUCED` | A trigger was attempted, but `execution_effects` is empty. | 2 |
| `RCE-INCONCLUSIVE` | Missing, malformed, inconsistent, tampered, or replayed evidence; unknown version/SAPI. | 3 |
| `RCE-BLOCKED` | Version meets the branch gate, or a decisive control is in force (non-web SAPI, upload progress disabled). | 1 |

Usage/input errors (missing file, bad top-level schema) exit `4`.

### Decision order

1. Parse and validate the top-level schema.
2. Recompute the branch gate from `php_version`. If at/above gate → `BLOCKED`.
3. Reject non-web SAPI → `BLOCKED`.
4. Reject `upload_progress_enabled=false` → `BLOCKED`.
5. Empty `execution_effects` → `NOT-REPRODUCED`.
6. Missing/invalid nonce, timestamp, request digest, marker digest → `INCONCLUSIVE`.
7. Marker file missing, hash mismatch, or nonce absent → `INCONCLUSIVE`.
8. Nonce already in the ledger for this asset → `INCONCLUSIVE` (replay).
9. Otherwise → `CONFIRMED`, and record the nonce in the ledger.

The patch gate and control checks run before the evidence checks. A "confirmed"
artifact claiming a patched version is blocked, not trusted.

## 4. Marker and nonce integrity

The marker file is the artifact written by the execution proof. It must contain the
nonce in plain text. The validator:

1. Reads the marker file as bytes.
2. Computes SHA-256 and compares it to `validation.marker_sha256`.
3. Searches for the nonce bytes inside the marker.
4. Checks the nonce ledger (`--seen-file`, default `.rce-nonces.json`) for reuse.

The ledger is keyed by asset:

```json
{
  "lab-web-01": ["9f2c4a7b1e8d3056c2a4f6b8d0e1f3a5"]
}
```

`CONFIRMED` appends the nonce. A second run with the same artifact returns
`INCONCLUSIVE`. Keep the ledger with the evidence bundle; do not reuse it across
different targets.

## 5. Commands

Validate one artifact:

```bash
bash scripts/rce-validate.sh \
  --evidence rce-evidence.json \
  --markers rce-marker.txt \
  --asset lab-web-01 \
  --seen-file .rce-nonces.json
```

Machine-readable output:

```bash
bash scripts/rce-validate.sh \
  --evidence rce-evidence.json \
  --markers rce-marker.txt \
  --asset lab-web-01 \
  --seen-file .rce-nonces.json \
  --json > rce.json
```

`--markers` is required for `RCE-CONFIRMED`. Without it, marker integrity cannot be
checked and the result is `INCONCLUSIVE`.

Full pipeline with RCE evidence:

```bash
bash scripts/run-audit.sh \
  --url http://127.0.0.1:8081/ \
  --asset lab-web-01 \
  --out audit-lab-web-01 \
  --rce-evidence rce-evidence.json \
  --markers rce-marker.txt
```

The report adds an `RCE` column and includes the RCE state in `findings.csv`.
`report.py` flags `RCE confirmed without evidence` and `RCE confirmed but marked patched`.

## 6. What "independently verifiable" means here

A `CONFIRMED` result means the artifact is internally consistent, bound to a fresh
nonce, tied to a below-gate web SAPI with upload progress enabled, and accompanied by
a marker whose hash matches. It does **not** prove the marker was produced by a
particular trigger. Independent verification still requires:

- Reproducing the trigger on the isolated lab target with the recorded request digest.
- Comparing the marker and execution effects to the expected behavior.
- Confirming the target version and SAPI independently from the artifact.

The validator is a consistency and anti-replay gate, not a substitute for the
trigger or for human review of the execution proof.

## 7. Troubleshooting

| Result | First check |
|---|---|
| `RCE-BLOCKED` unexpectedly | `php_version` may meet the gate; `web_sapi` may be CLI; upload progress may be off. |
| `RCE-NOT-REPRODUCED` unexpectedly | `execution_effects` is empty or the trigger did not execute. |
| `RCE-INCONCLUSIVE` with marker reason | Marker path, hash, or nonce text. Hash the exact bytes, not a normalized copy. |
| `RCE-INCONCLUSIVE` with replay | Use a fresh nonce or a fresh ledger for a new attempt; do not overwrite the old evidence. |
| `RCE-INCONCLUSIVE` with version/SAPI | Collect the web-SAPI version and SAPI from the target, not from `X-Powered-By`. |

## 8. Test coverage

`scripts/lab-verify.sh` covers:

- Confirmed artifact.
- Replayed nonce.
- Patched version → blocked.
- `upload_progress_enabled=false` → blocked.
- Empty execution effects → not reproduced.
- Tampered marker hash → inconclusive.
- Missing `--markers` → inconclusive.
- Human-readable output.
- End-to-end `run-audit.sh` → `report.md` with `RCE-CONFIRMED` and CSV output.
- Offline reproduction-report rendering (state, section, no RCE claim, CSV field).

`scripts/lab-integration.sh` is separate and Docker-gated. It runs the real
`lab-repro.sh` differential, feeds the artifact to `run-audit.sh`, and asserts
the report shows `REPRO-OOM-DIFFERENTIAL` and not `RCE-CONFIRMED`.

Run the offline suite; no PHP, Docker, or internet is required:

```bash
bash scripts/lab-verify.sh
```

Run the integration suite only with Docker and both images available:

```bash
bash scripts/lab-integration.sh --out lab-integration-1
```
