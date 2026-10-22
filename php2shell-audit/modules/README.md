# Validation modules

A validation module is separately supplied, explicitly authorized code that runs
one bounded experiment against the disposable vulnerable/patched lab pair. The
framework executes it with `scripts/module-run.sh`, records provenance, and
classifies the result with `scripts/impact-classify.py`.

The full contract is in [`../references/module-interface.md`](../references/module-interface.md).

## Bundled modules

| Directory | Real? | What it does |
|---|---|---|
| `oom-differential/` | Yes | Sends the upstream 150,000-header multipart shape to 8.4.26 and 8.4.27 Apache/mod_php; records OOM differential. Maximum impact: `crash-oom`. |
| `synthetic-fixture/` | **No** | Fabricates an execution claim/marker to prove the classifier rejects synthetic results. Always `inconclusive`. Requires `--allow-synthetic`. |

`oom-differential` is a research probe, not an exploit. It does **not** implement
heap grooming, memory disclosure, or code execution.

## Running the real module

```bash
bash scripts/module-run.sh \
  --module modules/oom-differential \
  --asset lab-vulnerable \
  --out module-runs/oom-1 \
  --timeout 90 \
  --json
```

The harness:

- creates a dedicated `--internal` Docker network with no published ports;
- starts `php:8.4.26-apache` and `php:8.4.27-apache` with the lab ini/probe;
- runs the module in its own hardened container with memory/CPU/PID limits;
- captures target logs, image IDs/digests, request/response hashes, and cleanup;
- writes `module-run.json` with an embedded conservative classification.

Exit codes: `0` completed, `2` unavailable, `3` module failed/timeout, `4`
usage/contract error.

## Running the synthetic fixture

```bash
bash scripts/module-run.sh \
  --module modules/synthetic-fixture \
  --allow-synthetic \
  --out module-runs/synthetic-1
```

The result must be `inconclusive`, regardless of the fabricated execution claim.
A synthetic result is never evidence.

## Supplying the authorized exploit module

Keep the exploit outside this repository in an access-controlled location. It
only needs a `module.json` and an entrypoint. A minimal manifest:

```json
{
  "kind": "php2shell-validation-module",
  "schema": 1,
  "id": "authorized-trigger",
  "version": "0.1.0",
  "runtime": {
    "image": "php:8.4.27-apache",
    "entrypoint": ["php", "/module/run.php"]
  },
  "output": "module-result.json",
  "claims": {
    "synthetic": false,
    "max_impact": "demonstrated-code-execution",
    "surface": "heap-groomed request state"
  }
}
```

The module receives `P2S_TARGET_URL`, `P2S_CONTROL_URL`, `P2S_NONCE`,
`P2S_OUTPUT_DIR`, and the other inputs documented in the contract. To claim code
execution it must:

1. write an `RCE-CONFIRMED` evidence artifact conforming to
   `references/rce-validation.md`;
2. write a marker inside the target process with a fresh nonce;
3. report `evidence.marker_path_in_target` and `evidence.marker_sha256`;
4. report non-empty `claims.execution_effects`.

The harness retrieves the marker from the target independently and runs
`scripts/rce-validate.sh`. The classifier only emits
`demonstrated-code-execution` when the validator says `RCE-CONFIRMED`, the
marker hash matches, the effect list is non-empty, and the module is not
synthetic. A crash or OOM can never be promoted.
