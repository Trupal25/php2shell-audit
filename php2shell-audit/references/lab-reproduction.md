# Lab reproduction evidence

This reference defines the **separate** `lab-reproduction` artifact produced by
`scripts/lab-repro.sh`. It is not an RCE artifact and it does not feed
`scripts/rce-validate.sh`.

The purpose is narrow: run one bounded multipart request against a real,
deliberately vulnerable Apache/mod_php image and the patched control, observe
what the web SAPI actually does, and give `report.py` the observed result. The
probe measures request-parsing memory exhaustion and worker-crash signals. It
does **not** implement or send a heap-grooming/exploitation chain.

## 1. What the lab run actually demonstrates

The reproduction sends a multipart body with:

- a `PHPSESSID` part and a `PHP_SESSION_UPLOAD_PROGRESS` part, so the advisory's
  early session-upload-progress consumer is engaged;
- one part with 150,000 ignored header lines;
- a low `memory_limit=8M` and raised input limits from
  `assets/lab/repro.ini`.

On PHP 8.4.26, the parser retains the ignored headers and exhausts the memory
limit while parsing. PHP returns a fatal `Allowed memory size ... exhausted`
page. On PHP 8.4.27, the parser keeps only the headers it uses, the request
reaches `assets/lab/repro.php`, and the normal JSON response is returned.

That is a **request-parsing OOM differential**, reproducible in the exact code
path changed by the security release. It is evidence that the vulnerable build
behaves differently from the patched control. It is **not** evidence of heap
grooming, memory disclosure, or code execution.

## 2. Evidence schema

`scripts/lab-repro.sh` writes `repro-evidence.json`:

```json
{
  "kind": "lab-reproduction",
  "schema": 1,
  "asset": "lab-php2shell-repro",
  "state": "REPRO-OOM-DIFFERENTIAL",
  "generated_at": "2026-10-22T10:00:00Z",
  "source": "scripts/lab-repro.sh",
  "state_reason": "Vulnerable build exhausted memory during multipart parsing; patched build returned the normal probe response.",
  "classification": {
    "vulnerable_oom": true,
    "patched_oom": false,
    "patched_normal": true,
    "crash_observed": false,
    "oom_differential": true
  },
  "request": {
    "method": "POST",
    "path": "/repro.php",
    "body_sha256": "…",
    "body_bytes": 1839274,
    "transfer_encoding": "Content-Length (curl --data-binary)",
    "parts": 3,
    "headers_on_large_part": 150000,
    "memory_limit": "8M",
    "post_max_size": "1G"
  },
  "environment": {
    "docker_version": "29.9.2",
    "host": "lab-host",
    "php_ini": "repro.ini",
    "php_ini_sha256": "…",
    "probe_script": "repro.php",
    "probe_script_sha256": "…"
  },
  "images": {
    "vulnerable": {"ref": "php:8.4.26-apache", "id": "sha256:…", "repo_digests": ["php@sha256:…"]},
    "patched": {"ref": "php:8.4.27-apache", "id": "sha256:…", "repo_digests": ["php@sha256:…"]}
  },
  "containers": {
    "vulnerable": {"name": "…", "port": 32768, "url": "http://127.0.0.1:32768/repro.php"},
    "patched": {"name": "…", "port": 32769, "url": "http://127.0.0.1:32769/repro.php"},
    "kept": false
  },
  "observations": {
    "vulnerable": {
      "http_status": 200,
      "curl_exit": 0,
      "oom_detected": true,
      "normal_detected": false,
      "crash_signal": false,
      "worker_pids_before": ["…"],
      "worker_pids_after": ["…"],
      "response_sha256": "…",
      "response_excerpt": "…"
    },
    "patched": {
      "http_status": 200,
      "curl_exit": 0,
      "oom_detected": false,
      "normal_detected": true,
      "crash_signal": false,
      "worker_pids_before": ["…"],
      "worker_pids_after": ["…"],
      "response_sha256": "…",
      "response_excerpt": "…"
    },
    "execution_effects": [],
    "rce_observed": false
  },
  "limitations": ["…"]
}
```

Field rules:

| Field | Rule |
|---|---|
| `kind` | Must be `lab-reproduction`. |
| `schema` | Must be `1`. |
| `state` | One of the states in section 3. |
| `images` | Both image references plus immutable IDs/digests. |
| `request` | Request path, body SHA-256, byte count, part/header shape, and lab limits. |
| `observations.vulnerable` / `.patched` | Captured HTTP status, OOM/normal/crash signals, worker PIDs, response digest and excerpt. Required for observation states. |
| `observations.execution_effects` | Must be empty. This artifact must not claim execution. |
| `observations.rce_observed` | Must be `false`. Any execution claim belongs in the separate `rce-validation` artifact. |

`REPRO-UNAVAILABLE` is the exception to the provenance requirement: if Docker or
an image is missing, the artifact can omit `images` and the vulnerable/patched
observations, because no request was sent. `run-audit.sh` keeps that state
instead of inventing observations.

`scripts/run-audit.sh --repro-evidence FILE` validates the shape, requires the
evidence asset to match the audit asset, and writes a normalized `repro.json`.
It does not alter the observed state. Invalid or mismatched evidence becomes
`REPRO-INCONCLUSIVE` rather than being dropped.

## 3. States

| State | Meaning |
|---|---|
| `REPRO-OOM-DIFFERENTIAL` | Vulnerable build OOMs during parsing; patched build returns the normal probe response. |
| `REPRO-FATAL-BOTH` | Both builds OOM; no vulnerable/patched differential on this probe. |
| `REPRO-NO-EFFECT` | Neither build OOMs on this probe; no differential. |
| `REPRO-CRASH-OBSERVED` | A worker crash signal (segfault/abort/heap corruption) appears in the Apache log. This is still not RCE. |
| `REPRO-UNAVAILABLE` | Docker, image, tool, or container readiness was unavailable; no request was sent. |
| `REPRO-INCONCLUSIVE` | Unexpected response combination or invalid evidence. Inspect the raw captures. |

`lab-repro.sh` exits `0` for `REPRO-OOM-DIFFERENTIAL` or
`REPRO-CRASH-OBSERVED`, `3` for a successful run with no differential, and `2`
for unavailable dependencies. The integration test treats a non-zero
reproduction result as a failed integration run, not as an RCE confirmation.

## 4. Report integration

`scripts/run-audit.sh` adds the reproduction as an evidence object and sets the
top-level `repro_state`. `scripts/report.py` renders:

- a `Repro` column in the findings table;
- a `Reproduction` summary count;
- a `## Reproduction evidence` section with vulnerable/patched observations;
- `repro_state` and `repro_summary` in `findings.csv`.

The report keeps `rce_state` separate. A reproduction artifact can never produce
`RCE-CONFIRMED`; that still requires the `rce-validate.sh` artifact, a fresh
nonce, a matching marker, and recorded execution effects.

## 5. Commands

Produce evidence:

```bash
cd php2shell-audit
bash scripts/lab-repro.sh --out repro-lab --json
```

First run, if the images are not local:

```bash
bash scripts/lab-repro.sh --out repro-lab --pull
```

Consume the evidence:

```bash
bash scripts/run-audit.sh \
  --url http://127.0.0.1:8081/ \
  --asset lab-vulnerable \
  --out audit-lab-vulnerable \
  --repro-evidence repro-lab/repro-evidence.json
```

Run the separate Docker-gated integration test:

```bash
bash scripts/lab-integration.sh --out lab-integration-1
```

It runs `lab-repro.sh` independently, feeds the resulting artifact to
`run-audit.sh`, and asserts that the report shows `REPRO-OOM-DIFFERENTIAL` and
does not show `RCE-CONFIRMED`.

## 6. Boundary: what remains unverified

The following are **not** implemented or proven by this artifact:

- Heap grooming, allocator-layout control, or a working UAF exploitation chain.
- Memory disclosure, code execution, command output, or a marker file.
- A reliable crash on every vulnerable request; a single OOM may be handled by
  the SAPI without a worker crash.
- The production request shape, which may use a different body size, chunked
  transfer, edge filtering, or `memory_limit`.

Closing those requires an authorized exploit harness that produces a separate
`rce-validation` artifact. Source code and an OOM differential are not enough.
