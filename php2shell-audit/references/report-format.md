# Findings format and scoring

## 1. JSONL record (one per asset)

```json
{
  "asset": "prod-web-03",
  "environment": "production",
  "owner": "platform-web",
  "sapi": "fpm",
  "php_version": "8.4.26",
  "build_date": "2026-09-25",
  "branch": "8.4",
  "patched_min": "8.4.27",
  "status": "vulnerable",
  "exposure": "internet",
  "priority": "P1",
  "interim_controls": {
    "session.upload_progress.enabled": "Off",
    "memory_limit": "-1",
    "max_memory_limit": "-1",
    "post_max_size": "8M",
    "upload_max_filesize": "2M",
    "max_input_vars": "1000",
    "max_input_nesting_level": "64",
    "max_multipart_body_parts": "100",
    "max_file_uploads": "20",
    "fatal_error_backtraces": "0"
  },
  "edge_controls": {
    "decoded_body_cap": "8M",
    "long_key_rule": "present",
    "multipart_blocked": "false",
    "waf_ruleset": "cloudflare-managed"
  },
  "evidence": [
    {"type": "version", "command": "php -v", "output": "PHP 8.4.26 (cli) ...", "at": "2026-10-22T10:00:00Z"},
    {"type": "ini", "command": "php-fpm -tt", "output": "php_admin_value[memory_limit] = -1", "at": "2026-10-22T10:01:00Z"},
    {"type": "http", "command": "edge-conformance.sh", "output": "HTTP 200", "at": "2026-10-22T10:05:00Z"}
  ],
  "remediation": "Rebuild image on php:8.4.27-fpm; keep interim controls; redeploy.",
  "verified_at": "2026-10-22T10:05:00Z",
  "repro_state": "REPRO-OOM-DIFFERENTIAL",
  "repro_summary": "vulnerable=OOM; patched=normal; no execution effects",
  "rce_state": "RCE-NOT-REPRODUCED",
  "notes": "Staging pool only; production pool still on 8.4.26."
}
```

Field rules:

- `status`: `vulnerable` | `patched` | `eol` | `unknown`.
- `exposure`: `internet` | `partner` | `internal` | `local`.
- `priority`: `P0` | `P1` | `P2` | `P3`.
- `patched_min`: branch gate (`8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`); `null` for EOL.
- `rce_state` (optional): `RCE-CONFIRMED` | `RCE-NOT-REPRODUCED` | `RCE-INCONCLUSIVE` | `RCE-BLOCKED`. Omit it if no RCE evidence was validated; do not infer it from a version banner.
- `repro_state` (optional): `REPRO-OOM-DIFFERENTIAL` | `REPRO-FATAL-BOTH` | `REPRO-NO-EFFECT` | `REPRO-CRASH-OBSERVED` | `REPRO-UNAVAILABLE` | `REPRO-INCONCLUSIVE`. This is a separate lab-reproduction observation, never an RCE claim.
- `repro_summary` (optional): short observed summary, e.g. `vulnerable=OOM; patched=normal; no execution effects`.
- `evidence`: at least one reproducible command per claim. No evidence, no finding.

### RCE evidence fields

A `RCE-CONFIRMED` claim must carry the validator artifact and the marker path. See
`references/rce-validation.md` for the full schema. The report flags:

- `RCE confirmed without evidence` — `rce_state` is confirmed but `evidence` is empty.
- `RCE confirmed but marked patched` — contradictory claim; resolve before publishing.

Never upgrade a suspected exposure to `RCE-CONFIRMED` because of `X-Powered-By`, a
version string, or an edge probe.

### Lab reproduction fields

A `repro_state` comes from `scripts/lab-repro.sh` and its
`references/lab-reproduction.md` schema. It records what the vulnerable and
patched Apache/mod_php containers actually did on one bounded request. It does
not imply execution. `report.py` flags reproduction states without evidence and
a differential that is marked patched. `RCE-CONFIRMED` still requires the
separate `rce-validation` artifact.

### URL assessment artifact (`assessment.json`)

Written by `scripts/assess-url.sh` for a remote, URL-only assessment (schema
`1`, kind `url-assessment`). Top-level fields:

- `tool` — name, version, script; `target` — url, origin, host/port, asset,
  `scope` (mode `scope-file` | `lab`, authorized entry, scope file path),
  exposure class.
- `safety` — `lab_mode`, `tls_verify: "on"`, `credentials_sent/cookies_sent/
  payload_sent: "none"`, `pinned_dns: true`, redirect policy, and the
  max-redirects / max-bytes / timeout bounds.
- `timestamps` — ISO-8601 UTC `started_at`/`finished_at`; `state` —
  `ok` | `unreachable` | `collection-failed` | `aborted-unsafe-redirect` |
  `aborted-redirect-limit` | `aborted-oversized-response`; `state_reason` —
  a truthful reason string.
- `collection` — one record per request: hop label, method, URL, pinned IP,
  `curl_exit`, status, time, bytes, `oversized`; plus redirects followed,
  edge result, baseline/final status.
- `version_evidence` — `definitive` is **always false**; `source` is
  `http-header-hint` or `none`; note explains that only an authenticated
  `php -v` establishes a version.
- `chain` — compact chain verdict (decision, version, gate, SAPI, proof,
  preconditions); `fingerprint` — compact passive-fingerprint summary.
- `rce` — `state` (empty when URL-only; validator states otherwise), honest
  `note`, `validator_artifact`, allowed states.
- `limits[]`, `limitations[]`, `not_tested[]`, `next_steps[]` — always
  present; `consistency` — `{ok, reasons[]}` contradiction list.
- `artifact_hashes.sha256` — every raw and derived artifact;
  `generated_sha256` — `report.md`/`findings.csv` added by `url-report.py`.
  `assess-url.sh --verify DIR` recomputes all hashes and re-checks
  `consistency`; exit 5 on tampering or contradiction.

The matching `findings.jsonl` record keeps `rce_state: ""` for URL-only runs
(no exception, unless a validator artifact was passed) and `repro_state: ""`
with `repro_summary` noting that no Docker reproduction was part of the run.

## 2. Markdown report template

```markdown
# PHP2Shell exposure audit — <scope>

**Audit window:** <start> – <end>
**Authorized by:** <ticket / lab handout / instructor>
**Assets in scope:** <n>
**Assets checked:** <n>
**Findings:** P0 <n> · P1 <n> · P2 <n> · P3 <n>

## Executive summary

<2–4 sentences: exposure, patch state, interim controls, biggest gap.>

## Patch state

| Asset | SAPI | Version | Gate | Status | Repro | RCE | Exposure | Priority |
|---|---|---|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... | ... | ... | ... |

## P0/P1 findings

### <asset> — <one-line finding>

- **Evidence:** `<command>` → `<output>` (timestamp)
- **Why it matters:** <confirmed RCE path / reachable SAPI / no interim control>
- **Interim control:** <what is in force, verified how>
- **Remediation:** <patched version / image / config diff>
- **Verification:** <post-change command and result>

## Interim hardening

| Control | Expected | Observed | Source | Result |
|---|---|---|---|---|
| session.upload_progress.enabled | Off | ... | php-fpm pool | PASS/FAIL |
| memory_limit | -1 | ... | ... | ... |
| max_memory_limit | -1 | ... | ... | ... |
| post_max_size | ≤ 8M | ... | ... | ... |
| upload_max_filesize | < post_max_size | ... | ... | ... |
| max_input_vars | ≤ 1000 | ... | ... | ... |
| max_input_nesting_level | ≤ 64 | ... | ... | ... |
| max_multipart_body_parts | ≤ 100 | ... | ... | ... |
| max_file_uploads | ≤ 20 | ... | ... | ... |
| fatal_error_backtraces | 0 (8.5) | ... | ... | ... |

## Edge/WAF

| Control | Expected | Observed | Evidence |
|---|---|---|---|
| Decoded body cap | ≤ 8M | ... | ... |
| Long key rejection | 4xx | ... | HTTP <code> |
| Multipart block (if unused) | 415 | ... | ... |
| Managed WAF rules | deployed | ... | ruleset ID |

## Detection coverage

- Log sources reviewed:
- Signals found:
- WAF events:
- Worker churn:
- Gaps:

## Remediation plan

| Asset | Action | Owner | Due | Verification |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

## Residual risk

<What remains after interim controls; why patching is still required.>

## Appendix — commands and raw evidence

<Paths to JSONL, logs, screenshots, curl transcripts.>
```

## 3. Lab reproduction evidence (optional)

Only include this section when `lab-repro.sh` has produced a state:

```markdown
## Reproduction evidence

| Asset | State | Vulnerable | Patched | Execution effects |
|---|---|---|---|---|
| lab-vulnerable | REPRO-OOM-DIFFERENTIAL | OOM | normal | none |

An OOM or crash differential is not proof of RCE. `RCE-CONFIRMED` still requires
a separate `rce-validation` artifact with execution effects, a fresh nonce, and
a matching marker.
```

- `REPRO-OOM-DIFFERENTIAL` means the vulnerable build exhausted memory in the
  parser and the patched build returned normally. It proves a behavior
  difference, not exploitation.
- `REPRO-CRASH-OBSERVED` means a worker crash signal was captured. It is still
  not RCE.
- `REPRO-FATAL-BOTH`, `REPRO-NO-EFFECT`, and `REPRO-INCONCLUSIVE` mean there is
  no usable differential; report them as such.
- `REPRO-UNAVAILABLE` means Docker, an image, a tool, or container readiness was
  missing; no request was sent.
- See `references/lab-reproduction.md` for the schema and boundary.

## 4. RCE evidence (optional)

Only include this section when `rce-validate.sh` has produced a state:

```markdown
## RCE evidence

| Asset | State | Version / gate | Nonce | Evidence |
|---|---|---|---|---|
| lab-web-01 | RCE-CONFIRMED | 8.4.26 / 8.4.27 | `9f2c...` | `rce.json`, `rce-marker.txt` |

- Confirmation requires execution effects, a web SAPI, upload progress enabled, a
  fresh nonce, a matching marker hash containing the nonce, and a 64-hex request digest.
- `RCE-NOT-REPRODUCED` means a trigger was attempted and produced no execution
  effects. Do not describe it as a vulnerability finding or as a failed audit.
- `RCE-INCONCLUSIVE` means the evidence is missing, malformed, tampered, replayed, or
  the version/SAPI is unknown. Collect the missing item and re-run.
- `RCE-BLOCKED` means the version meets the gate or a decisive control is in force.
  It is not a confirmation of exploitability.
- The trigger/heap-grooming chain is not part of this repository. See
  `references/rce-validation.md`.

## 5. Scoring rubric alignment

Use this to prioritize work and to make the report easy to grade.

| Dimension | Points | How to earn them |
|---|---|---|
| Exposure identification | 30 | Exact version + SAPI + reachability per asset; P0/P1 correctly separated |
| Patch verification | 25 | Web SAPI (not CLI), build date, container digest, post-restart recheck |
| Interim control proof | 20 | Observed values from the running pool/Apache, not a copied config file; caveats stated |
| Edge/WAF proof | 15 | One bounded request with status/timestamp; managed ruleset verified |
| Detection/hunt | 10 | Log/WAF/worker-churn evidence; false-positive notes |
| RCE evidence (optional) | 10 | Four-state validator output; reproducible execution effects, fresh nonce, marker integrity |
| Report quality | 10 | Reproducible commands, evidence per claim, owner/due dates |

Deductions:

- Version taken only from `X-Powered-By` or `Server`.
- CLI-only check for an FPM/Apache host.
- "WAF enabled" claimed without a ruleset ID or a probe.
- `memory_limit=-1` called a complete fix.
- A finding with no reproducible command.
- A control that was applied but not verified after restart.
- Claiming RCE from a version banner or an edge probe.
- Publishing `RCE-CONFIRMED` without the validator artifact and marker.

## 6. Fast aggregation

```bash
# JSONL → CSV for a spreadsheet
python3 scripts/report.py --input fleet.jsonl --csv findings.csv --md report.md
```

`report.py` groups by priority and status, emits a Markdown summary, and flags records missing evidence or a patch gate.
