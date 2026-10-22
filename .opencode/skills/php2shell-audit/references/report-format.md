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
  "notes": "Staging pool only; production pool still on 8.4.26."
}
```

Field rules:

- `status`: `vulnerable` | `patched` | `eol` | `unknown`.
- `exposure`: `internet` | `partner` | `internal` | `local`.
- `priority`: `P0` | `P1` | `P2` | `P3`.
- `patched_min`: branch gate (`8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`); `null` for EOL.
- `evidence`: at least one reproducible command per claim. No evidence, no finding.

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

| Asset | SAPI | Version | Gate | Status | Exposure | Priority |
|---|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... | ... |

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

## 3. Scoring rubric alignment

Use this to prioritize work and to make the report easy to grade.

| Dimension | Points | How to earn them |
|---|---|---|
| Exposure identification | 30 | Exact version + SAPI + reachability per asset; P0/P1 correctly separated |
| Patch verification | 25 | Web SAPI (not CLI), build date, container digest, post-restart recheck |
| Interim control proof | 20 | Observed values from the running pool/Apache, not a copied config file; caveats stated |
| Edge/WAF proof | 15 | One bounded request with status/timestamp; managed ruleset verified |
| Detection/hunt | 10 | Log/WAF/worker-churn evidence; false-positive notes |
| Report quality | 10 | Reproducible commands, evidence per claim, owner/due dates |

Deductions:

- Version taken only from `X-Powered-By` or `Server`.
- CLI-only check for an FPM/Apache host.
- "WAF enabled" claimed without a ruleset ID or a probe.
- `memory_limit=-1` called a complete fix.
- A finding with no reproducible command.
- A control that was applied but not verified after restart.

## 4. Fast aggregation

```bash
# JSONL → CSV for a spreadsheet
python3 scripts/report.py --input fleet.jsonl --csv findings.csv --md report.md
```

`report.py` groups by priority and status, emits a Markdown summary, and flags records missing evidence or a patch gate.
