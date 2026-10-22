# PHP2Shell audit — lab deliverable

This repository contains a reusable OpenCode skill for auditing PHP deployments against **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell).

## Where things live

| Path | Purpose |
|---|---|
| `php2shell-audit/` | **Canonical, version-controlled copy.** Edit this one. |
| `.opencode/skills/php2shell-audit/` | Installed copy that OpenCode discovers automatically. |
| `php2shell-audit/assets/lab/` | Disposable vulnerable/patched PHP pair for validating the audit. |

After editing the canonical copy, sync the installed copy:

```bash
./php2shell-audit/install.sh
```

Install globally instead:

```bash
./php2shell-audit/install.sh --global
```

## Quick test

```bash
cd php2shell-audit

# Local host, one decision
bash scripts/triage.sh --local

# HTTP-only target: one URL, one exposure decision
bash scripts/assess-url.sh --url https://target.example/ --scope-file scope.txt

# Precondition-chain verdict from collected artifacts
bash scripts/chain.sh --triage triage.jsonl --hardening hardening.jsonl --edge edge.json

# One invocation: URL -> raw artifacts -> report.md + findings.csv
bash scripts/run-audit.sh --url https://target.example/ --scope-file scope.txt \
  --asset web-01 --out audit-web-01

# Optional: validate externally produced RCE evidence
bash scripts/rce-validate.sh --evidence rce-evidence.json \
  --markers rce-marker.txt --asset lab-web-01

# Validate the tooling offline
bash scripts/lab-verify.sh

# Fleet
bash scripts/triage.sh --hosts scope.txt --scope-file scope.txt --json > fleet.jsonl
python3 scripts/report.py --input fleet.jsonl --md report.md --csv findings.csv
```

Private/loopback lab targets need no scope file. Public targets must be listed in `scope.txt` (copy `scope.txt.example`).

## What it checks

- Exact PHP version and build date on the **web SAPI**, not just CLI.
- Branch gate: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
- SAPI risk: mod_php and FrankenPHP (P0), FPM/LSAPI/CGI (P1), CLI/cron/queue (P2).
- Startup config: `session.upload_progress.enabled`, `memory_limit`, `max_memory_limit`, `post_max_size`, multipart/input caps, `fatal_error_backtraces`.
- Edge filtering: decoded body size, long parameter keys, multipart limits.
- Patch verification and regression gates.
- RCE evidence validation (optional): four states with patch-gate/control rechecks,
  nonce replay protection, and marker integrity.

## RCE states

| State | Meaning |
|---|---|
| `RCE-CONFIRMED` | Independently verifiable execution evidence, below-gate web SAPI, upload progress enabled, fresh nonce, matching marker. |
| `RCE-NOT-REPRODUCED` | A trigger was attempted but produced no execution effects. |
| `RCE-INCONCLUSIVE` | Evidence missing, malformed, tampered, replayed, or version/SAPI unknown. |
| `RCE-BLOCKED` | Patched version, non-web SAPI, or upload progress disabled. |

Exit codes: `0` confirmed, `1` blocked, `2` not reproduced, `3` inconclusive, `4`
usage/input error. Schema and criteria: `php2shell-audit/references/rce-validation.md`.

## Scope

It verifies exposure, configuration, edge filtering, and patch state. It does not
generate or send an exploit payload, and it does not include the heap-overflow
trigger or heap-grooming chain. The lab pair is for harmless vulnerable/patched
comparison.

`RCE-CONFIRMED` is only reachable with an artifact from a separate, authorized
validation module. Without one, the pipeline reports `RCE-NOT-REPRODUCED` or
`RCE-INCONCLUSIVE` rather than inventing a confirmation.

## Version

`1.2.0` — 2026-10-22. See `php2shell-audit/CHANGELOG.md`.
