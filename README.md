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

## Scope

It verifies exposure, configuration, edge filtering, and patch state. It does not generate or send an exploit payload. The lab pair is for harmless vulnerable/patched comparison.

## Version

`1.0.0` — 2026-10-22. See `php2shell-audit/CHANGELOG.md`.
