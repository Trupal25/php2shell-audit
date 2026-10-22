# PHP2Shell audit skill

Reusable, non-destructive audit workflow for **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell).

This folder is the canonical, version-controlled copy. OpenCode loads the installed copy at:

```text
.opencode/skills/php2shell-audit/SKILL.md
```

After editing here, run `./install.sh` to refresh the installed copy.

## Quick start

```bash
cd php2shell-audit

# One decision, local host
bash scripts/triage.sh --local

# One URL: fingerprint + one edge probe
bash scripts/assess-url.sh --url https://target/ --scope-file scope.txt

# Fleet decision (one host per line)
bash scripts/triage.sh --hosts scope.txt --scope-file scope.txt --json > fleet.jsonl

# Evidence + report
bash scripts/inventory.sh --local --fast --json > inventory.jsonl
python3 scripts/report.py --input fleet.jsonl --md report.md --csv findings.csv
```

Private/loopback lab targets need no scope file. Public targets must be listed in `scope.txt` (see `scope.txt.example`).

## Scripts

| Script | Purpose |
|---|---|
| `scripts/triage.sh` | Fast P0/P1/P2/P3/PATCHED decision from version + SAPI + key ini |
| `scripts/fingerprint.sh` | Passive HTTP classifier for targets without SSH |
| `scripts/assess-url.sh` | One URL in, one exposure decision out (fingerprint + one edge probe) |
| `scripts/inventory.sh` | Version, SAPI, ini, FPM/Apache overrides, app `ini_set`, containers |
| `scripts/verify-hardening.sh` | Checks interim directives on the running SAPI |
| `scripts/edge-conformance.sh` | One bounded long-key request; pass if 4xx |
| `scripts/report.py` | JSONL → Markdown + CSV, with evidence/priority flags |

## Requirements

- `bash`, `curl`, `python3` (for JSON/report output)
- Optional: `ssh` for fleet mode, `docker` for image inventory
- PHP is **not** required locally; the scripts read it from the target or a captured `php -i`

## What it does not do

It verifies exposure, configuration, edge filtering, and patch state. It does not generate or send an exploit payload. Use the isolated `assets/lab/` pair for a harmless vulnerable/patched comparison.

## Layout

```text
php2shell-audit/
├── SKILL.md
├── README.md
├── install.sh
├── VERSION
├── CHANGELOG.md
├── scope.txt.example
├── scripts/
│   ├── triage.sh
│   ├── fingerprint.sh
│   ├── assess-url.sh
│   ├── inventory.sh
│   ├── verify-hardening.sh
│   ├── edge-conformance.sh
│   └── report.py
├── references/
│   ├── advisory.md
│   ├── deployment-patterns.md
│   ├── hardening.md
│   ├── detection-and-edge.md
│   └── report-format.md
└── assets/lab/
    ├── docker-compose.yml
    └── index.php
```
