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

# One invocation: URL -> raw artifacts -> report.md + findings.csv
bash scripts/run-audit.sh --url https://target/ --scope-file scope.txt \
  --asset web-01 --out audit-web-01

# Optional: validate externally produced RCE evidence (four states)
bash scripts/rce-validate.sh --evidence rce-evidence.json \
  --markers rce-marker.txt --asset lab-web-01
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
| `scripts/chain.sh` | Aggregates triage/fingerprint/hardening/edge artifacts into CHAIN-OPEN/PARTIAL/BLOCKED |
| `scripts/run-audit.sh` | One invocation: fingerprint + edge + optional host evidence + chain + optional RCE validation + report |
| `scripts/rce-validate.sh` | Four-state validator for externally produced RCE evidence (CONFIRMED / NOT-REPRODUCED / INCONCLUSIVE / BLOCKED) |
| `scripts/lab-verify.sh` | Offline self-tests for every script (32 assertions; no PHP, no Docker, no internet) |
| `scripts/report.py` | JSONL → Markdown + CSV, with evidence/priority flags and an RCE column |

## RCE states

`rce-validate.sh` distinguishes what the evidence actually supports:

| State | Meaning |
|---|---|
| `RCE-CONFIRMED` | Execution effects + below-gate web SAPI + upload progress on + fresh nonce + marker hash/nonce match + request digest. |
| `RCE-NOT-REPRODUCED` | Trigger attempted, no execution effects recorded. |
| `RCE-INCONCLUSIVE` | Missing, malformed, tampered, replayed, or unknown-version/SAPI evidence. |
| `RCE-BLOCKED` | Patched version, non-web SAPI, or upload progress disabled. |

Exit codes: `0` confirmed, `1` blocked, `2` not reproduced, `3` inconclusive, `4`
usage/input error. The validator consumes an artifact; it does not generate the
trigger. Full schema and boundary: `references/rce-validation.md`.

## Requirements

- `bash`, `curl`, `python3` (for JSON/report output)
- Optional: `ssh` for fleet mode, `docker` for image inventory
- PHP is **not** required locally; the scripts read it from the target or a captured `php -i`

## What it does not do

It verifies exposure, configuration, edge filtering, and patch state. It does not
generate or send an exploit payload, and it does not implement the heap-overflow
trigger or heap-grooming chain.

It **does** validate an RCE evidence artifact produced by a separate, authorized
validation module. Without such an artifact, the pipeline cannot honestly reach
`RCE-CONFIRMED`: an attempted trigger with no effects is `RCE-NOT-REPRODUCED`, and
missing or inconsistent evidence is `RCE-INCONCLUSIVE`. See
`references/rce-validation.md` for the exact boundary and schema.

Use the isolated `assets/lab/` pair for a harmless vulnerable/patched version
comparison; it has no exploit endpoint.

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
│   ├── chain.sh
│   ├── run-audit.sh
│   ├── rce-validate.sh
│   ├── lab-verify.sh
│   └── report.py
├── references/
│   ├── advisory.md
│   ├── deployment-patterns.md
│   ├── hardening.md
│   ├── detection-and-edge.md
│   ├── report-format.md
│   └── rce-validation.md
└── assets/lab/
    ├── docker-compose.yml
    ├── index.php
    └── rce-evidence.example.json
```
