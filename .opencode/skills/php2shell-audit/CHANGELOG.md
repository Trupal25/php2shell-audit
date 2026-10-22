# Changelog

## 1.2.0 — 2026-10-22

- `rce-validate.sh`: four-state RCE evidence validator.
  `RCE-CONFIRMED` / `RCE-NOT-REPRODUCED` / `RCE-INCONCLUSIVE` / `RCE-BLOCKED`;
  exit codes 0/2/3/1 and 4 for input errors.
  Rechecks the patch gate and web-SAPI/upload-progress preconditions, validates
  nonce freshness, binds the nonce to a SHA-256 marker file, verifies the request
  digest shape, and rejects replays.
- `run-audit.sh`: one invocation from URL to `report.md` + `findings.csv`.
  Runs fingerprint → edge conformance → optional local/SSH triage/hardening →
  chain → optional RCE validation → report, preserving raw artifacts.
- `report.py`: `rce_state` column in Markdown/CSV; flags for RCE-confirmed without
  evidence and RCE-confirmed-but-patched.
- `lab-verify.sh`: expanded to 32 assertions, including all four RCE states,
  replay, tamper, missing-marker, asset mismatch, human output, end-to-end
  `run-audit.sh`, and no-PHP triage handling.
- `references/rce-validation.md`: evidence schema, decision order, marker/nonce
  integrity, commands, and the explicit missing-trigger boundary.
- Lab additions: `assets/lab/README.md` and `assets/lab/rce-evidence.example.json`.
- Known limitation: the heap-overflow trigger and heap-grooming/exploitation chain
  are **not implemented**. Confirmation requires an artifact from an authorized
  validation module; the validator does not generate or send a trigger.

## 1.1.0 — 2026-10-22

- `chain.sh`: precondition-chain verdict from triage/fingerprint/hardening/edge artifacts.
  Decisions: CHAIN-OPEN / CHAIN-PARTIAL / CHAIN-BLOCKED, with per-precondition status.
- `assess-url.sh`: one URL in, one exposure decision out (fingerprint + one bounded edge probe).
- `lab-verify.sh`: offline harness — 5 gate assertions, hardening fixtures, local HTTP fixtures for
  fingerprint/edge, chain decision checks, stub PHP binaries. No PHP, Docker, or internet.
- `triage.sh`: EOL branch + mod_php → P0; unknown version + mod_php → P0; evidence embedded in JSON.
- `verify-hardening.sh`: auto-detects patched hosts and downgrades interim checks to defense-in-depth.
- `install.sh`, VERSION, CHANGELOG, .gitignore for canonical ↔ installed copy sync.

## 1.0.0 — 2026-10-22

- Initial PHP2Shell audit skill.
- Verified gates: 8.2.35, 8.3.36, 8.4.27, 8.5.12 (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp).
- Fast triage, passive HTTP fingerprint, inventory, hardening verification, edge conformance, report aggregation.
- Lab assets for vulnerable/patched version comparison.
