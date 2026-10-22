# Changelog

## 1.3.0 — 2026-10-22

- `lab-repro.sh`: real Docker Apache/mod_php reproduction. Sends one bounded
  multipart request with the session upload-progress preamble and 150,000 ignored
  part headers to `php:8.4.26-apache` and `php:8.4.27-apache`. Records HTTP
  status, OOM/normal/crash signals, worker PIDs, response digests, Apache logs,
  image IDs/digests, and the exact lab ini/request digests.
  States: `REPRO-OOM-DIFFERENTIAL`, `REPRO-FATAL-BOTH`, `REPRO-NO-EFFECT`,
  `REPRO-CRASH-OBSERVED`, `REPRO-UNAVAILABLE`, `REPRO-INCONCLUSIVE`.
  The artifact always has empty `execution_effects` and `rce_observed: false`.
- `lab-integration.sh`: Docker-gated integration test. Runs the reproduction
  independently, feeds `repro-evidence.json` into `run-audit.sh`, and asserts the
  report shows the observed reproduction state and does not show `RCE-CONFIRMED`.
- `run-audit.sh`: `--repro-evidence FILE`; validates the artifact shape/asset,
  writes `repro.json`, and keeps `repro_state` separate from `rce_state`.
- `report.py`: separate `Repro` column, reproduction summary, `## Reproduction
  evidence` section, and `repro_state`/`repro_summary` CSV fields.
- `references/lab-reproduction.md`: evidence schema, states, commands, and the
  explicit boundary between OOM differential and RCE.
- Lab assets: `assets/lab/repro.ini` and `assets/lab/repro.php`.
- Tests: `lab-verify.sh` extended to 38 offline assertions (report rendering and
  inconsistent-state rejection); `lab-integration.sh` adds 14 Docker-gated
  assertions against the real image pair.
- Observed on 2026-10-22: 8.4.26 returned `Allowed memory size of 8388608 bytes
  exhausted` for the 150k-header body; 8.4.27 returned the normal probe JSON.
  No worker crash, memory disclosure, or code execution was observed.
- Known limitation unchanged: the heap-grooming/execution chain is **not**
  implemented. `RCE-CONFIRMED` still requires a separate authorized artifact.

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
