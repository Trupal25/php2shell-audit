# Changelog

## 1.4.0 — 2026-10-22

- `assess-url.sh`: full URL-based remote assessment workflow. One authorized URL
  in → `assessment.json` (schema 1, kind `url-assessment`), `report.md`,
  `findings.jsonl`, `findings.csv`, plus raw per-request captures. Pipeline:
  SSRF-safe authorization → bounded redirect-validated GET → one bounded
  long-key edge POST → derived `fingerprint.json`/`edge.json` → `chain.sh`
  verdict → optional `--rce-evidence` through the unchanged `rce-validate.sh`
  → report. Flags: positional URL or `--url`, `--out`, `--asset`,
  `--scope-file`, `--lab`, `--exposure`, `--connect-timeout`, `--timeout`,
  `--max-redirects`, `--max-bytes`, `--rce-evidence`, `--markers`, `--verify`,
  `--json`. Exit codes: 0 report generated; 2 invalid/unauthorized/unsafe
  (no request sent); 3 collection did not complete (unreachable, timeout,
  refused redirect, oversize, redirect limit) with a truthful failure report;
  4 internal error; 5 tampering/contradiction (`--verify` only).
  The old one-shot decision strings (`P0-EXPOSED`, …) are replaced by the same
  chain verdict vocabulary the rest of the skill uses (`CHAIN-OPEN`, …) plus a
  per-asset priority in `findings.jsonl`.
- `url_guard.py` (new): pre-flight URL authorization without contacting the
  target. Strict http/https parsing, refusal of credentials/whitespace/
  control characters, scope-file check **before** DNS resolution
  (`*.wildcard` + exact entries), address classification: loopback, private,
  link-local, unique-local, multicast, reserved, unspecified, and cloud
  metadata (`169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`) are all
  non-global and require `--lab`; public hosts require the scope file even
  with `--lab`; picks one pinned address per request for `curl --resolve`;
  refuses `https`→`http` redirect downgrades.
- `url-report.py` (new): renders the human report from `assessment.json`;
  reuses `report.py` normalization/rendering for the standard findings table
  and adds scope & authorization, safety model, outcome, request table, chain
  verdict with preconditions, RCE assessment (URL-only runs can never produce
  `RCE-CONFIRMED`), SHA-256 provenance, tested/not-tested, next steps, and
  limitations. Records the generated `report.md`/`findings.csv` hashes back
  into `assessment.json` (`generated_sha256`).
- Integrity: every raw and derived artifact is SHA-256-hashed into
  `assessment.json`; `assess-url.sh --verify DIR` recomputes and re-checks
  consistency (exit 5 on tampering or contradiction, e.g. an unbacked
  `RCE-CONFIRMED`).
- Safety model: DNS resolved once and pinned (`--resolve`), redirects
  re-authorized per hop with the guard, TLS verification never disabled, no
  credentials/cookies/session tokens/netrc or environment proxies sent
  (`--noproxy '*'`, `--netrc-file /dev/null`), body caps with truncation,
  per-request connect/total timeouts, redirect budget; a refused hop never
  causes a request to the refused destination.
- Tests: `lab-verify.sh` extended from 38 to 98 offline assertions — 14
  `url_guard.py` authorization cases (loopback without/with `--lab`, credentials, scheme,
  metadata endpoint, scope miss/hit, redirect downgrade, malformed port,
  unresolvable host) and 46 workflow cases over a local ThreadingHTTPServer
  mock (valid run incl. `--verify`, edge FAIL→P0 and edge PASS→P3, unreachable
  failure report, rejected unsafe redirect that never contacts the target,
  valid redirect follow, redirect budget, oversized-response abort, timeout,
  missing-version honesty, spoofed `PHP/9.9.9` hint-only, tamper detection,
  optional RCE evidence honored through the validator, CLI validation).
  No internet, no Docker, no PHP required.
- `install.sh`: chmod extended to the new Python entry points.
- Docs: README gains the "Remote URL assessment" section (usage, exit codes,
  safety model, artifact table, boundary claims); SKILL.md gains Phase 5b and
  the updated fast-path command; VERSION → 1.4.0.

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
