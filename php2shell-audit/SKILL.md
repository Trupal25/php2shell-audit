---
name: PHP2Shell Exposure Audit
description: Audit PHP deployments for CVE-2026-109618 and CVE-2026-109619 (PHP2Shell). Inventories SAPI and patch level, verifies startup-config hardening, checks edge filtering, hunts exploitation signals, validates externally produced RCE evidence, and produces an evidence-backed remediation report. Includes an opt-in isolated-lab RCE validation module that requires an operator-supplied authorized trigger; the URL assessment workflow remains non-exploitative. Use for PHP fleet audits, patch verification, WAF/edge review, or incident triage.
---

# PHP2Shell Exposure Audit

Answer four questions, in order:

1. **Which PHP runtimes are affected?**
2. **Which of those are reachable by untrusted traffic?**
3. **Which interim controls are actually in force** — not just written in a file?
4. **What evidence proves the fix?**

The default **URL assessment workflow is deliberately non-exploitative**. It does not contain, generate, or send an exploit payload to an arbitrary target, and it never confirms RCE from headers. The separate lab reproduction sends a bounded multipart body that exercises request parsing and can trigger memory exhaustion; it records the vulnerable/patched differential and never claims RCE.

The skill includes an **opt-in isolated-lab RCE validation module** (`modules/rce-modphp`) for the calibrated `php:8.4.26-apache` / mod_php / 8 MB profile. The module does **not** contain an exploit: it requires an operator-supplied, authorized copy of the public php2shell upstream trigger, mounted read-only with `--exploit-dir`. The trigger is not bundled or redistributed because the upstream project has no explicit license. It is never invoked by `assess-url.sh` and cannot be pointed at an arbitrary URL.

It also includes a **four-state validator for RCE evidence** (`scripts/rce-validate.sh`). The validator rechecks the patch gate and controls, enforces nonce freshness and marker integrity, and refuses to confirm RCE without reproducible execution effects. A separate **lab reproduction** (`scripts/lab-repro.sh`) records a request-parsing OOM differential as `repro_state`, never as RCE; see `references/lab-reproduction.md`.

A **controlled validation-module harness** (`scripts/module-run.sh`) executes authorized modules against the disposable pair and classifies what was actually observed (`suspected-exposure`, `crash-oom`, `memory-safety-failure`, `memory-disclosure`, `demonstrated-code-execution`, or `inconclusive`). A module's self-reported JSON is a claim until corroborated by harness artifacts; execution requires `RCE-CONFIRMED` plus a matching target marker and no patched-control marker. See `references/module-interface.md`.

## Operating assumptions

- **The lab target list is the scope.** Put the instructor-provided hosts in `scope.txt`; fleet and HTTP probe scripts use it. Private/loopback targets run without extra flags, so local labs have zero setup friction.
- **The URL workflow is an audit package, not an exploit kit.** It verifies version, configuration, edge filtering, and patch state. It does not generate or send a code-execution payload. The bounded lab reproduction is an OOM/crash observation, not exploitation. Use the isolated `assets/lab/` pair if the lab asks for a demonstration. The only execution path is the opt-in `rce-modphp` module, which runs an operator-supplied trigger inside the disposable lab.
- **One bounded probe.** `edge-conformance.sh` sends a single request, never retries, and stops on 502/504. That keeps the target stable and the evidence clean.
- **Non-destructive checks.** Remediation is emitted as a diff for the owner/instructor to apply.

## Competition fast path (run this first)

One command, local host, a few seconds:

```bash
bash scripts/triage.sh --local
```

No shell access? Give it a URL (public targets need `scope.txt`; loopback/private lab targets use `--lab` instead):

```bash
bash scripts/assess-url.sh https://target/ --scope-file scope.txt --asset web-01 --out url-audit-web-01
# local lab alternative:
bash scripts/assess-url.sh http://127.0.0.1:8080/ --lab
```

`assess-url.sh` runs the full safe workflow: SSRF-guarded authorization (HTTP/HTTPS only, pinned DNS, re-authorized redirects, TLS verify on), a bounded redirect-validated GET, one bounded long-key POST, then the same derived evidence + `chain.sh` verdict + `report.py` output as the local pipeline. It writes `assessment.json`, `report.md`, `findings.jsonl`, `findings.csv` plus raw captures, and prints the verdict:

- `CHAIN-OPEN` — header hint below the gate; edge forwarded the key (P0 for mod_php/FrankenPHP, else P1).
- `CHAIN-BLOCKED` — a decisive control is in force (edge rejected the key) or the hint meets the gate. Still confirm with `php -v`.
- `CHAIN-PARTIAL` / `UNKNOWN` — evidence inconclusive; do not conclude from absent headers.

Exit codes: `0` report generated · `2` invalid or unauthorized/unsafe target (nothing sent) · `3` collection did not complete (unreachable/timeout/refused redirect/oversize) with a truthful failure report · `4` internal error · `5` (`--verify`) tampering or contradiction detected.

Boundaries: this is remote assessment only — it sends no execution trigger, headers are hints (never a version proof), and `assess-url.sh --verify <dir>` re-checks artifact hashes and consistency. For headers only (no POST), use `bash scripts/fingerprint.sh --url ...`.

For a local or SSH-reachable host, `triage.sh` prints one decision — **P0 / P1 / P2 / P3 / PATCHED** — with the reason and the next action. It checks only the high-yield facts: web SAPI, exact version against the gate, `session.upload_progress.enabled`, `memory_limit`, `max_memory_limit`, and whether mod_php/FrankenPHP is present.

Rules for an ambiguous target:

- **Unknown version → assume affected.** Do not spend time proving a negative.
- `X-Powered-By` / `Server` are hints. One authenticated `php -v` beats ten fingerprints.
- **mod_php / FrankenPHP + affected or unknown + reachable → P0 now.** Capture version + SAPI evidence, then patch or isolate.
- **FPM / LSAPI / CGI + affected or unknown + reachable → P1.** Same action, slightly lower urgency.
- Do not inventory the whole estate before acting on the first P0/P1.

Deep audit (only after the fast decision, or when the report needs full coverage):

```bash
# 1. Local host: version, SAPI, ini, FPM/Apache overrides, app-level ini_set/.user.ini
bash scripts/inventory.sh --local --web-root /var/www --json > inventory.jsonl

# 2. Verify the web SAPI, not just CLI
bash scripts/verify-hardening.sh --php-bin "$(command -v php)" --strict

# 3. Edge conformance (staging only, one bounded request)
bash scripts/edge-conformance.sh --url https://staging.example.test/ --scope-file scope.txt

# 4. Precondition-chain verdict from every artifact you have collected
bash scripts/chain.sh --triage triage.jsonl --hardening hardening.jsonl \
  --fingerprint fingerprint.json --edge edge.json --asset web-01

# 5. One invocation: URL -> raw artifacts -> report.md + findings.csv
bash scripts/run-audit.sh --url https://staging.example.test/ \
  --scope-file scope.txt --asset web-01 --out audit-web-01
```

Fleet mode:

```bash
# scope.txt: one authorized host per line (hostname or user@host)
bash scripts/inventory.sh --hosts scope.txt --scope-file scope.txt --json > fleet.jsonl
```

Validate the tooling in a lab before the audit window:

```bash
# Offline self-tests: stub PHP binaries + local HTTP fixtures, no internet needed.
bash scripts/lab-verify.sh
```

## Phase 0 — Scope and evidence

Before any active check, record:

- Asset IDs and hostnames, environment (prod/staging/lab), and owner.
- Authorization reference (ticket, lab handout, instructor approval) and expiry.
- Network reachability: internet-facing, partner, internal, local-only.
- Time window and rate limits.
- Whether the target is stateful (single FPM worker, session affinity, canary pool).

Write `scope.txt` with one host per line. For the class lab, use the instructor-provided target list. Do not infer scope from a domain suffix.

Evidence standard for every finding:

- Exact version string **and** build date, from the web SAPI.
- Exact config key, value, and the file/pool it came from.
- HTTP status/header evidence, with timestamp and request ID.
- Command output or screenshot path. No finding without reproducible evidence.

## Phase 1 — Inventory (verify, don't trust)

Run `scripts/inventory.sh` locally or over the authorized fleet. It collects:

- `php -v`, `PHP_VERSION`, `PHP_SAPI`, build date, loaded ini file, scan dir.
- The directives that matter: `memory_limit`, `max_memory_limit`, `post_max_size`, `upload_max_filesize`, `session.upload_progress.enabled`, `max_input_vars`, `max_input_nesting_level`, `max_multipart_body_parts`, `max_file_uploads`, `fatal_error_backtraces`, `expose_php`, `log_errors`, `error_log`, `display_errors`, `enable_post_data_reading`.
- FPM pool / Apache `php_admin_value` overrides, because they beat `php.ini`.
- App-level `ini_set()` and `.user.ini` overrides, because they can restore a finite `memory_limit` after startup.
- Running containers and image tags/digests.
- CLI, FPM, Apache, cron, queue-worker, and CI PHP binaries separately.

**The CLI is not the web SAPI.** A host can show `8.4.27` in `php -v` while Apache/FPM still serves an older module or pool. Verify per SAPI:

```bash
php-fpm -v
php-fpm -tt                 # config test; prints pool values
apachectl -M | grep -i php  # mod_php present?
php -i | grep -E 'Server API|Loaded Configuration File|Scan this dir'
```

For containers, inspect the **image digest**, not the mutable tag:

```bash
docker ps --format '{{.Names}}\t{{.Image}}'
docker inspect --format '{{.Config.Image}} {{.Image}}' <container>
```

## Phase 2 — Triage decision table

Patch gates (all four branches, from the PHP advisory):

| Branch | Patched at | Notes |
|---|---|---|
| 8.5 | **8.5.12** | `fatal_error_backtraces=0` is relevant only below this |
| 8.4 | **8.4.27** | |
| 8.3 | **8.3.36** | |
| 8.2 | **8.2.35** | Security support ends 2026-12-31 |
| ≤ 8.1 | **none listed** | EOL. No official release in the advisory; do not assume a backport exists. A vendor backport must be provenance-checked and rebuilt, not trusted by branch name. |

SAPI susceptibility:

| SAPI | Assessment | Triage |
|---|---|---|
| **Apache mod_php** | Confirmed pre-auth RCE; request shutdown runs even when startup failed | **P0** if reachable |
| **FrankenPHP** | Likely susceptible (unconditional shutdown); treat like mod_php | **P0** if reachable |
| **PHP-FPM** | Susceptible; confirmed RCE with an application-specific producer; child exits on startup failure | **P1** |
| **LSAPI** | Models FPM; application-specific path likely | **P1** |
| **php-cgi** | Patch regardless; no SAPI-specific claim in the advisory | **P1** |
| **CLI / cron / queue** | No HTTP exposure, but long-lived workers can retain state | Patch; **P2** |

Priority:

- **P0** — internet-facing mod_php/FrankenPHP below the patch gate, or unknown version on those SAPIs. Patch or isolate now.
- **P1** — internet-facing FPM/LSAPI/CGI below the gate, or affected internal mod_php with untrusted users.
- **P2** — affected but not reachable from untrusted traffic; EOL branch with no vendor patch.
- **P3** — patched, but interim hardening/edge gaps remain.

Version strings from `X-Powered-By`, `Server`, or error pages are **hints only**. They can be spoofed, stripped, or belong to a different vhost. Confirm with authenticated inventory or the package manager.

## Phase 3 — Interim hardening (only if patching cannot happen immediately)

Full snippets are in `references/hardening.md`. Apply at **startup** — `php.ini`, FPM pool, or Apache `php_admin_value` — then restart every worker. `ini_set()` and `.user.ini` apply too late for the early-consumer paths.

Minimum set:

```ini
session.upload_progress.enabled = 0
memory_limit = -1
max_memory_limit = -1          ; PHP 8.5+: do not cap the -1 above
post_max_size = 8M             ; shrink to the app's real need
upload_max_filesize = 2M       ; must stay below post_max_size
max_input_vars = 1000
max_input_nesting_level = 64
max_multipart_body_parts = 100 ; if the directive exists
max_file_uploads = 20
fatal_error_backtraces = 0     ; PHP 8.5 only
expose_php = Off               ; hygiene, not a mitigation
```

Caveats that must appear in the report:

- `memory_limit=-1` is the advisory's primary interim control, but it is **not complete**. An `mmap()`/underlying allocation failure can still reach the vulnerable `longjmp()` path.
- Do **not** use `RLIMIT_AS` or `RLIMIT_DATA`; they cause `mmap()` failure and re-expose the path.
- cgroup `memory.max` is an alternative with limits: killing a container/cgroup can kill the master and all workers unless each worker has its own group.
- `post_max_size` alone is insufficient. Enforce **decoded** body size at the edge; `Content-Length` can be absent or false with chunked/HTTP2.
- `max_multipart_body_parts` limits parts, not headers inside a part. Cap part headers at the edge.
- `pm.max_requests=1` breaks cross-request state reuse but costs performance. Use it as a temporary link-breaker only.

Verify with `scripts/verify-hardening.sh` against the **web SAPI**, then restart and re-check. A value in `php.ini` that is overridden by a pool is not a control.

## Phase 4 — Edge/WAF conformance

Detailed rules and caveats are in `references/detection-and-edge.md`.

- Block multipart entirely if the application does not use it.
- Enforce decoded body size at the proxy/WAF, not just `Content-Length`.
- Cap the number of parts, headers per part, input fields, nesting depth, and file controls.
- Reject urlencoded parameter keys longer than ~1000 bytes: `(^|&)[^&=]{1000,}`. For multipart, check each `name="..."` length.
- Keep managed WAF protections enabled (Cloudflare free/paid rules are deployed by default; verify your plan and ruleset), but never treat WAF as the fix.
- After patching, keep the large-key and body-size rules as cheap DoS defense-in-depth.

`scripts/edge-conformance.sh` sends **one** urlencoded request with a bounded long key (default 2 KiB) and reports the status. Expected: 400/403/413/414. A 200 means the key-length control is absent — that is a finding, not an exploit. A 502/504 means stop and inspect worker logs.

## Phase 5 — Patch and verify

1. Upgrade via package manager, vendor backport, or rebuilt base image to **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** or later on that branch.
2. For EOL branches, upgrade to a supported branch. If a vendor backport is unavoidable, verify its source, build hash, and signer.
3. Rebuild immutable images; do not rely on `apt upgrade` inside a running container.
4. Restart PHP-FPM, Apache, FrankenPHP, LiteSpeed, and OPcache. Drain and replace workers.
5. Verify with the web SAPI:
   ```bash
   php -v
   php -i | grep -E 'PHP Version|Build Date|Server API|memory_limit'
   php-fpm -v
   ```
6. Re-run Phase 1 across the whole estate: forgotten subdomains, legacy vhosts, CI runners, cron PHP binaries, queue workers, serverless layers, and sidecar containers.
7. Remove temporary WAF rules only after every instance is patched; keep the cheap large-key/body-size rules.

## Phase 5b — Remote URL assessment (no SSH)

For hosts you cannot shell into, `scripts/assess-url.sh` produces the same kind of
evidence-backed decision over HTTP, safely by default:

```bash
bash scripts/assess-url.sh https://t.example/ --scope-file scope.txt \
  --asset web-01 --out url-audit-web-01 --exposure internet
# loopback/private lab target:
bash scripts/assess-url.sh http://127.0.0.1:8080/ --lab --out url-audit-lab
```

- **Authorization before anything:** `scripts/url_guard.py` parses strictly
  (http/https only, no embedded credentials), checks every resolved address
  against global-routability (loopback/private/link-local/metadata need
  `--lab`), enforces the scope file for public hosts, and returns one pinned
  address that every request (`curl --resolve`) reuses — rebinding-proof.
- **Bounded collection:** manual redirect loop with per-hop re-authorization
  (https→http downgrades refused), `--max-bytes`, `--connect-timeout`,
  `--timeout`, `--max-redirects`; TLS verification is never disabled; no
  credentials, cookies, or environment proxies are sent.
- **Evidence normalization:** the pinned captures are normalized into
  `fingerprint.json` / `edge.json` with the same decision rules as the local
  scripts, then `chain.sh` issues the verdict and `report.py` renders
  `findings.csv`; `url-report.py` writes the full `report.md`.
- **Honest reporting:** version evidence is labeled a hint (never definitive),
  `RCE not established` unless a validator artifact was passed with
  `--rce-evidence`, limitations/`not_tested`/`next_steps` sections are always
  present, and `assess-url.sh --verify <dir>` detects artifact tampering
  (exit 5).
- Exit codes: `0` report generated · `2` unauthorized/unsafe (nothing sent) ·
  `3` collection incomplete with a truthful failure report · `4` internal
  error · `5` tampering detected (`--verify`).

## Phase 6 — RCE evidence validation (optional, last)

Use this only when an authorized validation module has produced an execution artifact
for an isolated lab target. Do **not** treat a version/header finding as proof of RCE.

```bash
bash scripts/rce-validate.sh \
  --evidence rce-evidence.json \
  --markers rce-marker.txt \
  --asset web-01 \
  --seen-file .rce-nonces.json
```

Four states, four different report claims:

| State | Claim |
|---|---|
| `RCE-CONFIRMED` | Execution effects recorded, below-gate web SAPI, upload progress enabled, fresh nonce, marker hash/nonce match, request digest valid. |
| `RCE-NOT-REPRODUCED` | A trigger was attempted; no execution effects were recorded. |
| `RCE-INCONCLUSIVE` | Evidence missing, malformed, tampered, replayed, or the version/SAPI is unknown. |
| `RCE-BLOCKED` | Version meets the branch gate, or a decisive control is in force. |

Exit codes: `0` confirmed, `1` blocked, `2` not reproduced, `3` inconclusive, `4`
usage/input error.

Rules:

- Recheck the patch gate from the artifact's own `php_version`. Never trust a
  `below_gate` claim.
- Require a web SAPI and `session.upload_progress.enabled=true`. Either failing is
  `RCE-BLOCKED`, not "inconclusive".
- Require a fresh 16–128 hex nonce, a 64-hex request digest, and a marker file whose
  SHA-256 matches and which contains the nonce. Replays are `RCE-INCONCLUSIVE`.
- Empty `execution_effects` is `RCE-NOT-REPRODUCED`, not a failed audit.
- The trigger and heap grooming are **not implemented in this repository**. The
  opt-in `rce-modphp` adapter can execute an operator-supplied trigger in the
  disposable lab. Without such an artifact, the strongest honest result is
  `NOT-REPRODUCED` or `INCONCLUSIVE`.

Full detail, schema, and the missing-trigger boundary: `references/rce-validation.md`.

## Phase 6b — Real lab reproduction (Docker, optional)

The reproduction is separate from RCE validation. It sends one bounded multipart
request to `php:8.4.26-apache` and `php:8.4.27-apache`, with the session
upload-progress preamble and 150,000 ignored part headers. Under the lab's
`memory_limit=8M`, the vulnerable parser exhausts memory; the patched parser keeps
only the headers it uses and returns the normal probe JSON.

```bash
bash scripts/lab-repro.sh --out repro-lab --json
bash scripts/run-audit.sh --url http://127.0.0.1:8081/ --asset lab-vulnerable \
  --out audit-lab-vulnerable --repro-evidence repro-lab/repro-evidence.json
```

The artifact has `state: REPRO-OOM-DIFFERENTIAL`, empty `execution_effects`, and
`rce_observed: false`. It proves a request-parsing behavior difference, **not**
heap grooming or RCE. `REPRO-CRASH-OBSERVED` is also not RCE. The report shows a
separate `Repro` column and a `## Reproduction evidence` section.

Run the Docker-gated integration test only when Docker and both images are
available:

```bash
bash scripts/lab-integration.sh --out lab-integration-1
```

It runs the reproduction independently, consumes the artifact through
`run-audit.sh`, and asserts the report reflects the observed result without
`RCE-CONFIRMED`. It also executes the real `oom-differential` module twice
(repeatability), checks isolation/limits/cleanup/provenance, and consumes the
real module artifact through `run-audit.sh` (62 assertions). The offline
`scripts/lab-verify.sh` remains the default test (140 assertions).

The opt-in RCE repeatability test is separate and requires an authorized
external trigger:

```bash
bash scripts/rce-integration.sh \
  --exploit-dir /authorized/path/php2shell-upstream \
  --out rce-integration-1
```

It runs `modules/rce-modphp` twice against fresh disposable labs and asserts
`demonstrated-code-execution`, `RCE-CONFIRMED`, a nonce-bound marker, no patched
control marker, verified artifacts, and cleanup (34 assertions).

## Phase 6c — Controlled validation modules (optional)

Use this only with a module or trigger supplied by an authorized researcher and
only in the disposable local lab. The harness is not an exploit generator; it
executes and corroborates external code. The bundled `rce-modphp` module is an
adapter for an external trigger, not the trigger itself.

```bash
# Contract check without Docker (must succeed before any execution)
bash scripts/module-run.sh --module modules/oom-differential --dry-run --json

# Execute and classify
bash scripts/module-run.sh --module modules/oom-differential \
  --asset lab-vulnerable --out module-run-oom --json

# Normalize the run into an audit report
bash scripts/run-audit.sh --url http://127.0.0.1:8081/ --asset lab-vulnerable \
  --out audit-lab-module --module-run module-run-oom/module-run.json

# Or execute inside run-audit
bash scripts/run-audit.sh --url http://127.0.0.1:8081/ --asset lab-vulnerable \
  --out audit-lab-module --module modules/oom-differential

# Opt-in RCE validation with an operator-supplied external trigger
bash scripts/module-run.sh \
  --module modules/rce-modphp \
  --exploit-dir /authorized/path/php2shell-upstream \
  --asset lab-rce --out module-run-rce --timeout 180 --json
bash scripts/run-audit.sh --url http://127.0.0.1:8081/ --asset lab-rce \
  --out audit-lab-rce --module modules/rce-modphp \
  --module-exploit-dir /authorized/path/php2shell-upstream --module-timeout 180
```

The module always starts its own calibrated disposable pair; `--url` supplies
only the audit context and is never the exploit target.

Impact taxonomy: `suspected-exposure`, `crash-oom`, `memory-safety-failure`,
`memory-disclosure`, `demonstrated-code-execution`, `inconclusive`. The
classifier is deliberately conservative:

- OOM needs corroboration from the harness Apache log and/or response artifacts;
  a module's JSON claim alone is not enough.
- A crash/OOM is **not** memory corruption, disclosure, or execution.
- Disclosure needs the harness canary in a vulnerable-target dump and not in the
  patched control.
- Memory safety needs a sanitizer/heap-corruption signal corroborated by the
  harness.
- Execution needs `RCE-CONFIRMED` from `rce-validate.sh`, a marker that the
  harness independently retrieved from the vulnerable target with a matching
  hash and nonce, and **no** matching marker on the patched control.
- Synthetic modules require `--allow-synthetic` and always classify
  `inconclusive`; `run-audit.sh` ignores them as evidence.
- If the audit target meets the patch gate, lab validation is recorded but the
  target impact remains `inconclusive`; lab findings never make a patched target
  look vulnerable.

Isolation: internal Docker network, no published ports, module container with
`--cap-drop ALL`, `no-new-privileges`, read-only root, tmpfs `/tmp`, 512 MB /
1 CPU / 128 PIDs, hard timeout, no Docker socket; containers and network are
removed on exit unless `--keep`.

The bundled `modules/oom-differential` sends the upstream 150,000-header
multipart shape. On 2026-10-22 it produced `crash-oom` (`observed`):
`php:8.4.26-apache` OOMed under the 8 MB lab limit and `php:8.4.27-apache`
returned the normal probe JSON. No execution, disclosure, or memory corruption
was observed.

The bundled `modules/rce-modphp` adapter, run with the pinned upstream trigger,
produced `demonstrated-code-execution` and `RCE-CONFIRMED` on two consecutive
fresh labs; the marker contained the fresh harness nonce and the patched 8.4.27
control produced no marker. The trigger itself is not included. The adapter
refuses a target that does not match its calibrated version/SAPI/INI/arch, and
the harness rejects a run without `--exploit-dir`.

Full contract, trust model, and artifact schema: `references/module-interface.md`.
RCE module specifics: `modules/rce-modphp/README.md`.

## Phase 7 — Hunt and regression guard

**Hunt** (see `references/detection-and-edge.md` for queries):

- Unusual multipart requests followed by memory-limit errors or repeated HTTP 500s.
- Unexpectedly large or malformed `PHPSESSID` response cookies.
- Unexplained PHP worker churn, segfaults, or FPM child restarts.
- WAF events for the PHP2Shell managed rules.
- `Maximum execution time exceeded` on attacker-reachable routes.
- Warnings/deprecations emitted before target scripts run, or during extension/server cleanup.

**Regress:**

- CI gate: fail any image where `PHP_VERSION` is below the branch gate.
- Alert on any running container/image with an affected version.
- Periodic drift scan for `session.upload_progress.enabled`, `memory_limit`, `max_memory_limit`, and pool overrides.
- Keep audit logging on; absence of a log entry is not proof of safety.

## Output contract

Emit one JSON object per asset plus a Markdown report. Schema and template: `references/report-format.md`.

Minimum fields: `asset`, `environment`, `sapi`, `php_version`, `build_date`, `patched_min`, `status`, `exposure`, `priority`, `interim_controls`, `edge_controls`, `evidence[]`, `remediation`, `owner`, `verified_at`. If RCE evidence was validated, add `rce_state` and the evidence path. If lab reproduction was run, add `repro_state` and `repro_summary`; keep it separate from `rce_state`. If a validation module was executed or consumed, add `impact`, `impact_confidence`, `impact_applicable`, `impact_basis`, `validation_impact`, `validation_confidence`, `validation_synthetic`, `validation_summary`, `module_id`, and `module_state`. The target `impact` is not a synonym for `validation_impact`: a lab result only applies to a below-gate target, and synthetic/unverified module evidence is never promoted.

## Scoring alignment (class/lab)

Findings score on evidence, not on exploit attempts:

- **P0/P1** with exact version + SAPI + reachability evidence.
- **Interim control proof** from the running web SAPI, not a config file.
- **Edge proof**: one bounded request with status and timestamp.
- **RCE proof**: `RCE-CONFIRMED` only with reproducible execution evidence, fresh nonce, and a matching marker; otherwise report `NOT-REPRODUCED` / `INCONCLUSIVE` / `BLOCKED`.
- **Remediation proof**: patched version, restart evidence, re-audit result.
- **Coverage**: web SAPI, FPM pools, CLI, containers, CI, cron, queue.
- Deductions: trusting `X-Powered-By`, checking only CLI, claiming WAF replaces patching, reporting a finding without a reproducible command, or claiming RCE from a version banner.

## References

- `references/advisory.md` — verified CVE facts, SAPI matrix, mechanism, detection signals.
- `references/deployment-patterns.md` — fast SAPI/version fingerprinting for ambiguous targets.
- `references/hardening.md` — php.ini/FPM/Apache/Nginx/WAF snippets and rollback.
- `references/detection-and-edge.md` — hunt queries, WAF rules, canary design.
- `references/report-format.md` — JSON schema, Markdown report, scoring rubric.
- `references/rce-validation.md` — four-state evidence schema, criteria, missing-trigger boundary.
- `references/lab-reproduction.md` — real request-parsing OOM differential schema, states, and non-RCE boundary.
- `references/module-interface.md` — validation-module contract, trust model, impact taxonomy, and artifact schema.
- `references/rce-validation.md` — four-state validator, evidence schema, marker/nonce integrity, and module bridge.
- `modules/oom-differential/` — real request-parsing OOM differential module; `modules/rce-modphp/` — opt-in external-trigger RCE adapter; `modules/synthetic-fixture/` — synthetic trust-boundary fixture (never evidence).
- `assets/lab/repro.ini` / `repro.php` — lab-only PHP config and harmless probe endpoint.
- `assets/lab/docker-compose.yml` — disposable vulnerable/patched pair for validating the audit (no exploit endpoint).
- `assets/lab/rce-evidence.example.json` — shape of the optional RCE evidence artifact (placeholders only).
- `scope.txt.example` — authorized target list format.
