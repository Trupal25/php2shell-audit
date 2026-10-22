---
name: PHP2Shell Exposure Audit
description: Audit PHP deployments for CVE-2026-109618 and CVE-2026-109619 (PHP2Shell). Inventories SAPI and patch level, verifies startup-config hardening, checks edge filtering, hunts exploitation signals, and produces an evidence-backed remediation report. Use for PHP fleet audits, patch verification, WAF/edge review, or incident triage. Exposure assessment only; never sends exploit payloads.
---

# PHP2Shell Exposure Audit

Answer four questions, in order:

1. **Which PHP runtimes are affected?**
2. **Which of those are reachable by untrusted traffic?**
3. **Which interim controls are actually in force** — not just written in a file?
4. **What evidence proves the fix?**

This skill is deliberately **non-exploitative**. It does not contain, generate, or send a payload that triggers the vulnerability, discloses worker memory, or executes code. The public advisories already describe the mechanism; reproducing it adds risk without adding audit value.

## Operating assumptions

- **The lab target list is the scope.** Put the instructor-provided hosts in `scope.txt`; fleet and HTTP probe scripts use it. Private/loopback targets run without extra flags, so local labs have zero setup friction.
- **This is an audit package, not an exploit kit.** It verifies version, configuration, edge filtering, and patch state. It does not generate or send a payload that triggers the vulnerability. Use the isolated `assets/lab/` pair if the lab asks for a demonstration.
- **One bounded probe.** `edge-conformance.sh` sends a single request, never retries, and stops on 502/504. That keeps the target stable and the evidence clean.
- **Non-destructive checks.** Remediation is emitted as a diff for the owner/instructor to apply.

## Competition fast path (run this first)

One command, local host, a few seconds:

```bash
bash scripts/triage.sh --local
```

No shell access? Give it a URL:

```bash
bash scripts/assess-url.sh --url https://target/ --scope-file scope.txt
```

It does a passive fingerprint, then one bounded long-key POST, and returns one of:

- `P0-EXPOSED` / `P1-EXPOSED` — header hint below the gate; edge forwarded the key.
- `P0-EDGE-MITIGATED` / `P1-EDGE-MITIGATED` — header hint below the gate; edge rejected the key. Still patch.
- `LIKELY-PATCHED` — header hint meets the gate; confirm with one authenticated `php -v`.
- `P0-UNVERIFIED` / `P1-UNVERIFIED` — edge probe inconclusive.

Headers are hints, not proof. For headers only (no POST), use `bash scripts/fingerprint.sh --url ...`.

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
```

Fleet mode:

```bash
# scope.txt: one authorized host per line (hostname or user@host)
bash scripts/inventory.sh --hosts scope.txt --scope-file scope.txt --json > fleet.jsonl
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

## Phase 6 — Hunt and regression guard

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

Minimum fields: `asset`, `environment`, `sapi`, `php_version`, `build_date`, `patched_min`, `status`, `exposure`, `priority`, `interim_controls`, `edge_controls`, `evidence[]`, `remediation`, `owner`, `verified_at`.

## Scoring alignment (class/lab)

Findings score on evidence, not on exploit attempts:

- **P0/P1** with exact version + SAPI + reachability evidence.
- **Interim control proof** from the running web SAPI, not a config file.
- **Edge proof**: one bounded request with status and timestamp.
- **Remediation proof**: patched version, restart evidence, re-audit result.
- **Coverage**: web SAPI, FPM pools, CLI, containers, CI, cron, queue.
- Deductions: trusting `X-Powered-By`, checking only CLI, claiming WAF replaces patching, or reporting a finding without a reproducible command.

## References

- `references/advisory.md` — verified CVE facts, SAPI matrix, mechanism, detection signals.
- `references/deployment-patterns.md` — fast SAPI/version fingerprinting for ambiguous targets.
- `references/hardening.md` — php.ini/FPM/Apache/Nginx/WAF snippets and rollback.
- `references/detection-and-edge.md` — hunt queries, WAF rules, canary design.
- `references/report-format.md` — JSON schema, Markdown report, scoring rubric.
- `assets/lab/docker-compose.yml` — disposable vulnerable/patched pair for validating the audit (no exploit endpoint).
- `scope.txt.example` — authorized target list format.
