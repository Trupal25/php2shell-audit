# PHP2Shell — verified advisory notes

Last verified: **2026-10-22**. Re-check the vendor advisory before enforcing any gate; versions and guidance can change.

## Identifiers and severity

| Item | Value |
|---|---|
| CVE-2026-109618 | RCE via OOM corruption (PHP core) |
| CVE-2026-109619 | RCE via stale global state (PHP core) |
| Public name | PHP2Shell |
| Vendor severity | Critical, CVSS v4 9.2 |
| NVD CVSS v3.1 | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| Disclosure | 2026-10-21 |
| Affected since | PHP 5.4-era code; every branch below the gates is affected by at least one issue |

Primary advisories:

- `GHSA-w8hw-w9fx-j79w` — RCE via OOM corruption (CVE-2026-109618)
- `GHSA-6wmf-4rv5-p3rp` — RCE via stale global state (CVE-2026-109619)
- PHP release archive: `https://www.php.net/archive/2026.php#2026-10-21-5`
- Wiz analysis: `https://www.wiz.io/blog/php2shell-php-rce`
- Cloudflare WAF: `https://blog.cloudflare.com/php-vulnerabilities-waf-protection/`

## Patch gates

| Branch | Patched at | Notes |
|---|---|---|
| 8.5 | **8.5.12** | `fatal_error_backtraces=0` is a relevant interim control below this |
| 8.4 | **8.4.27** | |
| 8.3 | **8.3.36** | |
| 8.2 | **8.2.35** | Security support ends 2026-12-31 |
| ≤ 8.1 | **none listed** | EOL branch. No official release in the advisory. A vendor backport must be provenance-checked and rebuilt; do not trust a branch name alone. |

Treat "unknown version" as affected until authenticated inventory proves otherwise.

## Mechanism in one page

Both bugs are about what happens when a request is interrupted by a fatal condition — especially out-of-memory — and the worker survives to handle another request.

**CVE-2026-109618 (OOM corruption).** PHP uses `longjmp()` to abort a request on OOM. In some startup contexts, request memory is temporarily reachable before it is fully initialized. If an allocation fails there, PHP does not fully account for the early exit and leaves request memory in an invalid state. Request shutdown can then read or branch on that state. The patch replaces the `longjmp()` OOM path with a delayed soft OOM at the next VM safe point, plus a hard `_exit()` at a second, higher threshold.

Ways a request can reach OOM while staying inside apparent PHP limits:

- A multipart request without a usable declared content length can pass the initial `post_max_size` check and keep supplying decoded body data.
- A multipart part can carry an unrestricted number of headers; PHP's in-memory representation costs far more than the wire form.
- Empty file controls do not count toward `max_file_uploads` but still create metadata arrays.
- Nested field names multiply the generated array work.
- Application-specific large allocations or repeated memory use can do it too.

**CVE-2026-109619 (stale global state).** PHP keeps worker-global pointers to request-owned memory (error, session, object, extension state). A fatal error can abandon an operation before its matching reset, and a nonfatal diagnostic can repopulate error state after cleanup. The request heap is freed while the global still refers to it. A later request handled by the same worker can consume the stale value before normal initialization replaces it. Exploitation needs a **producer** (an operation that publishes request-owned state globally), an **interruption** (fatal error, timeout, parse/compile/uncaught error), and a **consumer** (an operation that runs before normal initialization and acts on the stale state).

Confirmed producer/consumer cases:

- **PHP 8.5 fatal-error backtrace** — `fatal_error_backtraces` stores request-owned backtrace state; reset is missed on shutdown. Confirmed mod_php RCE.
- **Session upload progress** — can initialize session/decoder state before normal module init; OOM or another fatal can prevent reset. Works without `session_start()`. Confirmed against mod_php and FPM.
- **OPcache type confusion** — a failed persistence step can leave a process-local frontier advanced while shared state still considers a slot free; another worker can reuse it with the wrong type. Demonstrated on WordPress.
- Other error/exception/object/extension state is conditional and application-dependent.

## SAPI susceptibility

| SAPI | Advisory position | Audit treatment |
|---|---|---|
| **Apache mod_php** | Unconditionally invokes request shutdown even when startup failed; confirmed pre-auth RCE with default input/memory limits | P0 if reachable |
| **FrankenPHP** | Calls request shutdown unconditionally, analogous to mod_php; likely susceptible | P0 if reachable |
| **PHP-FPM** | Exits the child when request startup fails, which removes some paths; confirmed RCE with an application-specific producer; invalid state can still be processed on shutdown after normal startup | P1 |
| **LSAPI** | Models FPM; application-specific exploits likely but unvalidated | P1 |
| **php-cgi** | Patch regardless; no SAPI-specific claim in the advisory | P1 |
| **CLI / cron / queue** | No HTTP exposure, but long-lived workers can retain state | P2; patch |

Multiple workers and unrelated traffic reduce success per request but do not remove the condition. The producer and consumer must reach the **same** worker.

## What the advisory says about mitigation

- Updating to a release with the complete patch is the **only complete mitigation**.
- For 109618, `memory_limit=-1` administratively is the primary interim control. It removes the predictable per-request limit, but is **not complete**: an `mmap()` or other underlying allocation failure can still trigger the vulnerable `longjmp()` path.
- Do **not** use `RLIMIT_AS` or `RLIMIT_DATA`; they make `mmap()` fail and re-expose the path.
- cgroup `memory.max` is an alternative with caveats; killing a container/cgroup can take the master and all workers unless each worker has its own group. Killing one FPM child only fails its current requests and the master replaces it.
- Keep `post_max_size` conservative and enforce **decoded** request size at the frontend.
- Reduce `max_input_nesting_level`; bound input variables, multipart parts, headers per part, and uploads.
- Block multipart at the frontend if the application does not use it.
- For 109619: `fatal_error_backtraces=0` on 8.5 and `session.upload_progress.enabled=0` remove the confirmed producer/consumer paths, but there is **no complete generic configuration mitigation**; other state families may remain.
- `pm.max_requests=1` breaks cross-request reuse if performance is not a concern.
- A PHP execution timeout is another fatal error; prevent attacker-controlled requests from predictably reaching `Maximum execution time exceeded`.

## Detection signals (from public analysis)

- Unusual multipart requests followed by memory-limit errors or repeated HTTP 500s.
- Unexpectedly large or malformed `PHPSESSID` response cookies.
- Unexplained PHP worker churn, FPM child restarts, or segfaults.
- WAF events for PHP2Shell managed rules.
- `Maximum execution time exceeded` on attacker-reachable routes.
- Warnings/deprecations emitted before target scripts run, or during extension/server cleanup.
- Requests with very long multipart field names, many part headers, many empty file controls, or deeply nested names — especially to endpoints that do not use uploads.

Application logs may contain little context because the bugs execute below the application layer. Absence of a log entry is not proof of safety.

## Fix verification

- `php -v` shows the version and build date; confirm the build date is after the patched release.
- `php -i | grep -E 'PHP Version|Build Date|Server API'` on the **web SAPI**.
- `php-fpm -v` for the FPM binary; `apachectl -M | grep -i php` for mod_php.
- Container image digest, not a mutable tag.
- Re-run inventory after restart; include subdomains, legacy vhosts, CI runners, cron PHP, queue workers, and serverless layers.
