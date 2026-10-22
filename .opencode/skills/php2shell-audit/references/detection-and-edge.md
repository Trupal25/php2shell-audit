# Edge filtering, detection, and canary testing

## 1. Edge control matrix

| Control | Target | Where | Notes |
|---|---|---|---|
| Decoded body size | ≤ 8 MiB (tune) | Nginx/Apache/WAF | Enforce while reading bytes; `Content-Length` can be absent or false with chunked/HTTP2 |
| Urlencoded key length | ≤ ~1000 bytes | WAF/body parser | `(^|&)[^&=]{1000,}` |
| Multipart field-name length | ≤ ~1000 bytes | WAF/body parser | Inspect `name="..."` inside each part |
| Part count | ≤ 100 | WAF/body parser or `max_multipart_body_parts` | PHP's directive limits parts, not headers per part |
| Headers per part | ≤ ~20 | WAF/body parser | This is inside the body; Nginx alone cannot do it |
| Input fields | ≤ 1000 | `max_input_vars` + WAF | |
| Nesting depth | ≤ 64 | `max_input_nesting_level` + WAF | Nested names multiply array work |
| File controls | ≤ 20 | `max_file_uploads` + WAF | Empty controls still create metadata |
| Multipart overall | block if unused | Nginx/Apache/WAF | `415` at the edge |
| Timeouts | short | proxy/WAF | Prevent `Maximum execution time exceeded` as an interruption |
| Rate limits | per IP/session | proxy/WAF | Reduces repeated attempts; not a fix |
| Worker recycling | `pm.max_requests=1` | FPM | Temporary; breaks cross-request reuse |

Keep the cheap body-size and key-length rules after patching. They are DoS defense-in-depth.

## 2. Nginx

```nginx
client_max_body_size 8m;
client_body_buffer_size 128k;
client_body_timeout 10s;
```

Block multipart if the app does not use it:

```nginx
if ($content_type ~* "^multipart/form-data") {
    return 415;
}
```

Nginx cannot inspect multipart part headers. Pair it with a body-parsing WAF (ModSecurity/Coraza, Cloudflare, AWS WAF, Fastly, Imperva) if you need part-level limits.

## 3. Apache

```apache
LimitRequestBody 8388608
```

`LimitRequestBody` is a transport cap, not a decoded-body cap. Combine with a WAF.

## 4. ModSecurity / Coraza

```apache
SecRequestBodyAccess On
SecRequestBodyLimit 8388608
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072

# Long urlencoded key
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" \
  "id:10961801,phase:2,deny,status:413,log,chain,msg:'PHP2Shell: oversized urlencoded parameter key'"
  SecRule REQUEST_BODY "@rx (?:^|&)[^&=]{1000,}" "t:none"

# Long multipart field name (validate against your engine)
SecRule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" \
  "id:10961802,phase:2,deny,status:413,log,chain,msg:'PHP2Shell: oversized multipart field name'"
  SecRule REQUEST_BODY "@rx name=\"[^\"]{1000,}\"" "t:none"
```

Rules are engine-dependent. Test with benign traffic first; body inspection can cost CPU and cause false positives on large JSON/base64 fields.

## 5. Cloudflare managed rules

Cloudflare deployed protections before disclosure. Confirm deployment in **Security → WAF → Managed rules**:

| Plan | Ruleset ID |
|---|---|
| Free | `77454fe2d30c4220b5701f6fdfb893ba` |
| Paid | `efb7b8c949ac4650a09736fc376e9aee` |
| Response firewall default | `afffe22785674c80a31875c848d2242a` |

Rule descriptions: "Generic Rules - Anomalous Execution - 1..7". Rule IDs differ by plan; use the Cloudflare blog/changelog as the source of truth. Keep WAF enabled after patching.

## 6. Log and telemetry hunts

Run these against the audit window and, if available, the last 30 days. Substitute your log paths.

```bash
# PHP fatal/OOM/timeout signals
rg -i -n 'PHP (Fatal error|Parse error)|Allowed memory size.*exhausted|Maximum execution time.*exceeded|out of memory' /var/log/php /var/log/apache2 /var/log/nginx 2>/dev/null

# Worker churn / crashes
journalctl -u php8.4-fpm --since '30 days ago' | rg -i 'child .* exited|segfault|SIGSEGV|signal 11|restart'
rg -i -n 'child pid .*exit signal Segmentation fault|zend_mm_heap corrupted' /var/log/apache2 2>/dev/null
dmesg -T 2>/dev/null | rg -i 'segfault|php'

# Suspicious multipart / large posts to non-upload routes
rg -i -n 'POST .*multipart/form-data' /var/log/nginx/access.log 2>/dev/null | head -200

# WAF events (Cloudflare Logpush / vendor console)
# Filter rule IDs above, action=block, path=/login,/search,/api/*, and large request bodies.
```

Generic SIEM queries (adapt field names):

```text
# Splunk
index=web sourcetype=php_fpm ("Allowed memory size" OR "Maximum execution time" OR "child exited on signal")
| stats count by host, pool, uri
| where count > 5

# Elastic / OpenSearch
event.dataset:(php.error OR apache.error) AND message:("Allowed memory size" OR "Maximum execution time" OR "Segmentation fault")
```

Hunt for:

- Repeated HTTP 500/502 on the same route with multipart bodies.
- A `PHPSESSID` response cookie that is much larger than the application's normal value, or malformed/URL-encoded binary.
- FPM child PIDs changing far faster than normal.
- `zend_mm_heap corrupted`, `Segmentation fault`, `SIGSEGV`, `SIGBUS`.
- WAF "Anomalous Execution" hits followed by a 500.
- Multipart requests to endpoints that do not accept uploads.
- Very long field names, many part headers, many empty file controls, deep nesting.

Application logs may contain little context because the bugs execute below the application layer. Absence of a log entry is not proof of safety.

## 7. Canary design (staging only)

The canary checks **edge conformance**, not exploitability. It answers: "Does the frontend reject an oversized parameter key with a 4xx instead of forwarding it?"

Rules:

- One target, one worker/pool, one request. No concurrency, no retries.
- Default key length 2 KiB; hard cap 8 KiB.
- `application/x-www-form-urlencoded` only. Do not send crafted multipart, serialized session data, or upload-progress fields.
- Baseline `GET` first, then the probe.
- Tag the request: `User-Agent: php2shell-audit/1.0` and `X-Audit-Request: php2shell-conformance`.
- Stop on 502/504 or if the worker PID changes unexpectedly. Record, do not retry.
- Never run against a production pool without the owner's approval and a rollback plan.

Expected results:

| Status | Meaning |
|---|---|
| 400/403/413/414 | Control present; pass |
| 200 | Control absent; finding |
| 3xx | Redirect; control not evaluated at this layer; follow up at the final origin |
| 502/504 | Upstream failure or worker crash; stop and inspect logs |
| 5xx other | Investigate; do not increase payload |

`scripts/edge-conformance.sh` implements these bounds. It refuses public IPs unless the host is listed in `scope.txt`; private/loopback lab targets run directly.

## 8. Incident triage

If you see a positive signal:

1. Preserve logs and worker/core dumps before restarting.
2. Identify the SAPI and exact version on the affected worker.
3. Check for the producer/consumer pattern: a request that ends in OOM/fatal, followed by a request to the same worker that triggers diagnostics or upload-progress handling.
4. Inspect response cookies for abnormal `PHPSESSID` values.
5. Treat the host as potentially compromised if RCE is plausible: isolate, rotate secrets that were in worker memory, and rebuild from a patched image.
6. Patch before re-enabling traffic. WAF is not a substitute.
7. Re-audit the whole estate, not just the affected vhost.

## 9. Evidence to capture

- `php -v` + build date from the web SAPI.
- `php -i` excerpt for the ten directives.
- FPM pool/Apache `php_admin_value` lines.
- Container image digest.
- `curl` status/headers/timestamp for the edge probe.
- Log excerpts with timestamps and request IDs.
- WAF rule IDs and deployment state.
- Diff of the remediation applied and the post-change verification.
