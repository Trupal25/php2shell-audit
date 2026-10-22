# Interim hardening — exact snippets and caveats

Apply at **startup** and restart every worker. `ini_set()` and `.user.ini` apply too late for the early-consumer paths in CVE-2026-109619, and can silently restore a finite `memory_limit` after startup.

> The only complete fix is the patched PHP release. Everything here is interim risk reduction.

## 1. Global `php.ini`

```ini
; PHP2Shell interim controls
session.upload_progress.enabled = 0
memory_limit = -1
max_memory_limit = -1            ; PHP 8.5+: must not cap memory_limit=-1
post_max_size = 8M               ; shrink to the application's real need
upload_max_filesize = 2M         ; must stay below post_max_size
max_input_vars = 1000
max_input_nesting_level = 64
max_multipart_body_parts = 100   ; ignored on builds without the directive
max_file_uploads = 20
fatal_error_backtraces = 0       ; PHP 8.5+ only
expose_php = Off                 ; hygiene, not a mitigation

; Audit visibility (keep on in production if your logging pipeline allows)
log_errors = On
error_log = /var/log/php/error.log
error_reporting = E_ALL
display_errors = Off             ; production hygiene; does NOT mitigate either CVE
```

Locate the loaded file:

```bash
php -i | grep -E 'Loaded Configuration File|Scan this dir|Server API'
```

`php -i` from the CLI is **not** proof for FPM/Apache. Verify the web SAPI.

## 2. PHP-FPM pool

Put security-critical values in `php_admin_value` / `php_admin_flag`. These cannot be overridden by `ini_set()` or `.user.ini`.

```ini
; /etc/php/<ver>/fpm/pool.d/www.conf
php_admin_value[session.upload_progress.enabled] = 0
php_admin_value[memory_limit] = -1
php_admin_value[max_memory_limit] = -1
php_admin_value[post_max_size] = 8M
php_admin_value[upload_max_filesize] = 2M
php_admin_value[max_input_vars] = 1000
php_admin_value[max_input_nesting_level] = 64
php_admin_value[max_multipart_body_parts] = 100
php_admin_value[max_file_uploads] = 20
php_admin_value[fatal_error_backtraces] = 0
php_admin_flag[expose_php] = off
php_admin_flag[log_errors] = on
php_admin_value[error_log] = /var/log/php/fpm-error.log
php_admin_value[error_reporting] = E_ALL
php_admin_flag[display_errors] = off

; Temporary link-breaker; costs performance
pm.max_requests = 1
```

Test and reload:

```bash
php-fpm -tt
systemctl reload php8.4-fpm     # or: kill -USR2 $(cat /run/php/php8.4-fpm.pid)
```

`reload` gracefully replaces workers. For a guaranteed clean state, restart the service and confirm old workers are gone.

## 3. Apache mod_php

```apache
# Inside the <VirtualHost> or <Directory>, server config only
php_admin_value session.upload_progress.enabled 0
php_admin_value memory_limit -1
php_admin_value max_memory_limit -1
php_admin_value post_max_size 8M
php_admin_value upload_max_filesize 2M
php_admin_value max_input_vars 1000
php_admin_value max_input_nesting_level 64
php_admin_value max_multipart_body_parts 100
php_admin_value max_file_uploads 20
php_admin_value fatal_error_backtraces 0
php_admin_flag expose_php off
php_admin_flag log_errors on
php_admin_value error_log /var/log/php/apache-error.log
php_admin_value error_reporting E_ALL
php_admin_flag display_errors off
```

```bash
apachectl configtest
apachectl -M | grep -i php
systemctl reload apache2
```

`php_admin_value` is not allowed in `.htaccess`, which is desirable: an application cannot relax it.

## 4. FrankenPHP / Caddy

FrankenPHP runs PHP in-process. Set the same values in the `php.ini` used by the FrankenPHP build, or via the `php_ini` / environment configuration supported by your version. Rebuild the image with the patched PHP; reload the service.

```bash
frankenphp version
ps -eo pid,cmd | grep -i frankenphp
```

## 5. Nginx / reverse proxy

```nginx
client_max_body_size 8m;
client_body_buffer_size 128k;
client_body_timeout 10s;
```

Important limits:

- `client_max_body_size` is a **transport** cap. It is not a substitute for a decoded-body cap at a body-parsing WAF.
- Nginx does not parse multipart part headers. `large_client_header_buffers` covers HTTP headers only, not headers inside a multipart part.
- If the application does not use multipart, block it:

```nginx
if ($content_type ~* "^multipart/form-data") {
    return 415;
}
```

- Do not trust `Content-Length`. HTTP/2 and chunked transfer can omit or misstate it; enforce while reading decoded bytes.

## 6. ModSecurity / Coraza

Enable body access first:

```apache
SecRequestBodyAccess On
SecRequestBodyLimit 8388608
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
```

Long urlencoded parameter key:

```apache
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" \
  "id:10961801,phase:2,deny,status:413,log,chain,msg:'PHP2Shell: oversized urlencoded parameter key'"
  SecRule REQUEST_BODY "@rx (?:^|&)[^&=]{1000,}" "t:none"
```

Multipart field-name length (engine-dependent; validate before production):

```apache
SecRule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" \
  "id:10961802,phase:2,deny,status:413,log,chain,msg:'PHP2Shell: oversized multipart field name'"
  SecRule REQUEST_BODY "@rx name=\"[^\"]{1000,}\"" "t:none"
```

Not every engine exposes a count of headers **inside** a multipart part. If yours does not, use a managed ruleset (Cloudflare/AWS/Fastly/Imperva) or an application-level parser with explicit limits. Do not claim a control you cannot verify.

## 7. Cloudflare

Cloudflare deployed managed protections before disclosure. Verify the ruleset is deployed in block mode:

- Free: Cloudflare Managed Free Ruleset, ID `77454fe2d30c4220b5701f6fdfb893ba`
- Paid: Cloudflare Managed Ruleset, ID `efb7b8c949ac4650a09736fc376e9aee`
- Response firewall default: rule `afffe22785674c80a31875c848d2242a`

Rule descriptions are "Generic Rules - Anomalous Execution - 1..7". Rule IDs differ between free and paid plans; see the Cloudflare blog. Keep WAF on after patching.

## 8. What not to do

- **Do not use `RLIMIT_AS` or `RLIMIT_DATA`.** They cause `mmap()`/allocation failure, which is exactly the path the advisory warns about.
- **Do not treat `memory_limit=-1` as a fix.** It removes the predictable OOM but an underlying allocation failure can still reach the vulnerable `longjmp()`.
- **Do not rely on `post_max_size` alone.** A multipart body without a usable declared length can pass the initial check.
- **Do not rely on `display_errors=Off` or `error_reporting=0`.** The stale-global-state access happens before PHP decides whether to report.
- **Do not put security-critical values in `.user.ini` or `ini_set()`.** They are applied after normal initialization and can be changed by the application.
- **Do not set `max_memory_limit` to a finite value while `memory_limit=-1`.** On PHP 8.5 it caps the `-1` and reintroduces the limit.

## 9. Verification checklist

Run against the web SAPI, after restart:

```bash
php -v
php -i | grep -E 'PHP Version|Build Date|Server API|memory_limit|max_memory_limit|post_max_size|upload_max_filesize|session.upload_progress.enabled|max_input_vars|max_input_nesting_level|max_multipart_body_parts|max_file_uploads|fatal_error_backtraces'
php-fpm -tt 2>&1 | grep -E 'php_admin_value|php_admin_flag|pm.max_requests'
```

Then use `scripts/verify-hardening.sh --from <captured-php-i.txt>` or point it at the FPM binary. For a definitive pool-level check, deploy a temporary authenticated endpoint:

```php
<?php
// Remove immediately after the audit. Never expose publicly.
header('Content-Type: application/json');
$keys = [
    'memory_limit', 'max_memory_limit', 'post_max_size', 'upload_max_filesize',
    'session.upload_progress.enabled', 'max_input_vars', 'max_input_nesting_level',
    'max_multipart_body_parts', 'max_file_uploads', 'fatal_error_backtraces',
    'expose_php', 'log_errors', 'error_log', 'display_errors',
];
$out = ['version' => PHP_VERSION, 'sapi' => PHP_SAPI, 'ini' => []];
foreach ($keys as $k) { $out['ini'][$k] = ini_get($k); }
echo json_encode($out), "\n";
```

Protect it with authentication, bind it to an internal-only vhost, and delete it after the audit.

## 10. Rollback

Keep the original files and a tested rollback before changing production:

```bash
cp -a /etc/php/8.4/fpm/php.ini /etc/php/8.4/fpm/php.ini.bak.$(date +%F)
cp -a /etc/php/8.4/fpm/pool.d/www.conf /etc/php/8.4/fpm/pool.d/www.conf.bak.$(date +%F)
php-fpm -tt
```

If a change breaks uploads or forms, restore the file, run `php-fpm -tt`, restart, and record the exception in the report. Do not leave a broken control in place and call it hardened.
