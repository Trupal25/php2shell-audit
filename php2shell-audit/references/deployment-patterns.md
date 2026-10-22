# Deployment fingerprints — classify fast under ambiguity

Use this when the target's stack is not documented. Work from the least intrusive signal to the most definitive. Stop as soon as the SAPI + version is proven; do not keep fingerprinting for its own sake.

## 1. Decision tree

```text
Can you read the host/container/registry directly?
├─ yes → triage.sh --local / --host / --hosts; read PHP_VERSION + SAPI
└─ no
   ├─ Is there an authenticated inventory/CMDB/panel? → use it
   ├─ Is there a container image or CI config? → inspect tags/digests
   └─ Only HTTP is available
      ├─ X-Powered-By: PHP/x.y.z        → hint (may be spoofed/stripped)
      ├─ Server: Apache + php_module    → mod_php (P0)
      ├─ Server: nginx + fastcgi_pass   → FPM (P1)
      ├─ Server: Caddy + FrankenPHP     → FrankenPHP (P0)
      ├─ Server: LiteSpeed + lsphp      → LSAPI (P1)
      └─ none of the above              → unknown; assume affected
```

**Rule:** one authenticated `php -v` outranks any number of HTTP fingerprints. If you cannot get it, label the asset `unknown` and treat it as affected.

## 2. HTTP hints (non-intrusive)

```bash
curl -sSI https://target/ | grep -iE '^(server|x-powered-by|set-cookie):'
curl -sS  https://target/ | grep -iE 'PHPSESSID|\.php'
```

| Signal | Reading |
|---|---|
| `X-Powered-By: PHP/8.4.26` | Version hint. Confirm; can be spoofed or removed via `expose_php=Off`. |
| `Server: Apache/2.4.x` + `X-Powered-By: PHP/...` | Likely mod_php or `mod_proxy_fcgi`. Check `apachectl -M` if you have access. |
| `Server: nginx` + `X-Powered-By: PHP/...` | Likely FPM behind nginx. |
| `Server: Caddy` + PHP behavior | Possibly FrankenPHP; check the process/image. |
| `Server: LiteSpeed` | LSAPI; check `lsphp` version. |
| `Set-Cookie: PHPSESSID=...` | PHP session in use; not a version proof. |
| `Server` only, no `X-Powered-By` | `expose_php=Off` or a proxy stripped it; do not conclude "not PHP". |

phpinfo exposure is a separate finding; check it only if the lab scope includes it. Do not turn it into a broad content-discovery scan.

## 3. Containers and Kubernetes

```bash
# Running containers and image tags
docker ps --format '{{.Names}}\t{{.Image}}'

# Image digest (immutable) and config
docker inspect --format '{{.Name}} {{.Config.Image}} {{.Image}}' <container>

# Kubernetes workloads
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'
kubectl get deploy,sts,ds -A -o yaml | grep -E '^\s+image:'
```

High-yield image names:

| Image pattern | SAPI | Audit note |
|---|---|---|
| `php:8.4-apache`, `php:8.4.x-apache` | mod_php | P0 if below gate |
| `php:8.4-fpm`, `php:8.4.x-fpm` | FPM | P1 |
| `frankenphp` / `dunglas/frankenphp` | FrankenPHP | P0 |
| `serversideup/php:*-fpm-*` | FPM | P1 |
| `serversideup/php:*-apache-*` | mod_php | P0 |
| `wordpress:php8.4-apache` | mod_php | P0 |
| `wordpress:php8.4-fpm` | FPM | P1 |
| `drupal:php8.4-apache` | mod_php | P0 |
| `joomla:php8.4-apache` | mod_php | P0 |
| `bitnami/php-fpm` | FPM | P1 |
| `litespeedtech/litespeed` | LSAPI | P1 |

Floating tags (`php:8.4-apache`) rebuild to the latest patch, but a cached image may still be old. Check the digest and rebuild timestamp. Do not trust the tag.

## 4. CI and build config

```bash
rg -n 'php-version|php:|setup-php|FROM php' .github .gitlab-ci.yml Dockerfile* docker-compose*.yml 2>/dev/null
rg -n '"platform"\s*:\s*\{' composer.json 2>/dev/null
```

| Pattern | Meaning |
|---|---|
| `shivammathur/setup-php` with `php-version: '8.4'` | Resolves latest 8.4 at run time; pass only if the runner is current. Pin exact for reproducibility. |
| `FROM php:8.4-apache` | Floating; rebuild to pick up the patch. |
| `FROM php:8.4.26-apache` | Pinned vulnerable; fail the gate. |
| `composer.json` `config.platform.php` | Dependency-resolution pin, **not** the runtime version. Do not use it as runtime proof. |
| `php:8.4` in a matrix | Each job may resolve a different patch; check the job log. |

CI gate:

```bash
# Fail if the runtime is below the branch gate.
php -r '$v=PHP_VERSION; $g=["8.2"=>"8.2.35","8.3"=>"8.3.36","8.4"=>"8.4.27","8.5"=>"8.5.12"][implode(".",array_slice(explode(".",$v),0,2))]??null; exit($g===null||version_compare($v,$g,"<")?1:0);'
```

## 5. Hosting panels and shared hosting

| Panel | Check |
|---|---|
| cPanel/WHM | `whmapi1 php_get_installed_versions`; `ea-php84 -v`; per-vhost PHP handler in `php-fpm` pools |
| Plesk | `plesk php -v`; `plesk bin php_handler --list` |
| RunCloud / Cloudways | Panel PHP version per app; FPM pool overrides |
| Shared hosting | Version often hidden. Ask the provider; do not assume the site's `X-Powered-By`. |

Legacy handlers to look for: `mod_php`, `mod_fcgid`, `suphp`, `php-cgi`, `lsphp`. All are patch targets; mod_php and FrankenPHP get P0.

## 6. Fast evidence set

For each asset, capture only these before moving on:

```text
asset, environment, owner
sapi (mod_php | fpm | frankenphp | lsapi | cgi | cli | unknown)
php_version + build_date (web SAPI)
patched_min for the branch
exposure (internet | partner | internal | local)
one config line per interim control (or "not set")
one edge probe result (optional)
```

Then run `triage.sh --json` and feed the records to `report.py`. Do not spend time on a full CMDB reconciliation before reporting the first P0.
