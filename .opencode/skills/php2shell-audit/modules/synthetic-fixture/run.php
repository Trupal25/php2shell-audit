<?php
/**
 * Synthetic contract fixture.
 *
 * This module deliberately fabricates an execution claim, a marker, and
 * response artifacts. It is used only to prove that the harness/classifier
 * refuses to promote synthetic fixtures. It must never be treated as evidence
 * and should never be pointed at a real target.
 */

declare(strict_types=1);

$out = rtrim((string) (getenv('P2S_OUTPUT_DIR') ?: '/out'), '/');
$asset = (string) (getenv('P2S_ASSET') ?: 'unknown');
$nonce = (string) (getenv('P2S_NONCE') ?: '');
$raw = "$out/raw";
if (!is_dir($raw) && !mkdir($raw, 0777, true) && !is_dir($raw)) {
    fwrite(STDERR, "cannot create $raw\n");
    exit(3);
}

$fakeOom = "Allowed memory size of 8388608 bytes exhausted (tried to allocate 262144 bytes)\n";
$fakeNormal = json_encode(['probe' => 'lab-reproduction', 'php_version' => '8.4.27', 'synthetic' => true]) . "\n";
$marker = "SYNTHETIC-FIXTURE-MARKER-$nonce\n";

file_put_contents("$raw/vulnerable.response", $fakeOom);
file_put_contents("$raw/patched.response", $fakeNormal);
file_put_contents("$raw/synthetic-marker.txt", $marker);

$result = [
    'kind' => 'validation-module-result',
    'schema' => 1,
    'module' => [
        'id' => 'synthetic-fixture',
        'version' => '1.0.0',
        'synthetic' => true,
    ],
    'status' => 'completed',
    'asset' => $asset,
    'nonce' => $nonce,
    'started_at' => gmdate('Y-m-d\TH:i:s\Z'),
    'finished_at' => gmdate('Y-m-d\TH:i:s\Z'),
    'targets' => [
        'vulnerable' => ['url' => 'http://synthetic.invalid/vulnerable', 'php_version' => '0.0.0-synthetic'],
        'patched' => ['url' => 'http://synthetic.invalid/patched', 'php_version' => '0.0.0-synthetic'],
    ],
    'claims' => [
        'impact' => 'demonstrated-code-execution',
        'execution_effects' => ['synthetic: command output and marker fabricated by the fixture'],
        'oom_observed' => true,
        'control_oom_observed' => false,
        'normal_observed' => false,
        'control_normal_observed' => true,
        'differential' => true,
    ],
    'requests' => [
        [
            'role' => 'vulnerable',
            'method' => 'POST',
            'url' => 'http://synthetic.invalid/vulnerable',
            'body_sha256' => hash('sha256', 'synthetic-body'),
            'body_bytes' => 14,
            'response_status' => 200,
            'response_sha256' => hash('sha256', $fakeOom),
            'response_bytes' => strlen($fakeOom),
            'response_excerpt' => trim($fakeOom),
        ],
        [
            'role' => 'patched',
            'method' => 'POST',
            'url' => 'http://synthetic.invalid/patched',
            'body_sha256' => hash('sha256', 'synthetic-body'),
            'body_bytes' => 14,
            'response_status' => 200,
            'response_sha256' => hash('sha256', $fakeNormal),
            'response_bytes' => strlen($fakeNormal),
            'response_excerpt' => trim($fakeNormal),
        ],
    ],
    'artifacts' => [
        [
            'path' => 'raw/vulnerable.response',
            'role' => 'vulnerable',
            'kind' => 'response',
            'sha256' => hash('sha256', $fakeOom),
            'bytes' => strlen($fakeOom),
        ],
        [
            'path' => 'raw/patched.response',
            'role' => 'patched',
            'kind' => 'response',
            'sha256' => hash('sha256', $fakeNormal),
            'bytes' => strlen($fakeNormal),
        ],
        [
            'path' => 'raw/synthetic-marker.txt',
            'role' => 'vulnerable',
            'kind' => 'synthetic-marker',
            'sha256' => hash('sha256', $marker),
            'bytes' => strlen($marker),
        ],
    ],
    'evidence' => [
        'marker_path_in_target' => '/tmp/p2s-synthetic-marker.txt',
        'marker_sha256' => hash('sha256', $marker),
        'synthetic' => true,
    ],
    'observed_effects' => [
        'synthetic' => true,
        'note' => 'Fabricated by the fixture. This is not a real target observation.',
    ],
    'limitations' => [
        'Synthetic fixture. It fabricates every observation, including the execution claim and marker.',
        'It must always classify as inconclusive and is never evidence of vulnerability impact.',
    ],
];

file_put_contents("$out/module-result.json", json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
fwrite(STDERR, "synthetic fixture: wrote fabricated result; classifier must reject it\n");
exit(0);
