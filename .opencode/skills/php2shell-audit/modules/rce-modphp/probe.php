<?php
// Minimal read-only endpoint for validating the audit skill.
// It intentionally does not process uploads or accept arbitrary input.
header('Content-Type: application/json');

$keys = [
    'memory_limit',
    'max_memory_limit',
    'post_max_size',
    'upload_max_filesize',
    'session.upload_progress.enabled',
    'max_input_vars',
    'max_input_nesting_level',
    'max_multipart_body_parts',
    'max_file_uploads',
    'fatal_error_backtraces',
    'expose_php',
    'display_errors',
    'log_errors',
];

$out = [
    'version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'build_date' => php_uname('v'),
    'ini' => [],
];

foreach ($keys as $key) {
    $out['ini'][$key] = ini_get($key);
}

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
