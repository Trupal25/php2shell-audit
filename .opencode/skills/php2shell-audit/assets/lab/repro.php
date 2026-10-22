<?php
// Harmless endpoint for the request-parsing reproduction.
//
// PHP has already parsed the multipart body before this script runs. The
// script only reports what the parser retained; it does not read uploaded
// files, start arbitrary sessions, execute commands, or write attacker data.
header('Content-Type: application/json');

$out = [
    'probe' => 'lab-reproduction',
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'memory_limit' => ini_get('memory_limit'),
    'post_count' => count($_POST),
    'file_count' => count($_FILES),
    'has_upload_progress_key' => array_key_exists('PHP_SESSION_UPLOAD_PROGRESS', $_POST),
    'session_status' => session_status(),
    'content_type' => $_SERVER['CONTENT_TYPE'] ?? '',
];

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
