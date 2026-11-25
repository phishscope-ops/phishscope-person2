<?php
declare(strict_types=1);
require __DIR__ . '/../src/bootstrap.php';

use P2\{Api, Config, Scanner, Store};

$cfg = Config::fromEnv();
$headers = [];
foreach ($_SERVER as $k => $v) {
    if (str_starts_with($k, 'HTTP_')) $headers[strtolower(str_replace('_', '-', substr($k, 5)))] = (string)$v;
}
$len = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
header('Content-Type: application/json; charset=utf-8');
if ($len > 15_000_000) { http_response_code(413); echo json_encode(['error' => 'body_too_large']); exit; }
$raw = file_get_contents('php://input') ?: '';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$store = new Store($cfg->dbPath, $cfg->scanTtlSeconds);
$api = new Api($cfg, new Scanner($cfg), $store);
[$status, $body] = $api->handle($_SERVER['REQUEST_METHOD'] ?? 'GET', $path, $headers, $raw, $_SERVER['REMOTE_ADDR'] ?? 'anon');
http_response_code($status);
echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
