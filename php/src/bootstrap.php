<?php
declare(strict_types=1);
spl_autoload_register(function (string $class): void {
    if (!str_starts_with($class, 'P2\\')) return;
    $name = substr($class, 3);
    // several small classes live in the file of their main class
    $map = ['BadUrl' => 'U', 'SsrfBlocked' => 'Ssrf', 'FetchError' => 'Fetcher', 'Hop' => 'Fetcher', 'Trace' => 'Fetcher',
        'IntelResult' => 'Intel', 'LocalBlocklist' => 'Intel', 'VirusTotal' => 'Intel', 'IntelHub' => 'Intel', 'Http' => 'Intel',
        'EngineResult' => 'Engines', 'Judgement' => 'Verdict'];
    $file = __DIR__ . '/' . ($map[$name] ?? $name) . '.php';
    if (is_file($file)) require_once $file;
});
