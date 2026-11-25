<?php
declare(strict_types=1);
// Tiny dependency-free test runner: php tests/run.php
require __DIR__ . '/../src/bootstrap.php';
require __DIR__ . '/helpers.php';

P2\LogSafe::$capture = true;
$pass = 0; $fail = 0; $failures = [];
function check(bool $cond, string $msg = ''): void { if (!$cond) throw new RuntimeException('assert failed ' . $msg); }
function eq(mixed $a, mixed $b, string $msg = ''): void { if ($a !== $b) throw new RuntimeException("expected " . var_export($b, true) . " got " . var_export($a, true) . " $msg"); }
function raises(string $cls, callable $f, string $msg = ''): void { try { $f(); } catch (Throwable $e) { if ($e instanceof $cls) return; throw $e; } throw new RuntimeException("no $cls raised $msg"); }

$files = glob(__DIR__ . '/r*_*.php');
sort($files);
foreach ($files as $file) {
    $tests = require $file;
    $round = basename($file, '.php');
    foreach ($tests as $name => $fn) {
        try { $fn(); $pass++; }
        catch (Throwable $e) { $fail++; $failures[] = "$round::$name: " . $e->getMessage() . ' @' . basename($e->getFile()) . ':' . $e->getLine(); }
    }
}
echo "rounds: " . count($files) . "  passed: $pass  failed: $fail\n";
foreach ($failures as $f) echo "FAIL $f\n";
exit($fail ? 1 : 0);
