<?php
// Quick test runner for Makkha8 scanner (standalone)
define('ABSPATH', dirname(__DIR__, 3) . DIRECTORY_SEPARATOR);
require_once __DIR__ . '/../includes/class-makkha8-scanner.php';

$scanner = new Makkha8_Scanner(ABSPATH);
$results = $scanner->scan();
echo "Found " . count($results) . " suspicious files:\n";
foreach (array_slice($results,0,20) as $r) {
    echo $r['score'] . "\t" . $r['file'] . "\t" . implode(',', $r['reasons']) . "\n";
}
