<?php
// Standalone bootstrap for early auto_prepend use.
// This file is intended to be referenced by auto_prepend_file and must use pure PHP only.

// Resolve plugin root and includes
$plugin_root = dirname(__DIR__, 2);
require_once $plugin_root . '/includes/class-makkha8-engine.php';
foreach (glob($plugin_root . '/includes/*-samma-*.php') as $f) {
    @include_once $f;
}

try {
    $request = Makkha8_Request::fromGlobals();
    $engine = new Makkha8_FirewallEngine();
    $map = [
        'Makkha8_Samma_Ditthi',
        'Makkha8_Samma_Sankappa',
        'Makkha8_Samma_Vaca',
        'Makkha8_Samma_Kammanta',
        'Makkha8_Samma_Ajiva',
        'Makkha8_Samma_Vayama',
        'Makkha8_Samma_Sati',
        'Makkha8_Samma_Samadhi',
    ];
    foreach ($map as $c) {
        if (class_exists($c)) $engine->register_module(new $c());
    }
    $results = $engine->run($request);
    if ($engine->is_blocked($results)) {
        // Early block: send minimal 403 and stop further processing
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "403 Forbidden - blocked by Makkha8 Firewall";
        exit;
    }
} catch (Throwable $e) {
    // Fail open: do not stop site if bootstrap errors, but log to error log
    error_log('Makkha8 early bootstrap error: ' . $e->getMessage());
}
