<?php
/**
 * Plugin Name:       Makkha8 Firewall
 * Plugin URI:        https://github.com/suchanon456/makkha8-firewall
 * Description:       A lightweight firewall implementing the Eightfold Path approach. Engine and modules are standalone PHP and can run outside WordPress.
 * Version:           0.1.1
 * Author:            Suchanon
 * Author URI:        https://github.com/suchanon456
 * Text Domain:       makkha8-firewall
 * Requires at least: 5.0
 * Requires PHP:      7.4
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly - for WP. For standalone, remove this line.
}

// Define constants
define('MAKKHA8_FIREWALL_VERSION', '0.1.1');
define('MAKKHA8_FIREWALL_PATH', __DIR__);
define('MAKKHA8_FIREWALL_URL', plugin_dir_url(__FILE__));

// --- Safe loader ---
function makkha8_safe_require($relative_path) {
    $full = MAKKHA8_FIREWALL_PATH . $relative_path;
    if (file_exists($full)) {
        require_once $full;
        return true;
    } else {
        error_log("[Makkha8 Firewall] Missing file: $relative_path");
        return false;
    }
}

// 1. Load engine
$has_engine = makkha8_safe_require('/includes/class-makkha8-engine.php');
$has_request = makkha8_safe_require('/includes/class-makkha8-request.php');

// 2. Load modules (Samma-*)
foreach (glob(MAKKHA8_FIREWALL_PATH . '/includes/*-samma-*.php') as $mod_file) {
    if (file_exists($mod_file)) {
        require_once $mod_file;
    }
}

// 3. Load admin only if in WP admin and file exists
if (is_admin()) {
    $has_admin = makkha8_safe_require('/admin/class-makkha8-admin.php');
    if ($has_admin && class_exists('Makkha8_Admin')) {
        add_action('plugins_loaded', function() {
            $admin = new Makkha8_Admin();
            if (method_exists($admin, 'init')) {
                $admin->init();
            }
        });
    }
}

// 4. Convenience function
if (!function_exists('makkha8_firewall_run')) {
    function makkha8_firewall_run($context = []) {
        if (!class_exists('Makkha8_FirewallEngine')) {
            return new WP_Error('missing_engine', 'Makkha8_FirewallEngine class not found. Check /includes folder.');
        }

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
        foreach ($map as $class) {
            if (class_exists($class)) {
                $engine->register_module(new $class());
            }
        }

        if (isset($context['request'])) {
            $request = $context['request'];
        } elseif (class_exists('Makkha8_Request') && method_exists('Makkha8_Request', 'fromGlobals')) {
            $request = Makkha8_Request::fromGlobals();
        } else {
            $request = $_REQUEST;
        }

        return $engine->run($request);
    }
}

// Activation hook - to catch errors early
register_activation_hook(__FILE__, function() {
    // Check PHP version
    if (version_compare(PHP_VERSION, '7.4', '<')) {
        wp_die('Makkha8 Firewall requires PHP 7.4 or higher.');
    }
    // Create storage folder if needed
    $storage = MAKKHA8_FIREWALL_PATH . '/storage';
    if (!file_exists($storage)) {
        @mkdir($storage, 0755, true);
    }
});
