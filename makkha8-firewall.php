<?php
/**
 * Plugin Name: Makkha8 Firewall
 * Description: A lightweight firewall implementing the Eightfold Path approach. Engine and modules are standalone PHP and can run outside WordPress.
 * Version: 0.1.0
 * Author: Generated
 */

if ( ! defined( 'ABSPATH' ) ) {
    // Allow standalone usage: nothing to do when directly loaded in WP-CLI or web
}

// Load engine (standalone, no WP functions inside)
require_once __DIR__ . '/includes/class-makkha8-engine.php';

// Load modules (they are standalone PHP files)
foreach ( glob( __DIR__ . '/includes/*-samma-*.php' ) as $mod_file ) {
    require_once $mod_file;
}

// If running inside WordPress, load admin integration
if ( defined( 'ABSPATH' ) ) {
    require_once __DIR__ . '/admin/class-makkha8-admin.php';
    // Initialize admin hooks
    add_action( 'init', function() {
        $admin = new Makkha8_Admin();
        $admin->init();
    } );
}

// Provide a convenience function to run the engine programmatically
if ( ! function_exists( 'makkha8_firewall_run' ) ) {
    function makkha8_firewall_run( $context = [] ) {
        $engine = new Makkha8_FirewallEngine();

        // register default modules if classes exist
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
        foreach ( $map as $class ) {
            if ( class_exists( $class ) ) {
                $engine->register_module( new $class() );
            }
        }

        $request = isset( $context['request'] ) ? $context['request'] : Makkha8_Request::fromGlobals();
        return $engine->run( $request );
    }
}
