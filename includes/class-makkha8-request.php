<?php
// Stub file - class Makkha8_Request is now defined in class-makkha8-engine.php
// This file exists only to satisfy file_exists check in makkha8-firewall.php
if (!class_exists('Makkha8_Request') && file_exists(__DIR__ . '/class-makkha8-engine.php')) {
    // Fallback, normally engine already loaded
    require_once __DIR__ . '/class-makkha8-engine.php';
}
