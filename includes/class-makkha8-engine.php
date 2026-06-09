<?php
// Standalone Firewall Engine: no WordPress functions used here

class Makkha8_Request {
    public $method;
    public $uri;
    public $headers = [];
    public $get = [];
    public $post = [];
    public $body = '';
    public $ip;
    public $cookies = [];
    public $server = [];

    public static function fromGlobals() {
        $r = new self();
        $r->method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $r->uri = ($_SERVER['REQUEST_URI'] ?? '') . (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING'] ? ('?' . $_SERVER['QUERY_STRING']) : '');
        $r->get = $_GET;
        $r->post = $_POST;
        $r->body = file_get_contents('php://input');
        $r->cookies = $_COOKIE;
        $r->server = $_SERVER;
        $r->ip = $_SERVER['REMOTE_ADDR'] ?? ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        $r->headers = self::getAllHeaders();
        return $r;
    }

    public static function getAllHeaders() {
        if ( function_exists('getallheaders') ) {
            return getallheaders();
        }
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }
}

interface Makkha8_Module_Interface {
    public function get_name();
    public function run(Makkha8_Request $request);
}

class Makkha8_FirewallEngine {
    protected $modules = [];
    protected $results = [];

    public function register_module(Makkha8_Module_Interface $module) {
        $this->modules[] = $module;
    }

    public function run(Makkha8_Request $request = null) {
        if ( ! $request ) {
            $request = Makkha8_Request::fromGlobals();
        }
        $this->results = [];
        foreach ($this->modules as $module) {
            try {
                $res = $module->run($request);
                if ( $res ) {
                    $this->results[$module->get_name()] = $res;
                    if ( ! empty( $res['block'] ) ) {
                        break;
                    }
                }
            } catch (Exception $e) {
                $this->results[$module->get_name()] = ['error' => $e->getMessage()];
            }
        }
        return $this->results;
    }

    public function is_blocked(array $results) {
        foreach ($results as $mod => $r) {
            if (!empty($r['block']) && $r['block']) return true;
        }
        return false;
    }
}

class Makkha8_Storage {
    public static function get($key) {
        if (function_exists('get_transient')) {
            return get_transient($key);
        }

        $file = self::get_storage_file($key);
        if (!is_file($file)) {
            return false;
        }

        $json = file_get_contents($file);
        if ($json === false) {
            return false;
        }

        $data = json_decode($json, true);
        if (!is_array($data) || !isset($data['expires']) || !array_key_exists('value', $data)) {
            return false;
        }

        if ($data['expires'] !== 0 && time() > $data['expires']) {
            @unlink($file);
            return false;
        }

        return $data['value'];
    }

    public static function set($key, $value, $ttl = 0) {
        if (function_exists('set_transient')) {
            return set_transient($key, $value, $ttl);
        }

        $file = self::get_storage_file($key);
        $data = [
            'expires' => $ttl > 0 ? time() + $ttl : 0,
            'value' => $value,
        ];

        return file_put_contents($file, json_encode($data)) !== false;
    }

    protected static function get_storage_file($key) {
        $dir = self::get_storage_dir();
        $safe_key = preg_replace('/[^A-Za-z0-9_-]/', '_', $key);
        return $dir . DIRECTORY_SEPARATOR . 'makkha8-' . $safe_key . '.json';
    }

    protected static function get_storage_dir() {
        $dir = dirname(__DIR__) . '/storage';
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        return $dir;
    }
}
