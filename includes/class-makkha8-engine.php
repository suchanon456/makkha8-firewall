<?php
/**
 * Makkha8 Firewall Engine - ปรับปรุงเพื่อความปลอดภัยและประสิทธิภาพ
 * 
 * @package Makkha8
 * @version 2.0
 */

// กำหนด Constants
define('MAKKHA8_VERSION', '2.0.0');
define('MAKKHA8_MAX_INPUT_SIZE', 1048576); // 1MB
define('MAKKHA8_REQUEST_ID_LENGTH', 32);

/**
 * Class Makkha8_Request - ปรับปรุงความปลอดภัยและการจัดการ Request
 */
class Makkha8_Request {
    public $method;
    public $uri;
    public $path;
    public $query_string;
    public $headers = [];
    public $get = [];
    public $post = [];
    public $body = '';
    public $ip;
    public $cookies = [];
    public $server = [];
    public $request_id;
    public $timestamp;
    public $user = null;
    public $module_results = [];
    
    // Trusted Proxies Configuration
    private static $trusted_proxies = [
        '127.0.0.1',
        '::1',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ];
    
    /**
     * Create Request from Globals (แบบปลอดภัย)
     */
    public static function fromGlobals($config = []) {
        $r = new self();
        
        // ตั้งค่า Trusted Proxies
        if (isset($config['trusted_proxies'])) {
            self::$trusted_proxies = array_merge(self::$trusted_proxies, $config['trusted_proxies']);
        }
        
        // ข้อมูลพื้นฐาน
        $r->request_id = self::generateRequestId();
        $r->timestamp = microtime(true);
        $r->method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $r->uri = self::sanitizeUri($_SERVER['REQUEST_URI'] ?? '/');
        $r->query_string = $_SERVER['QUERY_STRING'] ?? '';
        $r->path = self::extractPath($r->uri);
        
        // Headers (แบบปลอดภัย)
        $r->headers = self::getAllHeadersSecure();
        
        // IP (ป้องกัน Spoofing)
        $r->ip = self::getClientIp($_SERVER, $r->headers);
        
        // Input Data (จำกัดขนาด)
        $r->get = self::sanitizeInput($_GET);
        $r->post = self::sanitizeInput($_POST);
        $r->body = self::getRequestBody();
        $r->cookies = self::sanitizeInput($_COOKIE);
        $r->server = $_SERVER;
        
        return $r;
    }
    
    /**
     * Generate Unique Request ID
     */
    private static function generateRequestId() {
        return bin2hex(random_bytes(self::REQUEST_ID_LENGTH / 2));
    }
    
    /**
     * Sanitize URI (ป้องกัน Injection)
     */
    private static function sanitizeUri($uri) {
        // จำกัดความยาว
        $uri = substr($uri, 0, 4096);
        // ลบ Null Bytes
        $uri = str_replace("\0", '', $uri);
        // URL Decode (แต่ไม่ decode ทั้งหมดเพื่อป้องกันการ bypass)
        return $uri;
    }
    
    /**
     * Extract Path from URI
     */
    private static function extractPath($uri) {
        $parts = parse_url($uri);
        return $parts['path'] ?? '/';
    }
    
    /**
     * Get Client IP (ป้องกัน Spoofing)
     */
    private static function getClientIp($server, $headers) {
        // 1. ใช้ REMOTE_ADDR เป็นหลัก
        $ip = $server['REMOTE_ADDR'] ?? '';
        
        // 2. ถ้า REMOTE_ADDR เป็น Trusted Proxy และมี X-Forwarded-For
        if (self::isTrustedProxy($ip) && !empty($headers['x-forwarded-for'])) {
            $ips = array_map('trim', explode(',', $headers['x-forwarded-for']));
            foreach ($ips as $candidate) {
                if (!self::isTrustedProxy($candidate) && self::isValidIp($candidate)) {
                    return $candidate;
                }
            }
        }
        
        // 3. ตรวจสอบ Real IP (ถ้ามี)
        if (self::isTrustedProxy($ip) && !empty($headers['x-real-ip'])) {
            $real_ip = trim($headers['x-real-ip']);
            if (self::isValidIp($real_ip)) {
                return $real_ip;
            }
        }
        
        return $ip;
    }
    
    /**
     * ตรวจสอบว่าเป็น Trusted Proxy หรือไม่
     */
    private static function isTrustedProxy($ip) {
        if (empty($ip)) return false;
        
        foreach (self::$trusted_proxies as $range) {
            if (self::ipInRange($ip, $range)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * ตรวจสอบ IP ใน CIDR Range
     */
    private static function ipInRange($ip, $range) {
        if (strpos($range, '/') !== false) {
            list($subnet, $mask) = explode('/', $range);
            if (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ipLong = ip2long($ip);
                $subnetLong = ip2long($subnet);
                $maskLong = -1 << (32 - $mask);
                return ($ipLong & $maskLong) == ($subnetLong & $maskLong);
            }
        }
        return $ip === $range;
    }
    
    /**
     * ตรวจสอบว่าเป็น IP ที่ถูกต้อง
     */
    private static function isValidIp($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
    
    /**
     * Get All Headers (แบบปลอดภัย)
     */
    private static function getAllHeadersSecure() {
        $headers = [];
        
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
        } else {
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) === 'HTTP_') {
                    $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                    $headers[$key] = $value;
                }
            }
        }
        
        // Sanitize Headers
        $sanitized = [];
        foreach ($headers as $key => $value) {
            $sanitized[$key] = self::sanitizeHeader($value);
        }
        
        // Convert to lowercase for consistency
        return array_change_key_case($sanitized, CASE_LOWER);
    }
    
    /**
     * Sanitize Header Value
     */
    private static function sanitizeHeader($value) {
        // จำกัดความยาว
        $value = substr($value, 0, 8192);
        // ลบ Control Characters
        return preg_replace('/[\x00-\x1F\x7F]/', '', $value);
    }
    
    /**
     * Get Request Body (จำกัดขนาด)
     */
    private static function getRequestBody() {
        $content_length = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
        
        // ถ้าขนาดเกิน Limit
        if ($content_length > MAKKHA8_MAX_INPUT_SIZE) {
            return '';
        }
        
        $body = file_get_contents('php://input');
        if ($body === false) {
            return '';
        }
        
        // จำกัดขนาด
        if (strlen($body) > MAKKHA8_MAX_INPUT_SIZE) {
            $body = substr($body, 0, MAKKHA8_MAX_INPUT_SIZE);
        }
        
        return $body;
    }
    
    /**
     * Sanitize Input (ป้องกัน XSS และ Injection)
     */
    private static function sanitizeInput($input) {
        if (is_array($input)) {
            $result = [];
            foreach ($input as $key => $value) {
                $key = self::sanitizeInputKey($key);
                $result[$key] = self::sanitizeInput($value);
            }
            return $result;
        }
        
        if (is_string($input)) {
            // จำกัดความยาว
            $input = substr($input, 0, 10000);
            // ลบ Null Bytes
            $input = str_replace("\0", '', $input);
            // HTML Entities (แต่ไม่ decode)
            return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        }
        
        return $input;
    }
    
    /**
     * Sanitize Input Key
     */
    private static function sanitizeInputKey($key) {
        if (is_string($key)) {
            // อนุญาตเฉพาะตัวอักษร, ตัวเลข, ขีดล่าง และขีดกลาง
            return preg_replace('/[^a-zA-Z0-9_\-\.[]]/', '', substr($key, 0, 255));
        }
        return $key;
    }
}

/**
 * Interface Makkha8_Module_Interface (ไม่เปลี่ยนแปลง)
 */
interface Makkha8_Module_Interface {
    public function get_name();
    public function run(Makkha8_Request $request);
}

/**
 * Class Makkha8_FirewallEngine - ปรับปรุงประสิทธิภาพและการจัดการ
 */
class Makkha8_FirewallEngine {
    protected $modules = [];
    protected $results = [];
    protected $config = [];
    protected $storage;
    protected $cache = [];
    protected $metrics = [];
    protected $middlewares = [];
    protected $request_id;
    
    // Default Configuration
    private const DEFAULT_CONFIG = [
        'stop_on_block' => true,
        'enable_cache' => true,
        'cache_ttl' => 300, // 5 minutes
        'enable_metrics' => true,
        'metrics_sample_rate' => 0.1, // 10%
        'log_level' => 'info',
        'max_execution_time' => 5, // seconds
    ];
    
    public function __construct($config = [], $storage = null) {
        $this->config = array_merge(self::DEFAULT_CONFIG, $config);
        $this->storage = $storage ?? new Makkha8_Storage();
        $this->request_id = Makkha8_Request::generateRequestId();
        
        // ตั้งค่า Error Handler
        set_error_handler([$this, 'handleError']);
        set_exception_handler([$this, 'handleException']);
    }
    
    /**
     * Register Module (พร้อม Dependency Injection)
     */
    public function register_module(Makkha8_Module_Interface $module, $priority = 10) {
        $this->modules[$priority][] = $module;
        ksort($this->modules);
        return $this;
    }
    
    /**
     * Register Middleware
     */
    public function register_middleware(callable $middleware, $priority = 10) {
        $this->middlewares[$priority][] = $middleware;
        ksort($this->middlewares);
        return $this;
    }
    
    /**
     * Run Firewall (พร้อม Middleware Support)
     */
    public function run(Makkha8_Request $request = null) {
        $start_time = microtime(true);
        $this->results = [];
        
        // สร้าง Request ถ้ายังไม่มี
        if (!$request) {
            $request = Makkha8_Request::fromGlobals($this->config);
        }
        
        // ตั้งค่า Request ID
        $this->request_id = $request->request_id;
        
        // เตรียม Context
        $context = [
            'request_id' => $this->request_id,
            'start_time' => $start_time,
        ];
        
        try {
            // 1. Run Middlewares (ก่อน)
            $this->runMiddlewares($request, 'before', $context);
            
            // 2. ตรวจสอบ Cache
            $cache_key = $this->getCacheKey($request);
            if ($this->config['enable_cache']) {
                $cached_result = $this->getCachedResult($cache_key);
                if ($cached_result !== false) {
                    $this->results = $cached_result;
                    return $this->results;
                }
            }
            
            // 3. Run Modules
            $this->runModules($request, $context);
            
            // 4. เก็บ Cache
            if ($this->config['enable_cache'] && !$this->is_blocked($this->results)) {
                $this->cacheResult($cache_key, $this->results);
            }
            
            // 5. Run Middlewares (หลัง)
            $this->runMiddlewares($request, 'after', $context);
            
            // 6. เก็บ Metrics
            if ($this->config['enable_metrics']) {
                $this->collectMetrics($request, $start_time);
            }
            
            return $this->results;
            
        } catch (Exception $e) {
            $this->handleException($e);
            return ['error' => $e->getMessage()];
        } finally {
            // บันทึก Log
            $this->logRequest($request, $start_time);
        }
    }
    
    /**
     * Run All Modules
     */
    private function runModules($request, $context) {
        $timeout = $this->config['max_execution_time'];
        $start_time = time();
        
        foreach ($this->modules as $priority => $modules) {
            foreach ($modules as $module) {
                // ตรวจสอบ Timeout
                if ((time() - $start_time) > $timeout) {
                    $this->results['timeout'] = ['error' => 'Execution timeout exceeded'];
                    break 2;
                }
                
                $module_name = $module->get_name();
                
                try {
                    $res = $module->run($request);
                    
                    if ($res !== null && !empty($res)) {
                        $this->results[$module_name] = $res;
                        
                        // ถ้ามีการ Block และตั้งค่าให้หยุด
                        if (!empty($res['block']) && $this->config['stop_on_block']) {
                            break 2;
                        }
                    }
                } catch (Exception $e) {
                    $this->results[$module_name] = [
                        'error' => $e->getMessage(),
                        'trace' => $e->getTraceAsString()
                    ];
                    
                    if ($this->config['stop_on_block']) {
                        break;
                    }
                }
            }
        }
    }
    
    /**
     * Run Middlewares
     */
    private function runMiddlewares($request, $phase, $context) {
        foreach ($this->middlewares as $priority => $middlewares) {
            foreach ($middlewares as $middleware) {
                try {
                    $result = $middleware($request, $phase, $context);
                    if ($result === false) {
                        // Middleware บอกให้หยุด
                        return false;
                    }
                } catch (Exception $e) {
                    // Log แต่ไม่หยุดการทำงาน
                    error_log("Middleware error: " . $e->getMessage());
                }
            }
        }
        return true;
    }
    
    /**
     * ตรวจสอบว่า Request ถูก Block หรือไม่
     */
    public function is_blocked(array $results = null) {
        $results = $results ?? $this->results;
        
        foreach ($results as $mod => $r) {
            if (!empty($r['block']) && $r['block'] === true) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Get Block Reason (ถ้ามี)
     */
    public function get_block_reason(array $results = null) {
        $results = $results ?? $this->results;
        
        foreach ($results as $mod => $r) {
            if (!empty($r['block']) && $r['block'] === true) {
                return $r['reason'] ?? 'Blocked by module: ' . $mod;
            }
        }
        return null;
    }
    
    /**
     * Create Cache Key
     */
    private function getCacheKey($request) {
        $parts = [
            'firewall',
            $request->method,
            $request->path,
            md5($request->ip),
            md5(serialize($request->get)),
            md5(serialize($request->post)),
        ];
        return implode(':', $parts);
    }
    
    /**
     * Get Cached Result
     */
    private function getCachedResult($key) {
        try {
            $data = $this->storage->get('cache:' . $key);
            if ($data !== false && isset($data['results']) && isset($data['expires'])) {
                if (time() < $data['expires']) {
                    return $data['results'];
                }
            }
        } catch (Exception $e) {
            // Ignore cache errors
        }
        return false;
    }
    
    /**
     * Cache Result
     */
    private function cacheResult($key, $results) {
        try {
            $data = [
                'results' => $results,
                'expires' => time() + $this->config['cache_ttl'],
            ];
            $this->storage->set('cache:' . $key, $data, $this->config['cache_ttl']);
        } catch (Exception $e) {
            // Ignore cache errors
        }
    }
    
    /**
     * Collect Metrics
     */
    private function collectMetrics($request, $start_time) {
        // Sample Rate
        if (mt_rand(1, 100) > ($this->config['metrics_sample_rate'] * 100)) {
            return;
        }
        
        $duration = microtime(true) - $start_time;
        $memory = memory_get_peak_usage();
        
        $metrics = [
            'request_id' => $this->request_id,
            'timestamp' => time(),
            'duration' => round($duration, 4),
            'memory' => $memory,
            'method' => $request->method,
            'path' => $request->path,
            'ip' => $request->ip,
            'blocked' => $this->is_blocked(),
            'modules' => array_keys($this->results),
        ];
        
        try {
            $this->storage->lpush('metrics', json_encode($metrics));
            $this->storage->ltrim('metrics', 0, 9999); // เก็บ 10000 รายการ
        } catch (Exception $e) {
            // Ignore metrics errors
        }
    }
    
    /**
     * Log Request
     */
    private function logRequest($request, $start_time) {
        $duration = round(microtime(true) - $start_time, 4);
        $blocked = $this->is_blocked() ? 'BLOCKED' : 'ALLOWED';
        $reason = $this->get_block_reason() ?: '-';
        
        $log_entry = sprintf(
            "[%s] %s | REQ: %s | IP: %s | METHOD: %s | URI: %s | STATUS: %s | REASON: %s | DURATION: %.4fs\n",
            date('Y-m-d H:i:s'),
            $blocked,
            $this->request_id,
            $request->ip,
            $request->method,
            substr($request->uri, 0, 200),
            $blocked,
            $reason,
            $duration
        );
        
        error_log($log_entry, 3, '/var/log/makkha8_engine.log');
    }
    
    /**
     * Error Handler
     */
    public function handleError($errno, $errstr, $errfile, $errline) {
        if (!(error_reporting() & $errno)) {
            return false;
        }
        
        $log = sprintf(
            "[ERROR] %s: %s in %s:%d\n",
            $this->getErrorName($errno),
            $errstr,
            $errfile,
            $errline
        );
        
        error_log($log, 3, '/var/log/makkha8_error.log');
        return true;
    }
    
    /**
     * Exception Handler
     */
    public function handleException($e) {
        $log = sprintf(
            "[EXCEPTION] %s: %s in %s:%d\nTrace: %s\n",
            get_class($e),
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
            $e->getTraceAsString()
        );
        
        error_log($log, 3, '/var/log/makkha8_exception.log');
    }
    
    /**
     * Get Error Name
     */
    private function getErrorName($errno) {
        $names = [
            E_ERROR => 'Fatal Error',
            E_WARNING => 'Warning',
            E_PARSE => 'Parse Error',
            E_NOTICE => 'Notice',
            E_CORE_ERROR => 'Core Error',
            E_CORE_WARNING => 'Core Warning',
            E_COMPILE_ERROR => 'Compile Error',
            E_COMPILE_WARNING => 'Compile Warning',
            E_USER_ERROR => 'User Error',
            E_USER_WARNING => 'User Warning',
            E_USER_NOTICE => 'User Notice',
            E_STRICT => 'Strict',
            E_RECOVERABLE_ERROR => 'Recoverable Error',
            E_DEPRECATED => 'Deprecated',
            E_USER_DEPRECATED => 'User Deprecated',
        ];
        return $names[$errno] ?? "Unknown Error ($errno)";
    }
    
    /**
     * ฟังก์ชันเพิ่มเติม: Get Statistics
     */
    public function getStats() {
        return [
            'version' => MAKKHA8_VERSION,
            'modules' => count($this->modules),
            'middlewares' => count($this->middlewares),
            'config' => $this->config,
            'requests_processed' => $this->storage->get('stats:requests') ?? 0,
            'blocks' => $this->storage->get('stats:blocks') ?? 0,
        ];
    }
    
    /**
     * ฟังก์ชันเพิ่มเติม: Increment Stats
     */
    private function incrementStat($key) {
        try {
            $this->storage->increment($key);
        } catch (Exception $e) {
            // Ignore
        }
    }
}

/**
 * Class Makkha8_Storage - ปรับปรุงความปลอดภัยและประสิทธิภาพ
 */
class Makkha8_Storage {
    private $storage_dir;
    private $use_redis = false;
    private $redis = null;
    private $cache = [];
    private $cache_ttl = 60;
    
    public function __construct($config = []) {
        $this->storage_dir = $config['storage_dir'] ?? dirname(__DIR__) . '/storage';
        $this->ensureStorageDirectory();
        
        // รองรับ Redis
        if (!empty($config['redis'])) {
            try {
                $this->redis = new Redis();
                $this->redis->connect(
                    $config['redis']['host'] ?? '127.0.0.1',
                    $config['redis']['port'] ?? 6379
                );
                if (!empty($config['redis']['password'])) {
                    $this->redis->auth($config['redis']['password']);
                }
                $this->use_redis = true;
            } catch (Exception $e) {
                error_log("Redis connection failed: " . $e->getMessage());
                $this->use_redis = false;
            }
        }
    }
    
    /**
     * Get Value from Storage
     */
    public function get($key) {
        // Check Memory Cache
        if (isset($this->cache[$key])) {
            $cached = $this->cache[$key];
            if (time() < $cached['expires']) {
                return $cached['value'];
            }
            unset($this->cache[$key]);
        }
        
        // Redis
        if ($this->use_redis) {
            try {
                $data = $this->redis->get($key);
                if ($data !== false) {
                    $decoded = json_decode($data, true);
                    if (is_array($decoded)) {
                        $this->cache[$key] = [
                            'value' => $decoded,
                            'expires' => time() + $this->cache_ttl
                        ];
                        return $decoded;
                    }
                }
                return false;
            } catch (Exception $e) {
                // Fallback to file
            }
        }
        
        // File-based
        return $this->getFromFile($key);
    }
    
    /**
     * Set Value to Storage
     */
    public function set($key, $value, $ttl = 0) {
        // Update Memory Cache
        $this->cache[$key] = [
            'value' => $value,
            'expires' => time() + ($ttl > 0 ? $ttl : 3600)
        ];
        
        // Redis
        if ($this->use_redis) {
            try {
                $data = json_encode($value);
                if ($ttl > 0) {
                    return $this->redis->setex($key, $ttl, $data);
                } else {
                    return $this->redis->set($key, $data);
                }
            } catch (Exception $e) {
                // Fallback to file
            }
        }
        
        // File-based
        return $this->setToFile($key, $value, $ttl);
    }
    
    /**
     * Delete Value
     */
    public function delete($key) {
        unset($this->cache[$key]);
        
        if ($this->use_redis) {
            try {
                return $this->redis->del($key) > 0;
            } catch (Exception $e) {
                // Fallback
            }
        }
        
        $file = $this->getStorageFile($key);
        if (file_exists($file)) {
            return @unlink($file);
        }
        return false;
    }
    
    /**
     * Increment Value
     */
    public function increment($key, $by = 1) {
        if ($this->use_redis) {
            try {
                return $this->redis->incrBy($key, $by);
            } catch (Exception $e) {
                // Fallback
            }
        }
        
        // File-based increment
        $value = $this->get($key);
        if ($value === false) {
            $value = 0;
        }
        $value += $by;
        $this->set($key, $value);
        return $value;
    }
    
    /**
     * List Operations (สำหรับ Metrics)
     */
    public function lpush($key, $value) {
        if ($this->use_redis) {
            try {
                return $this->redis->lPush($key, $value);
            } catch (Exception $e) {
                // Fallback
            }
        }
        return false;
    }
    
    public function ltrim($key, $start, $stop) {
        if ($this->use_redis) {
            try {
                return $this->redis->lTrim($key, $start, $stop);
            } catch (Exception $e) {
                // Fallback
            }
        }
        return false;
    }
    
    /**
     * File-based Storage (แบบปลอดภัย)
     */
    private function getFromFile($key) {
        $file = $this->getStorageFile($key);
        if (!file_exists($file)) {
            return false;
        }
        
        // ใช้ Lock เพื่อป้องกัน Race Condition
        $handle = fopen($file, 'r');
        if (!$handle) {
            return false;
        }
        
        if (!flock($handle, LOCK_SH)) {
            fclose($handle);
            return false;
        }
        
        $json = fread($handle, filesize($file));
        flock($handle, LOCK_UN);
        fclose($handle);
        
        if ($json === false) {
            return false;
        }
        
        $data = json_decode($json, true);
        if (!is_array($data) || !isset($data['expires']) || !array_key_exists('value', $data)) {
            return false;
        }
        
        // ตรวจสอบ Expiration
        if ($data['expires'] !== 0 && time() > $data['expires']) {
            @unlink($file);
            return false;
        }
        
        // เก็บใน Memory Cache
        $this->cache[$key] = [
            'value' => $data['value'],
            'expires' => time() + $this->cache_ttl
        ];
        
        return $data['value'];
    }
    
    private function setToFile($key, $value, $ttl) {
        $file = $this->getStorageFile($key);
        $data = [
            'expires' => $ttl > 0 ? time() + $ttl : 0,
            'value' => $value,
        ];
        
        $json = json_encode($data);
        $tempFile = $file . '.tmp';
        
        // เขียนไฟล์ชั่วคราว
        if (file_put_contents($tempFile, $json) === false) {
            return false;
        }
        
        // ใช้ Lock เพื่อป้องกัน Race Condition
        $handle = fopen($file, 'c');
        if (!$handle) {
            @unlink($tempFile);
            return false;
        }
        
        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            @unlink($tempFile);
            return false;
        }
        
        // Rename (Atomic)
        if (!@rename($tempFile, $file)) {
            @unlink($tempFile);
            flock($handle, LOCK_UN);
            fclose($handle);
            return false;
        }
        
        flock($handle, LOCK_UN);
        fclose($handle);
        
        return true;
    }
    
    /**
     * Get Storage File Path (แบบปลอดภัย)
     */
    private function getStorageFile($key) {
        $safe_key = preg_replace('/[^A-Za-z0-9_-]/', '_', $key);
        return $this->storage_dir . DIRECTORY_SEPARATOR . $safe_key . '.json';
    }
    
    /**
     * Ensure Storage Directory (พร้อม Protection)
     */
    private function ensureStorageDirectory() {
        if (!is_dir($this->storage_dir)) {
            if (!@mkdir($this->storage_dir, 0755, true)) {
                $this->storage_dir = sys_get_temp_dir() . '/makkha8-storage';
                if (!is_dir($this->storage_dir)) {
                    @mkdir($this->storage_dir, 0755, true);
                }
            }
        }
        
        // สร้าง .htaccess เพื่อป้องกันการเข้าถึง
        $htaccess = $this->storage_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "Deny from all\n");
        }
        
        // สร้าง index.html
        $index = $this->storage_dir . '/index.html';
        if (!file_exists($index)) {
            file_put_contents($index, '');
        }
    }
}

/**
 * ฟังก์ชันช่วยเหลือ (ใช้งานง่าย)
 */
function makkha8_run() {
    static $engine = null;
    
    if ($engine === null) {
        $config = [
            'storage_dir' => __DIR__ . '/../storage',
            'enable_cache' => true,
            'cache_ttl' => 300,
        ];
        $engine = new Makkha8_FirewallEngine($config);
    }
    
    $request = Makkha8_Request::fromGlobals();
    $result = $engine->run($request);
    
    if ($engine->is_blocked($result)) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'forbidden',
            'reason' => $engine->get_block_reason($result),
            'request_id' => $request->request_id
        ]);
        exit;
    }
    
    return $result;
}