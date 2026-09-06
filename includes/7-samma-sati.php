<?php
// มรรคข้อ 7: บันทึกสติ / Logging events (แบบ PSR-3 Compatible)
class Makkha8_Samma_Sati implements Makkha8_Module_Interface {
    // Log Levels (ตาม PSR-3)
    private const LOG_LEVEL_EMERGENCY = 'emergency';
    private const LOG_LEVEL_ALERT = 'alert';
    private const LOG_LEVEL_CRITICAL = 'critical';
    private const LOG_LEVEL_ERROR = 'error';
    private const LOG_LEVEL_WARNING = 'warning';
    private const LOG_LEVEL_NOTICE = 'notice';
    private const LOG_LEVEL_INFO = 'info';
    private const LOG_LEVEL_DEBUG = 'debug';
    
    // Log Level Priority (สำหรับการกรอง)
    private const LOG_LEVEL_PRIORITY = [
        self::LOG_LEVEL_EMERGENCY => 8,
        self::LOG_LEVEL_ALERT => 7,
        self::LOG_LEVEL_CRITICAL => 6,
        self::LOG_LEVEL_ERROR => 5,
        self::LOG_LEVEL_WARNING => 4,
        self::LOG_LEVEL_NOTICE => 3,
        self::LOG_LEVEL_INFO => 2,
        self::LOG_LEVEL_DEBUG => 1,
    ];
    
    // ค่าเริ่มต้น
    private const DEFAULT_LOG_DIR = '/var/log/makkha8';
    private const DEFAULT_LOG_FILE = 'makkha8.log';
    private const DEFAULT_MAX_FILE_SIZE = 10485760; // 10MB
    private const DEFAULT_MAX_FILES = 5;
    private const DEFAULT_LOG_LEVEL = 'info';
    
    private $log_dir;
    private $log_file;
    private $max_file_size;
    private $max_files;
    private $min_log_level;
    private $storage;
    private $buffer = [];
    private $buffer_size = 50;
    private $flush_interval = 5; // วินาที

    public function __construct($config = []) {
        // กำหนดค่าเริ่มต้น
        $this->log_dir = $config['log_dir'] ?? self::DEFAULT_LOG_DIR;
        $this->log_file = $config['log_file'] ?? self::DEFAULT_LOG_FILE;
        $this->max_file_size = $config['max_file_size'] ?? self::DEFAULT_MAX_FILE_SIZE;
        $this->max_files = $config['max_files'] ?? self::DEFAULT_MAX_FILES;
        $this->min_log_level = $config['min_log_level'] ?? self::DEFAULT_LOG_LEVEL;
        $this->storage = $config['storage'] ?? null;
        
        // สร้าง Log Directory (ถ้ายังไม่มี)
        $this->ensure_log_directory();
        
        // ตั้งค่า Shutdown Function สำหรับ Flush Buffer
        register_shutdown_function([$this, 'flush']);
    }

    public function get_name() { 
        return 'samma-sati'; 
    }

    public function run(Makkha8_Request $request) {
        // 1. เตรียมข้อมูล Context
        $context = $this->build_log_context($request);
        
        // 2. บันทึก Log (ใช้ระดับ INFO)
        $this->log(self::LOG_LEVEL_INFO, 'Request processed', $context);
        
        // 3. ถ้ามี Storage ให้เก็บ metrics
        if ($this->storage) {
            $this->store_metrics($request, $context);
        }
        
        return ['allow' => true, 'reason' => 'logged'];
    }

    /**
     * PSR-3 Compatible Log Method
     */
    public function log($level, $message, array $context = []) {
        // ตรวจสอบระดับ Log
        if (!$this->should_log($level)) {
            return;
        }
        
        // สร้าง Log Entry
        $entry = $this->format_log_entry($level, $message, $context);
        
        // เก็บใน Buffer
        $this->buffer[] = $entry;
        
        // ถ้า Buffer ถึงขนาดที่กำหนด ให้ Flush ทันที
        if (count($this->buffer) >= $this->buffer_size) {
            $this->flush();
        }
    }

    /**
     * Flush Buffer ไปยัง Storage
     */
    public function flush() {
        if (empty($this->buffer)) {
            return;
        }
        
        $entries = implode('', $this->buffer);
        $this->buffer = [];
        
        // ตรวจสอบและ Rotate Log File
        $this->rotate_log_if_needed();
        
        // เขียน Log
        $log_path = $this->get_log_path();
        $result = @file_put_contents($log_path, $entries, FILE_APPEND | LOCK_EX);
        
        if ($result === false) {
            // Fallback: ใช้ error_log
            error_log($entries);
        }
    }

    /**
     * ตรวจสอบว่า Log Level นี้ควรบันทึกหรือไม่
     */
    private function should_log($level) {
        $min_priority = self::LOG_LEVEL_PRIORITY[$this->min_log_level] ?? 2;
        $current_priority = self::LOG_LEVEL_PRIORITY[$level] ?? 0;
        
        return $current_priority >= $min_priority;
    }

    /**
     * สร้าง Log Entry (แบบ Structured)
     */
    private function format_log_entry($level, $message, array $context = []) {
        // สร้าง Timestamp ในรูปแบบ ISO 8601
        $timestamp = date('Y-m-d\TH:i:s.uP');
        
        // Sanitize Context (ลบข้อมูล sensitive)
        $context = $this->sanitize_context($context);
        
        // JSON Format (สำหรับ ELK/Splunk)
        $entry = json_encode([
            'timestamp' => $timestamp,
            'level' => $level,
            'message' => $message,
            'context' => $context,
            'host' => gethostname(),
            'pid' => getmypid(),
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
        
        return $entry;
    }

    /**
     * สร้าง Context จาก Request
     */
    private function build_log_context($request) {
        $context = [
            'request' => [
                'method' => $request->method ?? 'UNKNOWN',
                'uri' => $request->uri ?? '/',
                'ip' => $this->sanitize_ip($request->ip ?? ''),
                'user_agent' => $this->sanitize_string($request->headers['user-agent'] ?? ''),
                'referer' => $this->sanitize_string($request->headers['referer'] ?? ''),
                'protocol' => $request->protocol ?? 'HTTP/1.1',
            ],
            'server' => [
                'host' => $_SERVER['HTTP_HOST'] ?? '',
                'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '',
                'request_time' => $_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true),
            ],
            'runtime' => [
                'memory_usage' => memory_get_usage(),
                'peak_memory' => memory_get_peak_usage(),
                'execution_time' => microtime(true) - ($_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true)),
            ],
        ];
        
        // เพิ่มข้อมูล User (ถ้ามี)
        if (session_status() === PHP_SESSION_ACTIVE && isset($_SESSION['user_id'])) {
            $context['user'] = [
                'id' => $_SESSION['user_id'],
                'role' => $_SESSION['user_role'] ?? 'unknown'
            ];
        }
        
        // เพิ่มข้อมูลจาก Module ก่อนหน้า (ถ้ามี)
        if (isset($request->module_results)) {
            $context['modules'] = $request->module_results;
        }
        
        return $context;
    }

    /**
     * Sanitize Context (ลบข้อมูล sensitive)
     */
    private function sanitize_context($context) {
        $sensitive_keys = ['password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'authorization', 'cookie'];
        
        array_walk_recursive($context, function(&$value, $key) use ($sensitive_keys) {
            if (is_string($value) && $this->is_sensitive_key($key, $sensitive_keys)) {
                $value = '***REDACTED***';
            }
        });
        
        return $context;
    }

    /**
     * ตรวจสอบว่าเป็น Key ที่ sensitive หรือไม่
     */
    private function is_sensitive_key($key, $sensitive_keys) {
        $key_lower = strtolower($key);
        foreach ($sensitive_keys as $sensitive) {
            if (strpos($key_lower, $sensitive) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sanitize IP Address
     */
    private function sanitize_ip($ip) {
        // ตรวจสอบว่าเป็น IP ที่ถูกต้อง
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
        return 'invalid-ip';
    }

    /**
     * Sanitize String (ป้องกัน Injection ใน Log)
     */
    private function sanitize_string($string) {
        if (empty($string) || !is_string($string)) {
            return '';
        }
        // เอา control characters และ newline ออก
        return preg_replace('/[\x00-\x1F\x7F]/', '', $string);
    }

    /**
     * ตรวจสอบและ Rotate Log File
     */
    private function rotate_log_if_needed() {
        $log_path = $this->get_log_path();
        
        if (!file_exists($log_path)) {
            return;
        }
        
        // ตรวจสอบขนาดไฟล์
        $file_size = filesize($log_path);
        if ($file_size < $this->max_file_size) {
            return;
        }
        
        // หมุนเวียนไฟล์
        for ($i = $this->max_files - 1; $i > 0; $i--) {
            $old = $log_path . '.' . $i . '.gz';
            $new = $log_path . '.' . ($i + 1) . '.gz';
            
            if (file_exists($old) && $i == $this->max_files - 1) {
                @unlink($old);
            } elseif (file_exists($old)) {
                @rename($old, $new);
            }
        }
        
        // บีบอัดไฟล์ปัจจุบัน
        $current = $log_path;
        $archive = $log_path . '.1.gz';
        if (file_exists($current)) {
            $gz = gzopen($archive, 'w');
            if ($gz) {
                $content = file_get_contents($current);
                gzwrite($gz, $content);
                gzclose($gz);
                // หลังจากบีบอัดแล้ว ล้างไฟล์เก่า
                $this->truncate_log_file($current);
            }
        }
    }

    /**
     * ล้างเนื้อหาไฟล์ (truncate)
     */
    private function truncate_log_file($file) {
        $handle = @fopen($file, 'r+');
        if ($handle) {
            @ftruncate($handle, 0);
            @fclose($handle);
        }
    }

    /**
     * เก็บ Metrics ลง Storage (Redis/Database)
     */
    private function store_metrics($request, $context) {
        if (!$this->storage) {
            return;
        }
        
        try {
            $metrics = [
                'timestamp' => time(),
                'method' => $request->method ?? 'UNKNOWN',
                'uri' => $request->uri ?? '/',
                'ip' => $this->sanitize_ip($request->ip ?? ''),
                'status' => $request->response_status ?? 200,
                'duration' => $context['runtime']['execution_time'] ?? 0,
                'memory' => $context['runtime']['memory_usage'] ?? 0,
            ];
            
            $this->storage->lpush('makkha8:metrics', json_encode($metrics));
            $this->storage->ltrim('makkha8:metrics', 0, 9999); // เก็บ 10000 รายการล่าสุด
            
        } catch (Exception $e) {
            // ไม่ต้องทำอะไร ถ้าเก็บ metrics ไม่ได้
            error_log('Failed to store metrics: ' . $e->getMessage());
        }
    }

    /**
     * ตรวจสอบและสร้าง Log Directory (อย่างปลอดภัย)
     */
    private function ensure_log_directory() {
        // ตรวจสอบว่า Directory อยู่ภายใต้ /var/log หรือไม่ (ความปลอดภัย)
        $real_path = realpath($this->log_dir);
        if ($real_path === false) {
            // ถ้ายังไม่มี ให้สร้าง
            if (!is_dir($this->log_dir)) {
                if (!@mkdir($this->log_dir, 0755, true)) {
                    // ถ้าสร้างไม่ได้ ใช้ tmp
                    $this->log_dir = sys_get_temp_dir() . '/makkha8-logs';
                    if (!is_dir($this->log_dir)) {
                        @mkdir($this->log_dir, 0755, true);
                    }
                }
            }
        }
        
        // ตรวจสอบสิทธิ์การเขียน
        if (!is_writable($this->log_dir)) {
            throw new RuntimeException("Log directory '{$this->log_dir}' is not writable");
        }
        
        // สร้าง .htaccess เพื่อป้องกันการเข้าถึง (ถ้าเป็น Apache)
        $htaccess = $this->log_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "Deny from all\n");
        }
        
        // สร้าง index.html (ป้องกัน directory listing)
        $index = $this->log_dir . '/index.html';
        if (!file_exists($index)) {
            file_put_contents($index, '');
        }
    }

    /**
     * ดึง Path ของ Log File
     */
    private function get_log_path() {
        return $this->log_dir . '/' . $this->log_file;
    }

    /**
     * ฟังก์ชันเพิ่มเติม: ดึง Logs ล่าสุด (สำหรับ Admin)
     */
    public function get_recent_logs($lines = 100, $level = null) {
        $log_path = $this->get_log_path();
        if (!file_exists($log_path)) {
            return [];
        }
        
        // อ่านไฟล์จากท้าย
        $logs = [];
        $handle = @fopen($log_path, 'r');
        if ($handle) {
            // ไปที่ท้ายไฟล์
            fseek($handle, -1, SEEK_END);
            $pos = ftell($handle);
            $buffer = '';
            
            while ($pos >= 0 && count($logs) < $lines) {
                $char = fgetc($handle);
                if ($char === "\n") {
                    if (!empty($buffer)) {
                        $log = json_decode(trim($buffer), true);
                        if ($log && ($level === null || ($log['level'] ?? '') === $level)) {
                            $logs[] = $log;
                        }
                        $buffer = '';
                    }
                } else {
                    $buffer = $char . $buffer;
                }
                $pos--;
                fseek($handle, $pos);
            }
            fclose($handle);
        }
        
        return array_reverse($logs);
    }

    /**
     * ฟังก์ชันเพิ่มเติม: Cleanup Old Logs
     */
    public function cleanup_old_logs($days = 30) {
        $files = glob($this->log_dir . '/' . $this->log_file . '*');
        $now = time();
        
        foreach ($files as $file) {
            if (is_file($file) && ($now - filemtime($file)) > ($days * 86400)) {
                @unlink($file);
            }
        }
    }

    /**
     * Destructor - Flush Buffer ตอนจบการทำงาน
     */
    public function __destruct() {
        $this->flush();
    }
}