<?php
// มรรคข้อ 6: ตรวจความพยายาม (Brute Force attempts) พร้อม Adaptive Blocking
class Makkha8_Samma_Vayama implements Makkha8_Module_Interface {
    // ค่าเริ่มต้น (ปรับได้)
    private const DEFAULT_MAX_ATTEMPTS = 10;       // จำนวนครั้งที่อนุญาต
    private const DEFAULT_WINDOW = 300;            // 5 นาที (วินาที)
    private const BLOCK_DURATION_SHORT = 900;      // 15 นาที
    private const BLOCK_DURATION_MEDIUM = 3600;    // 1 ชั่วโมง
    private const BLOCK_DURATION_LONG = 86400;     // 24 ชั่วโมง
    
    // Whitelist (ยกเว้น)
    private const WHITELIST_IPS = [
        '127.0.0.1', '::1',
        // '192.168.1.100',
    ];
    private const WHITELIST_PATHS = [
        '/health', '/ping',
    ];

    // Login Path Patterns (รองรับหลายรูปแบบ)
    private const LOGIN_PATHS = [
        '/wp-login.php',
        '/login',
        '/signin',
        '/auth',
        '/oauth/token',
        '/api/login',
        '/admin/login',
        '/user/login',
        '/logon',
    ];

    private $storage;
    private $max_attempts;
    private $window;
    private $trusted_proxies;

    public function __construct($storage = null, $max_attempts = self::DEFAULT_MAX_ATTEMPTS, $window = self::DEFAULT_WINDOW) {
        $this->storage = $storage ?? Makkha8_Storage::getInstance();
        $this->max_attempts = $max_attempts;
        $this->window = $window;
        
        // Trusted Proxies (ควรดึงจาก Config)
        $this->trusted_proxies = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
        ];
    }

    public function get_name() { 
        return 'samma-vayama'; 
    }

    public function run(Makkha8_Request $request) {
        // 1. ตรวจสอบ Whitelist
        if ($this->is_whitelisted($request)) {
            return ['allow' => true, 'reason' => 'whitelisted request'];
        }

        // 2. ตรวจสอบว่าเป็น Login Path หรือไม่
        if (!$this->is_login_path($request->uri ?? '')) {
            return ['allow' => true, 'reason' => 'not a login endpoint'];
        }

        // 3. ดึง Client IP ที่แท้จริง
        $client_ip = $this->get_real_client_ip($request);
        if (empty($client_ip)) {
            return ['block' => true, 'reason' => 'unable to determine client IP'];
        }

        // 4. สร้าง Key สำหรับ Tracking
        $username = $this->extract_username($request);
        $key = $this->build_tracking_key($client_ip, $username);

        // 5. ตรวจสอบว่า IP ถูก Block หรือไม่ (แบบ Progressive)
        $block_status = $this->check_block_status($client_ip);
        if ($block_status['blocked']) {
            return [
                'block' => true, 
                'reason' => 'temporarily blocked due to excessive attempts',
                'block_until' => $block_status['block_until'],
                'retry_after' => max(0, $block_status['block_until'] - time())
            ];
        }

        // 6. ตรวจสอบ Rate Limit ของ Login Attempts
        $current_attempts = $this->increment_attempts($key);
        
        // 7. ตรวจสอบว่าเกิน Limit หรือไม่
        if ($current_attempts > $this->max_attempts) {
            // เพิ่มการ Block ที่รุนแรงขึ้น
            $block_duration = $this->calculate_block_duration($client_ip);
            $this->block_ip($client_ip, $block_duration);
            
            // บันทึกเหตุการณ์
            $this->log_bruteforce($request, $client_ip, $username, $current_attempts);
            
            return [
                'block' => true, 
                'reason' => 'brute force attempt detected',
                'attempts' => $current_attempts,
                'max_attempts' => $this->max_attempts,
                'block_duration' => $block_duration,
                'retry_after' => $block_duration
            ];
        }

        // 8. อนุญาต
        return [
            'allow' => true,
            'attempts' => $current_attempts,
            'remaining' => max(0, $this->max_attempts - $current_attempts),
            'reason' => 'login attempt tracked'
        ];
    }

    /**
     * ตรวจสอบว่าเป็น Login Path หรือไม่ (รองรับหลายรูปแบบ)
     */
    private function is_login_path($uri) {
        $uri_lower = strtolower($uri);
        
        foreach (self::LOGIN_PATHS as $path) {
            if (strpos($uri_lower, $path) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * สร้าง Key สำหรับ Tracking (แยกตาม IP + Username)
     */
    private function build_tracking_key($ip, $username = '') {
        // แยกตาม IP
        $key_parts = ['bruteforce', $ip];
        
        // ถ้ามี Username ให้แยกตาม Username ด้วย (ป้องกัน DoS ด้วย Username)
        if (!empty($username) && $username !== 'unknown') {
            $key_parts[] = md5(strtolower($username));
        }
        
        return implode(':', $key_parts);
    }

    /**
     * เพิ่มจำนวน Attempts (Atomic Operation)
     */
    private function increment_attempts($key) {
        // ใช้ Redis Lua Script เพื่อ Atomic Operation
        if ($this->storage instanceof Redis) {
            try {
                $lua = <<<LUA
                    local current = redis.call('incr', KEYS[1])
                    if current == 1 then
                        redis.call('expire', KEYS[1], ARGV[1])
                    end
                    return current
LUA;
                return (int) $this->storage->eval($lua, [$key], [$this->window]);
            } catch (Exception $e) {
                // Fallback: ใช้วิธีปกติ
                return $this->increment_attempts_fallback($key);
            }
        }
        
        return $this->increment_attempts_fallback($key);
    }

    /**
     * Fallback Method สำหรับ Storage ที่ไม่ใช่ Redis
     */
    private function increment_attempts_fallback($key) {
        $lock_key = $key . '_lock';
        $lock = $this->storage->get($lock_key);
        
        if ($lock) {
            usleep(10000); // 10ms
            return $this->increment_attempts_fallback($key);
        }
        
        $this->storage->set($lock_key, 'locked', 1);
        
        try {
            $now = time();
            $data = $this->storage->get($key);
            
            if (empty($data) || !is_array($data)) {
                $data = ['count' => 0, 'window_start' => $now];
            }
            
            // ตรวจสอบว่า Window หมดอายุหรือไม่
            if (($now - $data['window_start']) > $this->window) {
                $data = ['count' => 0, 'window_start' => $now];
            }
            
            $data['count']++;
            $this->storage->set($key, $data, $this->window * 2);
            
            return $data['count'];
        } finally {
            $this->storage->delete($lock_key);
        }
    }

    /**
     * ตรวจสอบว่า IP ถูก Block หรือไม่ (Progressive Blocking)
     */
    private function check_block_status($ip) {
        $block_key = 'blocked:' . $ip;
        $block_data = $this->storage->get($block_key);
        
        if (empty($block_data) || !is_array($block_data)) {
            return ['blocked' => false];
        }
        
        $block_until = $block_data['block_until'] ?? 0;
        
        if (time() < $block_until) {
            return [
                'blocked' => true,
                'block_until' => $block_until,
                'reason' => $block_data['reason'] ?? 'excessive attempts'
            ];
        }
        
        // ลบ Block ที่หมดอายุ
        $this->storage->delete($block_key);
        return ['blocked' => false];
    }

    /**
     * คำนวณระยะเวลาการ Block แบบ Progressive (เพิ่มขึ้นเรื่อยๆ)
     */
    private function calculate_block_duration($ip) {
        $history_key = 'block_history:' . $ip;
        $history = $this->storage->get($history_key);
        
        if (empty($history) || !is_array($history)) {
            $history = [];
        }
        
        // นับจำนวนครั้งที่ถูก Block ใน 24 ชั่วโมง
        $now = time();
        $recent_blocks = array_filter($history, function($time) use ($now) {
            return ($now - $time) < 86400; // 24 ชั่วโมง
        });
        
        $block_count = count($recent_blocks);
        
        // Progressive Blocking
        if ($block_count >= 5) {
            return self::BLOCK_DURATION_LONG; // 24 ชั่วโมง
        } elseif ($block_count >= 3) {
            return self::BLOCK_DURATION_MEDIUM; // 1 ชั่วโมง
        } elseif ($block_count >= 1) {
            return self::BLOCK_DURATION_SHORT; // 15 นาที
        }
        
        return self::BLOCK_DURATION_SHORT; // 15 นาที
    }

    /**
     * Block IP (บันทึกพร้อมระยะเวลา)
     */
    private function block_ip($ip, $duration) {
        $block_key = 'blocked:' . $ip;
        $block_until = time() + $duration;
        
        $this->storage->set($block_key, [
            'block_until' => $block_until,
            'reason' => 'brute force attempt',
            'timestamp' => time()
        ], $duration + 60);
        
        // บันทึกประวัติการ Block
        $history_key = 'block_history:' . $ip;
        $history = $this->storage->get($history_key);
        if (empty($history) || !is_array($history)) {
            $history = [];
        }
        $history[] = time();
        // เก็บเฉพาะ 100 รายการล่าสุด
        if (count($history) > 100) {
            array_shift($history);
        }
        $this->storage->set($history_key, $history, 86400 * 7); // เก็บ 7 วัน
        
        // บันทึก Log
        error_log(sprintf(
            "[BLOCK] IP: %s | Duration: %ds | Until: %s\n",
            $ip,
            $duration,
            date('Y-m-d H:i:s', $block_until)
        ), 3, '/var/log/makkha8_bruteforce.log');
    }

    /**
     * ดึง Username (ถ้ามี) จาก Request
     */
    private function extract_username($request) {
        // ตรวจสอบใน POST
        if (!empty($request->post)) {
            $username_fields = ['username', 'user_login', 'email', 'user', 'login', 'uname'];
            foreach ($username_fields as $field) {
                if (!empty($request->post[$field])) {
                    return substr(trim($request->post[$field]), 0, 100); // จำกัดความยาว
                }
            }
        }
        
        // ตรวจสอบใน GET
        if (!empty($request->get)) {
            $username_fields = ['username', 'user_login', 'email', 'user', 'login'];
            foreach ($username_fields as $field) {
                if (!empty($request->get[$field])) {
                    return substr(trim($request->get[$field]), 0, 100);
                }
            }
        }
        
        // ตรวจสอบใน Body (JSON)
        if (!empty($request->body)) {
            $data = json_decode($request->body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($data)) {
                $username_fields = ['username', 'user_login', 'email', 'user', 'login', 'uname'];
                foreach ($username_fields as $field) {
                    if (!empty($data[$field]) && is_string($data[$field])) {
                        return substr(trim($data[$field]), 0, 100);
                    }
                }
            }
        }
        
        return 'unknown';
    }

    /**
     * บันทึกเหตุการณ์ Brute Force
     */
    private function log_bruteforce($request, $ip, $username, $attempts) {
        $log_entry = sprintf(
            "[%s] BRUTEFORCE | IP: %s | USER: %s | ATTEMPTS: %d/%d | URI: %s | METHOD: %s\n",
            date('Y-m-d H:i:s'),
            $ip,
            $username,
            $attempts,
            $this->max_attempts,
            $request->uri ?? '/',
            $request->method ?? 'GET'
        );
        
        error_log($log_entry, 3, '/var/log/makkha8_bruteforce.log');
        
        // ถ้าพบ Brute Force รุนแรง ให้แจ้งเตือน Admin
        if ($attempts > $this->max_attempts * 3) {
            $this->alert_admin($request, $ip, $username, $attempts);
        }
    }

    /**
     * แจ้งเตือน Admin (กรณี Brute Force รุนแรง)
     */
    private function alert_admin($request, $ip, $username, $attempts) {
        $subject = "🚨 Critical Brute Force Attack Detected";
        $message = "IP: {$ip}\n";
        $message .= "Username: {$username}\n";
        $message .= "Attempts: {$attempts}\n";
        $message .= "URI: {$request->uri ?? '/'}\n";
        $message .= "Time: " . date('Y-m-d H:i:s');
        
        // ส่ง Email หรือ Slack Alert
        // mail('admin@example.com', $subject, $message);
        error_log("[ALERT] {$subject} - {$message}", 0);
    }

    /**
     * ตรวจสอบ Whitelist
     */
    private function is_whitelisted($request) {
        // ตรวจสอบ IP
        $ip = $request->ip ?? '';
        foreach (self::WHITELIST_IPS as $whitelist_ip) {
            if ($this->ip_in_range($ip, $whitelist_ip)) {
                return true;
            }
        }
        
        // ตรวจสอบ Path
        $uri = $request->uri ?? '';
        foreach (self::WHITELIST_PATHS as $path) {
            if (strpos($uri, $path) !== false) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * ดึง Client IP ที่แท้จริง (ป้องกัน IP Spoofing)
     */
    private function get_real_client_ip($request) {
        $ip = $request->ip ?? $_SERVER['REMOTE_ADDR'] ?? '';
        
        if ($this->is_trusted_proxy($ip) && !empty($request->headers['x-forwarded-for'])) {
            $ips = array_map('trim', explode(',', $request->headers['x-forwarded-for']));
            foreach ($ips as $candidate) {
                if (!$this->is_trusted_proxy($candidate) && filter_var($candidate, FILTER_VALIDATE_IP)) {
                    return $candidate;
                }
            }
        }
        
        return $ip;
    }

    /**
     * ตรวจสอบว่าเป็น Trusted Proxy หรือไม่
     */
    private function is_trusted_proxy($ip) {
        if (empty($ip)) return false;
        
        foreach ($this->trusted_proxies as $range) {
            if ($this->ip_in_range($ip, $range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * ตรวจสอบ IP ใน CIDR range
     */
    private function ip_in_range($ip, $range) {
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
     * ฟังก์ชัน Admin: รีเซ็ตการ Block
     */
    public function unblock_ip($ip) {
        $block_key = 'blocked:' . $ip;
        $history_key = 'block_history:' . $ip;
        $this->storage->delete($block_key);
        $this->storage->delete($history_key);
        return true;
    }

    /**
     * ฟังก์ชัน Admin: ดึงสถานะของ IP
     */
    public function get_ip_status($ip) {
        $block_status = $this->check_block_status($ip);
        $attempts_key = 'bruteforce:' . $ip;
        $attempts_data = $this->storage->get($attempts_key);
        
        return [
            'blocked' => $block_status['blocked'],
            'block_until' => $block_status['block_until'] ?? null,
            'attempts' => $attempts_data['count'] ?? 0,
            'window_start' => $attempts_data['window_start'] ?? null
        ];
    }
}