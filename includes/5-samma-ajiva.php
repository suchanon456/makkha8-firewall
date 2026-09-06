<?php
// มรรคข้อ 5: ตรวจสิทธิ์ผู้ใช้ / Rate Limit (พร้อม Distributed Support)
class Makkha8_Samma_Ajiva implements Makkha8_Module_Interface {
    // ค่าเริ่มต้น (สามารถปรับผ่าน Constructor หรือ Config)
    private const DEFAULT_LIMIT = 60;      // จำนวน Request ต่อ Window
    private const DEFAULT_WINDOW = 60;     // ระยะเวลา Window (วินาที)
    private const STORAGE_TTL = 3600;      // TTL สำหรับ Storage (1 ชั่วโมง)
    
    // Whitelist (IP หรือ Path ที่ไม่ต้อง Rate Limit)
    private const WHITELIST_IPS = [
        '127.0.0.1', '::1',
        // '192.168.1.100',
    ];
    private const WHITELIST_PATHS = [
        '/health', '/ping', '/metrics',
        // '/api/webhook',
    ];

    private $storage;
    private $limit;
    private $window;
    private $trusted_proxies;

    public function __construct($storage = null, $limit = self::DEFAULT_LIMIT, $window = self::DEFAULT_WINDOW) {
        $this->storage = $storage ?? Makkha8_Storage::getInstance();
        $this->limit = $limit;
        $this->window = $window;
        
        // Trusted Proxies (ควรดึงจาก Config)
        $this->trusted_proxies = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
        ];
    }

    public function get_name() { 
        return 'samma-ajiva'; 
    }

    public function run(Makkha8_Request $request) {
        // 1. ตรวจสอบ Whitelist (ยกเว้น)
        if ($this->is_whitelisted($request)) {
            return ['allow' => true, 'reason' => 'whitelisted request'];
        }

        // 2. ดึง Client IP ที่แท้จริง (ป้องกัน Spoofing)
        $client_ip = $this->get_real_client_ip($request);
        if (empty($client_ip)) {
            return ['block' => true, 'reason' => 'unable to determine client IP'];
        }

        // 3. สร้าง Key สำหรับ Rate Limit (แยกตาม IP + Path? หรือเฉพาะ IP)
        $key = $this->build_rate_limit_key($request, $client_ip);
        
        // 4. ตรวจสอบ Rate Limit (ใช้ Redis Lua Script เพื่อ Atomic Operation)
        $current_count = $this->increment_and_check($key, $this->window, $this->limit);
        
        // 5. ตัดสินใจ
        if ($current_count > $this->limit) {
            // บันทึกเหตุการณ์
            $this->log_rate_limit_exceeded($request, $client_ip, $current_count);
            
            // ส่ง Header Retry-After
            return [
                'block' => true, 
                'reason' => 'rate limit exceeded',
                'retry_after' => $this->window,
                'current_count' => $current_count,
                'limit' => $this->limit
            ];
        }

        // 6. อนุญาต พร้อมข้อมูล Rate Limit (ให้ Client ทราบ)
        return [
            'allow' => true,
            'rate_limit' => [
                'limit' => $this->limit,
                'remaining' => max(0, $this->limit - $current_count),
                'reset' => time() + $this->window,
                'current' => $current_count
            ]
        ];
    }

    /**
     * ดึง Client IP ที่แท้จริง (ป้องกัน IP Spoofing)
     */
    private function get_real_client_ip($request) {
        $ip = $request->ip ?? $_SERVER['REMOTE_ADDR'] ?? '';
        
        // ถ้ามี Trusted Proxy และมี X-Forwarded-For
        if ($this->is_trusted_proxy($ip) && !empty($request->headers['x-forwarded-for'])) {
            $ips = array_map('trim', explode(',', $request->headers['x-forwarded-for']));
            // เลือก IP แรก (client จริง) ที่ไม่ใช่ Trusted Proxy
            foreach ($ips as $candidate) {
                if (!$this->is_trusted_proxy($candidate) && filter_var($candidate, FILTER_VALIDATE_IP)) {
                    return $candidate;
                }
            }
        }
        
        // ถ้าไม่ผ่าน proxy หรือไม่มี header
        return $ip;
    }

    /**
     * ตรวจสอบว่าเป็น Trusted Proxy หรือไม่ (รองรับ CIDR)
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
     * สร้าง Key สำหรับ Rate Limit (แยกตาม IP + Path สำหรับ API)
     */
    private function build_rate_limit_key($request, $client_ip) {
        // ใช้ IP เป็นหลัก
        $key_parts = ['rate_limit', $client_ip];
        
        // ถ้าเป็น API ให้แยกตาม Path ด้วย (ป้องกันการโจมตีเฉพาะ endpoint)
        if ($this->is_api_request($request)) {
            $path = parse_url($request->uri ?? '', PHP_URL_PATH) ?: '/';
            // ใช้เฉพาะ 2 ส่วนแรกของ path (เพื่อไม่ให้สร้าง key มากเกินไป)
            $path_parts = explode('/', trim($path, '/'));
            $path_prefix = isset($path_parts[0]) ? $path_parts[0] : '';
            if (!empty($path_parts[1])) {
                $path_prefix .= '/' . $path_parts[1];
            }
            $key_parts[] = $path_prefix;
        }
        
        return implode(':', $key_parts);
    }

    /**
     * ตรวจสอบและเพิ่มจำนวน Request (Atomic Operation)
     * ใช้ Redis Lua Script เพื่อป้องกัน Race Condition
     */
    private function increment_and_check($key, $window, $limit) {
        // ใช้ Lua Script เพื่อ Atomic Operation (ถ้าใช้ Redis)
        if ($this->storage instanceof Redis) {
            $lua = <<<LUA
                local current = redis.call('incr', KEYS[1])
                if current == 1 then
                    redis.call('expire', KEYS[1], ARGV[1])
                end
                return current
LUA;
            try {
                $current = $this->storage->eval($lua, [$key], [$window]);
                return (int) $current;
            } catch (Exception $e) {
                // Fallback: ใช้วิธีปกติ
                return $this->increment_and_check_fallback($key, $window);
            }
        }
        
        // Fallback สำหรับ Storage ทั่วไป
        return $this->increment_and_check_fallback($key, $window);
    }

    /**
     * Fallback Method สำหรับ Storage ที่ไม่ใช่ Redis
     */
    private function increment_and_check_fallback($key, $window) {
        // ใช้ Lock เพื่อป้องกัน Race Condition (อย่างง่าย)
        $lock_key = $key . '_lock';
        $lock = $this->storage->get($lock_key);
        
        if ($lock) {
            // ถ้ามี Lock ให้รอเล็กน้อย (ป้องกันการชน)
            usleep(10000); // 10ms
            return $this->increment_and_check_fallback($key, $window);
        }
        
        // สร้าง Lock (TTL 1 วินาที)
        $this->storage->set($lock_key, 'locked', 1);
        
        try {
            $now = time();
            $data = $this->storage->get($key);
            
            if (empty($data) || !is_array($data)) {
                $data = ['count' => 0, 'window_start' => $now];
            }
            
            // ตรวจสอบว่า Window หมดอายุหรือไม่
            if (($now - $data['window_start']) > $window) {
                $data = ['count' => 0, 'window_start' => $now];
            }
            
            // เพิ่มจำนวน
            $data['count']++;
            
            // บันทึก (TTL = window * 2)
            $this->storage->set($key, $data, $window * 2);
            
            return $data['count'];
        } finally {
            // ลบ Lock
            $this->storage->delete($lock_key);
        }
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
     * ตรวจสอบว่าเป็น API Request หรือไม่
     */
    private function is_api_request($request) {
        $uri = $request->uri ?? '';
        $api_prefixes = ['/api/', '/rest/', '/graphql', '/v1/', '/v2/'];
        foreach ($api_prefixes as $prefix) {
            if (strpos($uri, $prefix) !== false) {
                return true;
            }
        }
        
        // ตรวจสอบ Content-Type
        $headers = array_change_key_case($request->headers ?? [], CASE_LOWER);
        $content_type = $headers['content-type'] ?? '';
        if (strpos($content_type, 'application/json') !== false) {
            return true;
        }
        
        return false;
    }

    /**
     * บันทึกเหตุการณ์ Rate Limit Exceeded
     */
    private function log_rate_limit_exceeded($request, $client_ip, $count) {
        $log_entry = sprintf(
            "[%s] RATE_LIMIT | IP: %s | URI: %s | METHOD: %s | COUNT: %d/%d | WINDOW: %ds\n",
            date('Y-m-d H:i:s'),
            $client_ip,
            $request->uri ?? '/',
            $request->method ?? 'GET',
            $count,
            $this->limit,
            $this->window
        );
        
        // ใช้ error_log หรือ Logger ตามต้องการ
        error_log($log_entry, 3, '/var/log/makkha8_rate_limit.log');
        
        // ถ้ามีการเกินหลายครั้ง ให้แจ้งเตือน (ผ่าน Email/Slack)
        if ($count > $this->limit * 2) {
            $this->alert_admin($request, $client_ip, $count);
        }
    }

    /**
     * แจ้งเตือน Admin (กรณีเกิน Rate Limit มาก)
     */
    private function alert_admin($request, $client_ip, $count) {
        $subject = "⚠️ High Rate Limit Exceeded: {$client_ip}";
        $message = "IP: {$client_ip}\n";
        $message .= "URI: {$request->uri ?? '/'}\n";
        $message .= "Method: {$request->method ?? 'GET'}\n";
        $message .= "Count: {$count}/{$this->limit}\n";
        $message .= "Time: " . date('Y-m-d H:i:s');
        
        // ตัวอย่าง: ส่ง Email
        // mail('admin@example.com', $subject, $message);
        
        // หรือเก็บใน Log พิเศษ
        error_log("[ALERT] {$subject} - {$message}", 0);
    }

    /**
     * ฟังก์ชันเพิ่มเติม: รีเซ็ต Rate Limit สำหรับ IP (ใช้ใน Admin)
     */
    public function reset_rate_limit($ip) {
        $key = 'rate_limit:' . $ip;
        $this->storage->delete($key);
        return true;
    }

    /**
     * ฟังก์ชันเพิ่มเติม: ดึงสถานะ Rate Limit ของ IP
     */
    public function get_rate_limit_status($ip) {
        $key = 'rate_limit:' . $ip;
        $data = $this->storage->get($key);
        
        if (empty($data) || !is_array($data)) {
            return ['limit' => $this->limit, 'remaining' => $this->limit, 'reset' => time() + $this->window];
        }
        
        $remaining = max(0, $this->limit - $data['count']);
        $reset = $data['window_start'] + $this->window;
        
        return [
            'limit' => $this->limit,
            'remaining' => $remaining,
            'reset' => $reset,
            'current' => $data['count']
        ];
    }
}