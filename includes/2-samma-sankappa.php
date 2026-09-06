<?php
// มรรคข้อ 2: ตรวจ Routing (valid paths / suspicious endpoints)
class Makkha8_Samma_Sankappa implements Makkha8_Module_Interface {
    // กำหนดค่าคงที่สำหรับรูปแบบเส้นทางที่ต้องตรวจสอบ
    private const SENSITIVE_PATHS = [
        '/wp-admin/',
        '/xmlrpc.php',
        '/wp-login.php',
        '/wp-json/',          // เพิ่ม REST API
        '/.env',              // ไฟล์ environment
        '/.git/',             // Git directory
        '/admin/',            // Admin ทั่วไป
        '/phpmyadmin/',
    ];

    // รูปแบบเส้นทางที่ควรอนุญาตให้ผ่าน (ยกเว้น)
    private const ALLOWED_PATHS = [
        '/wp-admin/admin-ajax.php',
        '/wp-admin/admin-post.php',
    ];

    // ขีดจำกัดการพยายามเข้าถึง (ต่อ IP)
    private const RATE_LIMIT = 10;   // จำนวนครั้ง
    private const RATE_PERIOD = 60; // วินาที

    public function get_name() { 
        return 'samma-sankappa'; 
    }

    public function run(Makkha8_Request $request) {
        // 1. ตรวจสอบความถูกต้องของ Request
        if (empty($request->uri) || !is_string($request->uri)) {
            return ['block' => true, 'reason' => 'Invalid request URI'];
        }

        $uri = $this->normalize_uri($request->uri);
        $path = $this->extract_path($uri);
        $method = $this->get_method($request);
        $client_ip = $this->get_client_ip($request);

        // 2. ตรวจสอบ Rate Limiting
        if ($this->is_rate_limited($client_ip)) {
            return [
                'block' => true, 
                'reason' => 'Too many suspicious access attempts',
                'rate_limit' => self::RATE_LIMIT
            ];
        }

        // 3. ตรวจสอบว่าเป็นเส้นทางที่อนุญาตเป็นพิเศษหรือไม่
        if ($this->is_allowed_path($path)) {
            return ['allow' => true, 'reason' => 'Path is explicitly allowed'];
        }

        // 4. ตรวจสอบว่าเป็นเส้นทางที่ต้องสงสัยหรือไม่
        $sensitive_match = $this->is_sensitive_path($path);
        
        if ($sensitive_match !== false) {
            // ตรวจสอบ Cookie การตรวจสอบสิทธิ์
            $is_authenticated = $this->verify_auth_cookie($request);
            
            // ถ้ามี Cookie ที่ถูกต้อง และเป็น WordPress path
            if ($is_authenticated && $this->is_wordpress_path($sensitive_match)) {
                // บันทึกประวัติการเข้าถึง (แต่ไม่บล็อก)
                $this->log_access($client_ip, $path, 'authenticated_access');
                return ['allow' => true, 'reason' => 'Valid authentication cookie'];
            }

            // ตรวจสอบว่าเป็น HTTP Method ที่น่าสงสัยหรือไม่
            if ($this->is_suspicious_method($method, $path)) {
                $this->increment_rate_counter($client_ip);
                $this->log_access($client_ip, $path, 'suspicious_method', $method);
                return [
                    'block' => true, 
                    'reason' => "Suspicious HTTP method '{$method}' for path",
                    'suspicious' => true
                ];
            }

            // หากเข้าถึงโดยไม่มีสิทธิ์
            $this->increment_rate_counter($client_ip);
            $this->log_access($client_ip, $path, 'unauthorized_access');
            
            return [
                'block' => true, 
                'reason' => "Access denied to sensitive path: {$sensitive_match}",
                'suspicious' => true
            ];
        }

        // 5. ถ้าผ่านทุกการตรวจสอบ อนุญาตให้ผ่าน
        return ['allow' => true, 'reason' => 'Valid path'];
    }

    // --- ฟังก์ชันช่วยเหลือ (Helper Functions) ---

    /**
     * ปรับแต่ง URI ให้เป็นมาตรฐาน
     */
    private function normalize_uri($uri) {
        // แปลงเป็น lowercase เพื่อความสอดคล้อง
        $uri = strtolower($uri);
        // ตัด query string ทิ้ง (ตรวจสอบเฉพาะ path)
        if (strpos($uri, '?') !== false) {
            $uri = substr($uri, 0, strpos($uri, '?'));
        }
        return $uri;
    }

    /**
     * แยกเฉพาะ path จาก URI (ตัดส่วนของ domain)
     */
    private function extract_path($uri) {
        // ถ้ามี protocol ให้ตัดออก
        if (preg_match('#^https?://[^/]+(/?.*)#', $uri, $matches)) {
            return rtrim($matches[1], '/') . '/';
        }
        // ถ้าไม่มี protocol ให้ตัดเฉพาะ path
        return rtrim(parse_url($uri, PHP_URL_PATH) ?: '/', '/') . '/';
    }

    /**
     * ตรวจสอบว่า path อยู่ในรายการที่ต้องสงสัยหรือไม่
     * @return string|false คืนค่า pattern ที่ตรง หรือ false
     */
    private function is_sensitive_path($path) {
        foreach (self::SENSITIVE_PATHS as $pattern) {
            // ตรวจสอบแบบเจาะจง path (ไม่รวม query string)
            if (strpos($path, $pattern) !== false) {
                return $pattern;
            }
        }
        return false;
    }

    /**
     * ตรวจสอบว่า path อยู่ในรายการอนุญาตพิเศษหรือไม่
     */
    private function is_allowed_path($path) {
        foreach (self::ALLOWED_PATHS as $allowed) {
            if (strpos($path, $allowed) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * ตรวจสอบว่าเป็น WordPress path หรือไม่
     */
    private function is_wordpress_path($pattern) {
        $wp_patterns = ['/wp-admin/', '/xmlrpc.php', '/wp-login.php', '/wp-json/'];
        return in_array($pattern, $wp_patterns, true);
    }

    /**
     * ตรวจสอบความถูกต้องของ Cookie (ใช้ WordPress auth logic)
     */
    private function verify_auth_cookie($request) {
        // ตรวจสอบว่ามี cookie ที่จำเป็นหรือไม่
        if (empty($request->cookies) || !is_array($request->cookies)) {
            return false;
        }

        // ตรวจสอบ WordPress cookie (อย่างง่าย)
        $auth_cookies = [
            'wordpress_logged_in',
            'wordpress_sec',
            'wp-settings-time'
        ];

        foreach ($auth_cookies as $cookie_name) {
            if (!empty($request->cookies[$cookie_name])) {
                // สำหรับระบบ production ควรตรวจสอบความถูกต้องด้วย wp_validate_auth_cookie()
                // แต่ในที่นี้ตรวจสอบแค่ว่ามีค่าและไม่ว่าง
                return true;
            }
        }

        return false;
    }

    /**
     * ตรวจสอบ HTTP Method ที่น่าสงสัย
     */
    private function is_suspicious_method($method, $path) {
        $dangerous_methods = ['DELETE', 'PUT', 'PATCH', 'TRACE', 'CONNECT'];
        
        if (in_array($method, $dangerous_methods, true)) {
            // ยกเว้นบาง path ที่อนุญาตให้ใช้ PUT/PATCH
            $exceptions = ['/wp-json/', '/api/'];
            foreach ($exceptions as $exception) {
                if (strpos($path, $exception) !== false) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * ตรวจสอบ Rate Limiting (ใช้ Redis/Memcache หรือ File-based)
     */
    private function is_rate_limited($ip) {
        if (empty($ip)) {
            return false;
        }

        // ตัวอย่าง: ใช้ Session หรือ Cache (ควรใช้ Redis ใน Production)
        $key = "rate_limit:{$ip}";
        $attempts = $this->get_rate_counter($key);
        
        if ($attempts >= self::RATE_LIMIT) {
            return true;
        }

        return false;
    }

    private function increment_rate_counter($ip) {
        if (empty($ip)) {
            return;
        }

        $key = "rate_limit:{$ip}";
        // ตัวอย่าง: เก็บใน Session (จริงๆควรใช้ Redis)
        if (!isset($_SESSION[$key])) {
            $_SESSION[$key] = ['count' => 1, 'time' => time()];
        } else {
            $_SESSION[$key]['count']++;
        }
    }

    private function get_rate_counter($key) {
        if (isset($_SESSION[$key])) {
            $data = $_SESSION[$key];
            // รีเซ็ตถ้าเกินระยะเวลา
            if (time() - $data['time'] > self::RATE_PERIOD) {
                unset($_SESSION[$key]);
                return 0;
            }
            return $data['count'];
        }
        return 0;
    }

    /**
     * ดึง IP ของ client (รองรับ proxy)
     */
    private function get_client_ip($request) {
        // ถ้ามี trusted proxy header
        if (!empty($request->headers['x-forwarded-for'])) {
            $ips = explode(',', $request->headers['x-forwarded-for']);
            return trim($ips[0]);
        }
        return $request->ip ?? $_SERVER['REMOTE_ADDR'] ?? '';
    }

    /**
     * ดึง HTTP Method
     */
    private function get_method($request) {
        return strtoupper($request->method ?? $_SERVER['REQUEST_METHOD'] ?? 'GET');
    }

    /**
     * บันทึกประวัติการเข้าถึง (ควรเชื่อมต่อกับระบบ Log)
     */
    private function log_access($ip, $path, $action, $method = '') {
        // ตัวอย่าง: บันทึกใน file หรือ database
        $log_entry = sprintf(
            "[%s] IP: %s | PATH: %s | ACTION: %s | METHOD: %s\n",
            date('Y-m-d H:i:s'),
            $ip,
            $path,
            $action,
            $method
        );
        
        // ใน Production ควรใช้ Monolog หรือ PSR-3 Logger
        error_log($log_entry, 3, '/var/log/makkha8_access.log');
    }
}