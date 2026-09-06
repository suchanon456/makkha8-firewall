<?php
// มรรคข้อ 4: ตรวจการกระทำ (CSRF / method checks)
class Makkha8_Samma_Kammanta implements Makkha8_Module_Interface {
    // กำหนดค่าคงที่
    private const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];
    private const UNSAFE_METHODS = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'TRACK', 'CONNECT'];
    
    // ขีดจำกัด Rate Limiting สำหรับ state-changing requests
    private const RATE_LIMIT = 100;      // จำนวนครั้ง
    private const RATE_PERIOD = 300;     // 5 นาที (วินาที)
    
    // CSRF Token Settings
    private const CSRF_TOKEN_NAME = '_csrf';
    private const CSRF_HEADER_NAME = 'X-Csrf-Token';
    private const CSRF_TOKEN_LENGTH = 32;
    private const CSRF_TOKEN_EXPIRY = 3600; // 1 ชั่วโมง (วินาที)

    public function get_name() { 
        return 'samma-kammanta'; 
    }

    public function run(Makkha8_Request $request) {
        $method = strtoupper($request->method ?? 'GET');
        $client_ip = $this->get_client_ip($request);
        
        // 1. ตรวจสอบว่าเป็น Method ที่ปลอดภัย
        if (in_array($method, self::SAFE_METHODS, true)) {
            return ['allow' => true, 'reason' => "Safe HTTP method: {$method}"];
        }

        // 2. ตรวจสอบ Method ที่ไม่ปลอดภัยและอาจถูกบล็อก
        if (in_array($method, self::UNSAFE_METHODS, true)) {
            // ตรวจสอบว่าเป็น API request หรือไม่ (อาจต้องอนุญาต)
            if ($this->is_api_request($request)) {
                // API request ต้องมี API Key หรือ JWT
                if (!$this->validate_api_auth($request)) {
                    return [
                        'block' => true, 
                        'reason' => "Missing or invalid API authentication for {$method}",
                        'method' => $method
                    ];
                }
                // ผ่านการตรวจสอบ API
                return ['allow' => true, 'reason' => "Authenticated API {$method} request"];
            }

            // สำหรับ non-API, บล็อก unsafe methods
            return [
                'block' => true, 
                'reason' => "Unsafe HTTP method: {$method} is not allowed",
                'method' => $method
            ];
        }

        // 3. State-changing requests (POST, PUT, DELETE, PATCH)
        if ($this->is_state_changing_method($method)) {
            // ตรวจสอบ Rate Limiting
            if ($this->is_rate_limited($client_ip)) {
                return [
                    'block' => true, 
                    'reason' => 'Rate limit exceeded for state-changing requests',
                    'rate_limit' => self::RATE_LIMIT,
                    'period' => self::RATE_PERIOD
                ];
            }

            // ตรวจสอบ CSRF Protection
            $csrf_result = $this->validate_csrf($request);
            if (!$csrf_result['valid']) {
                $this->increment_rate_counter($client_ip);
                $this->log_suspicious($request, 'csrf_missing', $csrf_result['reason']);
                
                return [
                    'block' => true, 
                    'reason' => "CSRF validation failed: {$csrf_result['reason']}",
                    'suspicious' => true
                ];
            }

            // ตรวจสอบ SameSite Cookie (แนะนำ)
            $this->check_samesite_cookie($request);

            // ถ้าผ่านทุกอย่าง อนุญาต
            return [
                'allow' => true, 
                'reason' => 'Valid state-changing request with CSRF protection',
                'csrf_valid' => true
            ];
        }

        // กรณี Method อื่นๆ (ไม่ควรเกิด)
        return [
            'block' => true, 
            'reason' => "HTTP method '{$method}' is not supported"
        ];
    }

    /**
     * ตรวจสอบ CSRF Token อย่างสมบูรณ์
     */
    private function validate_csrf($request) {
        // 1. ดึง Token จากแหล่งต่างๆ
        $token = $this->extract_csrf_token($request);
        if (empty($token)) {
            return ['valid' => false, 'reason' => 'CSRF token missing'];
        }

        // 2. ตรวจสอบความยาว
        if (strlen($token) !== self::CSRF_TOKEN_LENGTH) {
            return ['valid' => false, 'reason' => 'Invalid CSRF token length'];
        }

        // 3. ตรวจสอบรูปแบบ (เป็น alphanumeric เท่านั้น)
        if (!ctype_alnum($token)) {
            return ['valid' => false, 'reason' => 'Invalid CSRF token format'];
        }

        // 4. ตรวจสอบว่ามีใน Session และตรงกัน
        $stored_token = $_SESSION['csrf_token'] ?? '';
        if (empty($stored_token) || !hash_equals($stored_token, $token)) {
            return ['valid' => false, 'reason' => 'CSRF token mismatch'];
        }

        // 5. ตรวจสอบอายุ Token (ถ้ามี timestamp)
        if (isset($_SESSION['csrf_token_time'])) {
            $age = time() - $_SESSION['csrf_token_time'];
            if ($age > self::CSRF_TOKEN_EXPIRY) {
                return ['valid' => false, 'reason' => 'CSRF token expired'];
            }
        }

        // 6. ตรวจสอบ Origin/Referer (เพิ่มความปลอดภัย)
        if (!$this->validate_origin($request)) {
            return ['valid' => false, 'reason' => 'Origin/Referer validation failed'];
        }

        // 7. Nonce (ป้องกันการใช้งานซ้ำ)
        if (!$this->validate_nonce($request, $token)) {
            return ['valid' => false, 'reason' => 'CSRF token already used (nonce violation)'];
        }

        return ['valid' => true, 'reason' => 'CSRF token validated'];
    }

    /**
     * ดึง CSRF Token จากหลายแหล่ง
     */
    private function extract_csrf_token($request) {
        // เช็คใน POST
        if (!empty($request->post) && isset($request->post[self::CSRF_TOKEN_NAME])) {
            return trim($request->post[self::CSRF_TOKEN_NAME]);
        }
        
        // เช็คใน GET (ไม่แนะนำ แต่อาจใช้ในบางกรณี)
        if (!empty($request->get) && isset($request->get[self::CSRF_TOKEN_NAME])) {
            return trim($request->get[self::CSRF_TOKEN_NAME]);
        }
        
        // เช็คใน Header
        if (!empty($request->headers)) {
            $headers = array_change_key_case($request->headers, CASE_LOWER);
            $header_name = strtolower(self::CSRF_HEADER_NAME);
            if (isset($headers[$header_name])) {
                return trim($headers[$header_name]);
            }
            // รองรับ Header แบบอื่น
            $alternative_headers = ['x-csrf-token', 'x-xsrf-token', 'csrf-token'];
            foreach ($alternative_headers as $alt) {
                if (isset($headers[$alt])) {
                    return trim($headers[$alt]);
                }
            }
        }
        
        // เช็คใน Cookie (ถ้ามี)
        if (!empty($request->cookies) && isset($request->cookies[self::CSRF_TOKEN_NAME])) {
            return trim($request->cookies[self::CSRF_TOKEN_NAME]);
        }
        
        return '';
    }

    /**
     * ตรวจสอบ Origin/Referer
     */
    private function validate_origin($request) {
        $headers = array_change_key_case($request->headers, CASE_LOWER);
        $origin = $headers['origin'] ?? '';
        $referer = $headers['referer'] ?? '';
        
        // ถ้าไม่มี Origin และ Referer (เช่นมาจาก CLI หรือบาง API)
        if (empty($origin) && empty($referer)) {
            // อนุญาตเฉพาะถ้าเป็น API request หรือ internal
            return $this->is_api_request($request) || $this->is_internal_request($request);
        }
        
        // ตรวจสอบ Origin
        if (!empty($origin)) {
            return $this->is_allowed_origin($origin);
        }
        
        // ตรวจสอบ Referer (ถ้าไม่มี Origin)
        if (!empty($referer)) {
            $referer_parts = parse_url($referer);
            $referer_host = $referer_parts['host'] ?? '';
            $referer_scheme = $referer_parts['scheme'] ?? '';
            
            // ตรวจสอบว่าเป็น same-site และเป็น HTTPS (ถ้า site ใช้ HTTPS)
            return $this->is_same_site($referer_host) && $this->is_secure_scheme($referer_scheme);
        }
        
        return false;
    }

    /**
     * ตรวจสอบว่า Origin อยู่ในรายการที่อนุญาต
     */
    private function is_allowed_origin($origin) {
        // ใช้ hostname ที่ตั้งค่าไว้ในระบบ
        $allowed_hosts = ['localhost', '127.0.0.1', '::1', $_SERVER['HTTP_HOST'] ?? ''];
        
        $origin_parts = parse_url($origin);
        $origin_host = $origin_parts['host'] ?? '';
        
        foreach ($allowed_hosts as $allowed) {
            if (strtolower($origin_host) === strtolower($allowed)) {
                return true;
            }
        }
        
        // ตรวจสอบว่าเป็น subdomain ของ domain ตัวเอง
        $site_domain = $_SERVER['HTTP_HOST'] ?? '';
        if (!empty($site_domain) && strpos($origin_host, '.' . $site_domain) !== false) {
            return true;
        }
        
        return false;
    }

    /**
     * ตรวจสอบว่าเป็น Same Site หรือไม่
     */
    private function is_same_site($host) {
        $site_host = $_SERVER['HTTP_HOST'] ?? '';
        return strtolower($host) === strtolower($site_host);
    }

    /**
     * ตรวจสอบว่าเป็น HTTPS (secure scheme)
     */
    private function is_secure_scheme($scheme) {
        $site_uses_https = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        if ($site_uses_https) {
            return strtolower($scheme) === 'https';
        }
        return true; // ถ้า site ใช้ HTTP ไม่ต้องบังคับ HTTPS
    }

    /**
     * ตรวจสอบ Nonce (ป้องกันการใช้ Token ซ้ำ)
     */
    private function validate_nonce($request, $token) {
        // เก็บ nonce ใน session
        if (!isset($_SESSION['used_nonces'])) {
            $_SESSION['used_nonces'] = [];
        }
        
        // ตรวจสอบว่า token นี้ถูกใช้ไปแล้วหรือไม่
        $token_hash = sha1($token);
        if (in_array($token_hash, $_SESSION['used_nonces'])) {
            return false;
        }
        
        // เก็บ nonce (จำกัดขนาดเพื่อป้องกัน DoS)
        $_SESSION['used_nonces'][] = $token_hash;
        if (count($_SESSION['used_nonces']) > 100) {
            array_shift($_SESSION['used_nonces']);
        }
        
        return true;
    }

    /**
     * ตรวจสอบว่าเป็น API Request หรือไม่
     */
    private function is_api_request($request) {
        // ตรวจสอบ Content-Type
        $headers = array_change_key_case($request->headers, CASE_LOWER);
        $content_type = $headers['content-type'] ?? '';
        $api_content_types = ['application/json', 'application/xml', 'application/x-www-form-urlencoded'];
        
        // ตรวจสอบ path
        $api_paths = ['/api/', '/rest/', '/graphql', '/v1/', '/v2/'];
        $uri = $request->uri ?? '';
        
        // ตรวจสอบ Content-Type
        foreach ($api_content_types as $type) {
            if (strpos($content_type, $type) !== false) {
                return true;
            }
        }
        
        // ตรวจสอบ path
        foreach ($api_paths as $path) {
            if (strpos($uri, $path) !== false) {
                return true;
            }
        }
        
        // ตรวจสอบ Accept header
        $accept = $headers['accept'] ?? '';
        if (strpos($accept, 'application/json') !== false) {
            return true;
        }
        
        return false;
    }

    /**
     * ตรวจสอบ API Authentication (อย่างง่าย)
     */
    private function validate_api_auth($request) {
        $headers = array_change_key_case($request->headers, CASE_LOWER);
        
        // ตรวจสอบ API Key
        $api_key = $headers['x-api-key'] ?? '';
        if (!empty($api_key)) {
            // ตรวจสอบว่า API Key ถูกต้อง (ควรใช้ Database)
            return $this->verify_api_key($api_key);
        }
        
        // ตรวจสอบ JWT Token
        $auth_header = $headers['authorization'] ?? '';
        if (!empty($auth_header) && strpos($auth_header, 'Bearer ') === 0) {
            $token = substr($auth_header, 7);
            return $this->verify_jwt_token($token);
        }
        
        return false;
    }

    private function verify_api_key($api_key) {
        // ตัวอย่าง: ตรวจสอบกับค่าที่ตั้งไว้
        $valid_keys = ['your-secret-api-key', 'development-key'];
        return in_array($api_key, $valid_keys, true);
    }

    private function verify_jwt_token($token) {
        // ตัวอย่าง: ตรวจสอบ JWT (ควรใช้ library จริง)
        return !empty($token) && strlen($token) > 20;
    }

    /**
     * ตรวจสอบ Rate Limiting
     */
    private function is_rate_limited($ip) {
        if (empty($ip)) {
            return false;
        }
        
        $key = "rate_limit_statechange:{$ip}";
        $attempts = $this->get_rate_counter($key);
        
        return $attempts >= self::RATE_LIMIT;
    }

    private function increment_rate_counter($ip) {
        if (empty($ip)) {
            return;
        }
        
        $key = "rate_limit_statechange:{$ip}";
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
     * ตรวจสอบ SameSite Cookie (แนะนำ)
     */
    private function check_samesite_cookie($request) {
        // ถ้าไม่มี session cookie ให้แนะนำ
        if (!session_id()) {
            return;
        }
        
        // ตรวจสอบว่า cookie มี samesite หรือไม่
        $headers = array_change_key_case($request->headers, CASE_LOWER);
        $cookie_header = $headers['cookie'] ?? '';
        if (empty($cookie_header)) {
            return;
        }
        
        // ตรวจสอบว่า samesite มีการตั้งค่าใน session config
        $samesite = ini_get('session.cookie_samesite') ?: 'None';
        if ($samesite === 'None' && $this->is_state_changing_method($request->method ?? 'GET')) {
            // บันทึก warning
            error_log('Warning: Session cookie without SameSite protection for state-changing request');
        }
    }

    /**
     * ตรวจสอบว่าเป็น Internal Request หรือไม่
     */
    private function is_internal_request($request) {
        $client_ip = $this->get_client_ip($request);
        $internal_ips = ['127.0.0.1', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
        
        foreach ($internal_ips as $range) {
            if ($this->ip_in_range($client_ip, $range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * ตรวจสอบว่าเป็น State-Changing Method หรือไม่
     */
    private function is_state_changing_method($method) {
        $state_changing = ['POST', 'PUT', 'DELETE', 'PATCH'];
        return in_array(strtoupper($method), $state_changing, true);
    }

    /**
     * ดึง IP ของ Client
     */
    private function get_client_ip($request) {
        if (!empty($request->headers['x-forwarded-for'])) {
            $ips = explode(',', $request->headers['x-forwarded-for']);
            return trim($ips[0]);
        }
        return $request->ip ?? $_SERVER['REMOTE_ADDR'] ?? '';
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
     * บันทึกเหตุการณ์ที่น่าสงสัย
     */
    private function log_suspicious($request, $type, $reason) {
        $log_entry = sprintf(
            "[%s] TYPE: %s | IP: %s | METHOD: %s | URI: %s | REASON: %s\n",
            date('Y-m-d H:i:s'),
            $type,
            $this->get_client_ip($request),
            $request->method ?? 'UNKNOWN',
            $request->uri ?? 'UNKNOWN',
            $reason
        );
        
        error_log($log_entry, 3, '/var/log/makkha8_security.log');
    }
}