<?php
// มรรคข้อ 1: ตรวจเจตนา/ประเภท Request (intent/whitelist/blacklist)
class Makkha8_Samma_Ditthi implements Makkha8_Module_Interface {
    // กำหนดค่าคงที่
    private const MAX_TRACE_DEPTH = 8;
    private const TRUSTED_PROXIES = [
        '127.0.0.1',
        '::1',
        '10.0.0.0/8',      // Private network
        '172.16.0.0/12',   // Private network
        '192.168.0.0/16',  // Private network
        // เพิ่ม IP ของ proxy ที่เชื่อถือได้ที่นี่
    ];
    
    private const PROXY_HEADERS = [
        'forwarded',
        'x-forwarded-for',
        'x-real-ip',
        'client-ip',
        'x-client-ip',
    ];

    public function get_name() { 
        return 'samma-ditthi'; 
    }

    public function run(Makkha8_Request $request) {
        // ตรวจสอบและ trace origin
        $traceResult = $this->trace_origin($request);
        
        // ถ้ามีการบล็อกจากการ trace
        if (!empty($traceResult['block'])) {
            return $traceResult;
        }

        // ตรวจสอบ IP ต้นทาง
        $originIp = $traceResult['origin_ip'] ?? '';
        
        // ถ้าไม่มี IP หรือ IP ไม่ถูกต้อง
        if (empty($originIp) || !self::is_valid_ip($originIp)) {
            // ถ้ามี trusted proxy และไม่มี header ที่เชื่อถือได้ ให้ใช้ remote addr
            if ($this->is_trusted_proxy($request->ip ?? '')) {
                $originIp = $this->get_real_remote_ip($request);
                if (!empty($originIp) && self::is_valid_ip($originIp)) {
                    return ['allow' => true, 'origin' => $originIp, 'reason' => 'using remote addr'];
                }
            }
            return ['block' => true, 'reason' => 'Invalid or missing source IP'];
        }

        // ตรวจสอบว่าเป็น localhost หรือไม่
        if (in_array($originIp, ['127.0.0.1', '::1'], true)) {
            return ['allow' => true, 'reason' => 'local origin trace'];
        }

        // ตรวจสอบ IP ใน whitelist (ถ้ามี)
        if ($this->is_whitelisted($originIp)) {
            return ['allow' => true, 'reason' => 'whitelisted IP', 'origin' => $originIp];
        }

        return ['allow' => true, 'origin' => $originIp];
    }

    protected function trace_origin(Makkha8_Request $request) {
        $headers = array_change_key_case($request->headers, CASE_LOWER);
        $currentIp = $request->ip ?? $this->get_real_remote_ip($request);
        $visited = [];
        $depth = 0;
        $hasProxyHeader = false;
        $trustedProxyFound = false;

        // ตรวจสอบว่า IP ปัจจุบันเป็น trusted proxy หรือไม่
        if ($this->is_trusted_proxy($currentIp)) {
            $trustedProxyFound = true;
        }

        while ($depth < self::MAX_TRACE_DEPTH) {
            // ตรวจสอบความถูกต้องของ IP
            if (!self::is_valid_ip($currentIp)) {
                break;
            }

            // ป้องกันการวนลูป
            if (isset($visited[$currentIp])) {
                break;
            }

            $visited[$currentIp] = true;
            $nextIp = '';

            // ถ้า IP ปัจจุบันไม่ใช่ trusted proxy ให้หยุดการ trace
            if (!$this->is_trusted_proxy($currentIp)) {
                break;
            }

            // ค้นหา IP ถัดไปจาก headers
            foreach (self::PROXY_HEADERS as $headerName) {
                if (empty($headers[$headerName])) {
                    continue;
                }

                $hasProxyHeader = true;
                $value = trim($headers[$headerName]);
                $candidate = $this->extract_ip_from_header($headerName, $value);

                if ($candidate && self::is_valid_ip($candidate) && !isset($visited[$candidate])) {
                    // ตรวจสอบว่า candidate เป็น trusted proxy หรือไม่
                    if (!$this->is_trusted_proxy($candidate)) {
                        $nextIp = $candidate;
                        break;
                    }
                }
            }

            // ถ้าไม่พบ IP ถัดไป หรือเป็น trusted proxy ให้หยุด
            if (empty($nextIp) || $this->is_trusted_proxy($nextIp)) {
                break;
            }

            $currentIp = $nextIp;
            $depth++;
            
            // ตรวจสอบว่า IP ถัดไปเป็น trusted proxy หรือไม่
            if ($this->is_trusted_proxy($currentIp)) {
                $trustedProxyFound = true;
            }
        }

        // ตรวจสอบความลึก
        if ($depth >= self::MAX_TRACE_DEPTH) {
            return ['block' => true, 'reason' => 'Trace depth exceeded maximum limit'];
        }

        // ถ้ามี proxy header แต่ไม่พบ trusted proxy
        if ($hasProxyHeader && !$trustedProxyFound) {
            return ['block' => true, 'reason' => 'Untrusted proxy detected'];
        }

        // ตรวจสอบ IP สุดท้าย
        if (empty($currentIp) || !self::is_valid_ip($currentIp)) {
            // ถ้าไม่มี trusted proxy ให้ใช้ remote addr แทน
            if (!$trustedProxyFound) {
                $remoteIp = $this->get_real_remote_ip($request);
                if (!empty($remoteIp) && self::is_valid_ip($remoteIp)) {
                    return ['origin_ip' => $remoteIp, 'depth' => 0];
                }
            }
            return ['block' => true, 'reason' => 'Invalid final IP address'];
        }

        return [
            'origin_ip' => $currentIp,
            'depth' => $depth,
            'has_proxy' => $hasProxyHeader,
            'trusted_proxy' => $trustedProxyFound,
        ];
    }

    protected function extract_ip_from_header($headerName, $value) {
        if ($headerName === 'forwarded') {
            return $this->parse_forwarded_header($value);
        }

        // สำหรับ headers ที่เป็น comma-separated
        $parts = array_map('trim', explode(',', $value));
        if (empty($parts)) {
            return '';
        }

        // เลือก IP แรกสุด (original client)
        $firstIp = $parts[0];
        
        // ตรวจสอบและแยกพอร์ตออก
        return $this->extract_ip_from_string($firstIp);
    }

    protected function parse_forwarded_header($value) {
        // จัดการ Forwarded header ที่ซับซ้อน
        // รองรับ for=client, for="[2001:db8::1]:8080"
        $pattern = '/for\s*=\s*(?:"([^"]*)"|([^,;]*))/i';
        
        if (preg_match($pattern, $value, $matches)) {
            $ipPart = !empty($matches[1]) ? $matches[1] : $matches[2];
            return $this->extract_ip_from_string($ipPart);
        }
        
        return '';
    }

    protected function extract_ip_from_string($ipString) {
        // แยกพอร์ตออกจาก IP
        $ipString = trim($ipString);
        
        // กรณี IPv6 ในวงเล็บเหลี่ยม [2001:db8::1]:8080
        if (preg_match('/^\[([^\]]+)\](?::\d+)?$/', $ipString, $matches)) {
            return $matches[1];
        }
        
        // กรณี IPv4:Port
        if (preg_match('/^(\d+\.\d+\.\d+\.\d+)(?::\d+)?$/', $ipString, $matches)) {
            return $matches[1];
        }
        
        // กรณี IPv6 แบบตรง
        if (filter_var($ipString, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $ipString;
        }
        
        return $ipString;
    }

    protected function is_trusted_proxy($ip) {
        if (empty($ip) || !self::is_valid_ip($ip)) {
            return false;
        }

        // ตรวจสอบว่า IP อยู่ใน trusted proxies list หรือไม่
        foreach (self::TRUSTED_PROXIES as $trusted) {
            if ($this->ip_in_range($ip, $trusted)) {
                return true;
            }
        }
        
        return false;
    }

    protected function ip_in_range($ip, $range) {
        // รองรับ CIDR notation (เช่น 192.168.0.0/16)
        if (strpos($range, '/') !== false) {
            list($subnet, $mask) = explode('/', $range);
            
            if (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                // IPv4
                $ipLong = ip2long($ip);
                $subnetLong = ip2long($subnet);
                $maskLong = -1 << (32 - $mask);
                
                return ($ipLong & $maskLong) == ($subnetLong & $maskLong);
            } else {
                // IPv6 - simple check
                return $ip === $subnet;
            }
        }
        
        // ตรงกันทุกประการ
        return $ip === $range;
    }

    protected function is_whitelisted($ip) {
        // ฟังก์ชันสำหรับตรวจสอบ whitelist (สามารถปรับปรุงเพิ่มเติมได้)
        $whitelist = [
            // '192.168.1.100',
            // '10.0.0.0/24',
        ];
        
        foreach ($whitelist as $whitelisted) {
            if ($this->ip_in_range($ip, $whitelisted)) {
                return true;
            }
        }
        
        return false;
    }

    protected function get_real_remote_ip($request) {
        // ดึง IP จริงจากการเชื่อมต่อโดยตรง
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    protected static function is_valid_ip($ip) {
        if (empty($ip) || !is_string($ip)) {
            return false;
        }
        
        // ตรวจสอบว่าเป็น IP ที่ถูกต้อง (ไม่ใช่ hostname)
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
}