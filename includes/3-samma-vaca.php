<?php
// มรรคข้อ 3: ตรวจวาจา/Input (detect SQLi / XSS-like patterns)
class Makkha8_Samma_Vaca implements Makkha8_Module_Interface {
    // กำหนดขีดจำกัดขนาดข้อมูล (10MB)
    private const MAX_INPUT_SIZE = 10485760;
    
    // ระดับความรุนแรงของรูปแบบที่ตรวจพบ
    private const SEVERITY_CRITICAL = 'critical';
    private const SEVERITY_HIGH = 'high';
    private const SEVERITY_MEDIUM = 'medium';
    private const SEVERITY_LOW = 'low';
    
    // SQL Injection Patterns (แบบเจาะจงมากขึ้น)
    private const SQLI_PATTERNS = [
        // Classic SQLi
        '/\b(?:union|select|insert|update|delete|drop|alter|create|rename|truncate|replace)\s+/i' => self::SEVERITY_CRITICAL,
        '/\b(?:information_schema|pg_catalog|mysql|sysdatabases)\b/i' => self::SEVERITY_HIGH,
        '/\b(?:load_file|into\s+(?:outfile|dumpfile)|exec\s+xp_)/i' => self::SEVERITY_CRITICAL,
        '/\b(?:and|or)\s+\d+\s*[=<>!]+\s*\d+/i' => self::SEVERITY_MEDIUM, // เช่น and 1=1
        '/\b(?:and|or)\s+\w+\s+like\s+[\'"]%[\'"]/i' => self::SEVERITY_MEDIUM,
        '/\b(?:sleep|benchmark)\s*\(/i' => self::SEVERITY_HIGH, // Time-based
        '/\b(?:@@version|@@datadir)\b/i' => self::SEVERITY_MEDIUM,
        '/\b(?:waitfor\s+delay|pg_sleep)\s*\(/i' => self::SEVERITY_HIGH,
        // Comment injection
        '/\/\*.*\*\//i' => self::SEVERITY_LOW,
        '/--\s*$/m' => self::SEVERITY_LOW,
        '/#\s*$/m' => self::SEVERITY_LOW,
    ];

    // XSS Patterns (ตรวจจับหลากหลาย)
    private const XSS_PATTERNS = [
        // Event handlers
        '/\b(on\w+)\s*=\s*["\']?[^"\'>]*["\']?/i' => self::SEVERITY_HIGH,
        // JavaScript protocol
        '/\b(javascript|vbscript|data):/i' => self::SEVERITY_CRITICAL,
        // HTML tags with dangerous attributes
        '/<script\b[^>]*>/i' => self::SEVERITY_CRITICAL,
        '/<iframe\b[^>]*>/i' => self::SEVERITY_HIGH,
        '/<object\b[^>]*>/i' => self::SEVERITY_HIGH,
        '/<embed\b[^>]*>/i' => self::SEVERITY_HIGH,
        '/<link\b[^>]*>/i' => self::SEVERITY_MEDIUM,
        // Dangerous functions
        '/\b(?:eval|setTimeout|setInterval|Function|atob)\s*\(/i' => self::SEVERITY_HIGH,
        '/\b(?:document\.cookie|document\.write|window\.location)\b/i' => self::SEVERITY_MEDIUM,
        // SVG with embedded scripts
        '/<svg\b[^>]*>/i' => self::SEVERITY_MEDIUM,
        // Unicode obfuscation
        '/\\\x[0-9a-f]{2}/i' => self::SEVERITY_LOW,
    ];

    // Path ที่อนุญาตให้มีอักขระพิเศษ (ยกเว้น)
    private const ALLOWED_SPECIAL_CHARS_IN_PATH = [
        '/api/', '/webhook/', '/callback/'
    ];

    public function get_name() { 
        return 'samma-vaca'; 
    }

    public function run(Makkha8_Request $request) {
        // 1. ตรวจสอบขนาดข้อมูล
        $input_size = $this->get_input_size($request);
        if ($input_size > self::MAX_INPUT_SIZE) {
            return [
                'block' => true, 
                'reason' => "Input size exceeds limit: {$input_size} bytes"
            ];
        }

        // 2. ตรวจสอบ Context และแยกประเภทข้อมูล
        $contexts = $this->extract_input_contexts($request);
        
        // 3. ตรวจสอบแต่ละ Context แยกกัน
        $findings = [];
        foreach ($contexts as $context_name => $data) {
            if (empty($data)) continue;
            
            $result = $this->inspect_context($data, $context_name, $request);
            if (!empty($result)) {
                $findings[$context_name] = $result;
            }
        }

        // 4. ตัดสินใจตามความรุนแรงและ Context
        return $this->make_decision($findings, $request);
    }

    /**
     * แยกข้อมูลตาม Context (URL, Body, Header, Cookie)
     */
    private function extract_input_contexts($request) {
        $contexts = [];

        // URL Path และ Query String
        if (!empty($request->uri)) {
            $parsed = parse_url($request->uri);
            $contexts['url_path'] = $parsed['path'] ?? '';
            $contexts['url_query'] = $parsed['query'] ?? '';
        }

        // GET Parameters
        if (!empty($request->get) && is_array($request->get)) {
            $contexts['get'] = $this->flatten_array($request->get);
        }

        // POST Parameters
        if (!empty($request->post) && is_array($request->post)) {
            $contexts['post'] = $this->flatten_array($request->post);
        }

        // JSON Body
        if (!empty($request->body)) {
            $decoded = json_decode($request->body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                $contexts['json_body'] = $this->flatten_array($decoded);
            } else {
                $contexts['raw_body'] = $request->body;
            }
        }

        // Headers (เฉพาะบาง header ที่เกี่ยวข้อง)
        if (!empty($request->headers) && is_array($request->headers)) {
            $dangerous_headers = ['user-agent', 'referer', 'cookie', 'x-forwarded-for'];
            foreach ($dangerous_headers as $header) {
                $key = 'header_' . $header;
                if (!empty($request->headers[$header])) {
                    $contexts[$key] = $request->headers[$header];
                }
            }
        }

        // Cookies
        if (!empty($request->cookies) && is_array($request->cookies)) {
            $contexts['cookies'] = $this->flatten_array($request->cookies);
        }

        return $contexts;
    }

    /**
     * ตรวจสอบ Context ที่กำหนด
     */
    private function inspect_context($data, $context_name, $request) {
        // ถ้าเป็น path ให้ตรวจสอบแบบพิเศษ
        if ($context_name === 'url_path' && $this->is_allowed_path($data)) {
            return [];
        }

        // Normalize ข้อมูล
        $normalized = $this->normalize_input($data, $context_name);
        if (empty($normalized)) {
            return [];
        }

        // ตรวจสอบ SQLi
        $sqli_result = $this->detect_sqli($normalized);
        if ($sqli_result['detected']) {
            return [
                'type' => 'sqli',
                'severity' => $sqli_result['severity'],
                'pattern' => $sqli_result['pattern'],
                'context' => $context_name
            ];
        }

        // ตรวจสอบ XSS
        $xss_result = $this->detect_xss($normalized);
        if ($xss_result['detected']) {
            return [
                'type' => 'xss',
                'severity' => $xss_result['severity'],
                'pattern' => $xss_result['pattern'],
                'context' => $context_name
            ];
        }

        return [];
    }

    /**
     * ตรวจจับ SQL Injection
     */
    private function detect_sqli($input) {
        foreach (self::SQLI_PATTERNS as $pattern => $severity) {
            if (preg_match($pattern, $input, $matches)) {
                return [
                    'detected' => true,
                    'severity' => $severity,
                    'pattern' => $matches[0]
                ];
            }
        }
        return ['detected' => false];
    }

    /**
     * ตรวจจับ XSS
     */
    private function detect_xss($input) {
        foreach (self::XSS_PATTERNS as $pattern => $severity) {
            if (preg_match($pattern, $input, $matches)) {
                return [
                    'detected' => true,
                    'severity' => $severity,
                    'pattern' => $matches[0]
                ];
            }
        }
        return ['detected' => false];
    }

    /**
     * Normalize Input (ถอดรหัส, แปลงเป็นรูปแบบมาตรฐาน)
     */
    private function normalize_input($input, $context) {
        if (is_array($input)) {
            // รวมค่าทุก element เป็น string
            $input = implode(' ', $this->flatten_array($input));
        }

        // ถอดรหัส URL
        $decoded = urldecode($input);
        
        // ถอดรหัส HTML entities (เฉพาะ context ที่เป็น HTML)
        if (in_array($context, ['post', 'json_body', 'raw_body', 'cookies'])) {
            $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        // ลบ whitespace ที่ไม่จำเป็น (แต่ไม่ลบทั้งหมด)
        $decoded = preg_replace('/\s+/', ' ', $decoded);

        // แปลงเป็น lowercase เพื่อการตรวจสอบ
        return strtolower($decoded);
    }

    /**
     * ตัดสินใจตามสิ่งที่ตรวจพบ
     */
    private function make_decision($findings, $request) {
        if (empty($findings)) {
            return ['allow' => true, 'reason' => 'No malicious patterns detected'];
        }

        // จัดลำดับความรุนแรง
        $severity_order = [
            self::SEVERITY_CRITICAL => 4,
            self::SEVERITY_HIGH => 3,
            self::SEVERITY_MEDIUM => 2,
            self::SEVERITY_LOW => 1,
        ];

        $max_severity = self::SEVERITY_LOW;
        $max_score = 0;
        $reasons = [];

        foreach ($findings as $context => $finding) {
            $severity = $finding['severity'] ?? self::SEVERITY_LOW;
            $score = $severity_order[$severity] ?? 0;
            
            if ($score > $max_score) {
                $max_score = $score;
                $max_severity = $severity;
            }

            $reasons[] = sprintf(
                "%s in %s: %s",
                $finding['type'] ?? 'unknown',
                $context,
                $finding['pattern'] ?? ''
            );
        }

        // ตัดสินใจตามความรุนแรงสูงสุด
        if ($max_severity === self::SEVERITY_CRITICAL) {
            return [
                'block' => true,
                'reason' => 'Critical malicious pattern detected: ' . implode('; ', $reasons),
                'severity' => $max_severity
            ];
        }

        if ($max_severity === self::SEVERITY_HIGH) {
            // ถ้าเป็น High แต่เป็น GET request อาจอนุญาตให้ผ่านแต่ flag
            if ($this->is_safe_method($request)) {
                return [
                    'suspicious' => true,
                    'reason' => 'High severity pattern in safe context: ' . implode('; ', $reasons),
                    'severity' => $max_severity
                ];
            }
            return [
                'block' => true,
                'reason' => 'High severity malicious pattern: ' . implode('; ', $reasons),
                'severity' => $max_severity
            ];
        }

        // Medium และ Low
        return [
            'suspicious' => true,
            'reason' => 'Suspicious pattern detected: ' . implode('; ', $reasons),
            'severity' => $max_severity
        ];
    }

    /**
     * ตรวจสอบว่าเป็น HTTP Method ที่ปลอดภัยหรือไม่
     */
    private function is_safe_method($request) {
        $method = strtoupper($request->method ?? 'GET');
        return in_array($method, ['GET', 'HEAD', 'OPTIONS'], true);
    }

    /**
     * ตรวจสอบว่าเป็น Path ที่อนุญาตให้มีอักขระพิเศษหรือไม่
     */
    private function is_allowed_path($path) {
        foreach (self::ALLOWED_SPECIAL_CHARS_IN_PATH as $allowed) {
            if (strpos($path, $allowed) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * แปลง array ที่ซ้อนกันเป็น 1 มิติ
     */
    private function flatten_array($array, $prefix = '') {
        $result = [];
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                $result = array_merge($result, $this->flatten_array($value, $prefix . $key . '_'));
            } else {
                $result[$prefix . $key] = $value;
            }
        }
        return $result;
    }

    /**
     * คำนวณขนาดรวมของ Input
     */
    private function get_input_size($request) {
        $size = 0;
        $sources = ['body', 'get', 'post', 'cookies', 'headers', 'uri'];
        
        foreach ($sources as $source) {
            if (!empty($request->$source)) {
                if (is_string($request->$source)) {
                    $size += strlen($request->$source);
                } elseif (is_array($request->$source)) {
                    $size += strlen(implode('', $this->flatten_array($request->$source)));
                }
            }
        }
        
        return $size;
    }
}