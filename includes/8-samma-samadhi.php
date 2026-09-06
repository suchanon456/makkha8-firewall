<?php
// มรรคข้อ 8: ตรวจความตั้งมั่น (Session / Token validation) รองรับ JWT และ Session
class Makkha8_Samma_Samadhi implements Makkha8_Module_Interface {
    // Token Types
    private const TOKEN_TYPE_JWT = 'jwt';
    private const TOKEN_TYPE_API_KEY = 'api_key';
    private const TOKEN_TYPE_SESSION = 'session';
    private const TOKEN_TYPE_OAUTH = 'oauth';
    
    // Token Validation Results
    private const VALID = 'valid';
    private const INVALID = 'invalid';
    private const EXPIRED = 'expired';
    private const REVOKED = 'revoked';
    private const MISSING = 'missing';
    
    // Paths ที่ไม่ต้องใช้ Token Authentication
    private const PUBLIC_PATHS = [
        '/health',
        '/ping',
        '/metrics',
        '/login',
        '/register',
        '/reset-password',
        '/api/public',
        '/webhook',
    ];
    
    private $secret_key;
    private $token_expiry;
    private $refresh_token_expiry;
    private $storage;
    private $jwt_algo;
    private $trusted_issuers;
    private $audience;

    public function __construct($config = []) {
        $this->secret_key = $config['secret_key'] ?? $this->generate_secret_key();
        $this->token_expiry = $config['token_expiry'] ?? 3600; // 1 ชั่วโมง
        $this->refresh_token_expiry = $config['refresh_token_expiry'] ?? 86400 * 7; // 7 วัน
        $this->storage = $config['storage'] ?? null;
        $this->jwt_algo = $config['jwt_algo'] ?? 'HS256';
        $this->trusted_issuers = $config['trusted_issuers'] ?? ['localhost'];
        $this->audience = $config['audience'] ?? $_SERVER['HTTP_HOST'] ?? 'localhost';
    }

    public function get_name() { 
        return 'samma-samadhi'; 
    }

    public function run(Makkha8_Request $request) {
        // 1. ตรวจสอบว่า Path เป็น Public หรือไม่
        if ($this->is_public_path($request->uri ?? '')) {
            return ['allow' => true, 'reason' => 'public path - no authentication required'];
        }

        // 2. ดึง Token จากหลายแหล่ง
        $token_data = $this->extract_token($request);
        
        // 3. ถ้าไม่มี Token
        if (empty($token_data['token'])) {
            $this->log_auth_event($request, 'token_missing', null);
            return [
                'block' => true, 
                'reason' => 'authentication token required',
                'error' => 'no_token',
                'suspicious' => true
            ];
        }

        // 4. ตรวจสอบ Token
        $validation_result = $this->validate_token($token_data);
        
        // 5. จัดการตามผลการตรวจสอบ
        return $this->handle_validation_result($validation_result, $request, $token_data);
    }

    /**
     * ดึง Token จากหลายแหล่ง (Header, GET, POST, Cookie)
     */
    private function extract_token($request) {
        $headers = array_change_key_case($request->headers ?? [], CASE_LOWER);
        $token = null;
        $token_type = null;
        
        // 1. ตรวจสอบ Authorization Header (Bearer Token)
        if (!empty($headers['authorization'])) {
            $auth = trim($headers['authorization']);
            if (preg_match('/^Bearer\s+(.+)$/i', $auth, $matches)) {
                $token = $matches[1];
                $token_type = self::TOKEN_TYPE_JWT;
            } elseif (preg_match('/^Basic\s+(.+)$/i', $auth, $matches)) {
                // Basic Auth (ใช้สำหรับ API Key)
                $decoded = base64_decode($matches[1]);
                if ($decoded && strpos($decoded, ':') !== false) {
                    list($username, $password) = explode(':', $decoded, 2);
                    // ตรวจสอบว่าเป็น API Key หรือไม่
                    if ($this->is_api_key($password)) {
                        $token = $password;
                        $token_type = self::TOKEN_TYPE_API_KEY;
                    }
                }
            }
        }
        
        // 2. ตรวจสอบ X-API-Key Header
        if (empty($token) && !empty($headers['x-api-key'])) {
            $token = trim($headers['x-api-key']);
            $token_type = self::TOKEN_TYPE_API_KEY;
        }
        
        // 3. ตรวจสอบ X-Auth-Token Header
        if (empty($token) && !empty($headers['x-auth-token'])) {
            $token = trim($headers['x-auth-token']);
            $token_type = self::TOKEN_TYPE_JWT;
        }
        
        // 4. ตรวจสอบ Cookie (Session ID)
        if (empty($token) && !empty($request->cookies)) {
            $session_cookies = ['session_id', 'sid', 'PHPSESSID', 'JSESSIONID'];
            foreach ($session_cookies as $cookie_name) {
                if (!empty($request->cookies[$cookie_name])) {
                    $token = trim($request->cookies[$cookie_name]);
                    $token_type = self::TOKEN_TYPE_SESSION;
                    break;
                }
            }
        }
        
        // 5. ตรวจสอบ GET Parameter
        if (empty($token) && !empty($request->get)) {
            $token_params = ['auth_token', 'token', 'access_token', 'api_key'];
            foreach ($token_params as $param) {
                if (!empty($request->get[$param])) {
                    $token = trim($request->get[$param]);
                    $token_type = $this->detect_token_type($token);
                    break;
                }
            }
        }
        
        // 6. ตรวจสอบ POST Parameter
        if (empty($token) && !empty($request->post)) {
            $token_params = ['auth_token', 'token', 'access_token', 'api_key'];
            foreach ($token_params as $param) {
                if (!empty($request->post[$param])) {
                    $token = trim($request->post[$param]);
                    $token_type = $this->detect_token_type($token);
                    break;
                }
            }
        }
        
        // 7. ตรวจสอบ OAuth Token (จาก JSON Body)
        if (empty($token) && !empty($request->body)) {
            $data = json_decode($request->body, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($data)) {
                $token_fields = ['access_token', 'refresh_token', 'token', 'auth_token'];
                foreach ($token_fields as $field) {
                    if (!empty($data[$field]) && is_string($data[$field])) {
                        $token = trim($data[$field]);
                        $token_type = $this->detect_token_type($token);
                        break;
                    }
                }
            }
        }
        
        return [
            'token' => $token,
            'type' => $token_type,
            'source' => $this->detect_token_source($request, $token)
        ];
    }

    /**
     * ตรวจสอบ Token อย่างสมบูรณ์
     */
    private function validate_token($token_data) {
        $token = $token_data['token'];
        $type = $token_data['type'];
        
        // ตรวจสอบว่า Token ถูกต้อง
        try {
            switch ($type) {
                case self::TOKEN_TYPE_JWT:
                    return $this->validate_jwt($token);
                    
                case self::TOKEN_TYPE_API_KEY:
                    return $this->validate_api_key($token);
                    
                case self::TOKEN_TYPE_SESSION:
                    return $this->validate_session($token);
                    
                case self::TOKEN_TYPE_OAUTH:
                    return $this->validate_oauth_token($token);
                    
                default:
                    // Auto-detect
                    return $this->validate_token_auto($token);
            }
        } catch (Exception $e) {
            return [
                'valid' => false,
                'status' => self::INVALID,
                'error' => $e->getMessage(),
                'reason' => 'Token validation error: ' . $e->getMessage()
            ];
        }
    }

    /**
     * ตรวจสอบ JWT Token
     */
    private function validate_jwt($token) {
        // แยกส่วนประกอบของ JWT
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Invalid JWT format'];
        }
        
        list($header_encoded, $payload_encoded, $signature) = $parts;
        
        // ตรวจสอบและถอดรหัส
        $header = json_decode(base64_decode($header_encoded), true);
        $payload = json_decode(base64_decode($payload_encoded), true);
        
        if (empty($header) || empty($payload)) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Invalid JWT structure'];
        }
        
        // ตรวจสอบ Signature (แบบง่าย)
        $expected_signature = $this->sign_jwt($header_encoded . '.' . $payload_encoded, $header['alg'] ?? 'HS256');
        if (!hash_equals($expected_signature, $signature)) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Invalid JWT signature'];
        }
        
        // ตรวจสอบ Expiration
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return ['valid' => false, 'status' => self::EXPIRED, 'reason' => 'JWT token expired'];
        }
        
        // ตรวจสอบ Not Before
        if (isset($payload['nbf']) && $payload['nbf'] > time()) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'JWT token not yet valid'];
        }
        
        // ตรวจสอบ Issuer
        if (isset($payload['iss']) && !in_array($payload['iss'], $this->trusted_issuers)) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Untrusted JWT issuer'];
        }
        
        // ตรวจสอบ Audience
        if (isset($payload['aud']) && $payload['aud'] !== $this->audience) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Invalid JWT audience'];
        }
        
        // ตรวจสอบ Revocation (ถ้ามี Storage)
        if ($this->storage && $this->is_token_revoked($token)) {
            return ['valid' => false, 'status' => self::REVOKED, 'reason' => 'JWT token revoked'];
        }
        
        return [
            'valid' => true,
            'status' => self::VALID,
            'payload' => $payload,
            'user_id' => $payload['sub'] ?? $payload['user_id'] ?? null,
            'roles' => $payload['roles'] ?? $payload['scope'] ?? [],
            'type' => self::TOKEN_TYPE_JWT
        ];
    }

    /**
     * ตรวจสอบ API Key
     */
    private function validate_api_key($token) {
        if (empty($this->storage)) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Storage not available for API key validation'];
        }
        
        try {
            $key_data = $this->storage->hgetall('api_keys:' . md5($token));
            if (empty($key_data)) {
                return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Invalid API key'];
            }
            
            // ตรวจสอบว่าหมดอายุหรือไม่
            if (isset($key_data['expires_at']) && $key_data['expires_at'] < time()) {
                return ['valid' => false, 'status' => self::EXPIRED, 'reason' => 'API key expired'];
            }
            
            // ตรวจสอบว่า Active หรือไม่
            if (isset($key_data['status']) && $key_data['status'] !== 'active') {
                return ['valid' => false, 'status' => self::REVOKED, 'reason' => 'API key revoked or inactive'];
            }
            
            return [
                'valid' => true,
                'status' => self::VALID,
                'payload' => $key_data,
                'user_id' => $key_data['user_id'] ?? null,
                'roles' => explode(',', $key_data['roles'] ?? ''),
                'type' => self::TOKEN_TYPE_API_KEY
            ];
        } catch (Exception $e) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'API key validation error: ' . $e->getMessage()];
        }
    }

    /**
     * ตรวจสอบ Session
     */
    private function validate_session($token) {
        // ตรวจสอบ Session ผ่าน PHP Session
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Session not active'];
        }
        
        // ตรวจสอบว่า session_id ตรงกับ token หรือไม่
        if (session_id() !== $token) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Session ID mismatch'];
        }
        
        // ตรวจสอบว่า Session มีข้อมูล User หรือไม่
        if (empty($_SESSION['user_id']) && empty($_SESSION['user'])) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Invalid session'];
        }
        
        // ตรวจสอบ Session Expiration (ถ้ามี)
        if (isset($_SESSION['expires_at']) && $_SESSION['expires_at'] < time()) {
            return ['valid' => false, 'status' => self::EXPIRED, 'reason' => 'Session expired'];
        }
        
        return [
            'valid' => true,
            'status' => self::VALID,
            'payload' => $_SESSION,
            'user_id' => $_SESSION['user_id'] ?? null,
            'roles' => $_SESSION['roles'] ?? [],
            'type' => self::TOKEN_TYPE_SESSION
        ];
    }

    /**
     * ตรวจสอบ OAuth Token (Refresh Token)
     */
    private function validate_oauth_token($token) {
        if (empty($this->storage)) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Storage not available'];
        }
        
        // ตรวจสอบว่าเป็น Refresh Token ที่ถูกต้อง
        $stored = $this->storage->get('oauth_refresh:' . md5($token));
        if (empty($stored)) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Invalid refresh token'];
        }
        
        $data = json_decode($stored, true);
        if (empty($data)) {
            return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Invalid refresh token data'];
        }
        
        // ตรวจสอบ Expiration
        if (isset($data['expires_at']) && $data['expires_at'] < time()) {
            return ['valid' => false, 'status' => self::EXPIRED, 'reason' => 'Refresh token expired'];
        }
        
        // ตรวจสอบ Revocation
        if (isset($data['revoked']) && $data['revoked'] === true) {
            return ['valid' => false, 'status' => self::REVOKED, 'reason' => 'Refresh token revoked'];
        }
        
        return [
            'valid' => true,
            'status' => self::VALID,
            'payload' => $data,
            'user_id' => $data['user_id'] ?? null,
            'roles' => $data['roles'] ?? [],
            'type' => self::TOKEN_TYPE_OAUTH
        ];
    }

    /**
     * Auto-detect Token Type
     */
    private function validate_token_auto($token) {
        // ตรวจสอบว่าเป็น JWT
        if (substr_count($token, '.') === 2) {
            return $this->validate_jwt($token);
        }
        
        // ตรวจสอบว่าเป็น Session ID
        if (preg_match('/^[a-zA-Z0-9]{26,40}$/', $token)) {
            return $this->validate_session($token);
        }
        
        // ตรวจสอบว่าเป็น API Key (UUID หรือ long string)
        if (preg_match('/^[a-f0-9-]{36}$/', $token) || strlen($token) >= 32) {
            return $this->validate_api_key($token);
        }
        
        return ['valid' => false, 'status' => self::INVALID, 'reason' => 'Unknown token type'];
    }

    /**
     * จัดการผลการตรวจสอบ
     */
    private function handle_validation_result($result, $request, $token_data) {
        // ถ้า Token ถูกต้อง
        if ($result['valid'] === true) {
            // เก็บข้อมูลผู้ใช้ใน Request (ให้ Module ถัดไปใช้)
            $request->user = [
                'id' => $result['user_id'] ?? null,
                'roles' => $result['roles'] ?? [],
                'token_type' => $result['type'] ?? 'unknown',
                'payload' => $result['payload'] ?? []
            ];
            
            // บันทึกการใช้งาน (ถ้าต้องการ)
            $this->log_auth_event($request, 'token_valid', $result['user_id']);
            
            // ตรวจสอบสิทธิ์เพิ่มเติม (RBAC)
            $authz_result = $this->check_authorization($request, $result);
            if ($authz_result !== true) {
                return $authz_result;
            }
            
            return ['allow' => true, 'reason' => 'valid token', 'user' => $request->user];
        }
        
        // กรณี Token หมดอายุ
        if ($result['status'] === self::EXPIRED) {
            $this->log_auth_event($request, 'token_expired', null);
            return [
                'block' => true,
                'reason' => 'token expired',
                'error' => 'token_expired',
                'suspicious' => true,
                'refresh_available' => $this->can_refresh_token($token_data)
            ];
        }
        
        // กรณี Token ถูกเพิกถอน
        if ($result['status'] === self::REVOKED) {
            $this->log_auth_event($request, 'token_revoked', null);
            return [
                'block' => true,
                'reason' => 'token revoked',
                'error' => 'token_revoked',
                'suspicious' => true
            ];
        }
        
        // กรณี Token ไม่ถูกต้อง
        $this->log_auth_event($request, 'token_invalid', null);
        return [
            'block' => true,
            'reason' => 'invalid token: ' . ($result['reason'] ?? 'unknown error'),
            'error' => 'invalid_token',
            'suspicious' => true
        ];
    }

    /**
     * ตรวจสอบการอนุญาต (Authorization/RBAC)
     */
    private function check_authorization($request, $token_result) {
        // ดึง roles และ permissions
        $user_roles = $token_result['roles'] ?? [];
        $required_permissions = $this->get_required_permissions($request->uri ?? '');
        
        if (empty($required_permissions)) {
            return true; // ไม่ต้องมี permission
        }
        
        // ตรวจสอบว่า user มี permission ที่ต้องการ
        foreach ($required_permissions as $permission) {
            if (!$this->user_has_permission($user_roles, $permission)) {
                $this->log_auth_event($request, 'permission_denied', $token_result['user_id']);
                return [
                    'block' => true,
                    'reason' => "insufficient permissions: {$permission} required",
                    'error' => 'permission_denied',
                    'required' => $required_permissions,
                    'user_roles' => $user_roles
                ];
            }
        }
        
        return true;
    }

    /**
     * ตรวจสอบว่า Token ถูกเพิกถอนหรือไม่
     */
    private function is_token_revoked($token) {
        if (empty($this->storage)) {
            return false;
        }
        
        $revoked_key = 'revoked_tokens:' . md5($token);
        return $this->storage->exists($revoked_key);
    }

    /**
     * ตรวจสอบว่า Token สามารถ Refresh ได้หรือไม่
     */
    private function can_refresh_token($token_data) {
        // ถ้ามี refresh token
        if (isset($token_data['refresh_token'])) {
            return true;
        }
        
        // ถ้าเป็น OAuth token
        if ($token_data['type'] === self::TOKEN_TYPE_OAUTH) {
            return true;
        }
        
        // ถ้าเป็น Session ให้ refresh โดยการ login ใหม่
        return false;
    }

    /**
     * ตรวจสอบว่า Path เป็น Public หรือไม่
     */
    private function is_public_path($uri) {
        $uri_lower = strtolower($uri);
        foreach (self::PUBLIC_PATHS as $path) {
            if (strpos($uri_lower, $path) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * ตรวจสอบว่าเป็น API Key หรือไม่
     */
    private function is_api_key($token) {
        return preg_match('/^[a-f0-9-]{36}$/', $token) || strlen($token) >= 32;
    }

    /**
     * ตรวจจับประเภท Token จากรูปแบบ
     */
    private function detect_token_type($token) {
        if (substr_count($token, '.') === 2) {
            return self::TOKEN_TYPE_JWT;
        }
        if (preg_match('/^[a-f0-9-]{36}$/', $token) || strlen($token) >= 32) {
            return self::TOKEN_TYPE_API_KEY;
        }
        return self::TOKEN_TYPE_SESSION;
    }

    /**
     * ตรวจจับแหล่งที่มาของ Token
     */
    private function detect_token_source($request, $token) {
        if (!empty($request->headers['authorization'])) {
            return 'authorization_header';
        }
        if (!empty($request->headers['x-api-key'])) {
            return 'api_key_header';
        }
        if (!empty($request->headers['x-auth-token'])) {
            return 'auth_token_header';
        }
        if (!empty($request->cookies)) {
            return 'cookie';
        }
        if (!empty($request->get)) {
            return 'get_parameter';
        }
        if (!empty($request->post)) {
            return 'post_parameter';
        }
        if (!empty($request->body)) {
            return 'json_body';
        }
        return 'unknown';
    }

    /**
     * สร้าง Secret Key
     */
    private function generate_secret_key() {
        return bin2hex(random_bytes(32));
    }

    /**
     * Sign JWT
     */
    private function sign_jwt($data, $algorithm = 'HS256') {
        switch ($algorithm) {
            case 'HS256':
                return hash_hmac('sha256', $data, $this->secret_key, true);
            case 'HS384':
                return hash_hmac('sha384', $data, $this->secret_key, true);
            case 'HS512':
                return hash_hmac('sha512', $data, $this->secret_key, true);
            default:
                throw new InvalidArgumentException("Unsupported JWT algorithm: {$algorithm}");
        }
    }

    /**
     * ดึง Required Permissions สำหรับ Path
     */
    private function get_required_permissions($uri) {
        // ตัวอย่าง: กำหนด permission ตาม path
        $permissions_map = [
            '/api/admin' => ['admin', 'moderator'],
            '/api/users' => ['user', 'admin'],
            '/api/posts' => ['user', 'editor'],
            '/api/settings' => ['admin'],
        ];
        
        foreach ($permissions_map as $path => $permissions) {
            if (strpos($uri, $path) !== false) {
                return $permissions;
            }
        }
        
        return [];
    }

    /**
     * ตรวจสอบว่า User มี Permission หรือไม่
     */
    private function user_has_permission($user_roles, $required_permission) {
        // ถ้าเป็น admin ทุกอย่าง
        if (in_array('admin', $user_roles, true)) {
            return true;
        }
        
        // ตรวจสอบ permission
        return in_array($required_permission, $user_roles, true);
    }

    /**
     * บันทึกเหตุการณ์ Authentication
     */
    private function log_auth_event($request, $event_type, $user_id) {
        $log_entry = sprintf(
            "[%s] AUTH | TYPE: %s | USER: %s | IP: %s | URI: %s | METHOD: %s\n",
            date('Y-m-d H:i:s'),
            $event_type,
            $user_id ?? 'anonymous',
            $request->ip ?? 'unknown',
            $request->uri ?? '/',
            $request->method ?? 'GET'
        );
        
        error_log($log_entry, 3, '/var/log/makkha8_auth.log');
    }

    /**
     * ฟังก์ชันเพิ่มเติม: สร้าง JWT Token
     */
    public function create_jwt_token($payload) {
        $header = json_encode([
            'alg' => $this->jwt_algo,
            'typ' => 'JWT'
        ]);
        
        // เติมข้อมูลที่จำเป็น
        $payload['iat'] = time();
        $payload['exp'] = time() + $this->token_expiry;
        $payload['iss'] = $this->audience;
        $payload['aud'] = $this->audience;
        
        $payload_encoded = base64_encode(json_encode($payload));
        $header_encoded = base64_encode($header);
        
        $signature = $this->sign_jwt($header_encoded . '.' . $payload_encoded);
        $signature_encoded = base64_encode($signature);
        
        return $header_encoded . '.' . $payload_encoded . '.' . $signature_encoded;
    }

    /**
     * ฟังก์ชันเพิ่มเติม: เพิกถอน Token
     */
    public function revoke_token($token, $duration = 86400) {
        if (empty($this->storage)) {
            return false;
        }
        
        $key = 'revoked_tokens:' . md5($token);
        $this->storage->setex($key, $duration, 'revoked');
        return true;
    }

    /**
     * ฟังก์ชันเพิ่มเติม: ตรวจสอบ Token (ภายนอก)
     */
    public function check_token($token) {
        $result = $this->validate_token_auto($token);
        return $result['valid'] ?? false;
    }
}