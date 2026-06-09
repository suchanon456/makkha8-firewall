<?php
// มรรคข้อ 1: ตรวจเจตนา/ประเภท Request (intent/whitelist/blacklist)
class Makkha8_Samma_Ditthi implements Makkha8_Module_Interface {
    public function get_name() { return 'samma-ditthi'; }

    public function run(Makkha8_Request $request) {
        $trace = $this->trace_origin($request);

        if (!empty($trace['block'])) {
            return $trace;
        }

        if (empty($trace['origin_ip']) || !self::is_valid_ip($trace['origin_ip'])) {
            return ['block' => true, 'reason' => 'Potential Call Stack Evasion detected in Samma-Ditthi'];
        }

        if ($trace['depth'] > 8) {
            return ['block' => true, 'reason' => 'Potential Call Stack Evasion detected in Samma-Ditthi'];
        }

        if (in_array($trace['origin_ip'], ['127.0.0.1', '::1'], true)) {
            return ['allow' => true, 'reason' => 'local origin trace'];
        }

        return ['allow' => true, 'origin' => $trace['origin_ip']];
    }

    protected function trace_origin(Makkha8_Request $request) {
        $headers = array_change_key_case($request->headers, CASE_LOWER);
        $current_ip = $request->ip ?? '';
        $visited = [];
        $depth = 0;
        $proxy_headers = [
            'forwarded',
            'x-forwarded-for',
            'x-real-ip',
            'client-ip',
            'x-client-ip',
        ];
        $hasProxyHeader = false;

        while ($depth < 8) {
            if (!self::is_valid_ip($current_ip)) {
                break;
            }

            if (isset($visited[$current_ip])) {
                break;
            }

            $visited[$current_ip] = true;
            $next_ip = '';

            foreach ($proxy_headers as $header_name) {
                if (empty($headers[$header_name])) {
                    continue;
                }

                $hasProxyHeader = true;
                $value = trim($headers[$header_name]);
                $candidate = $this->find_next_ip_from_header($header_name, $value);

                if ($candidate && self::is_valid_ip($candidate) && !isset($visited[$candidate])) {
                    $next_ip = $candidate;
                    break;
                }
            }

            if (empty($next_ip)) {
                break;
            }

            $current_ip = $next_ip;
            $depth++;
        }

        if ($depth >= 8) {
            return ['block' => true, 'reason' => 'Potential Call Stack Evasion detected in Samma-Ditthi'];
        }

        if ($hasProxyHeader && !self::is_valid_ip($current_ip)) {
            return ['block' => true, 'reason' => 'Potential Call Stack Evasion detected in Samma-Ditthi'];
        }

        return [
            'origin_ip' => $current_ip,
            'depth' => $depth,
            'trace' => array_keys($visited),
        ];
    }

    protected function find_next_ip_from_header($header_name, $value) {
        if ($header_name === 'forwarded') {
            // Forwarded: for=client, by=proxy; choose first for value
            if (preg_match('/for="?\[?([^\]";]+)\]?"?/i', $value, $matches)) {
                return trim($matches[1]);
            }
            return '';
        }

        $parts = preg_split('/,\s*/', $value);
        if (empty($parts)) {
            return '';
        }

        // X-Forwarded-For lists the original client first.
        return trim($parts[0]);
    }

    protected static function is_valid_ip($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
}
