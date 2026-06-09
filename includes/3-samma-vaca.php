<?php
// มรรคข้อ 3: ตรวจวาจา/Input (detect SQLi / XSS-like patterns)
class Makkha8_Samma_Vaca implements Makkha8_Module_Interface {
    public function get_name() { return 'samma-vaca'; }
    public function run(Makkha8_Request $request) {
        $payload = strtolower($request->body . ' ' . implode(' ', $request->get) . ' ' . implode(' ', $request->post));
        $pattern = '/(\'\s*or\s+|union\s+select|select\s+\*\s+from|drop\s+table|information_schema|<script|javascript:alert|onerror=)/i';

        if (preg_match($pattern, $payload, $matches)) {
            $match = strtolower($matches[0]);
            $is_sqli = stripos($match, "' or ") !== false
                || stripos($match, 'union select') !== false
                || stripos($match, 'select * from') !== false
                || stripos($match, 'drop table') !== false
                || stripos($match, 'information_schema') !== false;

            if ($is_sqli) {
                return ['block' => true, 'reason' => 'SQLi signature: ' . $match];
            }

            return ['suspicious' => true, 'reason' => 'XSS signature: ' . $match];
        }

        return [];
    }
}
