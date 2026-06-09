<?php
// มรรคข้อ 8: ตรวจความตั้งมั่น (Session / Token validation)
class Makkha8_Samma_Samadhi implements Makkha8_Module_Interface {
    public function get_name() { return 'samma-samadhi'; }
    public function run(Makkha8_Request $request) {
        // Validate a simple token if present (standalone logic)
        $token = $request->headers['X-Auth-Token'] ?? ($request->get['auth_token'] ?? ($request->post['auth_token'] ?? null));
        if ($token) {
            // simple check: token length and allowed chars
            if (!preg_match('/^[a-f0-9]{32}$/i', $token)) {
                return ['block' => true, 'reason' => 'invalid token format'];
            }
        }
        return [];
    }
}
