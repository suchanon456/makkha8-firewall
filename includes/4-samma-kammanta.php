<?php
// มรรคข้อ 4: ตรวจการกระทำ (CSRF / method checks)
class Makkha8_Samma_Kammanta implements Makkha8_Module_Interface {
    public function get_name() { return 'samma-kammanta'; }
    public function run(Makkha8_Request $request) {
        // Block unsafe methods for simple sites
        $unsafe = ['PUT','DELETE','TRACE','TRACK'];
        if (in_array(strtoupper($request->method), $unsafe)) {
            return ['block' => true, 'reason' => 'unsafe HTTP method: '.$request->method];
        }
        // Check presence of CSRF token in state-changing requests
        if (in_array(strtoupper($request->method), ['POST','PUT','DELETE'])) {
            $has_token = isset($request->post['_csrf']) || isset($request->headers['X-Csrf-Token']) || isset($request->get['_csrf']);
            if (!$has_token) {
                return ['suspicious' => true, 'reason' => 'possible missing CSRF token'];
            }
        }
        return [];
    }
}
