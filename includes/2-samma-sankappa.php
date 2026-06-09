<?php
// มรรคข้อ 2: ตรวจ Routing (valid paths / suspicious endpoints)
class Makkha8_Samma_Sankappa implements Makkha8_Module_Interface {
    public function get_name() { return 'samma-sankappa'; }
    public function run(Makkha8_Request $request) {
        $uri = strtolower($request->uri);
        $sensitive_patterns = ['/wp-admin/', '/xmlrpc.php', '/wp-login.php'];
        foreach ($sensitive_patterns as $p) {
            if (strpos($uri, $p) !== false && !empty($request->cookies['wordpress_logged_in'])) {
                return ['allow' => true, 'reason' => 'auth cookie present'];
            }
            if (strpos($uri, $p) !== false) {
                // flag but not block by default
                return ['suspicious' => true, 'reason' => 'accessing sensitive path: '.$p];
            }
        }
        return [];
    }
}
