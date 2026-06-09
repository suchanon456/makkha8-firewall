<?php
// มรรคข้อ 6: ตรวจความพยายาม (Brute Force attempts)
class Makkha8_Samma_Vayama implements Makkha8_Module_Interface {
    public function get_name() { return 'samma-vayama'; }
    public function run(Makkha8_Request $request) {
        $uri = strtolower($request->uri);
        if (strpos($uri, 'wp-login.php') !== false || strpos($uri, '/login') !== false) {
            $ip = $request->ip ?? 'unknown';
            $now = time();
            $window = 300; // 5 minutes
            $key = 'makkha8_bruteforce_' . md5($ip);

            $attempts = Makkha8_Storage::get($key);
            if (!is_array($attempts)) {
                $attempts = [];
            }

            $attempts = array_filter($attempts, function($t) use ($now, $window) {
                return ($t + $window) > $now;
            });

            $attempts[] = $now;
            Makkha8_Storage::set($key, $attempts, $window * 2);

            if (count($attempts) > 20) {
                return ['block' => true, 'reason' => 'brute force suspected'];
            }
        }
        return [];
    }
}
