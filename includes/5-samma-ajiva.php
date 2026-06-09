<?php
// มรรคข้อ 5: ตรวจสิทธิ์ผู้ใช้ / Rate Limit
class Makkha8_Samma_Ajiva implements Makkha8_Module_Interface {
    public function get_name() { return 'samma-ajiva'; }
    public function run(Makkha8_Request $request) {
        $ip = $request->ip ?? 'unknown';
        $now = time();
        $window = 60;
        $limit = 60; // 60 requests per minute
        $key = 'makkha8_rate_hits_' . md5($ip);

        $hits = Makkha8_Storage::get($key);
        if (!is_array($hits)) {
            $hits = [];
        }

        $hits = array_filter($hits, function($t) use ($now, $window) {
            return ($t + $window) > $now;
        });

        $hits[] = $now;
        Makkha8_Storage::set($key, $hits, $window * 5);

        if (count($hits) > $limit) {
            return ['block' => true, 'reason' => 'rate limit exceeded'];
        }

        return [];
    }
}
