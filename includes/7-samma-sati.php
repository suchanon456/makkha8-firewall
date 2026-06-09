<?php
// มรรคข้อ 7: บันทึกสติ / Logging events
class Makkha8_Samma_Sati implements Makkha8_Module_Interface {
    public function get_name() { return 'samma-sati'; }
    public function run(Makkha8_Request $request) {
        $log = sprintf("[%s] %s %s IP=%s\n", date('c'), $request->method, $request->uri, $request->ip);
        // Try to write to plugin's logs directory; fallback to error_log
        $logdir = __DIR__ . '/../logs';
        if (!is_dir($logdir)) @mkdir($logdir, 0755, true);
        $file = $logdir . '/makkha8.log';
        if (@file_put_contents($file, $log, FILE_APPEND | LOCK_EX) === false) {
            error_log($log);
        }
        return [];
    }
}
