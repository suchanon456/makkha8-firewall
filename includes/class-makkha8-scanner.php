<?php
// Standalone scanner class used from admin to scan and quarantine/remove infected files.
class Makkha8_Scanner {
    protected $root;
    protected $ignore_dirs = ['.git', 'node_modules', 'wp-content/plugins/makkha8-firewall/quarantine', 'wp-content/plugins/makkha8-firewall/system'];
    protected $plugin_core_path = 'wp-content/plugins/makkha8-firewall';
    protected $wp_core_paths = ['wp-includes/', 'wp-admin/'];

    // Risk tier thresholds: Critical(80+), High(50-79), Medium(30-49), Low(1-29)
    protected $risk_tiers = [
        'critical' => 80,
        'high' => 50,
        'medium' => 30,
        'low' => 1,
    ];

    public function __construct($root = null) {
        $this->root = $root ?: ABSPATH;
        // Always ignore the plugin itself (trusted zone)
        $this->ignore_dirs[] = str_replace(DIRECTORY_SEPARATOR, '/', 'wp-content/plugins/makkha8-firewall');
    }

    protected function get_risk_tier($score, $is_plugin_core = false) {
        if ($is_plugin_core) return 'whitelisted';
        if ($score >= $this->risk_tiers['critical']) return 'critical';
        if ($score >= $this->risk_tiers['high']) return 'high';
        if ($score >= $this->risk_tiers['medium']) return 'medium';
        return 'low';
    }

    protected function is_plugin_core($path) {
        $normalized = str_replace(DIRECTORY_SEPARATOR, '/', $path);
        return strpos($normalized, $this->plugin_core_path) !== false;
    }

    protected function is_whitelisted($path) {
        $whitelisted = get_option('makkha8_whitelist', []);
        if (is_array($whitelisted)) {
            return in_array($path, $whitelisted);
        }
        return false;
    }

    public function mark_as_safe($path) {
        $whitelisted = get_option('makkha8_whitelist', []);
        if (!is_array($whitelisted)) $whitelisted = [];
        if (!in_array($path, $whitelisted)) {
            $whitelisted[] = $path;
            update_option('makkha8_whitelist', $whitelisted);
        }
    }

    public function unmark_safe($path) {
        $whitelisted = get_option('makkha8_whitelist', []);
        if (is_array($whitelisted)) {
            $whitelisted = array_filter($whitelisted, function($p){ return $p !== $path; });
            update_option('makkha8_whitelist', array_values($whitelisted));
        }
    }

    public function scan($start = null) {
        $start = $start ?: $this->root;
        $results = [];
        if (!is_dir($start)) {
            return $results;
        }

        $directory = new RecursiveDirectoryIterator($start, RecursiveDirectoryIterator::SKIP_DOTS);
        $iterator = new RecursiveIteratorIterator($directory);
        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            $path = $file->getPathname();
            $normalized_path = str_replace(DIRECTORY_SEPARATOR, '/', $path);

            // Check if whitelisted
            if ($this->is_whitelisted($path)) continue;

            // skip plugin's own quarantine and trusted directories
            $skip = false;
            foreach ($this->ignore_dirs as $d) {
                if (strpos($normalized_path, $d) !== false) {
                    $skip = true;
                    break;
                }
            }
            if ($skip) continue;

            // prevent huge files from crashing the scanner
            if ($file->getSize() > 5 * 1024 * 1024) {
                continue;
            }

            // only scan php files and suspicious uploads
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (!in_array($ext, ['php','phps','phtml','php5','php7'])) {
                if (stripos($normalized_path, '.php') === false) continue;
            }

            $score = 0;
            $reasons = [];
            $content = @file_get_contents($path);
            if ($content === false) continue;

            // Detector: obfuscation patterns
            $patterns = [
                '/base64_decode\s*\(/i',
                '/eval\s*\(/i',
                '/gzuncompress\s*\(/i',
                '/str_rot13\s*\(/i',
                '/create_function\s*\(/i',
                '/preg_replace\s*\(\s*\/.+\/[e]\s*,/i',
                '/\$\w+\s*=\s*\"\\x/',
                '/exec\s*\(/i',
                '/shell_exec\s*\(/i',
                '/passthru\s*\(/i',
                '/assert\s*\(/i',
            ];
            foreach ($patterns as $p) {
                if (preg_match($p, $content)) { $score += 5; $reasons[] = 'obfuscation'; }
            }

            // Detector: suspicious functions or keywords
            $sigs = ['eval(', 'base64_decode', 'assert(', 'system(', 'passthru(', 'shell_exec', 'proc_open', 'popen', 'curl_exec', 'curl_multi_exec'];
            foreach ($sigs as $s) { if (stripos($content, $s) !== false) { $score += 3; $reasons[] = 'suspicious_func'; } }

            // Detector: long single-line strings (packed payloads)
            if (preg_match('/\S{200,}/', $content)) { $score += 2; $reasons[] = 'long_string'; }

            // Detector: recently modified (may be indicator)
            $mtime = $file->getMTime();
            if ($mtime > (time() - 7*24*3600)) { $score += 1; $reasons[] = 'recent_mod'; }

            // Detector: writable by others
            $perms = $file->getPerms();
            if (($perms & 0x0002) || ($perms & 0x0004)) { // world-writable or group-writable heuristic
                $score += 1; $reasons[] = 'writable';
            }

            // Combined heuristic: obfuscation + dangerous function is much worse
            if (in_array('obfuscation', $reasons, true) && in_array('suspicious_func', $reasons, true)) {
                $score += 40;
            }

            if ($score > 0) {
                $is_core = $this->is_plugin_core($path);
                $tier = $this->get_risk_tier($score, $is_core);
                
                // Skip plugin core files from results (auto-whitelisted)
                if (!$is_core) {
                    $results[] = [
                        'file' => $path,
                        'score' => $score,
                        'reasons' => array_values(array_unique($reasons)),
                        'mtime' => $mtime,
                        'size' => $file->getSize(),
                        'action' => 'review',
                        'risk_tier' => $tier,
                    ];
                }
            }
        }
        // sort by score desc
        usort($results, function($a,$b){ return $b['score'] <=> $a['score']; });
        return array_values($results);
    }

    public function quarantine($path) {
        if (strpos($path, '..') !== false || strpos($path, './') !== false || strpos($path, '.\\') !== false) {
            return false;
        }

        $real_path = realpath($path);
        if ($real_path === false || strpos(str_replace('\\', '/', $real_path), str_replace('\\', '/', $this->root)) !== 0) {
            return false;
        }

        $quarantine_dir = $this->root . 'wp-content/plugins/makkha8-firewall/quarantine/';
        if (!is_dir($quarantine_dir)) @mkdir($quarantine_dir, 0755, true);
        if (!file_exists($real_path)) return false;
        $rel = ltrim(str_replace($this->root, '', $real_path), DIRECTORY_SEPARATOR);
        $dest = $quarantine_dir . str_replace(DIRECTORY_SEPARATOR, '__', $rel);
        if (@rename($real_path, $dest)) {
            return $dest;
        }
        return false;
    }

    public function remove($path) {
        if (!file_exists($path)) return false;
        return @unlink($path);
    }
}
