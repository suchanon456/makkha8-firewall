<?php
// Makkha8 Scanner - Fixed version with whitelist and performance improvements
class Makkha8_Scanner {
    protected $root;
    protected $ignore_dirs = ['.git', 'node_modules', 'vendor', 'wp-content/plugins/makkha8-firewall/quarantine', 'wp-content/plugins/makkha8-firewall/system', 'wp-content/cache', 'wp-content/uploads/cache'];
    protected $plugin_core_path = 'wp-content/plugins/makkha8-firewall';
    protected $wp_core_paths = ['wp-includes/', 'wp-admin/'];

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
        // Ignore storage logs to avoid self-detection
        $this->ignore_dirs[] = 'makkha8_error.log';
        $this->ignore_dirs[] = 'makkha8_exception.log';
        $this->ignore_dirs[] = 'makkha8_engine.log';
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
            $whitelisted = array_filter($whitelisted, function($p) use ($path) { return $p !== $path; });
            update_option('makkha8_whitelist', array_values($whitelisted));
        }
    }

    public function scan($start = null) {
        @set_time_limit(300); // 5 minutes for XAMPP
        @ini_set('memory_limit', '512M');
        
        $start = $start ?: $this->root;
        $results = [];
        if (!is_dir($start)) {
            return $results;
        }

        $directory = new RecursiveDirectoryIterator($start, RecursiveDirectoryIterator::SKIP_DOTS);
        $iterator = new RecursiveIteratorIterator($directory, RecursiveIteratorIterator::SELF_FIRST);
        
        $scanned_count = 0;
        foreach ($iterator as $file) {
            // Prevent timeout on large sites - stop after 2000 files for now (can be made AJAX later)
            if ($scanned_count > 3000) break;
            
            if (!$file->isFile()) continue;
            $path = $file->getPathname();
            $normalized_path = str_replace(DIRECTORY_SEPARATOR, '/', $path);

            if ($this->is_whitelisted($path)) continue;

            $skip = false;
            foreach ($this->ignore_dirs as $d) {
                if (strpos($normalized_path, $d) !== false) {
                    $skip = true;
                    break;
                }
            }
            if ($skip) continue;

            if ($file->getSize() > 5 * 1024 * 1024) {
                continue;
            }

            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (!in_array($ext, ['php','phps','phtml','php5','php7'])) {
                if (stripos($normalized_path, '.php') === false) continue;
            }

            $scanned_count++;
            $score = 0;
            $reasons = [];
            $content = @file_get_contents($path);
            if ($content === false) continue;

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
                if (preg_match($p, $content)) { $score += 5; $reasons[] = 'obfuscation'; break; }
            }

            $sigs = ['eval(', 'base64_decode', 'assert(', 'system(', 'passthru(', 'shell_exec', 'proc_open', 'popen', 'curl_exec', 'curl_multi_exec'];
            foreach ($sigs as $s) { 
                if (stripos($content, $s) !== false) { 
                    $score += 3; 
                    $reasons[] = 'suspicious_func:'.$s; 
                    break;
                } 
            }

            if (preg_match('/\S{300,}/', $content)) { $score += 2; $reasons[] = 'long_string'; }

            $mtime = $file->getMTime();
            if ($mtime > (time() - 7*24*3600)) { $score += 1; $reasons[] = 'recent_mod'; }

            $perms = $file->getPerms();
            if (($perms & 0x0002)) {
                $score += 1; $reasons[] = 'world_writable';
            }

            if (in_array('obfuscation', $reasons, true) || !empty(array_filter($reasons, fn($r) => str_starts_with($r, 'suspicious_func')))) {
                // Only add heavy penalty if both present
                $has_obf = false; $has_func = false;
                foreach ($reasons as $r) {
                    if ($r === 'obfuscation') $has_obf = true;
                    if (str_starts_with($r, 'suspicious_func')) $has_func = true;
                }
                if ($has_obf && $has_func) $score += 40;
            }

            if ($score > 0) {
                $is_core = $this->is_plugin_core($path);
                $tier = $this->get_risk_tier($score, $is_core);
                
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
