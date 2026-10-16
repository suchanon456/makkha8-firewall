<?php
// Makkha8 Scanner - XAMPP Edition v2 - แสดงโค้ดที่เป็นช่องโหว่ + บรรทัด
class Makkha8_Scanner {
    protected $root;
    protected $ignore_dirs = ['.git', 'node_modules', 'vendor', 'quarantine', 'cache', '.vscode', '.idea'];
    protected $risk_tiers = ['critical'=>80,'high'=>50,'medium'=>30,'low'=>1];

    public function __construct($root = null) {
        $this->root = $root ?: __DIR__;
    }

    protected function get_risk_tier($score) {
        if ($score >= 80) return 'critical';
        if ($score >= 50) return 'high';
        if ($score >= 30) return 'medium';
        return 'low';
    }

    public function scan($start = null) {
        @set_time_limit(300);
        $start = $start ?: $this->root;
        $results = [];
        if (!is_dir($start)) return $results;

        $directory = new RecursiveDirectoryIterator($start, RecursiveDirectoryIterator::SKIP_DOTS);
        $iterator = new RecursiveIteratorIterator($directory, RecursiveIteratorIterator::SELF_FIRST);
        $scanned = 0;
        foreach ($iterator as $file) {
            if ($scanned > 3000) break;
            if (!$file->isFile()) continue;
            $path = $file->getPathname();
            $norm = str_replace(DIRECTORY_SEPARATOR, '/', $path);
            foreach ($this->ignore_dirs as $d) if (strpos($norm, $d)!==false) continue 2;
            if ($file->getSize() > 5*1024*1024) continue;
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (!in_array($ext, ['php','phtml','inc'])) continue;

            $scanned++;
            $content = @file_get_contents($path);
            if ($content===false) continue;
            $lines = explode("\n", $content);

            $findings = [];
            $score = 0;

            // Patterns ที่อันตรายจริงๆ
            $checks = [
                'eval(' => ['pattern'=>'/\beval\s*\(/i', 'score'=>20, 'desc'=>'พบ eval() - รันโค้ดจากสตริง'],
                'base64_decode' => ['pattern'=>'/base64_decode\s*\(/i', 'score'=>15, 'desc'=>'พบ base64_decode - อาจซ่อนโค้ด'],
                'shell_exec' => ['pattern'=>'/shell_exec\s*\(/i', 'score'=>25, 'desc'=>'พบ shell_exec - รันคำสั่ง OS'],
                'exec(' => ['pattern'=>'/\bexec\s*\(/i', 'score'=>25, 'desc'=>'พบ exec() - รันคำสั่ง OS'],
                'system(' => ['pattern'=>'/\bsystem\s*\(/i', 'score'=>25, 'desc'=>'พบ system() - รันคำสั่ง OS'],
                'passthru' => ['pattern'=>'/passthru\s*\(/i', 'score'=>25, 'desc'=>'พบ passthru()'],
                'preg_replace /e' => ['pattern'=>'/preg_replace\s*\(\s*[\'\"]?\/.*\/[a-z]*e[a-z]*[\'\"]?\s*,/i', 'score'=>30, 'desc'=>'preg_replace /e modifier - RCE'],
                'assert(' => ['pattern'=>'/\bassert\s*\(/i', 'score'=>15, 'desc'=>'พบ assert() - อาจเป็น RCE'],
                'create_function' => ['pattern'=>'/create_function\s*\(/i', 'score'=>15, 'desc'=>'create_function deprecated และอันตราย'],
                'long_obfuscated_string' => ['pattern'=>'/\S{400,}/', 'score'=>5, 'desc'=>'พบสตริงยาวผิดปกติ 400+ ตัว (อาจซ่อนโค้ด)'],
            ];

            foreach ($checks as $key=>$c) {
                foreach ($lines as $idx=>$line) {
                    if (preg_match($c['pattern'], $line)) {
                        // ข้ามถ้าเป็นไฟล์ scanner ตัวเอง (whitelist ตัวเอง)
                        if (strpos($path, 'class-makkha8-scanner')!==false && strpos($line, '$checks')!==false) continue;
                        if (strpos($path, 'class-makkha8-scanner')!==false && strpos($line, 'pattern')!==false) continue;
                        $findings[] = [
                            'line_no' => $idx+1,
                            'type' => $key,
                            'desc' => $c['desc'],
                            'code' => trim(substr($line,0,500)),
                            'score' => $c['score']
                        ];
                        $score += $c['score'];
                    }
                }
            }

            if ($score>0) {
                $results[] = [
                    'file'=>$path,
                    'score'=>$score,
                    'risk_tier'=>$this->get_risk_tier($score),
                    'findings'=>$findings,
                    'mtime'=>$file->getMTime(),
                    'size'=>$file->getSize()
                ];
            }
        }
        usort($results, fn($a,$b)=> $b['score'] <=> $a['score']);
        return $results;
    }
}
?>
