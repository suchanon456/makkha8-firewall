makkha8-firewall
A lightweight, standalone-first firewall implementing the Noble Eightfold Path approach. Engine and modules are pure PHP and can run outside WordPress.

Repo: https://github.com/suchanon456/makkha8-firewall

🔍 Quick Navigation (AI & Human Readable)
Core Entry
Plugin Entry: makkha8-firewall.php - Safe loader, activation hook
Fixed Version (Safe Activate): See issue with require_once -> use makkha8_safe_require()
Engine & Request
includes/class-makkha8-engine.php - Makkha8_FirewallEngine::register_module(), run()
includes/class-makkha8-request.php - Makkha8_Request::fromGlobals()
The 8 Modules (Makkha 8) - Click to view code
#	File (direct link)	Class	Purpose
1	includes/1-samma-ditthi.php	Makkha8_Samma_Ditthi	Right View - Whitelist, host validation
2	includes/2-samma-sankappa.php	Makkha8_Samma_Sankappa	Right Intention - Bot/UA detection
3	includes/3-samma-vaca.php	Makkha8_Samma_Vaca	Right Speech - XSS/SQLi filter
4	includes/4-samma-kammanta.php	Makkha8_Samma_Kammanta	Right Action - Method/file upload
5	includes/5-samma-ajiva.php	Makkha8_Samma_Ajiva	Right Livelihood - IP reputation
6	includes/6-samma-vayama.php	Makkha8_Samma_Vayama	Right Effort - Rate limit/brute force
7	includes/7-samma-sati.php	Makkha8_Samma_Sati	Right Mindfulness - Logging/anomaly
8	includes/8-samma-samadhi.php	Makkha8_Samma_Samadhi	Right Concentration - Final block decision
Admin & System
[admin/class-makkha8-admin.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/admin/class-makkha8-admin.php) - WP Admin UI
[system/Firewall/](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/system/FirewallEngine.php) - Legacy / experimental rules
[storage/](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/storage/index.php) - Logs (auto-created on activation)
[tests/](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/tests/run_scanner.php) - PHPUnit tests
Raw links for AI crawlers (direct file content):

[makkha8-firewall.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/makkha8-firewall.php)
[class-makkha8-engine.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/class-makkha8-engine.php)
[class-makkha8-scanner.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/class-makkha8-scanner.php)
[class-makkha8-request.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/class-makkha8-request.php)
[1-samma-ditthi.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/1-samma-ditthi.php)
[2-samma-sankappa.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/2-samma-sankappa.php)
[3-samma-vaca.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/3-samma-vaca.php)
[4-samma-kammanta.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/4-samma-kammanta.php)
[5-samma-ajiva.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/5-samma-ajiva.php)
[6-samma-vayama.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/6-samma-vayama.php)
[7-samma-sati.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/7-samma-sati.php)
[8-samma-samadhi.php](https://raw.githubusercontent.com/suchanon456/makkha8-firewall/main/includes/8-samma-samadhi.php)

Architecture
Request (fromGlobals) -> Engine -> [1..8] Samma Modules -> Result (Allow/Block) -> Admin Log
Why activation fails (fixed in v0.1.1)
Original file used unconditional require_once. Fixed version uses:

function makkha8_safe_require($path) {
  if (file_exists(__DIR__.$path)) require_once __DIR__.$path;
}
Installation
git clone https://github.com/suchanon456/makkha8-firewall.git wp-content/plugins/
Then Activate in WP Admin. If fails, check wp-content/debug.log or XAMPP C:\xampp\php\logs\php_error_log.

Standalone usage
$result = makkha8_firewall_run(['request' => Makkha8_Request::fromGlobals()]);
if ($result->isBlocked()) { http_response_code(403); exit; }
For AI reviewers: All modules are standalone PHP, no WP dependencies inside includes/. You can review each module by following the direct file links above.
