makkha8-firewall
A lightweight, standalone-first firewall implementing the Noble Eightfold Path approach. Engine and modules are pure PHP and can run outside WordPress. WordPress is just one adapter.

[PHP >=7.4](https://www.php.net/)
[WordPress](https://wordpress.org/)
[License: MIT](LICENSE)

Repo: suchanon456/makkha8-firewall

1. What is this?
makkha8-firewall ไม่ใช่แค่ WAF ทั่วไป แต่แบ่งการป้องกันออกเป็น 8 โมดูลตาม มรรค 8 เพื่อให้แต่ละส่วนทำหน้าที่เดียวและทดสอบได้ง่าย

Request -> Engine -> 8 Filters -> Allow / Block / Log
Core Concepts
Engine (Makkha8_FirewallEngine): ตัวกลาง register_module() และ run($request)
Request (Makkha8_Request): Value Object จาก fromGlobals() - ทำให้ทดสอบได้โดยไม่ต้องมี $_SERVER จริง
Modules: 8 ตัว แต่ละตัว implement check($request): bool|Result
Admin (Makkha8_Admin): แค่ Adapter สำหรับ WordPress Admin UI / Logs
2. Architecture / File Tree
makkha8-firewall/
├── makkha8-firewall.php          # Plugin entry + safe loader (WP + standalone)
├── includes/
│   ├── class-makkha8-engine.php  # Makkha8_FirewallEngine
│   ├── class-makkha8-request.php # Makkha8_Request::fromGlobals()
│   ├── 1-samma-ditthi.php        # Samma Ditthi - Right View - Validate intent / Whitelist
│   ├── 2-samma-sankappa.php     # Samma Sankappa - Right Intention - Bot / UA / Purpose
│   ├── 3-samma-vaca.php         # Samma Vaca - Right Speech - XSS / SQLi / Payload inspection
│   ├── 4-samma-kammanta.php     # Samma Kammanta - Right Action - Method / Rate / Action
│   ├── 5-samma-ajiva.php         # Samma Ajiva - Right Livelihood - IP reputation / Abuse
│   ├── 6-samma-vayama.php       # Samma Vayama - Right Effort - Rate limiting / Brute force
│   ├── 7-samma-sati.php         # Samma Sati - Right Mindfulness - Logging / Anomaly detection
│   └── 8-samma-samadhi.php      # Samma Samadhi - Right Concentration - Final decision / Block
├── admin/
│   └── class-makkha8-admin.php   # WP Admin UI, settings, log viewer
├── system/Firewall/              # (Legacy / experimental rules)
├── storage/                      # Logs, cache, blocks.json (gitignored, auto-created)
├── tests/                        # PHPUnit tests for engine + modules
└── README.md
AI-readable summary for crawlers:

Entry: makkha8-firewall.php -> function makkha8_firewall_run($context)
Engine class: Makkha8_FirewallEngine with methods register_module(), run()
Module classes: Makkha8_Samma_Ditthi ... Makkha8_Samma_Samadhi
No composer required, no WP functions inside includes/
3. The Eight Modules Explained
#	Pali	Module Class	Responsibility
1	Samma Ditthi	Makkha8_Samma_Ditthi	Right View - Validate host, referer, whitelisted paths
2	Samma Sankappa	Makkha8_Samma_Sankappa	Right Intention - Detect bots, fake crawlers, bad UA
3	Samma Vaca	Makkha8_Samma_Vaca	Right Speech - Filter XSS, SQLi, PHP injection in GET/POST
4	Samma Kammanta	Makkha8_Samma_Kammanta	Right Action - Block disallowed HTTP methods, file uploads
5	Samma Ajiva	Makkha8_Samma_Ajiva	Right Livelihood - IP blacklist/whitelist, geo, reputation
6	Samma Vayama	Makkha8_Samma_Vayama	Right Effort - Rate limit, brute force on wp-login, xmlrpc
7	Samma Sati	Makkha8_Samma_Sati	Right Mindfulness - Logging, anomaly scoring
8	Samma Samadhi	Makkha8_Samma_Samadhi	Right Concentration - Final verdict: allow/block/challenge
4. Installation
WordPress (recommended)
git clone https://github.com/suchanon456/makkha8-firewall.git to wp-content/plugins/
Or download ZIP from GitHub > Upload in Plugins > Add New > Upload
Activate. If it fails, enable WP_DEBUG_LOG and check wp-content/debug.log
Go to WP Admin > Makkha8 Firewall to view logs
Requirements: PHP 7.4+, WP 5.0+, writable storage/ folder.

Standalone (no WordPress)
require __DIR__ . '/makkha8-firewall.php';
$result = makkha8_firewall_run([
    'request' => Makkha8_Request::fromGlobals()
]);
if ($result->isBlocked()) {
    http_response_code(403);
    echo "Blocked by " . $result->getReason();
    exit;
}
Composer (if you add composer.json later)
{
  "autoload": {
    "psr-4": { "Makkha8\\": "system/Firewall/" },
    "files": ["includes/class-makkha8-engine.php"]
  }
}
5. Usage & API
// Manual run
$engine = new Makkha8_FirewallEngine();
$engine->register_module(new Makkha8_Samma_Ditthi());
$engine->register_module(new Makkha8_Samma_Vaca());
// ... register all 8
$request = Makkha8_Request::fromGlobals();
$result = $engine->run($request);
if ($result['blocked']) {
    // log to storage/logs.json
    file_put_contents(__DIR__.'/storage/block.log', json_encode($request), FILE_APPEND);
}
Request object shape:

[
  'ip' => '1.2.3.4',
  'method' => 'POST',
  'uri' => '/wp-login.php',
  'ua' => '...',
  'payload' => $_REQUEST
]
6. Debugging - Why Activation Fails
Common issues fixed in v0.1.1:

require_once without file_exists() -> Fatal error if includes/ not uploaded. Fixed: Use makkha8_safe_require().
Missing storage/ folder permission -> Fixed with register_activation_hook creating folder.
Module naming 1-samma-*.php -> glob() works but use natsort() to keep order 1-10 correct.
Enable logs:

// in wp-config.php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
Then check wp-content/debug.log or for XAMPP C:\xampp\php\logs\php_error_log.

7. Roadmap
 Rename modules to class-makkha8-samma-*.php for WP.org compliance
 Add Makkha8_Result object instead of array
 Admin dashboard: block chart, IP manager
 Export logs to CSV / JSON
 Unit tests: tests/test-engine.php
 PSR-4 autoloader + Composer support
8. Contributing
PRs welcome. Please keep includes/ free of WordPress functions so engine stays standalone-testable.

git clone https://github.com/suchanon456/makkha8-firewall
cd makkha8-firewall
php tests/run.php
License
MIT © Suchanon

Credits
Inspired by Noble Eightfold Path - each module does one thing mindfully.
