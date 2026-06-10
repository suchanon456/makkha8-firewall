<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class Makkha8_Admin {
    protected $engine;

    public function __construct() {
        // engine is standalone
        require_once plugin_dir_path( dirname(__FILE__) ) . 'includes/class-makkha8-engine.php';
        foreach ( glob( plugin_dir_path( dirname(__FILE__) ) . 'includes/*-samma-*.php' ) as $f ) {
            require_once $f;
        }
        // scanner
        if ( file_exists( plugin_dir_path( dirname(__FILE__) ) . 'includes/class-makkha8-scanner.php' ) ) {
            require_once plugin_dir_path( dirname(__FILE__) ) . 'includes/class-makkha8-scanner.php';
        }
        $this->engine = new Makkha8_FirewallEngine();
        $map = [
            'Makkha8_Samma_Ditthi',
            'Makkha8_Samma_Sankappa',
            'Makkha8_Samma_Vaca',
            'Makkha8_Samma_Kammanta',
            'Makkha8_Samma_Ajiva',
            'Makkha8_Samma_Vayama',
            'Makkha8_Samma_Sati',
            'Makkha8_Samma_Samadhi',
        ];
        foreach ($map as $c) {
            if (class_exists($c)) $this->engine->register_module(new $c());
        }
    }

    public function init() {
        add_action('init', [$this, 'maybe_handle_request'], 0);
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_post_makkha8_toggle_extended', [$this, 'handle_extended_post']);
        add_action('admin_post_makkha8_run_scan', [$this, 'handle_run_scan']);
        add_action('admin_post_makkha8_quarantine', [$this, 'handle_quarantine']);
        add_action('admin_post_makkha8_remove', [$this, 'handle_remove']);
        add_action('admin_post_makkha8_mark_safe', [$this, 'handle_mark_safe']);
    }

    public function maybe_handle_request() {
        $request = Makkha8_Request::fromGlobals();
        $results = $this->engine->run($request);
        if ($this->engine->is_blocked($results)) {
            wp_die('Request blocked by Makkha8 Firewall');
        }
    }

    public function add_admin_menu() {
        add_menu_page('Makkha8 Firewall', 'Makkha8 Firewall', 'manage_options', 'makkha8-firewall', [$this, 'render_admin'] );
        add_submenu_page('makkha8-firewall', 'Scanner', 'Scanner', 'manage_options', 'makkha8-firewall-scan', [$this, 'render_scanner']);
    }

    public function render_scanner() {
        echo '<div class="wrap"><h1>Makkha8 Scanner</h1>';
        $last = get_option('makkha8_last_scan', []);
        $action_url = admin_url('admin-post.php?action=makkha8_run_scan');
        echo '<form method="post" action="' . esc_attr($action_url) . '">';
        wp_nonce_field('makkha8-run-scan');
        submit_button('Run Scan');
        echo '</form>';

        if (!empty($_GET['makkha8_msg'])) {
            $msg = esc_html($_GET['makkha8_msg']);
            if ($msg === 'scan_done') echo '<div class="updated notice"><p>Scan completed successfully.</p></div>';
            if ($msg === 'quarantined') echo '<div class="updated notice"><p>File quarantined.</p></div>';
            if ($msg === 'removed') echo '<div class="updated notice"><p>File removed.</p></div>';
            if ($msg === 'marked_safe') echo '<div class="updated notice"><p>File marked as safe. It will be ignored in future scans.</p></div>';
        }

        if (!empty($last) && is_array($last)) {
            // Filter by risk tier
            $critical = array_filter($last, function($r){ return ($r['risk_tier'] ?? 'low') === 'critical'; });
            $high = array_filter($last, function($r){ return ($r['risk_tier'] ?? 'low') === 'high'; });
            $medium = array_filter($last, function($r){ return ($r['risk_tier'] ?? 'low') === 'medium'; });
            $low = array_filter($last, function($r){ return ($r['risk_tier'] ?? 'low') === 'low'; });
            
            echo '<h2>Scan Results Summary</h2>';
            echo '<p>' . '<span style="display:inline-block;margin-right:15px;"><span style="background:#dc3545;color:white;padding:3px 8px;border-radius:3px;">🔴 Critical: ' . count($critical) . '</span></span>' . '<span style="display:inline-block;margin-right:15px;"><span style="background:#fd7e14;color:white;padding:3px 8px;border-radius:3px;">🟠 High: ' . count($high) . '</span></span>' . '<span style="display:inline-block;margin-right:15px;"><span style="background:#ffc107;color:black;padding:3px 8px;border-radius:3px;">🟡 Medium: ' . count($medium) . '</span></span>' . '<span style="display:inline-block;"><span style="background:#28a745;color:white;padding:3px 8px;border-radius:3px;">🟢 Low: ' . count($low) . '</span></span>' . '</p>';
            
            // Tabs
            $current_tab = isset($_GET['makkha8_tab']) ? sanitize_text_field($_GET['makkha8_tab']) : 'critical';
            echo '<h3 style="border-bottom:1px solid #ccc;padding-bottom:10px;margin-bottom:20px;">';
            foreach (['critical' => '🔴 Critical', 'high' => '🟠 High', 'medium' => '🟡 Medium', 'low' => '🟢 Low'] as $tab => $label) {
                $active = ($tab === $current_tab) ? 'style="font-weight:bold;border-bottom:3px solid #0073aa;"' : '';
                echo '<a href="' . esc_url(add_query_arg('makkha8_tab', $tab)) . '" ' . $active . ' style="margin-right:20px;text-decoration:none;">' . $label . '</a>';
            }
            echo '</h3>';
            
            // Display current tab
            $to_show = [];
            if ($current_tab === 'critical') $to_show = $critical;
            elseif ($current_tab === 'high') $to_show = $high;
            elseif ($current_tab === 'medium') $to_show = $medium;
            else $to_show = $low;
            
            if (empty($to_show)) {
                echo '<p><em>No files in this category.</em></p>';
            } else {
                echo '<form method="post" action="' . esc_attr(admin_url('admin-post.php?action=makkha8_quarantine')) . '">';
                wp_nonce_field('makkha8-quarantine');
                echo '<table class="widefat"><thead><tr><th></th><th>File</th><th>Score</th><th>Reasons</th><th>Actions</th></tr></thead><tbody>';
                foreach ($to_show as $row) {
                    $file = esc_html($row['file']);
                    $score = intval($row['score']);
                    $reasons = esc_html(implode(', ', $row['reasons']));
                    $val = esc_attr(base64_encode($row['file']));
                    echo '<tr><td><input type="checkbox" name="files[]" value="' . $val . '"></td><td>' . $file . '</td><td>' . $score . '</td><td>' . $reasons . '</td><td><a href="' . esc_url(wp_nonce_url(add_query_arg(array('makkha8_action'=>'quarantine','file'=>$val), admin_url('admin-post.php?action=makkha8_quarantine')), 'makkha8-quarantine')) . '">Quarantine</a> | <a href="' . esc_url(wp_nonce_url(add_query_arg(array('file'=>$val), admin_url('admin-post.php?action=makkha8_mark_safe')), 'makkha8-mark-safe')) . '">Mark Safe</a></td></tr>';
                }
                echo '</tbody></table>';
                echo '<p><button class="button button-primary" type="submit">Quarantine selected</button></p></form>';
            }
        }
        echo '</div>';
    }

    public function handle_run_scan() {
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        check_admin_referer('makkha8-run-scan');
        $scanner = new Makkha8_Scanner(ABSPATH);
        $results = $scanner->scan();
        update_option('makkha8_last_scan', $results);
        wp_redirect(add_query_arg('makkha8_msg','scan_done', admin_url('admin.php?page=makkha8-firewall-scan')));
        exit;
    }

    public function handle_quarantine() {
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        check_admin_referer('makkha8-quarantine');
        $files = $_POST['files'] ?? [];
        $scanner = new Makkha8_Scanner(ABSPATH);
        foreach ($files as $f) {
            $path = base64_decode($f);
            $scanner->quarantine($path);
        }
        wp_redirect(add_query_arg('makkha8_msg','quarantined', admin_url('admin.php?page=makkha8-firewall-scan')));
        exit;
    }

    public function handle_remove() {
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        check_admin_referer('makkha8-quarantine');
        $file = $_REQUEST['file'] ?? '';
        $path = base64_decode($file);
        $scanner = new Makkha8_Scanner(ABSPATH);
        $scanner->remove($path);
        wp_redirect(add_query_arg('makkha8_msg','removed', admin_url('admin.php?page=makkha8-firewall-scan')));
        exit;
    }

    public function handle_mark_safe() {
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        check_admin_referer('makkha8-mark-safe');
        $file = $_REQUEST['file'] ?? '';
        $path = base64_decode($file);
        $scanner = new Makkha8_Scanner(ABSPATH);
        $scanner->mark_as_safe($path);
        wp_redirect(add_query_arg('makkha8_msg','marked_safe', admin_url('admin.php?page=makkha8-firewall-scan')));
        exit;
    }

    public function render_admin() {
        $status = $this->get_extended_status();
        $action = $status ? 'Disable' : 'Enable';
        $nonce = wp_create_nonce('makkha8-extended-protect');
        $action_url = admin_url('admin-post.php?action=makkha8_toggle_extended');

        echo '<div class="wrap"><h1>Makkha8 Firewall</h1>';
        echo '<p>Modules registered:</p><ul>';
        $map = [
            'Makkha8_Samma_Ditthi',
            'Makkha8_Samma_Sankappa',
            'Makkha8_Samma_Vaca',
            'Makkha8_Samma_Kammanta',
            'Makkha8_Samma_Ajiva',
            'Makkha8_Samma_Vayama',
            'Makkha8_Samma_Sati',
            'Makkha8_Samma_Samadhi',
        ];
        foreach ($map as $c) {
            if (class_exists($c)) echo '<li>' . esc_html($c) . '</li>';
        }
        echo '</ul>';

        echo '<h2>Extended Protection</h2>';
        echo '<p>Extended Protection will write an <code>.user.ini</code> or <code>.htaccess</code> entry in the site root to set <code>auto_prepend_file</code> so the firewall runs before WordPress.</p>';
        echo '<p>Current status: <strong>' . ($status ? 'Enabled' : 'Disabled') . '</strong></p>';

        echo '<form method="post" action="' . esc_attr($action_url) . '">';
        wp_nonce_field('makkha8-extended-protect');
        echo '<input type="hidden" name="makkha8_action" value="' . ($status ? 'disable' : 'enable') . '">';
        submit_button($action . ' Extended Protection');
        echo '</form>';

        echo '</div>';
    }

    public function handle_extended_post() {
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        check_admin_referer('makkha8-extended-protect');
        $act = sanitize_text_field($_POST['makkha8_action'] ?? '');
        if ($act === 'enable') {
            $ok = $this->enable_extended_protection();
            if ($ok !== true) wp_redirect(add_query_arg('makkha8_msg', 'error', admin_url('admin.php?page=makkha8-firewall')));
            else wp_redirect(add_query_arg('makkha8_msg', 'enabled', admin_url('admin.php?page=makkha8-firewall')));
            exit;
        } else {
            $ok = $this->disable_extended_protection();
            if ($ok !== true) wp_redirect(add_query_arg('makkha8_msg', 'error', admin_url('admin.php?page=makkha8-firewall')));
            else wp_redirect(add_query_arg('makkha8_msg', 'disabled', admin_url('admin.php?page=makkha8-firewall')));
            exit;
        }
    }

    protected function get_extended_status() {
        $root = ABSPATH;
        $target = realpath( plugin_dir_path( dirname(__FILE__) ) . 'system/Firewall/FirewallEngine.php' );
        if (!$target) return false;
        $userini = $root . '.user.ini';
        if (file_exists($userini)) {
            $contents = file_get_contents($userini);
            if (strpos($contents, "auto_prepend_file") !== false && strpos($contents, $target) !== false) return true;
        }
        $ht = $root . '.htaccess';
        if (file_exists($ht)) {
            $contents = file_get_contents($ht);
            if (strpos($contents, $target) !== false) return true;
        }
        return false;
    }

    protected function enable_extended_protection() {
        $root = ABSPATH;
        $target = realpath( plugin_dir_path( dirname(__FILE__) ) . 'system/Firewall/FirewallEngine.php' );
        if (!$target) return 'bootstrap_not_found';
        $line = "auto_prepend_file = '" . str_replace("'", "\\'", $target) . "'\n";

        $userini = $root . '.user.ini';
        // Try .user.ini first
        if (is_writable($root) || file_exists($userini) && is_writable($userini) || !file_exists($userini) && is_writable($root)) {
            $prev = file_exists($userini) ? file_get_contents($userini) : '';
            // remove any existing lines we added earlier
            $prev = preg_replace('/^auto_prepend_file\s*=.*$/mi', '', $prev);
            $new = trim($prev) . "\n" . $line;
            if (file_put_contents($userini, $new, LOCK_EX) === false) return 'write_failed_userini';
            return true;
        }

        // Fallback to .htaccess
        $ht = $root . '.htaccess';
        $entry = "# Makkha8 Firewall start\n<IfModule mod_php7.c>\nphp_value auto_prepend_file '" . str_replace("'","\\'", $target) . "'\n</IfModule>\n# Makkha8 Firewall end\n";
        $prev_ht = file_exists($ht) ? file_get_contents($ht) : '';
        // strip old block
        $prev_ht = preg_replace('/# Makkha8 Firewall start[\s\S]*# Makkha8 Firewall end\n?/mi', '', $prev_ht);
        $new_ht = $prev_ht . "\n" . $entry;
        if (file_put_contents($ht, $new_ht, LOCK_EX) === false) return 'write_failed_ht';
        return true;
    }

    protected function disable_extended_protection() {
        $root = ABSPATH;
        $userini = $root . '.user.ini';
        $target = realpath( plugin_dir_path( dirname(__FILE__) ) . 'system/Firewall/FirewallEngine.php' );
        if ($target && file_exists($userini)) {
            $contents = file_get_contents($userini);
            $new = preg_replace('/^auto_prepend_file\s*=.*$/mi', '', $contents);
            if (file_put_contents($userini, $new, LOCK_EX) === false) return 'write_failed_userini';
            return true;
        }
        $ht = $root . '.htaccess';
        if (file_exists($ht)) {
            $contents = file_get_contents($ht);
            $new = preg_replace('/# Makkha8 Firewall start[\s\S]*# Makkha8 Firewall end\n?/mi', '', $contents);
            if (file_put_contents($ht, $new, LOCK_EX) === false) return 'write_failed_ht';
            return true;
        }
        return true;
    }
}
