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
