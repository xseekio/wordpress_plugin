<?php
/**
 * Plugin Name: xSeek AI Bot Tracking
 * Description: Server-side AI bot detection for WordPress. Tracks AI bot visits via xSeek’s API (bots don’t execute JavaScript).
 * Version:     1.0.0
 * Author:      xSeek
 * License:     MIT
 * Text Domain: xseek-ai-bot-tracking
 * Requires PHP: 7.0
 *
 * Docs: https://www.xseek.io/integrations/api
 */
 
if (!defined('ABSPATH')) exit;

final class XSEEK_AI_Bot_Tracking_Plugin {
    const OPT = 'xseek_ai_bot_tracking_settings';
    const API_ENDPOINT = 'https://www.xseek.io/api/track-ai-bot';

    /** @var self|null */
    private static $instance;

    public static function instance() {
        return self::$instance ?? (self::$instance = new self());
    }

    private function __construct() {
        add_action('plugins_loaded', [$this, 'bootstrap'], 0);
        add_action('admin_menu',     [$this, 'admin_menu']);
        add_action('admin_init',     [$this, 'register_settings']);
        add_action('admin_post_xseek_send_test', [$this, 'handle_send_test']);

        register_activation_hook(__FILE__, [__CLASS__, 'activate']);
        register_deactivation_hook(__FILE__, [__CLASS__, 'deactivate']);
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'settings_link']);
    }

    /** ── Bootstrapping ───────────────────────────────────────────── */
    public function bootstrap() {
        $this->ensure_defaults();
        $this->capture_request_early();
    }

    private function ensure_defaults() {
        $opts = get_option(self::OPT, []);
        $defaults = [
            'enabled'         => 0,        // opt-in OFF by default
            'api_key_enc'     => '',       // encrypted API key blob (or empty)
            'website_id'      => '',
            'include_ip'      => 0,
            'include_referer' => 1,
            'sample_rate'     => 1.0,
            'exclude_regex'   => '#\.(?:css|js|png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|eot)$#i',
        ];

        $changed = false;
        foreach ($defaults as $k => $v) {
            if (!array_key_exists($k, $opts)) { $opts[$k] = $v; $changed = true; }
        }

        if (false === get_option(self::OPT, false)) {
            // create option with autoload = 'no'
            add_option(self::OPT, $opts, '', 'no');
        } elseif ($changed) {
            // keep autoload = 'no' on updates as well
            update_option(self::OPT, $opts, 'no');
        }
    }

    /** ── Admin UI ───────────────────────────────────────────────── */
    public function admin_menu() {
        add_options_page(
            __('xSeek AI Bot Tracking', 'xseek-ai-bot-tracking'),
            __('xSeek AI Tracking', 'xseek-ai-bot-tracking'),
            'manage_options',
            'xseek-ai-bot-tracking',
            [$this, 'render_settings']
        );
    }

    public function settings_link($links) {
        $url = admin_url('options-general.php?page=xseek-ai-bot-tracking');
        $links[] = '<a href="'.esc_url($url).'">'.esc_html__('Settings', 'xseek-ai-bot-tracking').'</a>';
        return $links;
    }

    public function register_settings() {
        register_setting('xseek_ai_bot_tracking_group', self::OPT, [$this, 'sanitize']);

        add_settings_section('xseek_main', __('xSeek API Settings', 'xseek-ai-bot-tracking'), function () {
            echo '<p>'.esc_html__('Detect AI bots server-side and send a tracking event to xSeek.', 'xseek-ai-bot-tracking').'</p>';
            echo '<p><a href="'.esc_url('https://www.xseek.io/integrations/api').'" target="_blank" rel="noopener noreferrer">'.esc_html__('View API integration docs', 'xseek-ai-bot-tracking').'</a></p>';
        }, 'xseek-ai-bot-tracking');

        $fields = [
            ['enabled',         __('Enable xSeek tracking (opt-in)', 'xseek-ai-bot-tracking'), 'checkbox'],
            ['website_id',      __('xSeek Website ID', 'xseek-ai-bot-tracking'), 'text'],
            ['api_key',         __('xSeek API Key', 'xseek-ai-bot-tracking'), 'password'],
            ['include_ip',      __('Include IP address (optional)', 'xseek-ai-bot-tracking'), 'checkbox'],
            ['include_referer', __('Include Referer header (optional)', 'xseek-ai-bot-tracking'), 'checkbox'],
            ['sample_rate',     __('Sample rate (0.0–1.0)', 'xseek-ai-bot-tracking'), 'number'],
            ['exclude_regex',   __('Exclude paths (regex)', 'xseek-ai-bot-tracking'), 'text'],
        ];

        foreach ($fields as $f) {
            add_settings_field(
                $f[0],
                $f[1],
                [$this, 'field'],
                'xseek-ai-bot-tracking',
                'xseek_main',
                ['key' => $f[0], 'type' => $f[2]]
            );
        }
    }

    /** Only return the array; DO NOT call update_option() here (prevents recursion). */
    public function sanitize($in) {
        $current = get_option(self::OPT, []);
        $out = $current;

        $out['enabled']         = !empty($in['enabled']) ? 1 : 0;
        $out['website_id']      = isset($in['website_id']) ? sanitize_text_field($in['website_id']) : '';
        $out['include_ip']      = !empty($in['include_ip']) ? 1 : 0;
        $out['include_referer'] = !empty($in['include_referer']) ? 1 : 0;
        $out['sample_rate']     = isset($in['sample_rate'])
            ? max(0.0, min(1.0, floatval($in['sample_rate'])))
            : 1.0;
        $out['exclude_regex']   = isset($in['exclude_regex']) ? wp_kses_post($in['exclude_regex']) : '';

        // API key handling: if admin typed something, replace; if blank, keep existing encrypted blob.
        $new_plain = isset($in['api_key']) ? trim($in['api_key']) : '';
        if ($new_plain !== '') {
            $out['api_key_enc'] = $this->encrypt_api_key($new_plain);
        } else {
            $out['api_key_enc'] = $current['api_key_enc'] ?? '';
        }

        return $out;
    }

    public function field($args) {
        $opts = get_option(self::OPT, []);
        $k = esc_attr($args['key']);
        $t = $args['type'];

        if ($t === 'checkbox') {
            $v = !empty($opts[$k]) ? 1 : 0;
            echo '<label><input type="checkbox" name="'.self::OPT.'['.$k.']" value="1" '.checked($v, 1, false).'> '.__('Enable', 'xseek-ai-bot-tracking').'</label>';
            return;
        }

        if ($t === 'number') {
            $v = isset($opts[$k]) ? $opts[$k] : '';
            echo '<input type="number" step="0.01" min="0" max="1" name="'.self::OPT.'['.$k.']" value="'.esc_attr($v).'">';
            return;
        }

        if ($t === 'password' && $k === 'api_key') {
            // Never echo the key back. Show a placeholder indicating one is stored.
            $placeholder = (!empty($opts['api_key_enc'])) ? __('(stored — type to replace)', 'xseek-ai-bot-tracking') : '';
            echo '<input type="password" class="regular-text" name="'.self::OPT.'[api_key]" value="" placeholder="'.esc_attr($placeholder).'" autocomplete="new-password">';
            echo '<p class="description">'.esc_html__('Type to set and leave blank to keep the existing value.', 'xseek-ai-bot-tracking').'</p>';
            return;
        }

        $v = isset($opts[$k]) ? $opts[$k] : '';
        echo '<input type="text" class="regular-text" name="'.self::OPT.'['.$k.']" value="'.esc_attr($v).'">';
    }

    public function render_settings() {
        if (!current_user_can('manage_options')) return;

        echo '<div class="wrap"><h1>xSeek AI Bot Tracking</h1>';
        echo '<form method="post" action="options.php">';
        settings_fields('xseek_ai_bot_tracking_group');
        do_settings_sections('xseek-ai-bot-tracking');
        submit_button();
        echo '</form>';

        $opts = get_option(self::OPT, []);
        $has_config = (!empty($opts['enabled']) && !empty($opts['website_id']) && !empty($opts['api_key_enc']));
        if ($has_config) {
            echo '<hr><h2>'.esc_html__('Health Check', 'xseek-ai-bot-tracking').'</h2>';
            echo '<p>'.esc_html__('API Endpoint:', 'xseek-ai-bot-tracking').' <code>'.esc_html(self::API_ENDPOINT).'</code></p>';
            echo '<p>'.esc_html__('Website ID:', 'xseek-ai-bot-tracking').' <code>'.esc_html($opts['website_id']).'</code></p>';
            echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'">';
            wp_nonce_field('xseek_test');
            echo '<input type="hidden" name="action" value="xseek_send_test">';
            submit_button(__('Send Test Event', 'xseek-ai-bot-tracking'), 'secondary');
            echo '</form>';
        }

        if (!empty($_GET['xseek_test'])) {
            $val = sanitize_text_field(wp_unslash($_GET['xseek_test']));
            if ($val === 'success') {
                echo '<div class="notice notice-success"><p>'.esc_html__('Test event sent successfully.', 'xseek-ai-bot-tracking').'</p></div>';
            } elseif ($val === 'error') {
                echo '<div class="notice notice-error"><p>'.esc_html__('Test event failed. Check your API key and Website ID.', 'xseek-ai-bot-tracking').'</p></div>';
            }
        }

        echo '<hr><p><em>'.esc_html__('Privacy:', 'xseek-ai-bot-tracking').'</em> '.esc_html__('Disabled by default. When enabled, this detects AI bots via User-Agent and sends botName, userAgent, url, websiteId, and optional ip/referer to xSeek.', 'xseek-ai-bot-tracking').'</p>';
        echo '</div>';
    }

    /** ── Crypto helpers ──────────────────────────────────────────── */
    private function crypto_key() {
        $base = AUTH_KEY . SECURE_AUTH_SALT;
        return substr(hash('sha256', $base, true), 0, 32);
    }

    private function encrypt_api_key($plain) {
        if (function_exists('sodium_crypto_secretbox')) {
            $k = $this->crypto_key();
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ct = sodium_crypto_secretbox($plain, $nonce, $k);
            return base64_encode($nonce . $ct);
        }

        return $plain;
    }

    private function decrypt_api_key($blob) {
        if ($blob === '' || $blob === null) return '';
        if (function_exists('sodium_crypto_secretbox_open')) {
            $raw = base64_decode($blob, true);
            if ($raw !== false && strlen($raw) > SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
                $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
                $ct = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
                $k = $this->crypto_key();
                $pt = @sodium_crypto_secretbox_open($ct, $nonce, $k);
                if ($pt !== false) return $pt;
            }
        }
        // Fallback: assume plaintext
        return $blob;
    }

    /** ── xSeek bot detection (patterns from xSeek docs) ─────────── */
    private function ai_bot_patterns() {
        return [
            'anthropic-ai' => '/anthropic-ai/i',
            'claudebot' => '/ClaudeBot/i',
            'claude-web' => '/claude-web/i',
            'claude-user' => '/Claude-User/i',
            'claude-searchbot' => '/Claude-SearchBot/i',
            'perplexitybot' => '/PerplexityBot/i',
            'perplexity-user' => '/Perplexity-User/i',
            'grokbot' => '/GrokBot(?!.*DeepSearch)/i',
            'grok-search' => '/xAI-Grok/i',
            'grok-deepsearch' => '/Grok-DeepSearch/i',
            'GPTBot' => '/GPTBot/i',
            'chatgpt-user' => '/ChatGPT-User/i',
            'oai-searchbot' => '/OAI-SearchBot/i',
            'google-extended' => '/Google-Extended/i',
            'applebot' => '/Applebot(?!-Extended)/i',
            'applebot-extended' => '/Applebot-Extended/i',
            'meta-external' => '/meta-externalagent/i',
            'meta-externalfetcher' => '/meta-externalfetcher/i',
            'bingbot' => '/Bingbot(?!.*AI)/i',
            'bingpreview' => '/bingbot.*Chrome/i',
            'microsoftpreview' => '/MicrosoftPreview/i',
            'cohere-ai' => '/cohere-ai/i',
            'cohere-training-data-crawler' => '/cohere-training-data-crawler/i',
            'youbot' => '/YouBot/i',
            'duckassistbot' => '/DuckAssistBot/i',
            'semanticscholarbot' => '/SemanticScholarBot/i',
            'ccbot' => '/CCBot/i',
            'ai2bot' => '/AI2Bot/i',
            'ai2bot-dolma' => '/AI2Bot-Dolma/i',
            'aihitbot' => '/aiHitBot/i',
            'amazonbot' => '/Amazonbot/i',
            'novaact' => '/NovaAct/i',
            'brightbot' => '/Brightbot/i',
            'bytespider' => '/Bytespider/i',
            'tiktokspider' => '/TikTokSpider/i',
            'cotoyogi' => '/Cotoyogi/i',
            'crawlspace' => '/Crawlspace/i',
            'pangubot' => '/PanguBot/i',
            'petalbot' => '/PetalBot/i',
            'semrushbot-ocob' => '/SemrushBot-OCOB/i',
            'semrushbot-swa' => '/SemrushBot-SWA/i',
            'sidetrade-indexer' => '/Sidetrade indexer bot/i',
            'timpibot' => '/Timpibot/i',
            'velenpublicwebcrawler' => '/VelenPublicWebCrawler/i',
            'omgili' => '/omgili/i',
            'omgilibot' => '/omgilibot/i',
            'webzio-extended' => '/Webzio-Extended/i',
            'baiduspider' => '/Baiduspider/i',
        ];
    }

    private function detect_bot_name($user_agent) {
        if ($user_agent === '') return null;
        foreach ($this->ai_bot_patterns() as $name => $pattern) {
            if (@preg_match($pattern, $user_agent)) return $name;
        }
        return null;
    }

    /** ── Test action handler ────────────────────────────────────── */
    public function handle_send_test() {
        if (!current_user_can('manage_options') || !check_admin_referer('xseek_test')) {
            wp_die('Forbidden', 403);
        }

        $opts = get_option(self::OPT, []);
        $api_key = $this->decrypt_api_key($opts['api_key_enc'] ?? '');
        $website_id = $opts['website_id'] ?? '';

        if (empty($opts['enabled']) || $api_key === '' || $website_id === '') {
            wp_safe_redirect(add_query_arg('xseek_test', 'error', admin_url('options-general.php?page=xseek-ai-bot-tracking')));
            exit;
        }

        $payload = [
            'botName' => 'xseek-test',
            'userAgent' => 'WordPress/xSeek-Test',
            'url' => admin_url('options-general.php?page=xseek-ai-bot-tracking'),
            'websiteId' => $website_id,
        ];

        $ok = $this->send_http_blocking($payload, $api_key);
        wp_safe_redirect(add_query_arg('xseek_test', $ok ? 'success' : 'error', admin_url('options-general.php?page=xseek-ai-bot-tracking')));
        exit;
    }

    /** ── Capture & payload ───────────────────────────────────────── */
    public function capture_request_early() {
        // Don’t run on admin screens to avoid background sends while saving settings
        if (is_admin()) return;
        if (function_exists('wp_doing_ajax') && wp_doing_ajax()) return;
        if (defined('DOING_CRON') && DOING_CRON) return;

        $opts = get_option(self::OPT, []);
        if (empty($opts['enabled'])) return;

        $api_key = $this->decrypt_api_key($opts['api_key_enc'] ?? '');
        $website_id = $opts['website_id'] ?? '';
        if ($api_key === '' || $website_id === '') return;

        // Sampling (optional)
        $sample = isset($opts['sample_rate']) ? (float)$opts['sample_rate'] : 1.0;
        if ($sample < 1.0 && mt_rand() / mt_getrandmax() > $sample) return;

        // Exclusions (skip static assets)
        $exclude = $opts['exclude_regex'] ?? '';
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if ($exclude && @preg_match($exclude, $uri)) return;

        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $bot_name = $this->detect_bot_name($ua);
        if (!$bot_name) return;

        $payload = $this->build_xseek_payload($bot_name, $ua);
        $this->ship($payload, $api_key);
    }

    private function current_domain() {
        // Prefer home_url() host; fallback to HTTP_HOST
        $home = home_url();
        $parts = wp_parse_url($home);
        return $parts['host'] ?? ($_SERVER['HTTP_HOST'] ?? '');
    }

    private function full_url_for_path($path) {
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $domain = $this->current_domain();
        return $scheme.'://'.$domain.$path;
    }

    private function client_ip() {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $leftMost = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
            return trim($leftMost);
        }
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    private function build_xseek_payload($bot_name, $user_agent) {
        $opts = get_option(self::OPT, []);
        $path = $_SERVER['REQUEST_URI'] ?? '/';
        $url = $this->full_url_for_path($path);

        $payload = [
            'botName' => $bot_name,
            'userAgent' => $user_agent,
            'url' => $url,
            'websiteId' => $opts['website_id'] ?? '',
        ];

        if (!empty($opts['include_ip'])) {
            $ip = $this->client_ip();
            if ($ip !== '') $payload['ip'] = $ip;
        }

        if (!empty($opts['include_referer']) && !empty($_SERVER['HTTP_REFERER'])) {
            $payload['referer'] = $_SERVER['HTTP_REFERER'];
        }

        return $payload;
    }

    /** ── Sending ─────────────────────────────────────────────────── */
    private function send_http_nonblocking($payload, $api_key) {
        $headers = [
            'Content-Type' => 'application/json',
            'x-api-key' => $api_key,
        ];

        // Fire-and-forget via WP HTTP API
        wp_remote_post(self::API_ENDPOINT, [
            'timeout'   => 0.01,            // don't wait
            'blocking'  => false,           // return immediately
            'headers'   => $headers,
            'body'      => wp_json_encode($payload),
            'sslverify' => true,
        ]);
    }

    private function send_http_blocking($payload, $api_key) {
        $headers = [
            'Content-Type' => 'application/json',
            'x-api-key' => $api_key,
        ];

        $res = wp_remote_post(self::API_ENDPOINT, [
            'timeout'   => 10,
            'blocking'  => true,
            'headers'   => $headers,
            'body'      => wp_json_encode($payload),
            'sslverify' => true,
        ]);

        if (is_wp_error($res)) return false;
        $code = wp_remote_retrieve_response_code($res);
        return ($code >= 200 && $code < 300);
    }

    private function ship($payload, $api_key) {
        // Optionally flush the response first if supported (true async)
        if (function_exists('fastcgi_finish_request')) { @fastcgi_finish_request(); }
        $this->send_http_nonblocking($payload, $api_key);
    }

    /** ── Lifecycle ──────────────────────────────────────────────── */
    public static function activate()  { self::instance()->ensure_defaults(); }
    public static function deactivate(){ /* nothing to clean up */ }
}

XSEEK_AI_Bot_Tracking_Plugin::instance();


