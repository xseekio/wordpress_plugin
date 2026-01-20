<?php
if (!defined('WP_UNINSTALL_PLUGIN')) exit;

// Remove settings on uninstall
delete_option('xseek_ai_bot_tracking_settings');
