<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) exit;

delete_option( 'pow_shield_options' );
delete_option( 'pow_shield_secret' );
delete_option( 'pow_shield_secret_prev' );

// Clean up any transients we created (prefix: pows_)
global $wpdb;
$wpdb->query(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_pows_%' OR option_name LIKE '_transient_timeout_pows_%'"
);
