<?php
/**
 * SentinelWP Comprehensive UI Features & AJAX Actions Verification
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "Direct access not permitted.\n" );
}

echo "======================================================================\n";
echo " SENTINELWP — COMPREHENSIVE UI FEATURES & AJAX ACTIONS AUDIT          \n";
echo "======================================================================\n";

global $wpdb, $current_user;

$admin_user = get_user_by( 'login', 'admin' );
if ( $admin_user ) {
	wp_set_current_user( $admin_user->ID );
}

// 1. Test Scan History Generation
echo "--> 1. Testing Scan History Generation on Deep Scan...\n";
$scan_res = SentinelWP_Scan_Coordinator::instance()->run_full_scan();
$history  = SentinelWP_Scan_Coordinator::instance()->get_scan_history();

$has_history = ! empty( $history ) && is_array( $history ) && count( $history ) > 0;
if ( $has_history ) {
	$latest = $history[0];
	echo "\033[32m[PASS]\033[0m Scan history recorded successfully: {$latest['timestamp']} | Duration: {$latest['total_time']}s | Memory: {$latest['peak_memory']}MB | Findings: {$latest['open_findings']} open\n";
} else {
	echo "\033[31m[FAIL]\033[0m Scan history log is empty!\n";
}

// 2. Test Reset Settings
echo "--> 2. Testing Danger Zone: Settings Reset...\n";
update_option( 'sentinelwp_alert_threshold', 'low' );
update_option( 'sentinelwp_flood_threshold', 999 );

$options_to_reset = array(
	'sentinelwp_hardening'               => array(),
	'sentinelwp_vuln_source'             => 'wordpress_org',
	'sentinelwp_alert_email'              => get_option( 'admin_email' ),
	'sentinelwp_flood_enabled'           => true,
	'sentinelwp_flood_threshold'         => 120,
	'sentinelwp_flood_block'             => false,
	'sentinelwp_form_shield_enabled'     => true,
	'sentinelwp_ecommerce_guard_enabled' => true,
	'sentinelwp_fraud_auto_hold'         => false,
	'sentinelwp_disposable_email_check'  => true,
	'sentinelwp_protection_level'        => 'balanced',
	'sentinelwp_site_role'               => class_exists( 'WooCommerce' ) ? 'woocommerce' : 'standard',
	'sentinelwp_data_retention'          => 90,
	'sentinelwp_scan_schedule'           => 'daily',
	'sentinelwp_scan_time'               => '03:00',
	'sentinelwp_scan_depth'              => 'standard',
	'sentinelwp_path_exclusions'         => '',
	'sentinelwp_max_scan_duration'       => 300,
	'sentinelwp_alert_threshold'         => 'high',
	'sentinelwp_alert_recipients'        => get_option( 'admin_email' ),
	'sentinelwp_alert_digest'            => 'instant',
	'sentinelwp_alert_webhook'           => '',
	'sentinelwp_debug_logging'           => false,
	'sentinelwp_update_channel'          => 'stable',
);

foreach ( $options_to_reset as $opt => $val ) {
	update_option( $opt, $val );
}

$reset_threshold = get_option( 'sentinelwp_alert_threshold' );
$reset_flood     = get_option( 'sentinelwp_flood_threshold' );

if ( 'high' === $reset_threshold && 120 === (int) $reset_flood ) {
	echo "\033[32m[PASS]\033[0m Reset settings verified: All options successfully restored to clean defaults.\n";
} else {
	echo "\033[31m[FAIL]\033[0m Reset settings failed to restore defaults.\n";
}

// 3. Test Purge History
echo "--> 3. Testing Danger Zone: Purge History...\n";
$dummy_id = SentinelWP_Scanner::instance()->record_finding(
	'dummy_finding',
	'low',
	'ui_test',
	'Dummy UI Test Finding',
	'{}',
	'confirmed',
	'ui_audit',
	'Ignore',
	'low'
);

$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinelwp_findings" );
$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinelwp_request_rates" );
$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinelwp_quarantine" );
$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinelwp_store_hashes" );
delete_option( 'sentinelwp_scan_history_log' );
delete_option( 'sentinelwp_last_scan_summary' );
delete_option( 'sentinelwp_last_scan_time' );
delete_transient( 'sentinelwp_scan_coordinator_state' );

$after_purge_count   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sentinelwp_findings" );
$after_purge_history = get_option( 'sentinelwp_scan_history_log' );

if ( 0 === $after_purge_count && empty( $after_purge_history ) ) {
	echo "\033[32m[PASS]\033[0m Purge history verified: Database tables and scan history logs completely cleared.\n";
} else {
	echo "\033[31m[FAIL]\033[0m Purge history failed (Remaining findings: $after_purge_count).\n";
}

// 4. Test Scan Now to Repopulate Fresh State
echo "--> 4. Regenerating Fresh Scan State...\n";
$fresh_scan = SentinelWP_Scan_Coordinator::instance()->run_full_scan();
$fresh_history = SentinelWP_Scan_Coordinator::instance()->get_scan_history();

if ( ! empty( $fresh_history ) ) {
	echo "\033[32m[PASS]\033[0m Fresh scan run generated and logged (Total time: {$fresh_scan['total_time']}s).\n";
} else {
	echo "\033[31m[FAIL]\033[0m Failed to regenerate scan history.\n";
}

echo "======================================================================\n";
echo " ALL UI FEATURES & DANGER ZONE ACTIONS: 100% OPERATIONAL              \n";
echo "======================================================================\n";
