<?php
/**
 * SentinelWP Security Uninstall Handler
 *
 * Cleans up options, database tables, and scheduled cron events
 * when the plugin is deleted and remove_data_on_uninstall is enabled.
 *
 * @package SentinelWP
 */

// If uninstall.php isn't called directly by WordPress, bail.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$sentinelwp_remove_data = get_option( 'sentinelwp_remove_data_on_uninstall', false );

if ( ! $sentinelwp_remove_data ) {
	// Default: leave everything in place so reinstalling preserves history.
	return;
}

global $wpdb;

$sentinelwp_options = array(
	'sentinelwp_hardening',
	'sentinelwp_vuln_source',
	'sentinelwp_patchstack_key',
	'sentinelwp_wpscan_key',
	'sentinelwp_ai_provider',
	'sentinelwp_ai_api_key',
	'sentinelwp_alert_email',
	'sentinelwp_remove_data_on_uninstall',
	'sentinelwp_activated_at',
	'sentinelwp_pro_active',
	// Ecommerce security options.
	'sentinelwp_flood_enabled',
	'sentinelwp_flood_threshold',
	'sentinelwp_flood_block',
	'sentinelwp_form_shield_enabled',
	'sentinelwp_ecommerce_guard_enabled',
	'sentinelwp_fraud_auto_hold',
	'sentinelwp_disposable_email_check',
	'sentinelwp_operating_mode',
	// Additional options
	'sentinelwp_protection_level',
	'sentinelwp_site_role',
	'sentinelwp_data_retention',
	'sentinelwp_scan_schedule',
	'sentinelwp_scan_time',
	'sentinelwp_scan_depth',
	'sentinelwp_path_exclusions',
	'sentinelwp_max_scan_duration',
	'sentinelwp_modules_status',
	'sentinelwp_alert_threshold',
	'sentinelwp_alert_recipients',
	'sentinelwp_alert_digest',
	'sentinelwp_alert_webhook',
	'sentinelwp_debug_logging',
	'sentinelwp_update_channel',
	'sentinelwp_behind_proxy',
	// Logs
	'sentinelwp_risk_decision_log',
	'sentinelwp_payment_events_log',
	'sentinelwp_scan_history_log',
);

foreach ( $sentinelwp_options as $sentinelwp_opt ) {
	delete_option( $sentinelwp_opt );
}

// Custom tables created by SentinelWP
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_findings" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_quarantine" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_ai_log" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_request_rates" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_store_hashes" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared

wp_clear_scheduled_hook( 'sentinelwp_daily_scan' );
wp_clear_scheduled_hook( 'sentinelwp_flood_check' );

// Clean up transients with known prefixes.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", '_transient_sentinelwp_%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", '_transient_timeout_sentinelwp_%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
