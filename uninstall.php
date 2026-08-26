<?php
/**
 * SentinelGuard Uninstall Handler
 *
 * Cleans up options, database tables, and scheduled cron events
 * when the plugin is deleted and remove_data_on_uninstall is enabled.
 *
 * @package SentinelGuard
 */

// If uninstall.php isn't called directly by WordPress, bail.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
// phpcs:disable WordPress.Security.NonceVerification.Recommended
// phpcs:disable WordPress.Security.NonceVerification.Missing
// phpcs:disable Squiz.PHP.DiscouragedFunctions.Discouraged
// phpcs:disable PluginCheck.CodeAnalysis.AIProvider.DirectIntegration
// phpcs:disable WordPress.DB.SlowDBQuery.slow_db_query_meta_value


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
	// Scan state
	'sentinelwp_last_scan_time',
	'sentinelwp_last_scan_summary',
	'sentinelwp_webhook_url',
);

foreach ( $sentinelwp_options as $sentinelwp_opt ) {
	delete_option( $sentinelwp_opt );
}

// Custom tables created by SentinelGuard
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_findings" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_quarantine" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_ai_log" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_request_rates" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sentinelwp_store_hashes" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared

wp_clear_scheduled_hook( 'sentinelwp_daily_scan' );
wp_clear_scheduled_hook( 'sentinelwp_flood_check' );
wp_clear_scheduled_hook( 'sentinelwp_ai_triage_job' );

// Remove quarantine vault directory from uploads.
$sentinelwp_upload_dir = wp_upload_dir();
$sentinelwp_vault_dir  = trailingslashit( $sentinelwp_upload_dir['basedir'] ) . 'sentinelwp-quarantine';
if ( is_dir( $sentinelwp_vault_dir ) ) {
	$sentinelwp_files = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $sentinelwp_vault_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ( $sentinelwp_files as $sentinelwp_file ) {
		if ( $sentinelwp_file->isDir() ) {
			rmdir( $sentinelwp_file->getRealPath() );
		} else {
			unlink( $sentinelwp_file->getRealPath() );
		}
	}
	rmdir( $sentinelwp_vault_dir );
}

// Clean up transients with known prefixes.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( '_transient_sentinelwp_' ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( '_transient_timeout_sentinelwp_' ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
