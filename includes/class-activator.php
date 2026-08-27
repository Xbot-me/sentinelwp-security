<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fires once on plugin activation. Creates the findings table and default
 * options, and schedules the daily scan.
 */
class SentinelWP_Activator {

	public static function activate() {
		self::create_tables();
		self::set_default_options();
		self::schedule_cron_events();

		update_option( 'sentinelwp_activated_at', time(), false );
	}

	private static function create_tables() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$table = $wpdb->prefix . 'sentinelwp_findings';
		$sql = "CREATE TABLE $table (
			id bigint(20) unsigned NOT NULL auto_increment,
			type varchar(40) NOT NULL,
			severity varchar(20) NOT NULL,
			confidence varchar(20) NOT NULL default 'medium',
			detector varchar(64) NOT NULL default '',
			source varchar(191) NOT NULL,
			title varchar(255) NOT NULL,
			details longtext,
			remediation text default NULL,
			false_positive_risk varchar(20) NOT NULL default 'low',
			ai_verdict varchar(40) default NULL,
			ai_reason text default NULL,
			status varchar(20) NOT NULL default 'new',
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY type (type),
			KEY severity (severity),
			KEY confidence (confidence),
			KEY detector (detector),
			KEY status (status),
			KEY created_at (created_at)
		) $charset_collate;";

		$log_table = $wpdb->prefix . 'sentinelwp_ai_log';
		$sql .= "CREATE TABLE $log_table (
			id bigint(20) unsigned NOT NULL auto_increment,
			provider varchar(40) NOT NULL,
			job_type varchar(40) NOT NULL,
			input_hash varchar(64) NOT NULL,
			verdict varchar(40) default NULL,
			confidence varchar(20) default NULL,
			fallback_used tinyint(1) NOT NULL default 0,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY job_type (job_type)
		) $charset_collate;";

		$rates_table = $wpdb->prefix . 'sentinelwp_request_rates';
		$sql .= "CREATE TABLE $rates_table (
			id bigint(20) unsigned NOT NULL auto_increment,
			ip_hash varchar(64) NOT NULL,
			endpoint varchar(40) NOT NULL,
			hit_count int(10) unsigned NOT NULL default 1,
			window_id bigint(20) unsigned NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY ip_endpoint_window (ip_hash, endpoint, window_id),
			KEY window_id (window_id)
		) $charset_collate;";

		$hashes_table = $wpdb->prefix . 'sentinelwp_store_hashes';
		$sql .= "CREATE TABLE $hashes_table (
			option_name varchar(191) NOT NULL,
			hash_value varchar(64) NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (option_name)
		) $charset_collate;";

		$quarantine_table = $wpdb->prefix . 'sentinelwp_quarantine';
		$sql .= "CREATE TABLE $quarantine_table (
			id bigint(20) unsigned NOT NULL auto_increment,
			finding_id bigint(20) unsigned default 0,
			original_path text NOT NULL,
			quarantine_filename varchar(255) NOT NULL,
			file_hash varchar(64) NOT NULL,
			file_size bigint(20) unsigned NOT NULL,
			permissions varchar(10) NOT NULL default '0644',
			file_content longtext default NULL,
			status varchar(20) NOT NULL default 'quarantined',
			created_at datetime NOT NULL,
			restored_at datetime default NULL,
			PRIMARY KEY  (id),
			KEY finding_id (finding_id),
			KEY status (status)
		) $charset_collate;";

		if ( ! function_exists( 'dbDelta' ) && file_exists( ABSPATH . 'wp-admin/includes/upgrade.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		}
		if ( function_exists( 'dbDelta' ) ) {
			dbDelta( $sql );
		}
	}

	/**
	 * Runtime schema upgrades for existing installations.
	 * Executes dbDelta safely.
	 */
	public static function maybe_upgrade_schema() {
		self::create_tables();
	}

	private static function set_default_options() {
		$defaults = array(
			'sentinelwp_hardening'                => array(),
			'sentinelwp_vuln_source'              => 'wordpress_org',
			'sentinelwp_patchstack_key'           => '',
			'sentinelwp_wpscan_key'               => '',
			'sentinelwp_ai_provider'              => '',
			'sentinelwp_ai_api_key'               => '',
			'sentinelwp_alert_email'              => get_option( 'admin_email' ),
			'sentinelwp_alert_webhook'            => '',
			'sentinelwp_remove_data_on_uninstall' => false,
			'sentinelwp_flood_enabled'            => true,
			'sentinelwp_flood_threshold'          => 120,
			'sentinelwp_flood_block'              => false,
			'sentinelwp_form_shield_enabled'      => true,
			'sentinelwp_ecommerce_guard_enabled'  => true,
			'sentinelwp_fraud_auto_hold'          => false,
			'sentinelwp_disposable_email_check'   => true,
			'sentinelwp_operating_mode'           => 'observe',
		);

		foreach ( $defaults as $key => $value ) {
			if ( false === get_option( $key ) ) {
				update_option( $key, $value, false );
			}
		}
	}

	private static function schedule_cron_events() {
		if ( ! wp_next_scheduled( 'sentinelwp_daily_scan' ) ) {
			// Schedule standard security scans
			wp_schedule_event( time(), 'daily', 'sentinelwp_daily_scan' );
		}

		if ( ! wp_next_scheduled( 'sentinelwp_flood_check' ) ) {
			// Flood monitor analysis runs every 5 minutes
			wp_schedule_event( time(), 'every_five_minutes', 'sentinelwp_flood_check' );
		}
	}
}
