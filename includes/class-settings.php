<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * All plugin options are registered here through the Settings API with
 * explicit sanitize callbacks. No handler anywhere in the plugin should
 * write raw $_POST data straight to an option.
 */
class SentinelWP_Settings {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'update_option_sentinelwp_scan_schedule', array( $this, 'reschedule_scan_cron' ), 10, 2 );
		add_action( 'update_option_sentinelwp_scan_time', array( $this, 'reschedule_scan_cron' ), 10, 2 );
	}

	/**
	 * Dynamically reschedule the scan cron event when settings change.
	 */
	public function reschedule_scan_cron() {
		$timestamp = wp_next_scheduled( 'sentinelwp_daily_scan' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'sentinelwp_daily_scan' );
		}

		$schedule = get_option( 'sentinelwp_scan_schedule', 'daily' );
		if ( 'off' === $schedule ) {
			return;
		}

		$time_str = get_option( 'sentinelwp_scan_time', '03:00' );
		$parts    = explode( ':', $time_str );
		$hour     = isset( $parts[0] ) ? absint( $parts[0] ) : 3;
		$minute   = isset( $parts[1] ) ? absint( $parts[1] ) : 0;

		$target = strtotime( sprintf( 'today %02d:%02d:00', $hour, $minute ) );
		if ( false === $target || $target <= time() ) {
			$target = strtotime( sprintf( 'tomorrow %02d:%02d:00', $hour, $minute ) );
		}

		$recurrence = in_array( $schedule, array( 'daily', 'twicedaily', 'weekly' ), true ) ? $schedule : 'daily';
		wp_schedule_event( $target ? $target : time(), $recurrence, 'sentinelwp_daily_scan' );
	}

	public function register_settings() {
		// ---- General tab ----
		register_setting(
			'sentinelwp_settings_general',
			'sentinelwp_hardening',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_hardening' ),
				'default'           => array(),
			)
		);
		register_setting(
			'sentinelwp_settings_general',
			'sentinelwp_protection_level',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_protection_level' ),
				'default'           => 'balanced',
			)
		);
		register_setting(
			'sentinelwp_settings_general',
			'sentinelwp_site_role',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_site_role' ),
				'default'           => class_exists( 'WooCommerce' ) ? 'woocommerce' : 'standard',
			)
		);
		register_setting(
			'sentinelwp_settings_general',
			'sentinelwp_data_retention',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_data_retention' ),
				'default'           => 90,
			)
		);

		// ---- Scanning tab ----
		register_setting(
			'sentinelwp_settings_scanning',
			'sentinelwp_scan_schedule',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_scan_schedule' ),
				'default'           => 'daily',
			)
		);
		register_setting(
			'sentinelwp_settings_scanning',
			'sentinelwp_scan_time',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '03:00',
			)
		);
		register_setting(
			'sentinelwp_settings_scanning',
			'sentinelwp_scan_depth',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_scan_depth' ),
				'default'           => 'standard',
			)
		);
		register_setting(
			'sentinelwp_settings_scanning',
			'sentinelwp_path_exclusions',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_textarea_field',
				'default'           => '',
			)
		);
		register_setting(
			'sentinelwp_settings_scanning',
			'sentinelwp_max_scan_duration',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
				'default'           => 300,
			)
		);
		register_setting(
			'sentinelwp_settings_scanning',
			'sentinelwp_vuln_source',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_vuln_source' ),
				'default'           => 'wordpress_org',
			)
		);
		register_setting(
			'sentinelwp_settings_scanning',
			'sentinelwp_patchstack_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_patchstack_key' ),
				'default'           => '',
			)
		);
		register_setting(
			'sentinelwp_settings_scanning',
			'sentinelwp_wpscan_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_wpscan_key' ),
				'default'           => '',
			)
		);

		// ---- Modules tab ----
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_operating_mode',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_operating_mode' ),
				'default'           => 'observe',
			)
		);
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_behind_proxy',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_flood_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_flood_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_flood_threshold' ),
				'default'           => 120,
			)
		);
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_flood_block',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_form_shield_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_ecommerce_guard_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_fraud_auto_hold',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_disposable_email_check',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);
		register_setting(
			'sentinelwp_settings_modules',
			'sentinelwp_modules_status',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_modules_status' ),
				'default'           => array(),
			)
		);

		// ---- Notifications tab ----
		register_setting(
			'sentinelwp_settings_notifications',
			'sentinelwp_alert_email',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_email' ),
				'default'           => get_option( 'admin_email' ),
			)
		);
		register_setting(
			'sentinelwp_settings_notifications',
			'sentinelwp_alert_threshold',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_alert_threshold' ),
				'default'           => 'high',
			)
		);
		register_setting(
			'sentinelwp_settings_notifications',
			'sentinelwp_alert_recipients',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_textarea_field',
				'default'           => get_option( 'admin_email' ),
			)
		);
		register_setting(
			'sentinelwp_settings_notifications',
			'sentinelwp_alert_digest',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_alert_digest' ),
				'default'           => 'instant',
			)
		);
		register_setting(
			'sentinelwp_settings_notifications',
			'sentinelwp_alert_webhook',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'esc_url_raw',
				'default'           => '',
			)
		);

		// ---- Advanced tab ----
		register_setting(
			'sentinelwp_settings_advanced',
			'sentinelwp_ai_provider',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_ai_provider' ),
				'default'           => '',
			)
		);
		register_setting(
			'sentinelwp_settings_advanced',
			'sentinelwp_ai_api_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_ai_api_key' ),
				'default'           => '',
			)
		);
		register_setting(
			'sentinelwp_settings_advanced',
			'sentinelwp_debug_logging',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);
		register_setting(
			'sentinelwp_settings_advanced',
			'sentinelwp_update_channel',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_update_channel' ),
				'default'           => 'stable',
			)
		);
		register_setting(
			'sentinelwp_settings_advanced',
			'sentinelwp_remove_data_on_uninstall',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);
	}

	public function sanitize_operating_mode( $input ) {
		$allowed = array( 'observe', 'protect', 'lockdown' );
		return in_array( $input, $allowed, true ) ? $input : 'observe';
	}

	public function sanitize_protection_level( $input ) {
		$allowed = array( 'monitor', 'balanced', 'aggressive' );
		return in_array( $input, $allowed, true ) ? $input : 'balanced';
	}

	public function sanitize_site_role( $input ) {
		$allowed = array( 'standard', 'woocommerce' );
		return in_array( $input, $allowed, true ) ? $input : 'standard';
	}

	public function sanitize_data_retention( $input ) {
		$allowed = array( 30, 90, 365 );
		$val = absint( $input );
		return in_array( $val, $allowed, true ) ? $val : 90;
	}

	public function sanitize_scan_schedule( $input ) {
		$allowed = array( 'off', 'daily', 'twicedaily', 'weekly' );
		return in_array( $input, $allowed, true ) ? $input : 'daily';
	}

	public function sanitize_scan_depth( $input ) {
		$allowed = array( 'quick', 'standard', 'deep' );
		return in_array( $input, $allowed, true ) ? $input : 'standard';
	}

	public function sanitize_modules_status( $input ) {
		if ( ! is_array( $input ) ) {
			return array();
		}
		$clean = array();
		foreach ( $input as $k => $v ) {
			$clean[ sanitize_key( $k ) ] = ! empty( $v ) ? 1 : 0;
		}
		return $clean;
	}

	public function sanitize_alert_threshold( $input ) {
		$allowed = array( 'critical', 'high', 'medium', 'low' );
		return in_array( $input, $allowed, true ) ? $input : 'high';
	}

	public function sanitize_alert_digest( $input ) {
		$allowed = array( 'instant', 'daily' );
		return in_array( $input, $allowed, true ) ? $input : 'instant';
	}

	public function sanitize_update_channel( $input ) {
		$allowed = array( 'stable', 'beta' );
		return in_array( $input, $allowed, true ) ? $input : 'stable';
	}

	public function sanitize_hardening( $input ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return get_option( 'sentinelwp_hardening', array() );
		}

		$allowed = array(
			'disable_file_edit',
			'hide_wp_version',
			'disable_xmlrpc',
			'disable_user_enum',
			'login_attempt_limit',
			'security_headers',
		);

		$clean = array();
		foreach ( $allowed as $key ) {
			$clean[ $key ] = ! empty( $input[ $key ] ) ? 1 : 0;
		}
		return $clean;
	}

	public function sanitize_vuln_source( $input ) {
		$allowed = array( 'wordpress_org', 'patchstack', 'wpscan' );
		return in_array( $input, $allowed, true ) ? $input : 'wordpress_org';
	}

	public function sanitize_ai_provider( $input ) {
		$allowed = array( '', 'claude', 'openai', 'gemini' );
		return in_array( $input, $allowed, true ) ? $input : '';
	}

	public function sanitize_patchstack_key( $input ) {
		return $this->sanitize_api_key( $input, 'sentinelwp_patchstack_key' );
	}

	public function sanitize_wpscan_key( $input ) {
		return $this->sanitize_api_key( $input, 'sentinelwp_wpscan_key' );
	}

	public function sanitize_ai_api_key( $input ) {
		return $this->sanitize_api_key( $input, 'sentinelwp_ai_api_key' );
	}

	/**
	 * API keys: strip whitespace/control characters, cap length, and
	 * never allow markup. Keys are never rendered back in full in the
	 * admin UI — the settings form shows a masked placeholder (see
	 * SentinelWP_Admin::mask_key()) instead of the real value. If the
	 * form is submitted with that placeholder untouched, we must not
	 * overwrite the real stored key with the dots.
	 */
	private function sanitize_api_key( $input, $option_name ) {
		$clean = sanitize_text_field( wp_unslash( $input ) );
		$clean = substr( $clean, 0, 200 );

		if ( 0 === strpos( $clean, str_repeat( '•', 8 ) ) ) {
			return get_option( $option_name, '' );
		}

		return $clean;
	}

	public function sanitize_email( $input ) {
		$clean = sanitize_email( $input );
		return is_email( $clean ) ? $clean : get_option( 'admin_email' );
	}

	/**
	 * Flood threshold: clamp to a sane range (30–600 req/min).
	 */
	public function sanitize_flood_threshold( $input ) {
		$value = absint( $input );
		return max( 30, min( 600, $value ) );
	}
}
