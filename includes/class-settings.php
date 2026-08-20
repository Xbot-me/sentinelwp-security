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
	}

	public function register_settings() {
		// Hardening toggles.
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_hardening',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_hardening' ),
				'default'           => array(),
			)
		);

		// Operating Mode (Observe, Protect, Lockdown).
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_operating_mode',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_operating_mode' ),
				'default'           => 'observe',
			)
		);

		// Reverse Proxy / Cloudflare support.
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_behind_proxy',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);

		// Which vulnerability source to use.
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_vuln_source',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_vuln_source' ),
				'default'           => 'wordpress_org',
			)
		);

		// API keys — write-only in the UI (rendered masked, never echoed
		// back in full), stored with autoload disabled.
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_patchstack_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_patchstack_key' ),
				'default'           => '',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_wpscan_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_wpscan_key' ),
				'default'           => '',
			)
		);

		// AI provider + key.
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_ai_provider',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_ai_provider' ),
				'default'           => '',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_ai_api_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_ai_api_key' ),
				'default'           => '',
			)
		);

		// Alert email — validated as an email, falls back to admin email.
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_alert_email',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_email' ),
				'default'           => get_option( 'admin_email' ),
			)
		);

		register_setting(
			'sentinelwp_settings',
			'sentinelwp_remove_data_on_uninstall',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);

		// Ecommerce protection settings.
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_flood_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_flood_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_flood_threshold' ),
				'default'           => 120,
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_flood_block',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_form_shield_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_ecommerce_guard_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_fraud_auto_hold',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_disposable_email_check',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);

		// General Tab Settings
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_protection_level',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_protection_level' ),
				'default'           => 'balanced',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_site_role',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_site_role' ),
				'default'           => class_exists( 'WooCommerce' ) ? 'woocommerce' : 'standard',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_data_retention',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_data_retention' ),
				'default'           => 90,
			)
		);

		// Scanning Tab Settings
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_scan_schedule',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_scan_schedule' ),
				'default'           => 'daily',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_scan_time',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '03:00',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_scan_depth',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_scan_depth' ),
				'default'           => 'standard',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_path_exclusions',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_textarea_field',
				'default'           => '',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_max_scan_duration',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
				'default'           => 300,
			)
		);

		// Modules Tab Settings
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_modules_status',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_modules_status' ),
				'default'           => array(),
			)
		);

		// Notifications Tab Settings
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_alert_threshold',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_alert_threshold' ),
				'default'           => 'high',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_alert_recipients',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_textarea_field',
				'default'           => get_option( 'admin_email' ),
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_alert_digest',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_alert_digest' ),
				'default'           => 'instant',
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_alert_webhook',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'esc_url_raw',
				'default'           => '',
			)
		);

		// Advanced Tab Settings
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_debug_logging',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);
		register_setting(
			'sentinelwp_settings',
			'sentinelwp_update_channel',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_update_channel' ),
				'default'           => 'stable',
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
