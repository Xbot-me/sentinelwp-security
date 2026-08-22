<?php
/**
 * Plugin Name:       SentinelWP Security — Ecommerce & Checkout Protection
 * Plugin URI:        https://github.com/Xbot-me/sentinelwp-security
 * Description:       Dedicated security layer for ecommerce revenue, checkout integrity, and payment flows. Magecart skimmer defense, card-testing prevention, stealth admin detection, and core integrity.
 * Version:           0.4.1
 * Requires at least: 6.0
 * Tested up to:      7.1
 * Requires PHP:      7.4
 * Author:            Mustafizur Rahman
 * Author URI:        https://mustafizur.info
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       sentinelwp-security
 * Domain Path:       /languages
 */

// Block direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SENTINELWP_VERSION', '0.4.1' );
define( 'SENTINELWP_FILE', __FILE__ );
define( 'SENTINELWP_PATH', plugin_dir_path( __FILE__ ) );
define( 'SENTINELWP_URL', plugin_dir_url( __FILE__ ) );
define( 'SENTINELWP_BASENAME', plugin_basename( __FILE__ ) );

/**
 * Simple, explicit autoloader. No Composer dependency for the free tier
 * so the plugin stays a single zip, drop-in install on shared hosting.
 */
spl_autoload_register(
	function ( $class ) {
		if ( strpos( $class, 'SentinelWP_' ) !== 0 ) {
			return;
		}

		$relative = strtolower( str_replace( '_', '-', substr( $class, strlen( 'SentinelWP_' ) ) ) );
		$candidates = array(
			SENTINELWP_PATH . 'includes/class-' . $relative . '.php',
			SENTINELWP_PATH . 'admin/class-' . $relative . '.php',
		);

		foreach ( $candidates as $file ) {
			if ( file_exists( $file ) ) {
				require_once $file;
				return;
			}
		}
	}
);

register_activation_hook( __FILE__, array( 'SentinelWP_Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'SentinelWP_Deactivator', 'deactivate' ) );

/**
 * Declare compatibility with WooCommerce High-Performance Order Storage
 * (HPOS / Custom Order Tables) and the Cart & Checkout blocks. This plugin
 * already branches its own queries on SentinelWP_Helper::is_hpos_enabled(),
 * so it's safe to declare — without this, WooCommerce shows the plugin as
 * "Unknown compatibility" on the Features screen even though it works.
 */
add_action(
	'before_woocommerce_init',
	function () {
		if ( class_exists( \Automattic\WooCommerce\Utilities\FeaturesUtil::class ) ) {
			\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', SENTINELWP_FILE, true );
			\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'cart_checkout_blocks', SENTINELWP_FILE, true );
		}
	}
);

/**
 * Register custom cron intervals (e.g. 5-minute flood check).
 */
function sentinelwp_add_cron_schedules( $schedules ) {
	if ( ! isset( $schedules['every_five_minutes'] ) ) {
		$schedules['every_five_minutes'] = array(
			'interval' => 300,
			'display'  => __( 'Every 5 Minutes', 'sentinelwp-security' ),
		);
	}
	return $schedules;
}
add_filter( 'cron_schedules', 'sentinelwp_add_cron_schedules' );

/**
 * Boot the plugin once all plugins are loaded, so we can safely check
 * for conflicts / dependencies and load the text domain.
 */
function sentinelwp_boot() {
	// Runtime schema check / upgrade.
	SentinelWP_Activator::maybe_upgrade_schema();

	SentinelWP_Settings::instance();
	SentinelWP_Hardening::instance();
	SentinelWP_Scanner::instance();
	SentinelWP_Alerts::instance();

	// Ecommerce security — works on any WordPress site.
	SentinelWP_Flood_Monitor::instance();
	SentinelWP_Form_Shield::instance();

	// Nulled detector and skimmer detector are singletons used by the
	// scanner during cron. Instantiating them here registers nothing on
	// the front end — they only do work when scan_all() is called.
	SentinelWP_Nulled_Detector::instance();
	SentinelWP_Skimmer_Detector::instance();

	// Admin account guard — real-time role escalation & hidden admin monitoring.
	SentinelWP_Admin_Guard::instance();

	// Multi-signal attack correlation & pre-gateway risk engine.
	SentinelWP_Attack_Correlator::instance();
	SentinelWP_Event_Normalizer::instance();
	SentinelWP_Risk_Engine::instance();

	// WooCommerce-specific protections — graceful no-op when WC is absent.
	if ( class_exists( 'WooCommerce' ) ) {
		SentinelWP_Ecommerce_Guard::instance();
		SentinelWP_Store_API_Guard::instance();
		SentinelWP_Payment_Adapter::instance();
	}

	if ( is_admin() ) {
		SentinelWP_Admin::instance();
	}
}
add_action( 'plugins_loaded', 'sentinelwp_boot' );
