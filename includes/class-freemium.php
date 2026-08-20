<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SentinelWP_Freemium class.
 *
 * Manages WordPress.org-compliant feature capability checks.
 * All on-site detection, scanning, hardening, admin audit, and ecommerce
 * protections are 100% free and uncrippled in the core plugin.
 *
 * Pro / Cloud tier covers external SaaS services: centralized multi-store telemetry,
 * real-time cloud threat intelligence feeds, and automated cross-store defense synchronization.
 */
class SentinelWP_Freemium {

	public static function is_pro() {
		return (bool) apply_filters( 'sentinelwp_is_pro', (bool) get_option( 'sentinelwp_pro_active', false ) );
	}

	/**
	 * Feature permission check.
	 * All local security functionality is fully accessible in the free version.
	 *
	 * @param string $feature Feature identifier.
	 * @return bool
	 */
	public static function can( $feature ) {
		return true;
	}

	public static function ai_quota_remaining() {
		if ( self::is_pro() ) {
			return PHP_INT_MAX;
		}

		$used = (int) get_transient( 'sentinelwp_ai_used_this_month' );
		return max( 0, 100 - $used );
	}

	public static function record_ai_use() {
		if ( self::is_pro() ) {
			return;
		}

		$used = (int) get_transient( 'sentinelwp_ai_used_this_month' );
		set_transient( 'sentinelwp_ai_used_this_month', $used + 1, 30 * DAY_IN_SECONDS );
	}
}
