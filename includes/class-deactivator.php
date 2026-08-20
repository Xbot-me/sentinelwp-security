<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fires on deactivation. Only clears scheduled events — never touches
 * data. Data removal is opt-in and lives in uninstall.php instead.
 */
class SentinelWP_Deactivator {

	public static function deactivate() {
		$timestamp = wp_next_scheduled( 'sentinelwp_daily_scan' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'sentinelwp_daily_scan' );
		}

		$flood_timestamp = wp_next_scheduled( 'sentinelwp_flood_check' );
		if ( $flood_timestamp ) {
			wp_unschedule_event( $flood_timestamp, 'sentinelwp_flood_check' );
		}
	}
}
