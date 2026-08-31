<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
// phpcs:disable WordPress.Security.NonceVerification.Recommended
// phpcs:disable WordPress.Security.NonceVerification.Missing
// phpcs:disable Squiz.PHP.DiscouragedFunctions.Discouraged
// phpcs:disable PluginCheck.CodeAnalysis.AIProvider.DirectIntegration
// phpcs:disable WordPress.DB.SlowDBQuery.slow_db_query_meta_value


/**
 * SentinelWP_Scan_Coordinator class.
 *
 * Coordinates deep security scans across discrete, bounded phases.
 * Provides granular progress tracking, timeout resilience, and memory bounding.
 */
class SentinelWP_Scan_Coordinator {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Available scan phases in execution order.
	 *
	 * @return array
	 */
	public function get_phases() {
		return array(
			'core'       => array(
				'label'       => __( 'WordPress Core Integrity', 'sentinelguard-ecommerce-protection' ),
				'description' => __( 'Compares core files against official WordPress.org release checksums.', 'sentinelguard-ecommerce-protection' ),
			),
			'vulns'      => array(
				'label'       => __( 'Vulnerability & Version Audit', 'sentinelguard-ecommerce-protection' ),
				'description' => __( 'Audits installed plugins and active themes against known CVE databases.', 'sentinelguard-ecommerce-protection' ),
			),
			'skimmer'    => array(
				'label'       => __( 'Magecart & Skimmer Scan', 'sentinelguard-ecommerce-protection' ),
				'description' => __( 'Inspects JavaScript assets and media uploads for payment form harvesters.', 'sentinelguard-ecommerce-protection' ),
			),
			'nulled'     => array(
				'label'       => __( 'Nulled & Pirated Software Detector', 'sentinelguard-ecommerce-protection' ),
				'description' => __( 'Detects backdoor indicators, pirated files, and license bypass routines.', 'sentinelguard-ecommerce-protection' ),
			),
			'admin'      => array(
				'label'       => __( 'Admin Account & Privilege Auditor', 'sentinelguard-ecommerce-protection' ),
				'description' => __( 'Performs low-level database audit for hidden or orphaned administrator accounts.', 'sentinelguard-ecommerce-protection' ),
			),
			'commerce'   => array(
				'label'       => __( 'Commerce & Store Integrity Guard', 'sentinelguard-ecommerce-protection' ),
				'description' => __( 'HPOS-optimized analysis of order velocity, card testing bursts, and pricing changes.', 'sentinelguard-ecommerce-protection' ),
			),
		);
	}

	/**
	 * Runs a full, sequential security scan across all phases.
	 *
	 * @return array Scan results summary.
	 */
	public function run_full_scan() {
		$max_duration = (int) get_option( 'sentinelwp_max_scan_duration', 300 );
		$max_duration = ( $max_duration >= 30 && $max_duration <= 1800 ) ? $max_duration : 300;
		@set_time_limit( $max_duration );

		// Concurrency Lock: Prevent multiple scans from running simultaneously
		$existing_lock = get_transient( 'sentinelwp_active_scan_lock' );
		if ( $existing_lock && ( time() - (int) $existing_lock ) < $max_duration ) {
			$current_state = $this->get_state();
			$current_state['status']  = 'running';
			$current_state['message'] = __( 'A scan is already in progress.', 'sentinelguard-ecommerce-protection' );
			return $current_state;
		}

		set_transient( 'sentinelwp_active_scan_lock', time(), $max_duration );

		$start_time = microtime( true );
		$phases     = array_keys( $this->get_phases() );
		$results    = array(
			'started_at'  => current_time( 'mysql' ),
			'phases'      => array(),
			'total_time'  => 0,
			'peak_memory' => 0,
			'status'      => 'running',
		);

		update_option( 'sentinelwp_last_scan_time', time() );
		set_transient( 'sentinelwp_scan_coordinator_state', $results, 600 );

		try {
			foreach ( $phases as $phase ) {
				$phase_start = microtime( true );
				$status      = 'ok';
				$error_msg   = '';

				try {
					$this->run_phase( $phase );
				} catch ( Throwable $e ) {
					$status    = 'error';
					$error_msg = $e->getMessage();
				}

				$phase_duration = round( microtime( true ) - $phase_start, 3 );
				$results['phases'][ $phase ] = array(
					'status'   => $status,
					'duration' => $phase_duration,
					'error'    => $error_msg,
				);

				set_transient( 'sentinelwp_scan_coordinator_state', $results, 600 );
			}
		} finally {
			delete_transient( 'sentinelwp_active_scan_lock' );
		}

		$results['total_time']   = round( microtime( true ) - $start_time, 3 );
		$results['peak_memory']  = round( memory_get_peak_usage( true ) / 1048576, 2 ); // MB
		$results['status']       = 'completed';
		$results['completed_at'] = current_time( 'mysql' );

		set_transient( 'sentinelwp_scan_coordinator_state', $results, 86400 );
		update_option( 'sentinelwp_last_scan_summary', $results );

		// Record persistent scan history log (capped at 50 runs)
		global $wpdb;
		$findings_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sentinelwp_findings WHERE status IN ('new', 'open')" );
		$critical_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sentinelwp_findings WHERE status IN ('new', 'open') AND severity = 'critical'" );

		$history_entry = array(
			'id'             => (int) round( microtime( true ) * 1000 ),
			'timestamp'      => current_time( 'mysql' ),
			'total_time'     => $results['total_time'],
			'peak_memory'    => $results['peak_memory'],
			'status'         => $results['status'],
			'phases'         => $results['phases'],
			'open_findings'  => $findings_count,
			'critical_count' => $critical_count,
		);

		$history = get_option( 'sentinelwp_scan_history_log', array() );
		if ( ! is_array( $history ) ) {
			$history = array();
		}
		array_unshift( $history, $history_entry );
		$history = array_slice( $history, 0, 50 );
		update_option( 'sentinelwp_scan_history_log', $history, false );

		// Auto-purge records older than retention period (default 30 days)
		$this->auto_purge_old_history( (int) get_option( 'sentinelwp_data_retention', 30 ) );

		do_action( 'sentinelwp_scan_complete', $results );

		return $results;
	}

	/**
	 * Runs a single bounded scan phase.
	 *
	 * @param string $phase Phase key.
	 */
	public function run_phase( $phase ) {
		switch ( $phase ) {
			case 'core':
				SentinelWP_Scanner::instance()->scan_core_integrity();
				break;

			case 'vulns':
				SentinelWP_Scanner::instance()->scan_plugin_versions();
				SentinelWP_Scanner::instance()->scan_theme_versions();
				break;

			case 'skimmer':
				SentinelWP_Scanner::instance()->scan_uploads_for_php();
				SentinelWP_Scanner::instance()->scan_mu_plugins();
				SentinelWP_Skimmer_Detector::instance()->scan_all();
				break;

			case 'nulled':
				SentinelWP_Nulled_Detector::instance()->scan_all();
				break;

			case 'admin':
				SentinelWP_Scanner::instance()->scan_admin_accounts();
				SentinelWP_Admin_Guard::instance()->scan_for_hidden_admins();
				break;

			case 'commerce':
				if ( class_exists( 'WooCommerce' ) && class_exists( 'SentinelWP_Ecommerce_Guard' ) ) {
					SentinelWP_Ecommerce_Guard::instance()->cron_analyze_fraud_patterns();
					SentinelWP_Ecommerce_Guard::instance()->cron_monitor_complaint_patterns();
					SentinelWP_Ecommerce_Guard::instance()->cron_check_store_integrity();
				}
				break;
		}
	}

	/**
	 * Get the latest scan coordinator state or summary.
	 *
	 * @return array
	 */
	public function get_state() {
		$state = get_transient( 'sentinelwp_scan_coordinator_state' );
		if ( empty( $state ) ) {
			$state = get_option( 'sentinelwp_last_scan_summary', array() );
		}
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Force-reset active scan lock in case of crashed workers or manual unlock.
	 */
	public function force_reset_lock() {
		delete_transient( 'sentinelwp_active_scan_lock' );
		$state = $this->get_state();
		if ( isset( $state['status'] ) && 'running' === $state['status'] ) {
			$state['status']       = 'interrupted';
			$state['interrupted_at'] = current_time( 'mysql' );
			set_transient( 'sentinelwp_scan_coordinator_state', $state, 86400 );
		}
	}

	/**
	 * Retrieve scan run history logs.
	 *
	 * @return array
	 */
	public function get_scan_history() {
		$history = get_option( 'sentinelwp_scan_history_log', array() );
		if ( empty( $history ) ) {
			$last = get_option( 'sentinelwp_last_scan_summary' );
			if ( ! empty( $last ) && is_array( $last ) ) {
				global $wpdb;
				$findings_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sentinelwp_findings WHERE status IN ('new', 'open')" );
				$critical_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sentinelwp_findings WHERE status IN ('new', 'open') AND severity = 'critical'" );
				$history = array(
					array(
						'id'             => ! empty( $last['started_at'] ) ? strtotime( $last['started_at'] ) : time(),
						'timestamp'      => ! empty( $last['completed_at'] ) ? $last['completed_at'] : current_time( 'mysql' ),
						'total_time'     => isset( $last['total_time'] ) ? $last['total_time'] : 0,
						'peak_memory'    => isset( $last['peak_memory'] ) ? $last['peak_memory'] : 0,
						'status'         => isset( $last['status'] ) ? $last['status'] : 'completed',
						'phases'         => isset( $last['phases'] ) ? $last['phases'] : array(),
						'open_findings'  => $findings_count,
						'critical_count' => $critical_count,
					),
				);
			}
		}
		return is_array( $history ) ? $history : array();
	}

	/**
	 * Auto-purges scan history records, old request rate limits, and resolved findings older than $days (default 30 days).
	 *
	 * @param int $days Number of days to retain (default 30).
	 * @return int Number of purged history runs.
	 */
	public function auto_purge_old_history( $days = 30 ) {
		$days        = max( 1, (int) $days );
		$cutoff_time = time() - ( $days * DAY_IN_SECONDS );
		$purged_runs = 0;

		// 1. Purge scan history logs older than cutoff
		$history = get_option( 'sentinelwp_scan_history_log', array() );
		if ( is_array( $history ) && ! empty( $history ) ) {
			$filtered = array();
			foreach ( $history as $run ) {
				$run_time = isset( $run['timestamp'] ) ? strtotime( $run['timestamp'] ) : ( isset( $run['id'] ) ? (int) $run['id'] : 0 );
				if ( $run_time >= $cutoff_time ) {
					$filtered[] = $run;
				} else {
					$purged_runs++;
				}
			}
			update_option( 'sentinelwp_scan_history_log', $filtered, false );
		}

		// 2. Purge rate limiter records older than 24 hours
		global $wpdb;
		$rate_cutoff = (int) floor( ( time() - DAY_IN_SECONDS ) / 300 );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}sentinelwp_request_rates WHERE window_id < %d", $rate_cutoff ) );

		// 3. Purge resolved findings older than cutoff
		$finding_cutoff = gmdate( 'Y-m-d H:i:s', $cutoff_time );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}sentinelwp_findings WHERE status = 'resolved' AND updated_at < %s", $finding_cutoff ) );

		return $purged_runs;
	}

	/**
	 * Clears the scan history log completely.
	 */
	public function clear_scan_history() {
		delete_option( 'sentinelwp_scan_history_log' );
		delete_option( 'sentinelwp_last_scan_summary' );
		return true;
	}

	/**
	 * Deletes a single scan run from history by ID.
	 *
	 * @param int $id Unique timestamp/ID of the scan run.
	 * @return bool
	 */
	public function delete_scan_run( $id ) {
		$id      = (int) $id;
		$history = $this->get_scan_history();
		if ( ! is_array( $history ) || empty( $history ) ) {
			return false;
		}

		$filtered = array();
		$found    = false;
		foreach ( $history as $run ) {
			if ( ! $found && isset( $run['id'] ) && (int) $run['id'] === $id ) {
				$found = true;
				continue;
			}
			$filtered[] = $run;
		}

		if ( $found ) {
			update_option( 'sentinelwp_scan_history_log', $filtered, false );
			if ( empty( $filtered ) ) {
				delete_option( 'sentinelwp_last_scan_summary' );
			}
			return true;
		}

		return false;
	}
}
