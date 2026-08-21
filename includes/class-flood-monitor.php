<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SentinelWP_Flood_Monitor class.
 * 
 * Detects application-layer DDoS, brute-force floods, and traffic anomalies
 * via per-IP request tracking across sensitive endpoints.
 *
 * Uses normalized integer window IDs (window_id = floor(time() / 300))
 * for 100% unified accounting across Redis/Memcached object cache and MySQL.
 */
class SentinelWP_Flood_Monitor {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		if ( get_option( 'sentinelwp_flood_enabled', 1 ) ) {
			add_action( 'init', array( $this, 'track_request' ), 1 );
		}

		add_action( 'sentinelwp_flood_check', array( $this, 'cron_analyze_rates' ) );
		add_action( 'sentinelwp_flood_check', array( $this, 'cron_prune_old_data' ) );
	}

	/**
	 * Hot-path request rate tracking.
	 * Hooks to 'init' at priority 1 with minimal overhead.
	 */
	public function track_request() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$ip_hash = $this->get_ip_hash();
		if ( empty( $ip_hash ) ) {
			return;
		}

		$endpoint  = $this->get_endpoint_type();
		$window_id = (int) floor( time() / 300 ); // Normalized 5-minute window ID
		$hit_count = 0;

		if ( wp_using_ext_object_cache() ) {
			// Unified Redis/Memcached cache key with exact endpoint and window ID
			$transient_key = 'sentinelwp_rr_' . $ip_hash . '_' . $endpoint . '_' . $window_id;
			$hit_count     = (int) get_transient( $transient_key );
			$hit_count++;
			set_transient( $transient_key, $hit_count, 300 );
		} else {
			global $wpdb;

			// Atomic UPSERT that also reads back the post-increment count in
			// a single round trip via MySQL's LAST_INSERT_ID(expr) trick —
			// this hook runs on every single front-end request, so avoiding
			// a second query here matters on high-traffic sites without an
			// external object cache.
			// LAST_INSERT_ID(1) on the fresh-insert branch and
			// LAST_INSERT_ID(hit_count + 1) on the update branch both set
			// the session's last-insert-id to the post-increment hit count
			// (independent of this table's own unrelated auto_increment
			// `id` column), so $wpdb->insert_id reads it back for free.
			$wpdb->query(
				$wpdb->prepare(
					"INSERT INTO {$wpdb->prefix}sentinelwp_request_rates (ip_hash, endpoint, hit_count, window_id) 
					VALUES (%s, %s, LAST_INSERT_ID(1), %d) 
					ON DUPLICATE KEY UPDATE hit_count = LAST_INSERT_ID(hit_count + 1)",
					$ip_hash,
					$endpoint,
					$window_id
				)
			);

			$hit_count = (int) $wpdb->insert_id;
		}

		$threshold = $this->get_endpoint_threshold( $endpoint );

		if ( $hit_count > $threshold ) {
			$alert_transient = 'sentinelwp_flood_alert_' . $ip_hash . '_' . $endpoint;
			
			if ( false === get_transient( $alert_transient ) ) {
				$this->record_finding(
					'flood_detected',
					'high',
					'flood_monitor',
					/* translators: 1: endpoint name, 2: hit count */
					sprintf( __( 'High request velocity on %1$s endpoint (%2$d req / 5min)', 'sentinelwp-security' ), ucfirst( $endpoint ), $hit_count ),
					/* translators: 1: IP hash prefix, 2: threshold count, 3: endpoint name */
					sprintf( __( 'Client IP hash %1$s exceeded threshold of %2$d requests on the %3$s route.', 'sentinelwp-security' ), esc_html( substr( $ip_hash, 0, 12 ) . '...' ), $threshold, esc_html( $endpoint ) ),
					'likely',
					'flood_monitor',
					__( 'Investigate traffic patterns from this client and enable edge firewall/WAF rate limits if abusive.', 'sentinelwp-security' ),
					'low'
				);
				
				// Debounce to max 1 alert per IP/endpoint per hour
				set_transient( $alert_transient, true, HOUR_IN_SECONDS );
			}

			$this->maybe_block_request( $hit_count, $threshold );
		}
	}

	/**
	 * Analyze aggregate traffic across all visitors.
	 */
	public function cron_analyze_rates() {
		if ( wp_using_ext_object_cache() ) {
			return;
		}

		global $wpdb;
		$window_id  = (int) floor( time() / 300 );

		$total_requests = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT SUM(hit_count) FROM {$wpdb->prefix}sentinelwp_request_rates WHERE window_id = %d",
				$window_id
			)
		);

		$avg_rate = (int) get_transient( 'sentinelwp_avg_req_rate' );

		if ( $avg_rate > 50 && $total_requests > ( $avg_rate * 3 ) ) {
			$this->record_finding(
				'flood_detected',
				'critical',
				'flood_monitor',
				__( 'Aggregate application traffic surge detected across all routes', 'sentinelwp-security' ),
				/* translators: 1: current request count, 2: average request count */
				sprintf( __( 'Current 5-minute volume (%1$d requests) is over 3x the baseline average (%2$d requests).', 'sentinelwp-security' ), $total_requests, $avg_rate ),
				'likely',
				'flood_monitor',
				__( 'Check server access logs and upstream CDN/WAF metrics for distributed DDoS traffic.', 'sentinelwp-security' ),
				'medium'
			);
		}

		// Update 24h rolling average
		if ( 0 === $avg_rate ) {
			$new_avg = $total_requests;
		} else {
			$new_avg = (int) ( ( $avg_rate * 287 + $total_requests ) / 288 );
		}

		set_transient( 'sentinelwp_avg_req_rate', $new_avg, DAY_IN_SECONDS );
	}

	/**
	 * Prune old data from the DB.
	 */
	public function cron_prune_old_data() {
		global $wpdb;
		$two_hours_ago_window = (int) floor( ( time() - 2 * HOUR_IN_SECONDS ) / 300 );

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}sentinelwp_request_rates WHERE window_id < %d",
				$two_hours_ago_window
			)
		);
	}

	private function get_ip_hash() {
		if ( class_exists( 'SentinelWP_Helper' ) ) {
			return SentinelWP_Helper::get_ip_hash();
		}
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return ! empty( $ip ) ? hash( 'sha256', $ip ) : '';
	}

	private function get_endpoint_type() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		if ( false !== strpos( $uri, 'wp-login.php' ) ) {
			return 'login';
		}
		if ( false !== strpos( $uri, 'xmlrpc.php' ) ) {
			return 'xmlrpc';
		}
		if ( false !== strpos( $uri, 'admin-ajax.php' ) ) {
			return 'ajax';
		}
		if ( false !== strpos( $uri, 'wp-json/' ) || isset( $_GET['rest_route'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return 'rest';
		}
		if ( false !== strpos( $uri, 'wp-cron.php' ) ) {
			return 'cron';
		}
		if ( class_exists( 'WooCommerce' ) ) {
			if ( ( function_exists( 'is_checkout' ) && is_checkout() ) || false !== strpos( $uri, 'checkout' ) ) {
				return 'checkout';
			}
		}

		return 'general';
	}

	private function get_endpoint_threshold( $endpoint ) {
		$base_threshold = (int) get_option( 'sentinelwp_flood_threshold', 120 );

		switch ( $endpoint ) {
			case 'login':
				return 30;
			case 'xmlrpc':
				return 10;
			case 'ajax':
				return 80;
			case 'rest':
				return 120;
			case 'checkout':
				return 30;
			case 'cron':
				return 15;
			default:
				return $base_threshold;
		}
	}

	private function record_finding( $type, $severity, $source, $title, $details, $confidence = 'likely', $detector = 'flood_monitor', $remediation = '', $fp_risk = 'low' ) {
		global $wpdb;

		$existing_id = $wpdb->get_var( $wpdb->prepare(
			"SELECT id FROM {$wpdb->prefix}sentinelwp_findings WHERE type = %s AND title = %s AND status != 'resolved' LIMIT 1",
			$type,
			$title
		) );

		if ( $existing_id ) {
			$wpdb->update(
				$wpdb->prefix . 'sentinelwp_findings',
				array( 'updated_at' => current_time( 'mysql' ) ),
				array( 'id' => $existing_id ),
				array( '%s' ),
				array( '%d' )
			);
			return false;
		}

		$inserted = $wpdb->insert(
			$wpdb->prefix . 'sentinelwp_findings',
			array(
				'type'                => $type,
				'severity'            => $severity,
				'confidence'          => $confidence,
				'detector'            => $detector,
				'source'              => $source,
				'title'               => $title,
				'details'             => $details,
				'remediation'         => $remediation,
				'false_positive_risk' => $fp_risk,
				'status'              => 'new',
				'created_at'          => current_time( 'mysql' ),
				'updated_at'          => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( $inserted ) {
			$finding_id = $wpdb->insert_id;
			do_action( 'sentinelwp_new_finding', $finding_id, $type, $severity, $title );
			return $finding_id;
		}

		return false;
	}

	/**
	 * Opt-in non-destructive blocking guard.
	 */
	private function maybe_block_request( $rate, $threshold ) {
		$block_enabled = (bool) get_option( 'sentinelwp_flood_block', false );
		if ( ! $block_enabled ) {
			return; // Default posture: Detect & Alert only.
		}

		if ( $rate >= ( $threshold * 2 ) ) {
			status_header( 429 );
			header( 'Retry-After: 300' );
			wp_die(
				esc_html__( 'Too many requests. Please wait a few minutes and try again.', 'sentinelwp-security' ),
				esc_html__( 'Rate Limit Exceeded', 'sentinelwp-security' ),
				array( 'response' => 429 )
			);
		}
	}
}
