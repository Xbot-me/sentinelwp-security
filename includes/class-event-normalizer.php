<?php
/**
 * SentinelWP Event Normalizer
 *
 * Extracts and normalizes contextual identity, journey, cart, and request signals
 * into a standardized event context for the Pre-Gateway Risk Engine.
 *
 * @package SentinelWP
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SentinelWP_Event_Normalizer {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Builds a normalized context array from the current HTTP request and WooCommerce session.
	 *
	 * @param WP_REST_Request|null $request Optional REST request object.
	 * @param array                $extra   Optional extra contextual overrides.
	 * @return array Normalized event context.
	 */
	public function build_context( $request = null, array $extra = array() ) {
		$ip       = SentinelWP_Helper::get_client_ip();
		$ip_hash  = hash( 'sha256', $ip );
		$ua       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$lang     = isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ) : '';
		$endpoint = $this->resolve_endpoint( $request );

		// Session & Identity
		$session_id = $this->resolve_session_id();
		$user_id    = get_current_user_id();

		// Email Resolution
		$email        = $this->resolve_email( $request );
		$email_hash   = $email ? hash( 'sha256', strtolower( trim( $email ) ) ) : '';
		$email_domain = $email ? substr( strrchr( $email, '@' ), 1 ) : '';
		$is_disposable = $this->is_disposable_email( $email_domain );

		// Cart & Commerce Signals
		$cart_data     = $this->resolve_cart_data( $request );
		$cart_total    = $cart_data['total'];
		$cart_items    = $cart_data['item_count'];
		$cart_sku_sig  = $cart_data['sku_signature'];
		
		// Order Distribution Percentiles (p05, p50, p95)
		$percentiles   = $this->get_store_order_percentiles();
		$p05_threshold = $percentiles['p05'] ?? 5.0;
		$is_micro_cart = ( $cart_total > 0 && $cart_total < $p05_threshold );

		// Journey Duration & Cadence
		$journey_seconds = $this->resolve_journey_duration();
		$has_journey     = ( $journey_seconds >= 5.0 );

		// Mobile-Aware Multi-Signal Cluster Identifier
		$cluster_id = $this->compute_cluster_id( array(
			'session_id'   => $session_id,
			'email_domain' => $email_domain,
			'cart_sku_sig' => $cart_sku_sig,
			'ip_subnet'    => $this->get_ip_subnet( $ip ),
			'has_journey'  => $has_journey,
			'ua_family'    => substr( $ua, 0, 32 ),
		) );

		// Velocity & Failure Signals
		$recent_failures = (int) get_transient( 'sentinelwp_pay_fail_' . $ip_hash );
		$recent_orders   = (int) get_transient( 'sentinelwp_ord_vel_ip_' . $ip_hash );
		$cluster_fails   = (int) get_transient( 'sentinelwp_cluster_fails_' . $cluster_id );

		$context = array(
			'timestamp'         => time(),
			'ip'                => $ip,
			'ip_hash'           => $ip_hash,
			'user_agent'        => $ua,
			'endpoint'          => $endpoint,
			'session_id'        => $session_id,
			'user_id'           => $user_id,
			'email'             => $email,
			'email_domain'      => $email_domain,
			'is_disposable'     => $is_disposable,
			'cart_total'        => $cart_total,
			'cart_items'        => $cart_items,
			'cart_sku_sig'      => $cart_sku_sig,
			'order_percentiles' => $percentiles,
			'is_micro_cart'     => $is_micro_cart,
			'journey_seconds'   => $journey_seconds,
			'has_journey'       => $has_journey,
			'cluster_id'        => $cluster_id,
			'ip_failures'       => $recent_failures,
			'ip_orders'         => $recent_orders,
			'cluster_failures'  => $cluster_fails,
		);

		return array_merge( $context, $extra );
	}

	/**
	 * Computes a robust cluster ID with mobile carrier IP-shift resilience.
	 */
	public function compute_cluster_id( array $signals ) {
		// If legitimate session exists with normal journey, preserve session identity across mobile IP hops
		$ip_part = ( ! empty( $signals['has_journey'] ) && ! empty( $signals['session_id'] ) && strpos( $signals['session_id'], 'anon_' ) !== 0 )
			? 'mobile_carrier_resilient'
			: ( $signals['ip_subnet'] ?? '' );

		$seed = sprintf(
			'%s|%s|%s|%s',
			$signals['session_id'] ?? '',
			$signals['email_domain'] ?? '',
			$signals['cart_sku_sig'] ?? '',
			$ip_part
		);
		return 'cluster_' . substr( hash( 'sha256', $seed ), 0, 16 );
	}

	private function resolve_endpoint( $request ) {
		if ( $request instanceof WP_REST_Request ) {
			return $request->get_route();
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		if ( false !== strpos( $uri, 'wc/store' ) ) {
			return 'store_api';
		}
		if ( false !== strpos( $uri, 'admin-ajax.php' ) && isset( $_REQUEST['action'] ) ) {
			return 'ajax_' . sanitize_key( $_REQUEST['action'] );
		}
		return 'classic_checkout';
	}

	private function resolve_session_id() {
		if ( function_exists( 'WC' ) && WC()->session ) {
			$cookie = WC()->session->get_customer_id();
			if ( ! empty( $cookie ) ) {
				return (string) $cookie;
			}
		}
		$cookie_header = isset( $_COOKIE['wp_woocommerce_session'] ) ? sanitize_text_field( wp_unslash( $_COOKIE['wp_woocommerce_session'] ) ) : '';
		if ( ! empty( $cookie_header ) ) {
			return substr( hash( 'sha256', $cookie_header ), 0, 16 );
		}
		return 'anon_' . substr( hash( 'sha256', SentinelWP_Helper::get_client_ip() ), 0, 12 );
	}

	private function resolve_email( $request ) {
		if ( $request instanceof WP_REST_Request ) {
			$params = $request->get_json_params();
			if ( isset( $params['billing_address']['email'] ) ) {
				return sanitize_email( $params['billing_address']['email'] );
			}
		}
		if ( isset( $_POST['billing_email'] ) ) {
			return sanitize_email( wp_unslash( $_POST['billing_email'] ) );
		}
		return '';
	}

	private function resolve_cart_data( $request ) {
		$total    = 0.0;
		$items    = 0;
		$sku_list = array();

		if ( function_exists( 'WC' ) && WC()->cart ) {
			$total = (float) WC()->cart->get_total( 'edit' );
			$items = (int) WC()->cart->get_cart_contents_count();
			foreach ( WC()->cart->get_cart() as $cart_item ) {
				$sku_list[] = (string) ( $cart_item['product_id'] ?? 0 );
			}
		}

		sort( $sku_list );
		return array(
			'total'         => $total,
			'item_count'    => $items,
			'sku_signature' => ! empty( $sku_list ) ? substr( md5( implode( ',', $sku_list ) ), 0, 12 ) : 'empty_cart',
		);
	}

	/**
	 * Calculates statistical distribution percentiles for store orders over the last 60 days.
	 *
	 * @return array Array containing p01, p05, p10, p25, p50 (median), p75, p90, p95, p99, mean, count.
	 */
	public function get_store_order_percentiles() {
		$cached = get_transient( 'sentinelwp_wc_order_percentiles' );
		if ( is_array( $cached ) && isset( $cached['p05'] ) ) {
			return $cached;
		}

		global $wpdb;
		$defaults = array(
			'p01'   => 2.0,
			'p05'   => 5.0,
			'p10'   => 10.0,
			'p25'   => 25.0,
			'p50'   => 50.0,
			'p75'   => 95.0,
			'p90'   => 150.0,
			'p95'   => 250.0,
			'p99'   => 500.0,
			'mean'  => 65.0,
			'count' => 0,
		);

		$amounts = array();
		$cutoff  = date( 'Y-m-d H:i:s', time() - ( 60 * DAY_IN_SECONDS ) );

		if ( class_exists( 'Automattic\WooCommerce\Utilities\OrderUtil' ) && \Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled() ) {
			$orders_table = $wpdb->prefix . 'wc_orders';
			$rows = $wpdb->get_col( $wpdb->prepare( "SELECT total_amount FROM {$orders_table} WHERE status = 'wc-completed' AND date_created_gmt >= %s LIMIT 1000", $cutoff ) );
			if ( is_array( $rows ) ) {
				foreach ( $rows as $r ) {
					if ( is_numeric( $r ) && (float) $r > 0 ) {
						$amounts[] = (float) $r;
					}
				}
			}
		}

		$count = count( $amounts );
		if ( $count < 10 ) {
			set_transient( 'sentinelwp_wc_order_percentiles', $defaults, 6 * HOUR_IN_SECONDS );
			return $defaults;
		}

		sort( $amounts );
		$calc_percentile = function( $p ) use ( $amounts, $count ) {
			$idx = (int) floor( ( $p / 100.0 ) * ( $count - 1 ) );
			return round( $amounts[ $idx ], 2 );
		};

		$dist = array(
			'p01'   => $calc_percentile( 1 ),
			'p05'   => $calc_percentile( 5 ),
			'p10'   => $calc_percentile( 10 ),
			'p25'   => $calc_percentile( 25 ),
			'p50'   => $calc_percentile( 50 ),
			'p75'   => $calc_percentile( 75 ),
			'p90'   => $calc_percentile( 90 ),
			'p95'   => $calc_percentile( 95 ),
			'p99'   => $calc_percentile( 99 ),
			'mean'  => round( array_sum( $amounts ) / $count, 2 ),
			'count' => $count,
		);

		set_transient( 'sentinelwp_wc_order_percentiles', $dist, 12 * HOUR_IN_SECONDS );
		return $dist;
	}

	private function resolve_journey_duration() {
		if ( isset( $_COOKIE['sentinelwp_journey_start'] ) ) {
			$start = (int) $_COOKIE['sentinelwp_journey_start'];
			if ( $start > 0 && $start <= time() ) {
				return (float) ( time() - $start );
			}
		}
		return 0.0;
	}

	private function is_disposable_email( $domain ) {
		if ( empty( $domain ) ) {
			return false;
		}
		$domains_file = SENTINELWP_PATH . 'data/disposable-email-domains.php';
		if ( file_exists( $domains_file ) ) {
			$list = include $domains_file;
			if ( is_array( $list ) && in_array( strtolower( $domain ), $list, true ) ) {
				return true;
			}
		}
		return false;
	}

	private function get_ip_subnet( $ip ) {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
		}
		return 'ipv6';
	}
}
