<?php
/**
 * SentinelGuard Store API Guard
 *
 * Intercepts WooCommerce Store API and classic checkout lifecycle events,
 * evaluates pre-gateway risk before processor dispatch, and augments native rate limiting.
 *
 * @package SentinelGuard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SentinelWP_Store_API_Guard {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		// Hook REST Store API pre-dispatch
		add_filter( 'rest_pre_dispatch', array( $this, 'intercept_rest_store_api' ), 5, 3 );

		// Hook Classic Checkout prior to gateway processing
		add_action( 'woocommerce_before_checkout_process', array( $this, 'intercept_classic_checkout' ), 5 );

		// Augment native WooCommerce Store API rate limiting with Cluster ID
		add_filter( 'woocommerce_store_api_rate_limit_id', array( $this, 'filter_store_api_rate_limit_id' ), 10, 2 );

		// Track failed payments per cluster
		add_action( 'woocommerce_order_status_failed', array( $this, 'on_payment_failed' ), 5, 1 );
	}

	/**
	 * Fast preflight filter on REST pre-dispatch.
	 * Bails immediately (<0.05ms) for non-commerce routes.
	 */
	public function intercept_rest_store_api( $result, $server, $request ) {
		$route = $request->get_route();

		// Fast route check: Only inspect WooCommerce Store API checkout & cart mutations
		if ( false === strpos( $route, '/wc/store/' ) ) {
			return $result;
		}

		// Only target checkout and cart mutation endpoints
		$is_checkout = ( false !== strpos( $route, '/checkout' ) || false !== strpos( $route, '/order' ) );
		$is_cart     = ( false !== strpos( $route, '/cart' ) && 'POST' === $request->get_method() );

		if ( ! $is_checkout && ! $is_cart ) {
			return $result;
		}

		$context  = SentinelWP_Event_Normalizer::instance()->build_context( $request );
		$decision = SentinelWP_Risk_Engine::instance()->evaluate_payment_attempt( $context );

		if ( SentinelWP_Risk_Engine::DECISION_HARD_BLOCK === $decision['decision'] ) {
			return new WP_Error(
				'sentinelwp_checkout_blocked',
				__( 'Checkout request blocked by security policy.', 'sentinelguard-ecommerce-protection' ),
				array(
					'status'     => 403,
					'reasons'    => $decision['reasons'],
					'cluster_id' => $decision['cluster_id'],
				)
			);
		}

		if ( SentinelWP_Risk_Engine::DECISION_SOFT_BLOCK === $decision['decision'] ) {
			return new WP_Error(
				'sentinelwp_checkout_throttled',
				__( 'Too many checkout attempts. Please wait a moment and try again.', 'sentinelguard-ecommerce-protection' ),
				array(
					'status'     => 429,
					'reasons'    => $decision['reasons'],
					'cluster_id' => $decision['cluster_id'],
				)
			);
		}

		return $result;
	}

	/**
	 * Intercepts classic checkout submissions prior to gateway processing.
	 */
	public function intercept_classic_checkout() {
		$context  = SentinelWP_Event_Normalizer::instance()->build_context();
		$decision = SentinelWP_Risk_Engine::instance()->evaluate_payment_attempt( $context );

		if ( SentinelWP_Risk_Engine::DECISION_HARD_BLOCK === $decision['decision'] ) {
			$msg = __( 'Unable to process checkout. Please contact store support.', 'sentinelguard-ecommerce-protection' );
			wc_add_notice( $msg, 'error' );
			throw new Exception( esc_html( $msg ) );
		} elseif ( SentinelWP_Risk_Engine::DECISION_SOFT_BLOCK === $decision['decision'] ) {
			$msg = __( 'Too many checkout attempts. Please wait a moment and try again.', 'sentinelguard-ecommerce-protection' );
			wc_add_notice( $msg, 'error' );
			throw new Exception( esc_html( $msg ) );
		}
	}

	/**
	 * Augments WooCommerce native Store API rate limiting by providing smart cluster ID.
	 */
	public function filter_store_api_rate_limit_id( $rate_limit_id, $request ) {
		$context = SentinelWP_Event_Normalizer::instance()->build_context( $request );
		if ( ! empty( $context['cluster_id'] ) ) {
			return 'sentinelwp_' . $context['cluster_id'];
		}
		return $rate_limit_id;
	}

	/**
	 * Tracks failed payment attempts against cluster ID.
	 */
	public function on_payment_failed( $order_id ) {
		$context    = SentinelWP_Event_Normalizer::instance()->build_context();
		$cluster_id = $context['cluster_id'] ?? '';

		if ( ! empty( $cluster_id ) ) {
			$key = 'sentinelwp_cluster_fails_' . $cluster_id;
			$cnt = (int) get_transient( $key );
			set_transient( $key, $cnt + 1, 15 * MINUTE_IN_SECONDS );
		}
	}
}
