<?php
/**
 * SentinelWP Canonical Payment Event Adapter
 *
 * Maps disparate gateway hooks and WooCommerce order transitions into standard,
 * canonical payment lifecycle events for uniform risk evaluation.
 *
 * @package SentinelWP
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SentinelWP_Payment_Adapter {

	const EVENT_ATTEMPT  = 'PAYMENT_ATTEMPT';
	const EVENT_SUCCESS  = 'PAYMENT_SUCCESS';
	const EVENT_DECLINED = 'PAYMENT_DECLINED';
	const EVENT_ERROR    = 'PAYMENT_ERROR';
	const EVENT_TIMEOUT  = 'PAYMENT_TIMEOUT';

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		// Canonical Attempt
		add_action( 'woocommerce_checkout_order_processed', array( $this, 'on_checkout_processed' ), 10, 3 );

		// Canonical Success
		add_action( 'woocommerce_payment_complete', array( $this, 'on_payment_complete' ), 10, 1 );
		add_action( 'woocommerce_order_status_completed', array( $this, 'on_payment_complete' ), 10, 1 );

		// Canonical Decline / Error
		add_action( 'woocommerce_order_status_failed', array( $this, 'on_payment_failed' ), 10, 1 );
		add_action( 'woocommerce_order_status_cancelled', array( $this, 'on_payment_cancelled' ), 10, 1 );
	}

	/**
	 * Record and normalize a canonical payment lifecycle event.
	 *
	 * @param string $event_type One of EVENT_* constants.
	 * @param int    $order_id   WooCommerce Order ID.
	 * @param array  $meta       Optional additional metadata.
	 * @return array Normalized payment event record.
	 */
	public function record_payment_event( $event_type, $order_id, array $meta = array() ) {
		$context = SentinelWP_Event_Normalizer::instance()->build_context();
		$order   = function_exists( 'wc_get_order' ) ? wc_get_order( $order_id ) : null;

		$amount     = $order ? (float) $order->get_total() : (float) ( $context['cart_total'] ?? 0.0 );
		$gateway_id = $order ? $order->get_payment_method() : 'unknown';
		$currency   = $order ? $order->get_currency() : 'USD';
		$cluster_id = $context['cluster_id'] ?? 'cluster_general';

		$event = array(
			'timestamp'    => time(),
			'datetime'     => current_time( 'mysql' ),
			'event_type'   => $event_type,
			'order_id'     => (int) $order_id,
			'gateway_id'   => sanitize_key( $gateway_id ),
			'amount'       => $amount,
			'currency'     => sanitize_text_field( $currency ),
			'ip'           => $context['ip'] ?? '',
			'session_id'   => $context['session_id'] ?? '',
			'cluster_id'   => $cluster_id,
			'decline_code' => $meta['decline_code'] ?? '',
			'error_msg'    => $meta['error_msg'] ?? '',
		);

		$this->update_cluster_metrics( $event );
		$this->log_payment_event( $event );

		do_action( 'sentinelwp_canonical_payment_event', $event );

		return $event;
	}

	public function on_checkout_processed( $order_id, $posted_data = array(), $order = null ) {
		$this->record_payment_event( self::EVENT_ATTEMPT, $order_id );
	}

	public function on_payment_complete( $order_id ) {
		$this->record_payment_event( self::EVENT_SUCCESS, $order_id );
	}

	public function on_payment_failed( $order_id ) {
		$this->record_payment_event( self::EVENT_DECLINED, $order_id, array(
			'error_msg' => __( 'Payment processing failed or card declined by gateway.', 'sentinelwp-security' ),
		) );
	}

	public function on_payment_cancelled( $order_id ) {
		$this->record_payment_event( self::EVENT_ERROR, $order_id, array(
			'error_msg' => __( 'Payment cancelled or abandoned.', 'sentinelwp-security' ),
		) );
	}

	private function update_cluster_metrics( array $event ) {
		$cluster_id = $event['cluster_id'];
		if ( empty( $cluster_id ) ) {
			return;
		}

		$key = 'sentinelwp_cluster_fails_' . $cluster_id;

		if ( in_array( $event['event_type'], array( self::EVENT_DECLINED, self::EVENT_ERROR ), true ) ) {
			$cnt = (int) get_transient( $key );
			set_transient( $key, $cnt + 1, 15 * MINUTE_IN_SECONDS );
		} elseif ( self::EVENT_SUCCESS === $event['event_type'] ) {
			// Successful payment diminishes failure count
			$cnt = (int) get_transient( $key );
			if ( $cnt > 0 ) {
				set_transient( $key, max( 0, $cnt - 1 ), 15 * MINUTE_IN_SECONDS );
			}
		}
	}

	private function log_payment_event( array $event ) {
		$log = get_option( 'sentinelwp_payment_events_log', array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		array_unshift( $log, $event );
		if ( count( $log ) > 100 ) {
			$log = array_slice( $log, 0, 100 );
		}

		update_option( 'sentinelwp_payment_events_log', $log, false );
	}

	public function get_payment_events_log() {
		$log = get_option( 'sentinelwp_payment_events_log', array() );
		return is_array( $log ) ? $log : array();
	}
}
