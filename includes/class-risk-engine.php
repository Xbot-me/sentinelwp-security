<?php
/**
 * SentinelWP Risk Engine
 *
 * Evaluates contextual checkout and payment signals, calculates additive threat scores,
 * assigns machine-readable reason codes, and returns policy decisions based on a dual
 * Risk + Confidence matrix.
 *
 * @package SentinelWP
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SentinelWP_Risk_Engine {

	const DECISION_ALLOW      = 'ALLOW';
	const DECISION_SOFT_BLOCK = 'SOFT_BLOCK';
	const DECISION_CHALLENGE  = 'CHALLENGE';
	const DECISION_HARD_BLOCK = 'HARD_BLOCK';

	const MODE_OBSERVE  = 'observe';
	const MODE_PROTECT  = 'protect';
	const MODE_LOCKDOWN = 'lockdown';

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Get the current operating mode (default: observe).
	 *
	 * @return string 'observe'|'protect'|'lockdown'
	 */
	public function get_mode() {
		$mode = get_option( 'sentinelwp_operating_mode', self::MODE_OBSERVE );
		return in_array( $mode, array( self::MODE_OBSERVE, self::MODE_PROTECT, self::MODE_LOCKDOWN ), true ) ? $mode : self::MODE_OBSERVE;
	}

	/**
	 * Update the operating mode.
	 *
	 * @param string $mode
	 */
	public function set_mode( $mode ) {
		if ( in_array( $mode, array( self::MODE_OBSERVE, self::MODE_PROTECT, self::MODE_LOCKDOWN ), true ) ) {
			update_option( 'sentinelwp_operating_mode', $mode );
		}
	}

	/**
	 * Evaluates a pre-gateway payment attempt using the dual Risk + Confidence policy matrix.
	 *
	 * @param array $context Normalized event context from SentinelWP_Event_Normalizer.
	 * @return array Structured risk evaluation decision.
	 */
	public function evaluate_payment_attempt( array $context ) {
		$score   = 0;
		$reasons = array();
		$mode    = $this->get_mode();

		// 1. Payment Failure Velocity
		if ( ( $context['cluster_failures'] ?? 0 ) >= 3 ) {
			$score    += 35;
			$reasons[] = 'REPEATED_PAYMENT_FAILURE';
			$reasons[] = 'DISTRIBUTED_IDENTITY_CLUSTER';
		} elseif ( ( $context['ip_failures'] ?? 0 ) >= 2 ) {
			$score    += 25;
			$reasons[] = 'REPEATED_PAYMENT_FAILURE';
		}

		// 2. High Order Creation Velocity
		if ( ( $context['ip_orders'] ?? 0 ) >= 5 ) {
			$score    += 30;
			$reasons[] = 'CARD_TESTING_VELOCITY';
		}

		// 3. Direct Store API Checkout without Journey Cadence
		if ( empty( $context['has_journey'] ) && ( false !== strpos( $context['endpoint'] ?? '', 'store' ) || 'store_api' === ( $context['endpoint'] ?? '' ) ) ) {
			$score    += 20;
			$reasons[] = 'DIRECT_CHECKOUT_WITHOUT_JOURNEY';
		}

		// 4. Micro-Cart Anomaly (Relative to Store p05 Distribution)
		if ( ! empty( $context['is_micro_cart'] ) ) {
			$score    += 15;
			$reasons[] = 'MICRO_CART_ANOMALY';
		}

		// 5. Disposable / Temporary Email Domain
		if ( ! empty( $context['is_disposable'] ) ) {
			$score    += 15;
			$reasons[] = 'DISPOSABLE_EMAIL_DOMAIN';
		}

		// Cap score between 0 and 100
		$score = max( 0, min( 100, $score ) );

		// Confidence is based on corroborating evidence, independently of the additive risk score.
		$confidence = 0.0;
		if ( in_array( 'REPEATED_PAYMENT_FAILURE', $reasons, true ) ) {
			$confidence += 0.40;
		}
		if ( in_array( 'CARD_TESTING_VELOCITY', $reasons, true ) ) {
			$confidence += 0.35;
		}
		if ( in_array( 'DISTRIBUTED_IDENTITY_CLUSTER', $reasons, true ) ) {
			$confidence += 0.35;
		}
		if ( in_array( 'DIRECT_CHECKOUT_WITHOUT_JOURNEY', $reasons, true ) ) {
			$confidence += 0.10;
		}
		if ( in_array( 'MICRO_CART_ANOMALY', $reasons, true ) ) {
			$confidence += 0.05;
		}
		if ( in_array( 'DISPOSABLE_EMAIL_DOMAIN', $reasons, true ) ) {
			$confidence += 0.05;
		}
		$confidence = round( min( 1.0, $confidence ), 2 );

		// Check for Corroborating Attack Reasons
		$has_corroborating_reasons = (
			( in_array( 'CARD_TESTING_VELOCITY', $reasons, true ) || in_array( 'DISTRIBUTED_IDENTITY_CLUSTER', $reasons, true ) ) &&
			in_array( 'REPEATED_PAYMENT_FAILURE', $reasons, true )
		);

		// --- DUAL RISK + CONFIDENCE POLICY MATRIX ---
		$raw_verdict = self::DECISION_ALLOW;

		if ( $score >= 85 && $confidence >= 0.85 && $has_corroborating_reasons ) {
			$raw_verdict = self::DECISION_HARD_BLOCK;
		} elseif ( $score >= 70 && $confidence >= 0.70 ) {
			$raw_verdict = self::DECISION_CHALLENGE;
		} elseif ( $score >= 40 && $confidence >= 0.40 ) {
			$raw_verdict = self::DECISION_SOFT_BLOCK;
		} else {
			$raw_verdict = self::DECISION_ALLOW;
		}

		// Enforce Operating Mode.
		// The hard-block safety invariant is identical in every enforcement mode.
		$decision           = self::DECISION_ALLOW;
		$would_have_blocked = ( self::DECISION_HARD_BLOCK === $raw_verdict );

		if ( self::MODE_LOCKDOWN === $mode ) {
			$decision = $raw_verdict;
		} elseif ( self::MODE_PROTECT === $mode ) {
			$decision = $raw_verdict;
		} else {
			// OBSERVE mode: always ALLOW live traffic, but record simulated action.
			$decision = self::DECISION_ALLOW;
		}

		$result = array(
			'decision'           => $decision,
			'raw_verdict'        => $raw_verdict,
			'risk_score'         => $score,
			'confidence'         => $confidence,
			'reasons'            => array_values( array_unique( $reasons ) ),
			'cluster_id'         => $context['cluster_id'] ?? 'cluster_general',
			'mode'               => $mode,
			'would_have_blocked' => $would_have_blocked,
			'simulated_action'   => $raw_verdict,
			'actual_result'      => $decision,
			'ip'                 => $context['ip'] ?? '',
			'timestamp'          => current_time( 'mysql' ),
			'recommended_action' => $this->get_recommended_action( $raw_verdict, $reasons ),
		);

		// Only commit telemetry log for anomalous/actionable events to ensure zero overhead on clean checkouts
		if ( $score > 0 || self::DECISION_ALLOW !== $raw_verdict ) {
			$this->log_decision( $result, $context );
		}

		return $result;
	}

	private function get_recommended_action( $verdict, array $reasons ) {
		if ( in_array( 'CARD_TESTING_VELOCITY', $reasons, true ) || in_array( 'DISTRIBUTED_IDENTITY_CLUSTER', $reasons, true ) ) {
			return __( 'Throttling Store API checkout for this identity cluster to mitigate card testing.', 'sentinelwp-security' );
		}
		if ( in_array( 'MICRO_CART_ANOMALY', $reasons, true ) && in_array( 'REPEATED_PAYMENT_FAILURE', $reasons, true ) ) {
			return __( 'Multiple failed micro-order attempts detected; challenge verification recommended.', 'sentinelwp-security' );
		}
		return __( 'Monitoring checkout session telemetry.', 'sentinelwp-security' );
	}

	private function log_decision( array $result, array $context ) {
		$log = get_option( 'sentinelwp_risk_decision_log', array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$entry = array(
			'id'                 => time() . '_' . substr( md5( ( $result['cluster_id'] ?? '' ) . microtime() ), 0, 6 ),
			'timestamp'          => current_time( 'mysql' ),
			'decision'           => $result['decision'],
			'raw_verdict'        => $result['raw_verdict'],
			'risk_score'         => $result['risk_score'],
			'confidence'         => $result['confidence'],
			'reasons'            => $result['reasons'],
			'cluster_id'         => $result['cluster_id'],
			'mode'               => $result['mode'],
			'would_have_blocked' => $result['would_have_blocked'],
			'cart_total'         => $context['cart_total'] ?? 0,
			'endpoint'           => $context['endpoint'] ?? '',
		);

		array_unshift( $log, $entry );
		if ( count( $log ) > 100 ) {
			$log = array_slice( $log, 0, 100 );
		}

		update_option( 'sentinelwp_risk_decision_log', $log, false );
	}

	/**
	 * Retrieve logged risk decisions for timeline visualizer.
	 */
	public function get_decision_log() {
		$log = get_option( 'sentinelwp_risk_decision_log', array() );
		return is_array( $log ) ? $log : array();
	}
}
