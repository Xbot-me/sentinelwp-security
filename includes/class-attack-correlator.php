<?php
/**
 * SentinelGuard Attack Correlator
 *
 * Synthesizes disparate signals (traffic rate anomalies, failed payment bursts,
 * checkout velocity, disposable emails, JavaScript skimmers, and store config changes)
 * into high-confidence, actionable attack incidents.
 *
 * @package SentinelGuard
 */

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


class SentinelWP_Attack_Correlator {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Analyzes current active findings and rate metrics to synthesize correlated attack incidents.
	 *
	 * @return array List of synthesized attack incidents.
	 */
	public function get_active_incidents() {
		global $wpdb;

		// Fetch all open findings
		$open_findings = $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}sentinelwp_findings WHERE status = 'open' ORDER BY created_at DESC",
			ARRAY_A
		);

		if ( empty( $open_findings ) ) {
			$open_findings = array();
		}

		$incidents = array();

		// Rule 1: Checkout Compromise & Magecart Payment Skimmer
		$skimmer_incident = $this->correlate_checkout_compromise( $open_findings );
		if ( ! empty( $skimmer_incident ) ) {
			$incidents[] = $skimmer_incident;
		}

		// Rule 2: Active Card-Testing & Checkout Velocity Attack
		$card_test_incident = $this->correlate_card_testing_attack( $open_findings );
		if ( ! empty( $card_test_incident ) ) {
			$incidents[] = $card_test_incident;
		}

		// Rule 3: Store API Scraping & Bot Resource Exhaustion
		$scraping_incident = $this->correlate_store_scraping_flood( $open_findings );
		if ( ! empty( $scraping_incident ) ) {
			$incidents[] = $scraping_incident;
		}

		// Rule 4: Rogue Admin & Store Hijack Attempt
		$hijack_incident = $this->correlate_store_hijack_attempt( $open_findings );
		if ( ! empty( $hijack_incident ) ) {
			$incidents[] = $hijack_incident;
		}

		return apply_filters( 'sentinelwp_correlated_incidents', $incidents, $open_findings );
	}

	/**
	 * Correlates Magecart payment skimmer & checkout script compromise.
	 *
	 * @param array $findings List of open findings.
	 * @return array|null Incident data or null.
	 */
	private function correlate_checkout_compromise( array $findings ) {
		$matched_findings = array();
		$has_skimmer      = false;
		$has_fake_image   = false;
		$has_db_injection = false;
		$has_config_tamper = false;

		foreach ( $findings as $f ) {
			$type = $f['type'] ?? '';
			if ( 'checkout_skimmer' === $type ) {
				$has_skimmer        = true;
				$matched_findings[] = $f;
			} elseif ( 'fake_image_payload' === $type ) {
				$has_fake_image     = true;
				$matched_findings[] = $f;
			} elseif ( 'db_script_injection' === $type ) {
				$has_db_injection   = true;
				$matched_findings[] = $f;
			} elseif ( 'store_config_changed' === $type ) {
				$has_config_tamper  = true;
				$matched_findings[] = $f;
			}
		}

		if ( ! $has_skimmer && ! $has_fake_image && ! $has_db_injection ) {
			return null;
		}

		// Calculate dynamic confidence score
		$signals_count = count( $matched_findings );
		$confidence    = 92;
		if ( $has_skimmer && ( $has_fake_image || $has_db_injection || $has_config_tamper ) ) {
			$confidence = 98;
		} elseif ( $has_skimmer ) {
			$confidence = 95;
		}

		$signal_bullets = array();
		foreach ( $matched_findings as $mf ) {
			$signal_bullets[] = sprintf( '%s: %s', ucfirst( str_replace( '_', ' ', $mf['type'] ) ), $mf['title'] );
		}

		return array(
			'id'                 => 'incident_checkout_compromise',
			'type'               => 'checkout_compromise',
			'title'              => __( 'Checkout Compromise & Payment Data Exfiltration Threat', 'sentinelguard-ecommerce-protection' ),
			'severity'           => 'critical',
			'confidence_score'   => $confidence,
			/* translators: %d: confidence percentage number */
			'confidence_label'   => sprintf( __( '%d%% Confidence', 'sentinelguard-ecommerce-protection' ), $confidence ),
			'summary'            => __( 'An unverified script or backdoor payload was detected interacting with checkout payment fields. Customer payment card credentials are at immediate risk of interception.', 'sentinelguard-ecommerce-protection' ),
			'signals'            => $signal_bullets,
			'matched_count'      => $signals_count,
			'finding_ids'        => wp_list_pluck( $matched_findings, 'id' ),
			'recommended_action' => __( '1-Click Quarantine the flagged script file immediately and verify payment gateway API settings.', 'sentinelguard-ecommerce-protection' ),
			'action_type'        => 'quarantine',
		);
	}

	/**
	 * Correlates card-testing attacks and checkout velocity floods.
	 *
	 * @param array $findings List of open findings.
	 * @return array|null Incident data or null.
	 */
	private function correlate_card_testing_attack( array $findings ) {
		$matched_findings = array();

		foreach ( $findings as $f ) {
			$type = $f['type'] ?? '';
			if ( in_array( $type, array( 'card_testing', 'order_velocity', 'order_anomaly', 'disposable_email' ), true ) ) {
				$matched_findings[] = $f;
			}
		}

		if ( empty( $matched_findings ) ) {
			return null;
		}

		$signals_count = count( $matched_findings );
		$confidence = min( 98, 70 + ( $signals_count * 8 ) );

		$signal_bullets = array();
		foreach ( $matched_findings as $mf ) {
			$signal_bullets[] = sprintf( '%s: %s', ucfirst( str_replace( '_', ' ', $mf['type'] ) ), $mf['title'] );
		}

		return array(
			'id'                 => 'incident_card_testing_attack',
			'type'               => 'card_testing_attack',
			'title'              => __( 'Automated Card-Testing & Checkout Velocity Attack', 'sentinelguard-ecommerce-protection' ),
			'severity'           => 'critical',
			'confidence_score'   => $confidence,
			/* translators: %d: confidence percentage number */
			'confidence_label'   => sprintf( __( '%d%% Confidence', 'sentinelguard-ecommerce-protection' ), $confidence ),
			'summary'            => __( 'Automated bots are hitting checkout endpoints with rapid failed transactions to validate stolen payment cards. This attack risks gateway dispute penalties and server resource exhaustion.', 'sentinelguard-ecommerce-protection' ),
			'signals'            => $signal_bullets,
			'matched_count'      => count( $matched_findings ),
			'finding_ids'        => wp_list_pluck( $matched_findings, 'id' ),
			'recommended_action' => __( 'Enable 429 Checkout Throttling in Flood Protection settings and review flagged order IDs.', 'sentinelguard-ecommerce-protection' ),
			'action_type'        => 'throttle',
		);
	}

	/**
	 * Correlates Store API scraping & bot resource exhaustion.
	 *
	 * @param array $findings List of open findings.
	 * @return array|null Incident data or null.
	 */
	private function correlate_store_scraping_flood( array $findings ) {
		$matched_findings = array();

		foreach ( $findings as $f ) {
			$type = $f['type'] ?? '';
			if ( 'flood_detected' === $type ) {
				$matched_findings[] = $f;
			}
		}

		if ( empty( $matched_findings ) ) {
			return null;
		}

		$confidence = 88;
		$signal_bullets = array();
		foreach ( $matched_findings as $mf ) {
			$signal_bullets[] = sprintf( '%s: %s', __( 'Traffic Anomaly', 'sentinelguard-ecommerce-protection' ), $mf['title'] );
		}

		return array(
			'id'                 => 'incident_store_scraping_flood',
			'type'               => 'store_scraping_flood',
			'title'              => __( 'Automated Store API Scraping & Resource Flood', 'sentinelguard-ecommerce-protection' ),
			'severity'           => 'high',
			'confidence_score'   => $confidence,
			/* translators: %d: confidence percentage number */
			'confidence_label'   => sprintf( __( '%d%% Confidence', 'sentinelguard-ecommerce-protection' ), $confidence ),
			'summary'            => __( 'High-frequency automated traffic is scraping product catalogs and Store API routes, consuming database connections and server memory.', 'sentinelguard-ecommerce-protection' ),
			'signals'            => $signal_bullets,
			'matched_count'      => count( $matched_findings ),
			'finding_ids'        => wp_list_pluck( $matched_findings, 'id' ),
			'recommended_action' => __( 'Enable Form Shield and adjust rate limits under Settings -> Modules -> Flood Protection.', 'sentinelguard-ecommerce-protection' ),
			'action_type'        => 'settings',
		);
	}

	/**
	 * Correlates stealth admin creations and payment config tampering.
	 *
	 * @param array $findings List of open findings.
	 * @return array|null Incident data or null.
	 */
	private function correlate_store_hijack_attempt( array $findings ) {
		$matched_findings = array();
		$has_admin_threat = false;
		$has_config_threat = false;

		foreach ( $findings as $f ) {
			$type = $f['type'] ?? '';
			if ( in_array( $type, array( 'hidden_admin_detected', 'unauthorized_admin_creation', 'admin_role_granted', 'orphaned_admin_meta' ), true ) ) {
				$has_admin_threat   = true;
				$matched_findings[] = $f;
			} elseif ( in_array( $type, array( 'store_config_changed', 'core_integrity', 'malware_signature' ), true ) ) {
				$has_config_threat  = true;
				$matched_findings[] = $f;
			}
		}

		if ( ! $has_admin_threat || ! $has_config_threat ) {
			return null;
		}

		$confidence = 97;
		$signal_bullets = array();
		foreach ( $matched_findings as $mf ) {
			$signal_bullets[] = sprintf( '%s: %s', ucfirst( str_replace( '_', ' ', $mf['type'] ) ), $mf['title'] );
		}

		return array(
			'id'                 => 'incident_store_hijack_attempt',
			'type'               => 'store_hijack_attempt',
			'title'              => __( 'Privilege Escalation & Store Gateway Tamper Attempt', 'sentinelguard-ecommerce-protection' ),
			'severity'           => 'critical',
			'confidence_score'   => $confidence,
			/* translators: %d: confidence percentage number */
			'confidence_label'   => sprintf( __( '%d%% Confidence', 'sentinelguard-ecommerce-protection' ), $confidence ),
			'summary'            => __( 'An unauthorized administrator account was generated and coincides with modified core files or payment gateway settings.', 'sentinelguard-ecommerce-protection' ),
			'signals'            => $signal_bullets,
			'matched_count'      => count( $matched_findings ),
			'finding_ids'        => wp_list_pluck( $matched_findings, 'id' ),
			'recommended_action' => __( 'Purge rogue administrator accounts and rotate payment gateway secret keys immediately.', 'sentinelguard-ecommerce-protection' ),
			'action_type'        => 'review_admins',
		);
	}
}
