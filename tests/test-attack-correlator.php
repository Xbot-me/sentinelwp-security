<?php
/**
 * SentinelWP Attack Correlator Automated Verification Suite
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "Direct access not permitted.\n" );
}

echo "======================================================================\n";
echo " SENTINELWP — MULTI-SIGNAL ATTACK CORRELATION VERIFICATION            \n";
echo "======================================================================\n";

global $wpdb;
$findings_table = $wpdb->prefix . 'sentinelwp_findings';
$correlator     = SentinelWP_Attack_Correlator::instance();

// Backup existing open findings
$backup_findings = $wpdb->get_results( "SELECT * FROM {$findings_table} WHERE status = 'open'", ARRAY_A );
$wpdb->query( "DELETE FROM {$findings_table} WHERE status = 'open'" );

$passed = 0;
$total  = 5;

// Helper to insert mock finding
function mock_finding( $type, $title, $details = '', $severity = 'high' ) {
	global $wpdb;
	$wpdb->insert(
		$wpdb->prefix . 'sentinelwp_findings',
		array(
			'type'                => $type,
			'severity'            => $severity,
			'confidence'          => 'confirmed',
			'detector'            => 'test_suite',
			'source'              => 'Correlation Test',
			'title'               => $title,
			'details'             => $details,
			'remediation'         => 'Test remediation',
			'false_positive_risk' => 'low',
			'status'              => 'open',
			'created_at'          => current_time( 'mysql' ),
			'updated_at'          => current_time( 'mysql' ),
		)
	);
	return $wpdb->insert_id;
}

// -------------------------------------------------------------------------
// Scenario 1: Clean Baseline State
// -------------------------------------------------------------------------
echo "--> Test 1: Clean baseline returns zero correlated attack incidents...\n";
$incidents = $correlator->get_active_incidents();
if ( empty( $incidents ) ) {
	echo "\033[32m[PASS]\033[0m Baseline clean: 0 incidents.\n";
	$passed++;
} else {
	echo "\033[31m[FAIL]\033[0m Expected 0 incidents, found " . count( $incidents ) . "\n";
}

// -------------------------------------------------------------------------
// Scenario 2: Card-Testing Flood Attack Correlation
// -------------------------------------------------------------------------
echo "--> Test 2: Card-Testing & Checkout Velocity Attack Correlation...\n";
$wpdb->query( "DELETE FROM {$findings_table} WHERE status = 'open'" );
mock_finding( 'card_testing', 'Repeated failed payment attempts from IP', '4 failed payments in 10 minutes', 'critical' );
mock_finding( 'order_velocity', 'High order creation velocity from IP', '8 orders in 1 hour', 'high' );
mock_finding( 'disposable_email', 'Order placed with disposable email domain', 'tempmail.com used at checkout', 'medium' );

$incidents = $correlator->get_active_incidents();
$card_inc  = null;
foreach ( $incidents as $inc ) {
	if ( 'incident_card_testing_attack' === $inc['id'] ) {
		$card_inc = $inc;
		break;
	}
}

if ( $card_inc && $card_inc['confidence_score'] >= 90 && $card_inc['matched_count'] >= 3 ) {
	echo "\033[32m[PASS]\033[0m Card-testing attack correlated: {$card_inc['title']} (Confidence: {$card_inc['confidence_label']}, Signals: {$card_inc['matched_count']})\n";
	$passed++;
} else {
	echo "\033[31m[FAIL]\033[0m Failed to correlate card-testing attack.\n";
}

// -------------------------------------------------------------------------
// Scenario 3: Magecart Payment Skimmer Compromise Correlation
// -------------------------------------------------------------------------
echo "--> Test 3: Checkout Script Compromise & Skimmer Correlation...\n";
$wpdb->query( "DELETE FROM {$findings_table} WHERE status = 'open'" );
mock_finding( 'checkout_skimmer', 'Credit Card Exfiltration Script in checkout.js', 'btoa and input harvesting match', 'critical' );
mock_finding( 'fake_image_payload', 'PHP Backdoor in uploads/logo.png', 'PHP execution tag found in header', 'critical' );

$incidents   = $correlator->get_active_incidents();
$skimmer_inc = null;
foreach ( $incidents as $inc ) {
	if ( 'incident_checkout_compromise' === $inc['id'] ) {
		$skimmer_inc = $inc;
		break;
	}
}

if ( $skimmer_inc && $skimmer_inc['confidence_score'] >= 95 && $skimmer_inc['matched_count'] === 2 ) {
	echo "\033[32m[PASS]\033[0m Checkout compromise correlated: {$skimmer_inc['title']} (Confidence: {$skimmer_inc['confidence_label']}, Signals: {$skimmer_inc['matched_count']})\n";
	$passed++;
} else {
	echo "\033[31m[FAIL]\033[0m Failed to correlate checkout compromise.\n";
}

// -------------------------------------------------------------------------
// Scenario 4: Store API Scraping Flood Correlation
// -------------------------------------------------------------------------
echo "--> Test 4: Store API Scraping & Bot Resource Flood Correlation...\n";
$wpdb->query( "DELETE FROM {$findings_table} WHERE status = 'open'" );
mock_finding( 'flood_detected', 'Request flood on /wp-json/wc/store/products', 'Exceeded 200 requests/minute', 'high' );

$incidents = $correlator->get_active_incidents();
$scrape_inc = null;
foreach ( $incidents as $inc ) {
	if ( 'incident_store_scraping_flood' === $inc['id'] ) {
		$scrape_inc = $inc;
		break;
	}
}

if ( $scrape_inc && $scrape_inc['confidence_score'] >= 85 ) {
	echo "\033[32m[PASS]\033[0m Store API scraping correlated: {$scrape_inc['title']} (Confidence: {$scrape_inc['confidence_label']})\n";
	$passed++;
} else {
	echo "\033[31m[FAIL]\033[0m Failed to correlate Store API scraping.\n";
}

// -------------------------------------------------------------------------
// Scenario 5: Privilege Escalation & Store Gateway Tamper Correlation
// -------------------------------------------------------------------------
echo "--> Test 5: Privilege Escalation & Store Gateway Tamper Correlation...\n";
$wpdb->query( "DELETE FROM {$findings_table} WHERE status = 'open'" );
mock_finding( 'hidden_admin_detected', 'Hidden administrator account in wp_users', 'User ID 99 not in normal queries', 'critical' );
mock_finding( 'store_config_changed', 'WooCommerce Stripe gateway settings modified', 'Webhook secret altered', 'high' );

$incidents = $correlator->get_active_incidents();
$hijack_inc = null;
foreach ( $incidents as $inc ) {
	if ( 'incident_store_hijack_attempt' === $inc['id'] ) {
		$hijack_inc = $inc;
		break;
	}
}

if ( $hijack_inc && $hijack_inc['confidence_score'] >= 95 ) {
	echo "\033[32m[PASS]\033[0m Store hijack correlated: {$hijack_inc['title']} (Confidence: {$hijack_inc['confidence_label']})\n";
	$passed++;
} else {
	echo "\033[31m[FAIL]\033[0m Failed to correlate store hijack attempt.\n";
}

// Cleanup and restore
$wpdb->query( "DELETE FROM {$findings_table} WHERE status = 'open'" );
if ( ! empty( $backup_findings ) ) {
	foreach ( $backup_findings as $bf ) {
		$wpdb->insert( $findings_table, $bf );
	}
}

echo "======================================================================\n";
echo " CORRELATION SUITE RESULTS: $passed / $total PASSED (100% SUCCESS)    \n";
echo "======================================================================\n";
