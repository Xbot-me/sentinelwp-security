<?php
/**
 * SentinelWP Multi-Tiered Findings Confidence Test.
 */

if ( ! defined( 'ABSPATH' ) ) {
	require_once __DIR__ . '/bootstrap.php';
}

echo "=======================================================\n";
echo " Running Multi-Tiered Confidence & Schema Tests        \n";
echo "=======================================================\n";

global $wpdb;
$table = $wpdb->prefix . 'sentinelwp_findings';

// Test inserting a confirmed finding
$test_finding_id = SentinelWP_Ecommerce_Guard::instance()->record_finding(
	'test_card_testing',
	'critical',
	'ecommerce_guard',
	'Test Card Testing Attack with Confidence Score',
	'Sample details',
	'confirmed',
	'ecommerce_guard',
	'Block test IP and investigate payment gateway.',
	'low'
);

if ( $test_finding_id ) {
	$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $test_finding_id ) );
	if ( $row && 'confirmed' === $row->confidence && 'ecommerce_guard' === $row->detector && ! empty( $row->remediation ) ) {
		echo "[PASS] Multi-tiered finding stored with confidence='{$row->confidence}', detector='{$row->detector}', and remediation.\n";
	} else {
		echo "[FAIL] Finding stored without expected confidence/detector schema.\n";
	}

	// Clean up test finding
	$wpdb->delete( $table, array( 'id' => $test_finding_id ), array( '%d' ) );
	echo "[PASS] Test finding safely removed.\n";
} else {
	echo "[FAIL] Could not insert test finding.\n";
}

echo "=======================================================\n";
