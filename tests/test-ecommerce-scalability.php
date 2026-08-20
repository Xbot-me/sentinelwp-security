<?php
/**
 * SentinelWP Ecommerce Scalability & HPOS Benchmark Test.
 */

if ( ! defined( 'ABSPATH' ) ) {
	require_once __DIR__ . '/bootstrap.php';
}

echo "=======================================================\n";
echo " Running SentinelWP Ecommerce Scalability Benchmark    \n";
echo "=======================================================\n";

global $wpdb;

// Verify Helper and HPOS detection
$is_hpos = SentinelWP_Helper::is_hpos_enabled();
echo "HPOS Active: " . ( $is_hpos ? "YES" : "NO (Legacy mode)" ) . "\n";

$initial_memory = memory_get_usage();
$start_time = microtime( true );

// Execute fraud analysis aggregation
SentinelWP_Ecommerce_Guard::instance()->cron_analyze_fraud_patterns();
SentinelWP_Ecommerce_Guard::instance()->cron_monitor_complaint_patterns();
SentinelWP_Ecommerce_Guard::instance()->cron_check_store_integrity();

$elapsed_time = microtime( true ) - $start_time;
$peak_memory  = ( memory_get_peak_usage() - $initial_memory ) / 1048576; // MB

echo sprintf( "Execution Time: %.4f seconds\n", $elapsed_time );
echo sprintf( "Memory Delta: %.2f MB\n", $peak_memory );

if ( $peak_memory < 5.0 ) {
	echo "[PASS] Memory bounded strictly under 5MB target.\n";
} else {
	echo "[FAIL] Memory consumption exceeded 5MB threshold.\n";
}

if ( $elapsed_time < 1.0 ) {
	echo "[PASS] Query execution completed in under 1 second.\n";
} else {
	echo "[WARN] Query execution exceeded 1 second threshold.\n";
}

echo "=======================================================\n";
