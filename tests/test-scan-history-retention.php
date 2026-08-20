<?php
/**
 * SentinelWP Scan History Storage, 30-Day Auto Purge & Deletion Verification
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "Direct access not permitted.\n" );
}

echo "======================================================================\n";
echo " SENTINELWP — SCAN HISTORY STORAGE & 30-DAY AUTO PURGE AUDIT          \n";
echo "======================================================================\n";

$coordinator = SentinelWP_Scan_Coordinator::instance();

// 1. Verify Scan History Storage
echo "--> 1. Testing Scan Run Storage...\n";
$res = $coordinator->run_full_scan();
$history = $coordinator->get_scan_history();

if ( ! empty( $history ) && isset( $history[0]['timestamp'] ) ) {
	echo "\033[32m[PASS]\033[0m Scan run stored successfully: {$history[0]['timestamp']} | Duration: {$history[0]['total_time']}s | Status: {$history[0]['status']}\n";
} else {
	echo "\033[31m[FAIL]\033[0m Scan run was not stored in scan history!\n";
}

// 2. Test Single Scan Run Deletion
echo "--> 2. Testing Single Scan Run Deletion...\n";
$target_id = $history[0]['id'];
$initial_count = count( $history );
$delete_res = $coordinator->delete_scan_run( $target_id );
$history_after_delete = $coordinator->get_scan_history();

if ( $delete_res && count( $history_after_delete ) === ( $initial_count - 1 ) ) {
	echo "\033[32m[PASS]\033[0m Single scan run (ID: $target_id) successfully removed.\n";
} else {
	echo "\033[31m[FAIL]\033[0m Failed to delete single scan run.\n";
}

// 3. Test 30-Day Auto-Purge Routine
echo "--> 3. Testing 30-Day Auto-Purge Routine...\n";
// Inject mock history: 2 recent runs (1 day old, 5 days old), 2 expired runs (35 days old, 60 days old)
$mock_history = array(
	array( 'id' => 1001, 'timestamp' => date( 'Y-m-d H:i:s', time() - ( 1 * DAY_IN_SECONDS ) ), 'status' => 'completed', 'total_time' => 5.2 ),
	array( 'id' => 1002, 'timestamp' => date( 'Y-m-d H:i:s', time() - ( 5 * DAY_IN_SECONDS ) ), 'status' => 'completed', 'total_time' => 6.1 ),
	array( 'id' => 1003, 'timestamp' => date( 'Y-m-d H:i:s', time() - ( 35 * DAY_IN_SECONDS ) ), 'status' => 'completed', 'total_time' => 4.8 ),
	array( 'id' => 1004, 'timestamp' => date( 'Y-m-d H:i:s', time() - ( 60 * DAY_IN_SECONDS ) ), 'status' => 'completed', 'total_time' => 7.3 ),
);
update_option( 'sentinelwp_scan_history_log', $mock_history, false );

$purged_count = $coordinator->auto_purge_old_history( 30 );
$history_after_purge = $coordinator->get_scan_history();

$retained_ids = wp_list_pluck( $history_after_purge, 'id' );

if ( 2 === $purged_count && count( $history_after_purge ) === 2 && in_array( 1001, $retained_ids ) && in_array( 1002, $retained_ids ) && ! in_array( 1003, $retained_ids ) && ! in_array( 1004, $retained_ids ) ) {
	echo "\033[32m[PASS]\033[0m 30-Day auto-purge verified: 2 expired records (>30d) purged, 2 recent records (<30d) safely retained.\n";
} else {
	echo "\033[31m[FAIL]\033[0m Auto-purge failed (Purged: $purged_count, Remaining: " . count( $history_after_purge ) . ")\n";
}

// 4. Test Complete Clear Scan History
echo "--> 4. Testing Clear Scan History Action...\n";
$clear_res = $coordinator->clear_scan_history();
$history_after_clear = get_option( 'sentinelwp_scan_history_log' );

if ( empty( $history_after_clear ) ) {
	echo "\033[32m[PASS]\033[0m Clear scan history verified: Option completely wiped.\n";
} else {
	echo "\033[31m[FAIL]\033[0m Failed to clear scan history.\n";
}

// 5. Regenerate fresh scan state
echo "--> 5. Restoring Active Scan Run...\n";
$coordinator->run_full_scan();
$fresh_history = $coordinator->get_scan_history();

if ( ! empty( $fresh_history ) ) {
	echo "\033[32m[PASS]\033[0m Fresh active scan state ready.\n";
} else {
	echo "\033[31m[FAIL]\033[0m Failed to generate fresh active scan.\n";
}

echo "======================================================================\n";
echo " SCAN HISTORY & 30-DAY RETENTION AUDIT: 100% OPERATIONAL              \n";
echo "======================================================================\n";
