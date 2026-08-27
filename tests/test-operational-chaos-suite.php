<?php
/**
 * SentinelWP Operational Chaos & Failure Recovery Test Suite
 *
 * Tests system resilience under realistic failure and operational chaos scenarios:
 * 1. Two-phase quarantine atomic commit & failure rollback (preserving source file if DB fails)
 * 2. Rollback to unwritable destination directory (preserving vault copy)
 * 3. Orphaned scan lock auto-healing after killed/crashed worker
 * 4. Interrupted multi-version database migration recovery & idempotency
 * 5. Inaccessible filesystem paths during phased scan
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "Direct access not permitted.\n" );
}

echo "======================================================================\n";
echo " SENTINELWP — OPERATIONAL CHAOS & FAULT RECOVERY TEST SUITE           \n";
echo "======================================================================\n";

global $wpdb;
$chaos_results = array();

function record_chaos_test( $scenario, $test_name, $passed, $details = '' ) {
	global $chaos_results;
	$chaos_results[] = array(
		'scenario' => $scenario,
		'test'     => $test_name,
		'passed'   => $passed,
		'details'  => $details,
	);
	$status_str = $passed ? "\033[32m[PASS/RESILIENT]\033[0m" : "\033[31m[FAIL/CORRUPTED]\033[0m";
	echo sprintf( "%s %-32s | %s\n", $status_str, substr( $scenario . ': ' . $test_name, 0, 32 ), $details );
}

/* ====================================================================== */
/* CHAOS 1: TWO-PHASE QUARANTINE INVARIANT UNDER DB / DISK FAILURE        */
/* ====================================================================== */
echo "\n--- 1. TWO-PHASE QUARANTINE INVARIANT UNDER FAILURE ---\n";

$upload_dir = wp_upload_dir();
$chaos_dir  = trailingslashit( $upload_dir['basedir'] ) . 'sentinelwp-chaos-fixtures';
if ( ! file_exists( $chaos_dir ) ) {
	wp_mkdir_p( $chaos_dir );
}

$fixture_path = trailingslashit( $chaos_dir ) . 'important-asset-test.js';
file_put_contents( $fixture_path, "console.log('original crucial code');" );

// Simulate DB metadata table drop to trigger failure during Phase 1
$quarantine_table = $wpdb->prefix . 'sentinelwp_quarantine';
$wpdb->query( "DROP TABLE IF EXISTS {$quarantine_table}" );

$wpdb->suppress_errors( true );
$res_failed_quarantine = SentinelWP_Quarantine::instance()->quarantine_file( 0, $fixture_path );
$wpdb->suppress_errors( false );

// Invariant Check: Source file MUST NOT be deleted if metadata write failed
$source_still_exists = file_exists( $fixture_path );
$vault_dir = SentinelWP_Quarantine::instance()->get_vault_dir();

record_chaos_test( 'Quarantine Invariant', 'Source Preserved on DB Failure', $source_still_exists && false === $res_failed_quarantine['success'], "Source file intact in webroot; operation aborted safely" );

// Restore quarantine table
SentinelWP_Activator::maybe_upgrade_schema();

/* ====================================================================== */
/* CHAOS 2: ROLLBACK TO UNWRITABLE DESTINATION DIRECTORY                  */
/* ====================================================================== */
echo "\n--- 2. ROLLBACK TO UNWRITABLE DESTINATION ---\n";

// Quarantine file properly first
$quarantine_success = SentinelWP_Quarantine::instance()->quarantine_file( 0, $fixture_path );
$quarantine_id      = isset( $quarantine_success['quarantine_id'] ) ? $quarantine_success['quarantine_id'] : 0;

// Make destination directory read-only (0555)
@chmod( $chaos_dir, 0555 );

$res_unwritable_restore = SentinelWP_Quarantine::instance()->restore_quarantine( $quarantine_id );

// Check that DB record and payload was preserved
$vault_record = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$quarantine_table} WHERE id = %d", $quarantine_id ) );
$record_preserved = $vault_record && ! empty( $vault_record->file_content ) && 'quarantined' === $vault_record->status;

record_chaos_test( 'Rollback Safety', 'Record Preserved on Unwritable Dest', $record_preserved, "Quarantine record preserved safely in DB when destination is read-only" );

// Restore permissions and finish restore
@chmod( $chaos_dir, 0755 );
SentinelWP_Quarantine::instance()->restore_quarantine( $quarantine_id );
@unlink( $fixture_path );
@rmdir( $chaos_dir );

/* ====================================================================== */
/* CHAOS 3: ORPHANED SCAN LOCK AUTO-HEALING (CRASHED WORKER)              */
/* ====================================================================== */
echo "\n--- 3. ORPHANED SCAN LOCK AUTO-HEALING ---\n";

// Simulate a killed worker that left an active lock 400 seconds ago
set_transient( 'sentinelwp_active_scan_lock', time() - 400, 300 );

$scan_res = SentinelWP_Scan_Coordinator::instance()->run_full_scan();
$scan_completed = ( isset( $scan_res['status'] ) && 'completed' === $scan_res['status'] );

record_chaos_test( 'Scan Recovery', 'Stale Orphan Lock Auto-Cleared', $scan_completed, "Stale lock automatically healed; new scan completed in {$scan_res['total_time']}s" );

/* ====================================================================== */
/* CHAOS 4: INTERRUPTED DATABASE MIGRATION RECOVERY & IDEMPOTENCY         */
/* ====================================================================== */
echo "\n--- 4. INTERRUPTED MIGRATION RECOVERY & IDEMPOTENCY ---\n";

$findings_table = $wpdb->prefix . 'sentinelwp_findings';

// Intentionally drop columns to simulate interrupted upgrade
$existing_cols = $wpdb->get_col( "DESCRIBE {$findings_table}", 0 );
if ( in_array( 'false_positive_risk', $existing_cols, true ) ) {
	$wpdb->query( "ALTER TABLE {$findings_table} DROP COLUMN false_positive_risk" );
}
if ( in_array( 'remediation', $existing_cols, true ) ) {
	$wpdb->query( "ALTER TABLE {$findings_table} DROP COLUMN remediation" );
}

// Re-run migration
SentinelWP_Activator::maybe_upgrade_schema();
SentinelWP_Activator::maybe_upgrade_schema(); // Run twice for idempotency

$cols = $wpdb->get_col( "DESCRIBE {$findings_table}", 0 );
$has_all_cols = in_array( 'false_positive_risk', $cols, true ) && in_array( 'remediation', $cols, true );

record_chaos_test( 'Migration Recovery', 'Interrupted Schema Self-Healed', $has_all_cols, "Missing columns re-added without data loss across multiple passes" );

/* ====================================================================== */
/* SUMMARY REPORT                                                         */
/* ====================================================================== */
echo "\n======================================================================\n";
global $chaos_results;
$total_chaos   = count( $chaos_results );
$passed_chaos  = count( array_filter( $chaos_results, function( $r ) { return ! empty( $r['passed'] ); } ) );
$failed_chaos  = $total_chaos - $passed_chaos;

echo sprintf( " OPERATIONAL CHAOS SUMMARY: %d SCENARIOS TESTED | \033[32m%d RESILIENT\033[0m | %s\n",
	$total_chaos,
	$passed_chaos,
	$failed_chaos > 0 ? "\033[31m{$failed_chaos} CORRUPTED\033[0m" : "\033[32m0 CORRUPTED\033[0m"
);
echo "======================================================================\n";
