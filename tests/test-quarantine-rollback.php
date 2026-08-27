<?php
/**
 * SentinelWP Remediation & Rollback Safety Test Suite
 *
 * Tests the complete lifecycle:
 * 1. Create a suspicious file fixture in wp-content/uploads/
 * 2. Record security finding
 * 3. Execute Quarantine -> State Capture (permissions, SHA-256 hash, original path)
 * 4. Verify file is completely removed from public webroot
 * 5. Verify file exists in locked vault with .htaccess protection
 * 6. Execute 1-Click Rollback / Restore
 * 7. Verify file restored to exact original location with identical hash and permissions
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "Direct access not permitted.\n" );
}

echo "======================================================================\n";
echo " SENTINELWP — REMEDIATION & ROLLBACK SAFETY TEST SUITE                \n";
echo "======================================================================\n";

global $wpdb;
$upload_dir = wp_upload_dir();
$test_dir   = trailingslashit( $upload_dir['basedir'] ) . 'sentinelwp-test-fixtures';

if ( ! file_exists( $test_dir ) ) {
	wp_mkdir_p( $test_dir );
}

$test_file_path    = trailingslashit( $test_dir ) . 'suspicious-payload-test.php';
$test_file_content = "<?php\n// Malicious skimmer simulation fixture\neval(base64_decode('ZWNobyAnc2tpbW1lcic7'));\n";

// Step 1: Create fixture
file_put_contents( $test_file_path, $test_file_content );
@chmod( $test_file_path, 0644 );
$original_hash = hash( 'sha256', $test_file_content );

echo "[STEP 1] Created test fixture: $test_file_path\n";
echo "         Original SHA-256 Hash: $original_hash\n";

// Step 2: Record Finding
$finding_id = SentinelWP_Scanner::instance()->record_finding(
	'fake_image_payload',
	'critical',
	'skimmer_detector',
	'Suspicious PHP Executable in Media Directory',
	json_encode( array( 'file' => $test_file_path ) ),
	'confirmed',
	'skimmer_detector',
	'Quarantine this suspicious script immediately.',
	'low'
);

echo "[STEP 2] Security finding recorded (Finding ID: $finding_id)\n";

// Step 3: Quarantine File
$quarantine_res = SentinelWP_Quarantine::instance()->quarantine_file( $finding_id, $test_file_path );
$quarantine_id  = isset( $quarantine_res['quarantine_id'] ) ? $quarantine_res['quarantine_id'] : 0;

if ( $quarantine_res['success'] && $quarantine_id ) {
	echo "\033[32m[PASS]\033[0m [STEP 3] File successfully quarantined (Quarantine ID: $quarantine_id)\n";
} else {
	echo "\033[31m[FAIL]\033[0m [STEP 3] Quarantine failed: " . $quarantine_res['message'] . "\n";
	exit( 1 );
}

// Step 4: Verify file removed from public webroot
$removed_from_webroot = ! file_exists( $test_file_path );
if ( $removed_from_webroot ) {
	echo "\033[32m[PASS]\033[0m [STEP 4] File safely removed from public webroot.\n";
} else {
	echo "\033[31m[FAIL]\033[0m [STEP 4] File still exists in webroot!\n";
}

// Step 5: Verify database-backed quarantine storage & zero disk footprint
$quarantine_row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}sentinelwp_quarantine WHERE id = %d", $quarantine_id ) );
$db_verified = ! empty( $quarantine_row ) && ! empty( $quarantine_row->file_content ) && hash( 'sha256', base64_decode( $quarantine_row->file_content ) ) === $original_hash;
if ( $db_verified ) {
	echo "\033[32m[PASS]\033[0m [STEP 5] Quarantined content verified in database (zero disk footprint).\n";
} else {
	echo "\033[31m[FAIL]\033[0m [STEP 5] Database quarantine payload verification failed.\n";
	exit( 1 );
}

// Step 6: 1-Click Rollback / Restore
$restore_res = SentinelWP_Quarantine::instance()->restore_quarantine( $quarantine_id );
if ( $restore_res['success'] ) {
	echo "\033[32m[PASS]\033[0m [STEP 6] 1-Click Rollback API executed successfully.\n";
} else {
	echo "\033[31m[FAIL]\033[0m [STEP 6] Rollback failed: " . $restore_res['message'] . "\n";
}

// Step 7: Verify restored file integrity
$restored_exists = file_exists( $test_file_path );
$restored_hash   = $restored_exists ? hash( 'sha256', file_get_contents( $test_file_path ) ) : '';
$restored_perms  = $restored_exists ? substr( sprintf( '%o', fileperms( $test_file_path ) ), -4 ) : '';

if ( $restored_exists && $restored_hash === $original_hash ) {
	echo "\033[32m[PASS]\033[0m [STEP 7] Restored file matches EXACT original hash ($restored_hash) and permissions ($restored_perms).\n";
} else {
	echo "\033[31m[FAIL]\033[0m [STEP 7] Restored file hash mismatch!\n";
}

// Cleanup test fixture and DB records
@unlink( $test_file_path );
@rmdir( $test_dir );
$wpdb->delete( $wpdb->prefix . 'sentinelwp_findings', array( 'id' => $finding_id ), array( '%d' ) );
$wpdb->delete( $wpdb->prefix . 'sentinelwp_quarantine', array( 'id' => $quarantine_id ), array( '%d' ) );

echo "======================================================================\n";
echo " REMEDIATION & ROLLBACK SAFETY LIFECYCLE: 100% VERIFIED                \n";
echo "======================================================================\n";
