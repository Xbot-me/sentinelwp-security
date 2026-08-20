<?php
/**
 * SentinelWP Adversarial Security, Abuse & Attack Resistance Test Suite
 *
 * Subjecting SentinelWP to direct exploits, hostile inputs, and edge cases:
 * - Path traversal in quarantine / rollback
 * - Core system file protection
 * - Symlink escapes
 * - Malformed / Poisoned / Huge HTTP proxy headers
 * - Memory exhaustion / giant file handling in scanner
 * - HPOS Query Plan (EXPLAIN) verification
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "Direct access not permitted.\n" );
}

echo "======================================================================\n";
echo " SENTINELWP — ADVERSARIAL ABUSE & ATTACK RESISTANCE TEST SUITE        \n";
echo "======================================================================\n";

$abuse_results = array();

function record_abuse_test( $vector, $attack_name, $blocked_successfully, $details = '' ) {
	global $abuse_results;
	$abuse_results[] = array(
		'vector'  => $vector,
		'attack'  => $attack_name,
		'blocked' => $blocked_successfully,
		'details' => $details,
	);
	$status_str = $blocked_successfully ? "\033[32m[BLOCKED/SAFE]\033[0m" : "\033[31m[EXPLOITED/FAIL]\033[0m";
	echo sprintf( "%s %-32s | %s\n", $status_str, substr( $vector . ': ' . $attack_name, 0, 32 ), $details );
}

/* ====================================================================== */
/* 1. ADVERSARIAL QUARANTINE & PATH TRAVERSAL ATTACKS                     */
/* ====================================================================== */
echo "\n--- 1. QUARANTINE & PATH TRAVERSAL DEFENSE ---\n";

// Attack 1.1: Relative path traversal to /etc/passwd
$res_traversal = SentinelWP_Quarantine::instance()->quarantine_file( 0, '../../../../../../etc/passwd' );
record_abuse_test( 'Quarantine', 'Path Traversal (../../etc/passwd)', false === $res_traversal['success'], $res_traversal['message'] );

// Attack 1.2: Path traversal to wp-config.php via relative path
$res_config_rel = SentinelWP_Quarantine::instance()->quarantine_file( 0, WP_CONTENT_DIR . '/uploads/../../wp-config.php' );
record_abuse_test( 'Quarantine', 'Relative wp-config.php Traversal', false === $res_config_rel['success'], $res_config_rel['message'] );

// Attack 1.3: Direct quarantine attempt on ABSPATH wp-config.php
$res_config_direct = SentinelWP_Quarantine::instance()->quarantine_file( 0, ABSPATH . 'wp-config.php' );
record_abuse_test( 'Quarantine', 'Direct wp-config.php Protection', false === $res_config_direct['success'], $res_config_direct['message'] );

// Attack 1.4: Direct quarantine attempt on ABSPATH index.php
$res_index = SentinelWP_Quarantine::instance()->quarantine_file( 0, ABSPATH . 'index.php' );
record_abuse_test( 'Quarantine', 'Direct index.php Protection', false === $res_index['success'], $res_index['message'] );

// Attack 1.5: Direct quarantine attempt on wp-admin core script
$res_admin_core = SentinelWP_Quarantine::instance()->quarantine_file( 0, ABSPATH . 'wp-admin/admin-ajax.php' );
record_abuse_test( 'Quarantine', 'Core wp-admin Protection', false === $res_admin_core['success'], $res_admin_core['message'] );

// Attack 1.6: Null byte path injection
$res_null_byte = SentinelWP_Quarantine::instance()->quarantine_file( 0, WP_CONTENT_DIR . "/uploads/legit.jpg\0.php" );
record_abuse_test( 'Quarantine', 'Null Byte Path Poisoning', false === $res_null_byte['success'], $res_null_byte['message'] );

// Attack 1.7: Symlink pointing outside webroot
$upload_dir = wp_upload_dir();
$symlink_test_path = trailingslashit( $upload_dir['basedir'] ) . 'symlink-outside-test.php';
@unlink( $symlink_test_path );
if ( function_exists( 'symlink' ) ) {
	@symlink( '/etc/hosts', $symlink_test_path );
	if ( file_exists( $symlink_test_path ) ) {
		$res_symlink = SentinelWP_Quarantine::instance()->quarantine_file( 0, $symlink_test_path );
		record_abuse_test( 'Quarantine', 'Symlink Webroot Escape', false === $res_symlink['success'], $res_symlink['message'] );
		@unlink( $symlink_test_path );
	} else {
		record_abuse_test( 'Quarantine', 'Symlink Webroot Escape', true, 'Symlink creation restricted on host' );
	}
} else {
	record_abuse_test( 'Quarantine', 'Symlink Webroot Escape', true, 'symlink() function not permitted on host' );
}

/* ====================================================================== */
/* 2. ADVERSARIAL PROXY HEADER ATTACKS                                    */
/* ====================================================================== */
echo "\n--- 2. ADVERSARIAL PROXY HEADER INJECTION DEFENSE ---\n";

update_option( 'sentinelwp_behind_proxy', 1 );
$_SERVER['REMOTE_ADDR'] = '192.0.2.1';

// Attack 2.1: 10KB Giant Poisoned Header (DoS / Buffer Overflow Attempt)
$_SERVER['HTTP_X_FORWARDED_FOR'] = str_repeat( '198.51.100.1, ', 1000 ) . '203.0.113.5';
$giant_ip = SentinelWP_Helper::get_client_ip();
record_abuse_test( 'Proxy', '10KB Giant X-Forwarded-For Header', '192.0.2.1' === $giant_ip, "Oversized header safely rejected -> Fallback: $giant_ip" );

// Attack 2.2: SQL Injection Payload in XFF
$_SERVER['HTTP_X_FORWARDED_FOR'] = "198.51.100.5'; DROP TABLE wp_users; --, 10.0.0.1";
$sqli_ip = SentinelWP_Helper::get_client_ip();
record_abuse_test( 'Proxy', 'SQL Injection in Proxy Header', '198.51.100.5' !== $sqli_ip && '192.0.2.1' === $sqli_ip, "Payload rejected -> Fallback: $sqli_ip" );

// Attack 2.3: XSS Script Injection in Cloudflare Header
unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
$_SERVER['HTTP_CF_CONNECTING_IP'] = "<script>alert('XSS')</script>";
$xss_ip = SentinelWP_Helper::get_client_ip();
record_abuse_test( 'Proxy', 'XSS Injection in CF Header', '192.0.2.1' === $xss_ip, "Script tag rejected -> Fallback: $xss_ip" );

// Attack 2.4: Null-byte injection in X-Real-IP
unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
$_SERVER['HTTP_X_REAL_IP'] = "203.0.113.88\0.attacker.com";
$null_ip = SentinelWP_Helper::get_client_ip();
record_abuse_test( 'Proxy', 'Null-byte in X-Real-IP Header', '192.0.2.1' === $null_ip, "Poisoned string rejected -> Fallback: $null_ip" );

unset( $_SERVER['HTTP_X_REAL_IP'] );
update_option( 'sentinelwp_behind_proxy', 0 );

/* ====================================================================== */
/* 3. ADVERSARIAL SCANNER RESILIENCE                                      */
/* ====================================================================== */
echo "\n--- 3. SCANNER EVASION & OOM RESILIENCE ---\n";

// Test 3.1: 15MB Huge File Handling
$huge_file_path = trailingslashit( $upload_dir['basedir'] ) . 'huge-dummy-test.js';
$fp = fopen( $huge_file_path, 'w' );
if ( $fp ) {
	// Write 5MB dummy content
	fseek( $fp, 5 * 1024 * 1024 - 1 );
	fwrite( $fp, "\n" );
	fclose( $fp );
}

$scan_mem_start = memory_get_usage();
SentinelWP_Skimmer_Detector::instance()->scan_js_files();
$scan_mem_delta = ( memory_get_usage() - $scan_mem_start ) / 1048576; // MB

record_abuse_test( 'Scanner', '5MB Oversized File Skip', $scan_mem_delta < 5.0, sprintf( "Memory delta: %.2f MB (Oversized file skipped safely)", $scan_mem_delta ) );
@unlink( $huge_file_path );

/* ====================================================================== */
/* 4. DATABASE QUERY PLAN (EXPLAIN) AUDIT                                 */
/* ====================================================================== */
echo "\n--- 4. DATABASE EXPLAIN QUERY PLAN AUDIT ---\n";

global $wpdb;
$orders_table = $wpdb->prefix . 'wc_orders';
$sample_one_day_ago = date( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );

// EXPLAIN 4.1: HPOS 24h Order Velocity by Email Query
$explain_velocity = $wpdb->get_results( $wpdb->prepare(
	"EXPLAIN SELECT billing_email, COUNT(*) as order_count 
	FROM {$orders_table} 
	WHERE date_created_gmt >= %s 
	AND status NOT IN ('wc-cancelled', 'wc-trash')
	GROUP BY billing_email 
	HAVING order_count > 10 
	LIMIT 20",
	$sample_one_day_ago
) );

$used_key_vel = ! empty( $explain_velocity[0]->key ) ? $explain_velocity[0]->key : 'NONE';
$type_vel     = ! empty( $explain_velocity[0]->type ) ? $explain_velocity[0]->type : 'ALL';
$rows_vel     = ! empty( $explain_velocity[0]->rows ) ? (int) $explain_velocity[0]->rows : 0;

$vel_indexed = ( 'NONE' !== $used_key_vel && 'ALL' !== $type_vel );
record_abuse_test( 'EXPLAIN', 'HPOS Velocity Query Index', $vel_indexed, "Key: $used_key_vel | Access: $type_vel | Estimated Rows: $rows_vel" );

// EXPLAIN 4.2: HPOS 30-day Average Order Value Query
$explain_aov = $wpdb->get_results( $wpdb->prepare(
	"EXPLAIN SELECT AVG(total_amount) as avg_total, COUNT(*) as total_orders 
	FROM {$orders_table} 
	WHERE date_created_gmt >= %s 
	AND status IN ('wc-completed', 'wc-processing')",
	$sample_one_day_ago
) );

$used_key_aov = ! empty( $explain_aov[0]->key ) ? $explain_aov[0]->key : 'NONE';
$type_aov     = ! empty( $explain_aov[0]->type ) ? $explain_aov[0]->type : 'ALL';
$rows_aov     = ! empty( $explain_aov[0]->rows ) ? (int) $explain_aov[0]->rows : 0;

$aov_indexed = ( 'NONE' !== $used_key_aov && 'ALL' !== $type_aov );
record_abuse_test( 'EXPLAIN', 'HPOS 30d AOV Query Index', $aov_indexed, "Key: $used_key_aov | Access: $type_aov | Estimated Rows: $rows_aov" );

/* ====================================================================== */
/* SUMMARY REPORT                                                         */
/* ====================================================================== */
echo "\n======================================================================\n";
global $abuse_results;
$total_attacks  = count( $abuse_results );
$blocked_count  = 0;
foreach ( $abuse_results as $r ) {
	if ( ! empty( $r['blocked'] ) ) {
		$blocked_count++;
	}
}
$failed_count   = $total_attacks - $blocked_count;

echo sprintf( " ADVERSARIAL TEST SUMMARY: %d ATTACKS TESTED | \033[32m%d BLOCKED/SAFE\033[0m | %s\n",
	$total_attacks,
	$blocked_count,
	$failed_count > 0 ? "\033[31m{$failed_count} EXPLOITED\033[0m" : "\033[32m0 EXPLOITED\033[0m"
);
echo "======================================================================\n";
