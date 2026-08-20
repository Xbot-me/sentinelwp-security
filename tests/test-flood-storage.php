<?php
/**
 * SentinelWP Flood Storage & Proxy IP Resolution Test.
 */

if ( ! defined( 'ABSPATH' ) ) {
	require_once __DIR__ . '/bootstrap.php';
}

echo "=======================================================\n";
echo " Running SentinelWP Flood Storage & Proxy Tests        \n";
echo "=======================================================\n";

// 1. Test window_id normalization
$base  = 1700000100 - ( 1700000100 % 300 ); // Perfectly aligned to 300-sec boundary
$time1 = $base + 10;
$time2 = $base + 150; // Same 5-min window
$time3 = $base + 310; // Next 5-min window

$w1 = (int) floor( $time1 / 300 );
$w2 = (int) floor( $time2 / 300 );
$w3 = (int) floor( $time3 / 300 );

if ( $w1 === $w2 && $w3 === ( $w1 + 1 ) ) {
	echo "[PASS] Window ID normalized correctly ($w1 vs $w2, next $w3).\n";
} else {
	echo "[FAIL] Window ID calculation mismatch ($w1 vs $w2 vs $w3).\n";
}

// 2. Test Proxy IP parsing
$_SERVER['REMOTE_ADDR'] = '10.0.0.1'; // Internal load balancer
$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.195'; // Real client
update_option( 'sentinelwp_behind_proxy', 1 );

$client_ip = SentinelWP_Helper::get_client_ip();
if ( '203.0.113.195' === $client_ip ) {
	echo "[PASS] Cloudflare CF-Connecting-IP resolved correctly ($client_ip).\n";
} else {
	echo "[FAIL] Proxy IP resolution failed (got $client_ip).\n";
}

// 3. Test X-Forwarded-For chain parsing
unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.44, 10.0.0.2, 10.0.0.1';
$client_ip_xff = SentinelWP_Helper::get_client_ip();
if ( '198.51.100.44' === $client_ip_xff ) {
	echo "[PASS] X-Forwarded-For leftmost public IP resolved correctly ($client_ip_xff).\n";
} else {
	echo "[FAIL] XFF parsing failed (got $client_ip_xff).\n";
}

// 4. Test safe fallback when proxy header support is disabled
update_option( 'sentinelwp_behind_proxy', 0 );
$client_ip_direct = SentinelWP_Helper::get_client_ip();
if ( '10.0.0.1' === $client_ip_direct ) {
	echo "[PASS] Safe direct fallback to REMOTE_ADDR when proxy support disabled ($client_ip_direct).\n";
} else {
	echo "[FAIL] Fallback failed (got $client_ip_direct).\n";
}

echo "=======================================================\n";
