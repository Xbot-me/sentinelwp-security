<?php
/**
 * SentinelGuard — Skimmer Signatures & Flood Endpoint Hardening Verification Suite
 *
 * Verifies:
 * 1. The three new CloudSEK June 2026 skimmer signatures in data/skimmer-signatures.php:
 *    a) Overlay form/input injection near Stripe/WCPay element.
 *    b) Google Analytics suppression flag (ga-disable-G-XXXXXX).
 *    c) Obfuscator.io string array rotation with payment/decoder keywords.
 *    Each tested with positive (should match) and negative (should not match) fixtures.
 *
 * 2. Endpoint classification in SentinelWP_Flood_Monitor::get_endpoint_type():
 *    - ?wc-ajax=checkout => 'checkout'
 *    - ?wc-ajax=add_to_cart => 'checkout'
 *    - ?wc-ajax=update_order_review => 'checkout'
 *    - /wp-json/wc/store/v1/checkout => 'checkout'
 *    - /wp-json/wc/store/v1/cart => 'checkout'
 *    - ?rest_route=/wc/store/v1/checkout => 'checkout'
 *    - /wp-json/wp/v2/posts => 'rest'
 *    - ?wc-ajax=get_refreshed_fragments => 'general'
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "Direct access not permitted.\n" );
}

echo "======================================================================\n";
echo " SENTINELGUARD — SKIMMER & ENDPOINT HARDENING TEST SUITE              \n";
echo "======================================================================\n";

$GLOBALS['sh_passed'] = 0;
$GLOBALS['sh_failed'] = 0;

function assert_test( $name, $condition, $details = '' ) {
	if ( $condition ) {
		$GLOBALS['sh_passed']++;
		echo "[PASS] " . str_pad( $name, 58 ) . "\n";
	} else {
		$GLOBALS['sh_failed']++;
		echo "[FAIL] " . str_pad( $name, 58 ) . " | $details\n";
	}
}

// ----------------------------------------------------------------------
// PART 1: SKIMMER SIGNATURES TEST
// ----------------------------------------------------------------------
echo "\n--- 1. CLOUDSEK JUNE 2026 SKIMMER SIGNATURE VERIFICATION ---\n";

$signatures = include SENTINELWP_PATH . 'data/skimmer-signatures.php';

// Find the three specific signatures from the array
$sig_overlay = null;
$sig_ga      = null;
$sig_obf     = null;

foreach ( $signatures as $pattern => $label ) {
	if ( strpos( $pattern, 'wcpay-payment-element' ) !== false ) {
		$sig_overlay = $pattern;
	}
	if ( strpos( $pattern, 'ga-disable-G-' ) !== false ) {
		$sig_ga = $pattern;
	}
	if ( strpos( $pattern, 'while' ) !== false && strpos( $pattern, 'push|shift' ) !== false ) {
		$sig_obf = $pattern;
	}
}

assert_test( 'Signature (a) Overlay Injection Loaded', ! empty( $sig_overlay ), 'Pattern not found in signatures array' );
assert_test( 'Signature (b) GA Opt-Out Suppression Loaded', ! empty( $sig_ga ), 'Pattern not found in signatures array' );
assert_test( 'Signature (c) Obfuscator.io Rotation Loaded', ! empty( $sig_obf ), 'Pattern not found in signatures array' );

// --- Test Signature (a): WCPay / StripeElement DOM Overlay ---
if ( $sig_overlay ) {
	$pos_fixture_a1 = 'const container = document.getElementById("wcpay-payment-element"); const fakeInput = document.createElement("input"); fakeInput.name = "cc_number"; container.parentNode.appendChild(fakeInput);';
	$pos_fixture_a2 = 'const overlayForm = document.createElement("form"); overlayForm.id = "custom-form"; document.querySelector(".StripeElement").appendChild(overlayForm);';
	$neg_fixture_a1 = 'const container = document.getElementById("wcpay-payment-element"); const wrapper = document.createElement("div"); wrapper.className = "layout-box"; container.appendChild(wrapper);';
	$neg_fixture_a2 = 'const legitimateForm = document.createElement("form"); legitimateForm.action = "/contact"; document.body.appendChild(legitimateForm);';

	assert_test( 'Signature (a) POSITIVE: WCPay + createElement("input")', 1 === preg_match( $sig_overlay, $pos_fixture_a1 ) );
	assert_test( 'Signature (a) POSITIVE: StripeElement + createElement("form")', 1 === preg_match( $sig_overlay, $pos_fixture_a2 ) );
	assert_test( 'Signature (a) NEGATIVE: WCPay + createElement("div")', 0 === preg_match( $sig_overlay, $neg_fixture_a1 ) );
	assert_test( 'Signature (a) NEGATIVE: Standard form without payment container', 0 === preg_match( $sig_overlay, $neg_fixture_a2 ) );
}

// --- Test Signature (b): Google Analytics Suppression Flag ---
if ( $sig_ga ) {
	$pos_fixture_b1 = 'window["ga-disable-G-A1B2C3D4"] = true;';
	$pos_fixture_b2 = 'if (window["ga-disable-G-99887766"]) { console.log("suppressed"); }';
	$pos_fixture_b3 = 'var flag = "ga-disable-G-ABCDEF12";';
	$neg_fixture_b1 = 'gtag("config", "G-A1B2C3D4", { "anonymize_ip": true });';
	$neg_fixture_b2 = 'ga("send", "pageview", "/checkout");';

	assert_test( 'Signature (b) POSITIVE: window["ga-disable-G-A1B2C3D4"] = true', 1 === preg_match( $sig_ga, $pos_fixture_b1 ) );
	assert_test( 'Signature (b) POSITIVE: reading ga-disable-G-99887766 flag', 1 === preg_match( $sig_ga, $pos_fixture_b2 ) );
	assert_test( 'Signature (b) POSITIVE: variable with ga-disable-G-ABCDEF12', 1 === preg_match( $sig_ga, $pos_fixture_b3 ) );
	assert_test( 'Signature (b) NEGATIVE: standard gtag config call', 0 === preg_match( $sig_ga, $neg_fixture_b1 ) );
	assert_test( 'Signature (b) NEGATIVE: standard ga pageview call', 0 === preg_match( $sig_ga, $neg_fixture_b2 ) );
}

// --- Test Signature (c): Obfuscator.io String-Array Rotation ---
if ( $sig_obf ) {
	$pos_fixture_c1 = '(function(_0x1234, _0x5678) { var _0xabcd = function(_0xef01) { while (--_0xef01) { _0x1234["push"](_0x1234["shift"]()); } }; _0xabcd(++_0x5678); }(_0x9abc, 0x123)); const cardNum = "4111";';
	$pos_fixture_c2 = 'const atobVal = atob("cGF5bWVudA=="); (function(arr, count) { var rot = function(c) { while (--c) { arr.push(arr.shift()); } }; rot(++count); })(table, 10);';
	$neg_fixture_c1 = 'for (let i = 10; i > 0; i--) { console.log(i); }';
	$neg_fixture_c2 = '(function(arr, count) { var rot = function(c) { while (--c) { arr.push(arr.shift()); } }; rot(++count); })(table, 10); console.log("hello world");'; // benign rotation without payment/decoders

	assert_test( 'Signature (c) POSITIVE: Obfuscator.io IIFE + card keyword', 1 === preg_match( $sig_obf, $pos_fixture_c1 ) );
	assert_test( 'Signature (c) POSITIVE: Obfuscator.io IIFE + atob() decoder', 1 === preg_match( $sig_obf, $pos_fixture_c2 ) );
	assert_test( 'Signature (c) NEGATIVE: Standard for loop countdown', 0 === preg_match( $sig_obf, $neg_fixture_c1 ) );
	assert_test( 'Signature (c) NEGATIVE: String rotation without payment keywords', 0 === preg_match( $sig_obf, $neg_fixture_c2 ) );
}

// ----------------------------------------------------------------------
// PART 2: ENDPOINT CLASSIFICATION TEST
// ----------------------------------------------------------------------
echo "\n--- 2. FLOOD MONITOR ENDPOINT CLASSIFICATION TESTS ---\n";

$flood_monitor = SentinelWP_Flood_Monitor::instance();
$reflection = new ReflectionClass( $flood_monitor );
$method = $reflection->getMethod( 'get_endpoint_type' );
if ( method_exists( $method, 'setAccessible' ) ) {
	@$method->setAccessible( true );
}

function classify_request( $flood_monitor, $method, $uri, $get_params = array() ) {
	$_SERVER['REQUEST_URI'] = $uri;
	$_GET = $get_params;
	return $method->invoke( $flood_monitor );
}

$endpoint_tests = array(
	// WooCommerce AJAX query parameter checks (tightened to 'checkout')
	array(
		'name'     => 'wc-ajax=checkout routes to checkout bucket',
		'uri'      => '/?wc-ajax=checkout',
		'get'      => array( 'wc-ajax' => 'checkout' ),
		'expected' => 'checkout',
	),
	array(
		'name'     => 'wc-ajax=add_to_cart routes to checkout bucket',
		'uri'      => '/?wc-ajax=add_to_cart',
		'get'      => array( 'wc-ajax' => 'add_to_cart' ),
		'expected' => 'checkout',
	),
	array(
		'name'     => 'wc-ajax=update_order_review routes to checkout bucket',
		'uri'      => '/?wc-ajax=update_order_review',
		'get'      => array( 'wc-ajax' => 'update_order_review' ),
		'expected' => 'checkout',
	),
	// WooCommerce Store API REST routes (tightened to 'checkout')
	array(
		'name'     => '/wp-json/wc/store/v1/checkout routes to checkout bucket',
		'uri'      => '/wp-json/wc/store/v1/checkout',
		'get'      => array(),
		'expected' => 'checkout',
	),
	array(
		'name'     => '/wp-json/wc/store/v1/cart routes to checkout bucket',
		'uri'      => '/wp-json/wc/store/v1/cart',
		'get'      => array(),
		'expected' => 'checkout',
	),
	array(
		'name'     => '?rest_route=/wc/store/v1/checkout routes to checkout bucket',
		'uri'      => '/index.php?rest_route=/wc/store/v1/checkout',
		'get'      => array( 'rest_route' => '/wc/store/v1/checkout' ),
		'expected' => 'checkout',
	),
	// Standard routes maintain existing classifications
	array(
		'name'     => '/wp-json/wp/v2/posts routes to generic rest bucket',
		'uri'      => '/wp-json/wp/v2/posts',
		'get'      => array(),
		'expected' => 'rest',
	),
	array(
		'name'     => '/wp-login.php routes to login bucket',
		'uri'      => '/wp-login.php',
		'get'      => array(),
		'expected' => 'login',
	),
	array(
		'name'     => '/xmlrpc.php routes to xmlrpc bucket',
		'uri'      => '/xmlrpc.php',
		'get'      => array(),
		'expected' => 'xmlrpc',
	),
	array(
		'name'     => '/wp-admin/admin-ajax.php routes to ajax bucket',
		'uri'      => '/wp-admin/admin-ajax.php',
		'get'      => array(),
		'expected' => 'ajax',
	),
	array(
		'name'     => '/wp-cron.php routes to cron bucket',
		'uri'      => '/wp-cron.php',
		'get'      => array(),
		'expected' => 'cron',
	),
	array(
		'name'     => 'Unrelated wc-ajax routes to general bucket',
		'uri'      => '/?wc-ajax=get_refreshed_fragments',
		'get'      => array( 'wc-ajax' => 'get_refreshed_fragments' ),
		'expected' => 'general',
	),
	array(
		'name'     => 'Standard shop page routes to general bucket',
		'uri'      => '/shop/',
		'get'      => array(),
		'expected' => 'general',
	),
);

foreach ( $endpoint_tests as $t ) {
	$actual = classify_request( $flood_monitor, $method, $t['uri'], $t['get'] );
	assert_test( $t['name'], $actual === $t['expected'], "Expected '{$t['expected']}', got '$actual'" );
}

// Reset globals
$_SERVER['REQUEST_URI'] = '';
$_GET = array();

echo "\n======================================================================\n";
echo " SKIMMER & ENDPOINT HARDENING SUMMARY: " . $GLOBALS['sh_passed'] . " PASSED | " . $GLOBALS['sh_failed'] . " FAILED\n";
echo "======================================================================\n";

$GLOBALS['sentinelwp_test_result'] = ( $GLOBALS['sh_failed'] === 0 ) ? 'PASS' : 'FAIL';
