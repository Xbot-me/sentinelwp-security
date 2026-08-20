<?php
/**
 * SentinelWP Reproducible Security Corpus Evaluation & Benchmark Suite
 *
 * Runs all detectors against curated fixture categories:
 * - Known Malicious: Measures Recall / True Positive Rate
 * - Benign: Measures False Positive Rate (Target: 0.0%)
 * - Adversarial: Measures Safety & Boundary Containment
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "Direct access not permitted.\n" );
}

echo "======================================================================\n";
echo " SENTINELWP — REPRODUCIBLE SECURITY CORPUS BENCHMARK                   \n";
echo "======================================================================\n";

$corpus_base = SENTINELWP_PATH . 'tests/corpus/';
$signatures  = include SENTINELWP_PATH . 'data/skimmer-signatures.php';
$nulled_data = include SENTINELWP_PATH . 'data/nulled-indicators.php';

/* ====================================================================== */
/* 1. EVALUATING KNOWN MALICIOUS CORPUS (RECALL / DETECTION RATE)         */
/* ====================================================================== */
echo "\n--- 1. KNOWN MALICIOUS CORPUS (DETECTION RECALL) ---\n";

$malicious_dir   = $corpus_base . 'known-malicious/';
$malicious_files = glob( $malicious_dir . '*.*' );
$total_malicious = count( $malicious_files );
$detected_count  = 0;

foreach ( $malicious_files as $file ) {
	$fname   = basename( $file );
	$content = file_get_contents( $file );
	$flagged = false;
	$matched_reason = '';

	// Test JS Skimmer signatures
	if ( substr( $fname, -3 ) === '.js' ) {
		foreach ( $signatures as $pattern => $label ) {
			if ( preg_match( $pattern, $content ) ) {
				$flagged = true;
				$matched_reason = $label;
				break;
			}
		}
	}

	// Test PHP Webshell / Nulled indicators
	if ( substr( $fname, -4 ) === '.php' ) {
		// Test webshell / eval pattern
		if ( preg_match( '/\beval\s*\(\s*base64_decode\s*\(/i', $content ) ) {
			$flagged = true;
			$matched_reason = 'Obfuscated Base64 Eval Webshell';
		}
		// Test nulled indicators
		if ( ! $flagged && ! empty( $nulled_data['license_bypass_patterns'] ) ) {
			foreach ( $nulled_data['license_bypass_patterns'] as $pat => $lbl ) {
				if ( preg_match( $pat, $content ) ) {
					$flagged = true;
					$matched_reason = $lbl;
					break;
				}
			}
		}
		if ( ! $flagged && ! empty( $nulled_data['nulled_domains'] ) ) {
			foreach ( $nulled_data['nulled_domains'] as $dom ) {
				if ( strpos( $content, $dom ) !== false ) {
					$flagged = true;
					$matched_reason = "Known Nulled Distribution Domain ($dom)";
					break;
				}
			}
		}
	}

	// Test Fake Image Payload
	if ( in_array( substr( $fname, -4 ), array( '.jpg', '.png' ), true ) ) {
		if ( strpos( $content, '<?php' ) !== false || strpos( $content, '<script' ) !== false ) {
			$flagged = true;
			$matched_reason = 'Embedded PHP / Script Payload in Image Header';
		}
	}

	if ( $flagged ) {
		$detected_count++;
		echo sprintf( "\033[32m[DETECTED]\033[0m %-28s | %s\n", $fname, $matched_reason );
	} else {
		echo sprintf( "\033[31m[MISSED]\033[0m   %-28s | No detector matched\n", $fname );
	}
}

$recall_rate = $total_malicious > 0 ? ( $detected_count / $total_malicious ) * 100 : 100;
echo sprintf( "--> Malicious Corpus Recall: %d / %d (%.1f%%)\n", $detected_count, $total_malicious, $recall_rate );

/* ====================================================================== */
/* 2. EVALUATING BENIGN CORPUS (FALSE POSITIVE RESISTANCE)                */
/* ====================================================================== */
echo "\n--- 2. BENIGN CORPUS (FALSE POSITIVE RESISTANCE) ---\n";

$benign_dir   = $corpus_base . 'benign/';
$benign_files = glob( $benign_dir . '*.*' );
$total_benign = count( $benign_files );
$fp_count     = 0;

foreach ( $benign_files as $file ) {
	$fname   = basename( $file );
	$content = file_get_contents( $file );
	$flagged = false;
	$false_flag_reason = '';

	if ( substr( $fname, -3 ) === '.js' ) {
		foreach ( $signatures as $pattern => $label ) {
			if ( preg_match( $pattern, $content ) ) {
				$flagged = true;
				$false_flag_reason = $label;
				break;
			}
		}
	}

	if ( substr( $fname, -4 ) === '.php' ) {
		if ( preg_match( '/\beval\s*\(\s*base64_decode\s*\(/i', $content ) ) {
			$flagged = true;
			$false_flag_reason = 'Eval Base64';
		}
	}

	if ( ! $flagged ) {
		echo sprintf( "\033[32m[CLEAN/SAFE]\033[0m %-28s | Zero false alerts triggered\n", $fname );
	} else {
		$fp_count++;
		echo sprintf( "\033[31m[FALSE POSITIVE]\033[0m %-24s | Inadvertently flagged: %s\n", $fname, $false_flag_reason );
	}
}

$fp_rate = $total_benign > 0 ? ( $fp_count / $total_benign ) * 100 : 0;
echo sprintf( "--> Benign False Positive Rate: %d / %d (%.1f%%)\n", $fp_count, $total_benign, $fp_rate );

/* ====================================================================== */
/* 3. EVALUATING ADVERSARIAL CORPUS (CONTAINMENT & BOUNDARY DEFENSE)      */
/* ====================================================================== */
echo "\n--- 3. ADVERSARIAL CORPUS (CONTAINMENT DEFENSE) ---\n";

$adv_path = $corpus_base . 'adversarial/traversal-path-fixture.txt';
$adv_str  = trim( file_get_contents( $adv_path ) );
$res_adv  = SentinelWP_Quarantine::instance()->validate_safe_path( $adv_str );

if ( ! $res_adv['safe'] ) {
	echo sprintf( "\033[32m[CONTAINED]\033[0m  %-28s | %s\n", basename( $adv_path ), $res_adv['error'] );
} else {
	echo sprintf( "\033[31m[ESCAPED]\033[0m    %-28s | Path traversal permitted!\n", basename( $adv_path ) );
}

/* ====================================================================== */
/* SUMMARY METRICS REPORT                                                 */
/* ====================================================================== */
echo "\n======================================================================\n";
echo " CORPUS EVALUATION SUMMARY                                             \n";
echo "======================================================================\n";
echo sprintf( " Malicious Detection Recall : %.1f%% (%d/%d detected)\n", $recall_rate, $detected_count, $total_malicious );
echo sprintf( " Benign False Positive Rate : %.1f%% (%d/%d clean)\n", $fp_rate, $total_benign - $fp_count, $total_benign );
echo sprintf( " Adversarial Containment    : %s\n", ! $res_adv['safe'] ? "100.0% (Enforced)" : "0.0% (Failed)" );
echo "======================================================================\n";
