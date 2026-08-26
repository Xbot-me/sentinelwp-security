<?php
/**
 * SentinelWP Unified Test Runner.
 *
 * Runs all unit, integration, and security verification tests.
 * Returns exit code 0 if all tests pass, 1 if any fail.
 */

require_once __DIR__ . '/bootstrap.php';

$test_files = array(
	'test-flood-storage.php',
	'test-findings-confidence.php',
	'test-risk-engine-phase1.php',
	'test-attack-correlator.php',
	'test-adversarial-abuse-suite.php',
	'test-concurrency-and-failure.php',
	'test-quarantine-rollback.php',
	'test-operational-chaos-suite.php',
	'test-scan-history-retention.php',
	'test-corpus-benchmark.php',
	'test-code-quality.php',
	'test-skimmer-and-endpoint-hardening.php',
);

echo "======================================================================\n";
echo " SENTINELWP SECURITY — COMPREHENSIVE TEST RUNNER                      \n";
echo " PHP Version: " . PHP_VERSION . "\n";
echo " Date: " . date( 'Y-m-d H:i:s' ) . "\n";
echo "======================================================================\n\n";

$failed_suites = array();
$passed_suites = 0;

foreach ( $test_files as $file ) {
	$path = __DIR__ . '/' . $file;
	if ( ! file_exists( $path ) ) {
		echo "\033[33m[SKIP]\033[0m Missing test file: $file\n";
		continue;
	}

	echo "\n----------------------------------------------------------------------\n";
	echo " RUNNING: $file\n";
	echo "----------------------------------------------------------------------\n";

	ob_start();
	try {
		include $path;
		$output = ob_get_clean();
		echo $output;

		if ( strpos( $output, '[FAIL]' ) !== false || strpos( $output, '[ERROR]' ) !== false ) {
			$failed_suites[] = $file;
		} else {
			$passed_suites++;
		}
	} catch ( Throwable $t ) {
		$output = ob_get_clean();
		echo $output;
		echo "\n\033[31m[FATAL EXCEPTION]\033[0m in $file: " . $t->getMessage() . " at " . $t->getFile() . ":" . $t->getLine() . "\n";
		$failed_suites[] = $file;
	}
}

echo "\n======================================================================\n";
echo " TEST SUMMARY\n";
echo "======================================================================\n";
echo " Suites Passed: $passed_suites / " . count( $test_files ) . "\n";

if ( ! empty( $failed_suites ) ) {
	echo "\033[31m Failed Suites:\033[0m\n";
	foreach ( $failed_suites as $fail ) {
		echo "  - $fail\n";
	}
	echo "\n\033[31m[OVERALL: FAILED]\033[0m\n";
	exit( 1 );
} else {
	echo "\n\033[32m[OVERALL: ALL TEST SUITES PASSED CLEANLY]\033[0m\n";
	exit( 0 );
}
