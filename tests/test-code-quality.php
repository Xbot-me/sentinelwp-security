<?php
/**
 * SentinelGuard Code Quality & Regression Prevention Test Suite
 *
 * Static analysis tests that catch the exact types of bugs found during
 * the v0.4.4 audit: undefined variables in DB calls, JS/HTML selector
 * mismatches, incomplete uninstall cleanup, dead URLs, version drift,
 * and branding inconsistencies.
 *
 * These tests read source files directly — no WordPress runtime needed.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( "Direct access not permitted.\n" );
}

echo "======================================================================\n";
echo " SENTINELGUARD — CODE QUALITY & REGRESSION PREVENTION SUITE          \n";
echo "======================================================================\n";

$plugin_root = dirname( __DIR__ ) . '/';
$passed = 0;
$failed = 0;
$errors = array();

function cq_pass( $label, &$passed ) {
	$passed++;
	echo "[PASS] " . str_pad( $label, 55 ) . "\n";
}

function cq_fail( $label, $detail, &$failed, &$errors ) {
	$failed++;
	echo "[FAIL] " . str_pad( $label, 55 ) . " | $detail\n";
	$errors[] = "$label: $detail";
}

/* ------------------------------------------------------------------ */
/* 1. VERSION CONSISTENCY                                              */
/* ------------------------------------------------------------------ */
echo "\n--- 1. VERSION CONSISTENCY ACROSS FILES ---\n";

$readme = file_get_contents( $plugin_root . 'readme.txt' );
$main_php = file_get_contents( $plugin_root . 'sentinelguard-ecommerce-protection.php' );

// Extract versions
preg_match( '/Stable tag:\s*(.+)/i', $readme, $m_stable );
preg_match( '/\*\s*Version:\s*(.+)/i', $main_php, $m_header );
preg_match( "/define\(\s*'SENTINELWP_VERSION',\s*'([^']+)'/", $main_php, $m_const );

$v_stable = trim( $m_stable[1] ?? '' );
$v_header = trim( $m_header[1] ?? '' );
$v_const  = trim( $m_const[1] ?? '' );

if ( $v_stable === $v_header && $v_header === $v_const && ! empty( $v_stable ) ) {
	cq_pass( "Version match: readme=$v_stable, header=$v_header, const=$v_const", $passed );
} else {
	cq_fail( "Version mismatch", "readme=$v_stable, header=$v_header, const=$v_const", $failed, $errors );
}

// Check Tested up to matches between readme and plugin header
preg_match( '/Tested up to:\s*(.+)/i', $readme, $m_readme_tested );
preg_match( '/\*\s*Tested up to:\s*(.+)/i', $main_php, $m_php_tested );
$tested_readme = trim( $m_readme_tested[1] ?? '' );
$tested_php    = trim( $m_php_tested[1] ?? '' );

if ( $tested_readme === $tested_php && ! empty( $tested_readme ) ) {
	cq_pass( "Tested up to match: readme=$tested_readme, header=$tested_php", $passed );
} else {
	cq_fail( "Tested up to mismatch", "readme=$tested_readme, header=$tested_php", $failed, $errors );
}

// Check no duplicate Tested up to in plugin header
$tested_count = preg_match_all( '/\*\s*Tested up to:/i', $main_php );
if ( $tested_count <= 1 ) {
	cq_pass( "No duplicate 'Tested up to' in plugin header", $passed );
} else {
	cq_fail( "Duplicate Tested up to", "$tested_count occurrences in plugin header", $failed, $errors );
}

/* ------------------------------------------------------------------ */
/* 2. DB INSERT VARIABLE VERIFICATION                                  */
/* ------------------------------------------------------------------ */
echo "\n--- 2. DATABASE INSERT TABLE REFERENCE CHECKS ---\n";

$php_files = glob( $plugin_root . 'includes/class-*.php' );
$php_files[] = $plugin_root . 'admin/class-admin.php';

foreach ( $php_files as $file ) {
	$basename = basename( $file );
	$content  = file_get_contents( $file );
	$lines    = explode( "\n", $content );

	foreach ( $lines as $i => $line ) {
		$line_num = $i + 1;

		// Check for $wpdb->insert() with $table_name that isn't defined
		if ( preg_match( '/\$wpdb->insert\(\s*\$table_name\b/', $line ) ) {
			// Check if $table_name is defined anywhere earlier in the same method
			// Simple heuristic: search backwards for $table_name = 
			$found_def = false;
			for ( $j = $i - 1; $j >= max( 0, $i - 50 ); $j-- ) {
				if ( preg_match( '/\$table_name\s*=/', $lines[ $j ] ) ) {
					$found_def = true;
					break;
				}
				// Stop at function boundary
				if ( preg_match( '/\bfunction\s+\w+/', $lines[ $j ] ) ) {
					break;
				}
			}
			if ( ! $found_def ) {
				cq_fail( "Undefined \$table_name in $basename:$line_num", "wpdb->insert uses \$table_name but it's never assigned", $failed, $errors );
			}
		}

		// Also check $wpdb->update, $wpdb->delete, $wpdb->get_row, $wpdb->get_results with $table_name
		if ( preg_match( '/\$wpdb->(update|delete|get_row|get_results|get_var|get_col)\(\s*\$table_name\b/', $line ) ) {
			$found_def = false;
			for ( $j = $i - 1; $j >= max( 0, $i - 50 ); $j-- ) {
				if ( preg_match( '/\$table_name\s*=/', $lines[ $j ] ) ) {
					$found_def = true;
					break;
				}
				if ( preg_match( '/\bfunction\s+\w+/', $lines[ $j ] ) ) {
					break;
				}
			}
			if ( ! $found_def ) {
				cq_fail( "Undefined \$table_name in $basename:$line_num", "wpdb method uses \$table_name but it's never assigned", $failed, $errors );
			}
		}
	}
}

if ( $failed === 0 || ! preg_grep( '/Undefined \$table_name/', $errors ) ) {
	cq_pass( "All \$wpdb->insert() calls reference defined tables", $passed );
}

/* ------------------------------------------------------------------ */
/* 3. JS SELECTOR ↔ HTML ID SYNC                                      */
/* ------------------------------------------------------------------ */
echo "\n--- 3. JAVASCRIPT SELECTOR ↔ HTML ID SYNC ---\n";

$admin_js   = file_get_contents( $plugin_root . 'admin/js/admin.js' );
$admin_php  = file_get_contents( $plugin_root . 'admin/class-admin.php' );

// Extract jQuery ID selectors from JS: $( '#some-id' ) or $( "#some-id" )
preg_match_all( "/\\$\\(\\s*['\"]#([a-zA-Z0-9_-]+)['\"]\\s*\\)/", $admin_js, $js_ids );
$js_selectors = array_unique( $js_ids[1] );

// Extract all id="..." and id='...' from admin PHP
preg_match_all( '/id=["\']([a-zA-Z0-9_-]+)["\']/', $admin_php, $html_ids );
$html_id_list = array_unique( $html_ids[1] );

$missing_ids = array();
foreach ( $js_selectors as $sel ) {
	if ( ! in_array( $sel, $html_id_list, true ) ) {
		$missing_ids[] = $sel;
	}
}

if ( empty( $missing_ids ) ) {
	cq_pass( "All " . count( $js_selectors ) . " JS selectors match HTML IDs", $passed );
} else {
	cq_fail( "JS selectors without matching HTML", implode( ', ', $missing_ids ), $failed, $errors );
}

/* ------------------------------------------------------------------ */
/* 4. UNINSTALL COMPLETENESS                                           */
/* ------------------------------------------------------------------ */
echo "\n--- 4. UNINSTALL OPTION CLEANUP COMPLETENESS ---\n";

$uninstall = file_get_contents( $plugin_root . 'uninstall.php' );

// Find all option names used across the codebase
$all_php = '';
foreach ( glob( $plugin_root . 'includes/class-*.php' ) as $f ) {
	$all_php .= file_get_contents( $f );
}
$all_php .= file_get_contents( $plugin_root . 'admin/class-admin.php' );
$all_php .= $main_php;

// Extract option names from update_option() and add_option() calls
preg_match_all( "/(update_option|add_option|get_option)\(\s*'(sentinelwp_[a-z_]+)'/", $all_php, $opt_matches );
$options_used = array_unique( $opt_matches[2] );

// Extract option names listed in uninstall.php
preg_match_all( "/'(sentinelwp_[a-z_]+)'/", $uninstall, $opt_uninstall );
$options_in_uninstall = array_unique( $opt_uninstall[1] );

$missing_options = array();
foreach ( $options_used as $opt ) {
	// Skip the uninstall flag itself — it's self-referential
	if ( $opt === 'sentinelwp_remove_data_on_uninstall' ) {
		continue;
	}
	if ( ! in_array( $opt, $options_in_uninstall, true ) ) {
		$missing_options[] = $opt;
	}
}

if ( empty( $missing_options ) ) {
	cq_pass( "All " . count( $options_used ) . " options accounted for in uninstall.php", $passed );
} else {
	cq_fail( "Options missing from uninstall.php", implode( ', ', $missing_options ), $failed, $errors );
}

// Check cron hooks
preg_match_all( "/wp_schedule_event\([^,]+,\s*[^,]+,\s*'(sentinelwp_[a-z_]+)'/", $all_php, $cron_matches );
preg_match_all( "/wp_clear_scheduled_hook\(\s*'(sentinelwp_[a-z_]+)'/", $uninstall, $cron_uninstall );
$crons_scheduled = array_unique( $cron_matches[1] );
$crons_cleared   = array_unique( $cron_uninstall[1] );

$missing_crons = array_diff( $crons_scheduled, $crons_cleared );
if ( empty( $missing_crons ) ) {
	cq_pass( "All scheduled cron hooks cleared in uninstall.php", $passed );
} else {
	cq_fail( "Cron hooks not cleared", implode( ', ', $missing_crons ), $failed, $errors );
}

/* ------------------------------------------------------------------ */
/* 5. BRANDING CONSISTENCY                                             */
/* ------------------------------------------------------------------ */
echo "\n--- 5. BRANDING & LEGACY REFERENCE CHECKS ---\n";

// Check for sentinelwp.io URLs (old domain) in all PHP files
$branding_issues = array();
$all_source_files = array_merge(
	glob( $plugin_root . 'includes/class-*.php' ),
	array( $plugin_root . 'admin/class-admin.php' ),
	array( $plugin_root . 'sentinelguard-ecommerce-protection.php' ),
	array( $plugin_root . 'readme.txt' )
);

foreach ( $all_source_files as $file ) {
	$content = file_get_contents( $file );
	$lines   = explode( "\n", $content );
	$bn      = basename( $file );

	foreach ( $lines as $i => $line ) {
		$ln = $i + 1;
		// Check for sentinelwp.io URLs
		if ( stripos( $line, 'sentinelwp.io' ) !== false ) {
			$branding_issues[] = "$bn:$ln contains sentinelwp.io URL";
		}
		// Check for old text domain in translation functions
		if ( preg_match( "/(__|_e|esc_html__|esc_html_e|esc_attr__|esc_attr_e|_n)\([^)]*'sentinelwp-security'/", $line ) ) {
			$branding_issues[] = "$bn:$ln uses old text domain 'sentinelwp-security'";
		}
	}
}

if ( empty( $branding_issues ) ) {
	cq_pass( "No legacy sentinelwp.io URLs or old text domains found", $passed );
} else {
	foreach ( $branding_issues as $issue ) {
		cq_fail( "Legacy branding", $issue, $failed, $errors );
	}
}

// Check License URI consistency
preg_match( '/License URI:\s*(.+)/i', $readme, $m_lic_readme );
preg_match( '/\*\s*License URI:\s*(.+)/i', $main_php, $m_lic_php );
$lic_readme = trim( $m_lic_readme[1] ?? '' );
$lic_php    = trim( $m_lic_php[1] ?? '' );

if ( $lic_readme === $lic_php ) {
	cq_pass( "License URI matches between readme and plugin header", $passed );
} else {
	cq_fail( "License URI mismatch", "readme='$lic_readme' vs header='$lic_php'", $failed, $errors );
}

// Check all readme URLs use HTTPS
preg_match_all( '/https?:\/\/[^\s\)]+/', $readme, $readme_urls );
$http_urls = array();
foreach ( $readme_urls[0] as $url ) {
	if ( strpos( $url, 'http://' ) === 0 ) {
		$http_urls[] = $url;
	}
}

if ( empty( $http_urls ) ) {
	cq_pass( "All readme.txt URLs use HTTPS", $passed );
} else {
	cq_fail( "HTTP URLs in readme.txt", implode( ', ', $http_urls ), $failed, $errors );
}

/* ------------------------------------------------------------------ */
/* 6. URL HEALTH CHECK (readme.txt)                                    */
/* ------------------------------------------------------------------ */
echo "\n--- 6. README URL HEALTH CHECK ---\n";

// Extract all URLs from readme that point to external services
preg_match_all( '/https:\/\/[a-z0-9\.\-\/]+/i', $readme, $all_urls );
$check_urls = array_unique( $all_urls[0] );

// Filter to only service/policy URLs (skip wordpress.org download page etc)
$policy_urls = array_filter( $check_urls, function( $url ) {
	return preg_match( '/(terms|privacy|policy|policies|legal)/i', $url );
} );

$url_errors = array();
foreach ( $policy_urls as $url ) {
	$ctx = stream_context_create( array(
		'http' => array(
			'method'          => 'HEAD',
			'timeout'         => 10,
			'follow_location' => 1,
			'ignore_errors'   => true,
			'user_agent'      => 'SentinelGuard-Test/1.0',
		),
		'ssl' => array(
			'verify_peer' => false,
		),
	) );

	$headers = @get_headers( $url, true, $ctx );
	$code = 0;
	if ( $headers && is_array( $headers ) ) {
		// Get the last status code (follows redirects)
		foreach ( $headers as $key => $val ) {
			if ( is_int( $key ) && preg_match( '/HTTP\/\d\.\d\s+(\d{3})/', $val, $hm ) ) {
				$code = (int) $hm[1];
			}
		}
	}

	if ( $code === 0 && function_exists( 'curl_init' ) ) {
		$ch = curl_init();
		curl_setopt( $ch, CURLOPT_URL, $url );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
		curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
		curl_setopt( $ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' );
		curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt( $ch, CURLOPT_RANGE, '0-100' );
		curl_exec( $ch );
		$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		if ( PHP_VERSION_ID < 80500 ) {
			curl_close( $ch );
		}
	}

	if ( ( $code >= 200 && $code < 400 ) || 403 === $code ) {
		$status_label = ( 403 === $code ) ? "URL reachable (403 WAF)" : "URL OK ($code)";
		cq_pass( "$status_label: " . substr( $url, 0, 50 ), $passed );
	} else {
		cq_fail( "URL BROKEN ($code)", $url, $failed, $errors );
		$url_errors[] = $url;
	}
}

/* ------------------------------------------------------------------ */
/* 7. ABSPATH CHECK PRESENCE                                           */
/* ------------------------------------------------------------------ */
echo "\n--- 7. ABSPATH SECURITY GUARD VERIFICATION ---\n";

$all_php_files = array_merge(
	glob( $plugin_root . 'includes/class-*.php' ),
	array( $plugin_root . 'admin/class-admin.php' ),
	glob( $plugin_root . 'data/*.php' )
);

$missing_abspath = array();
foreach ( $all_php_files as $file ) {
	$content = file_get_contents( $file );
	$bn = basename( $file );
	if ( strpos( $content, "defined( 'ABSPATH' )" ) === false && strpos( $content, "defined('ABSPATH')" ) === false ) {
		$missing_abspath[] = $bn;
	}
}

if ( empty( $missing_abspath ) ) {
	cq_pass( "All " . count( $all_php_files ) . " PHP files have ABSPATH guard", $passed );
} else {
	cq_fail( "Missing ABSPATH guard", implode( ', ', $missing_abspath ), $failed, $errors );
}

/* ------------------------------------------------------------------ */
/* 8. ZIP CONTENTS VERIFICATION                                        */
/* ------------------------------------------------------------------ */
echo "\n--- 8. ZIP PACKAGE CLEANLINESS ---\n";

$zip_path = dirname( $plugin_root ) . '/sentinelguard-ecommerce-protection.zip';
if ( file_exists( $zip_path ) ) {
	$zip = new ZipArchive();
	$zip->open( $zip_path );
	$banned_patterns = array( '.git/', '.github/', 'tests/', 'assets/', '.DS_Store', 'PLAN.md', 'THREAT_MODEL.md' );
	$banned_found = array();

	for ( $i = 0; $i < $zip->numFiles; $i++ ) {
		$name = $zip->getNameIndex( $i );
		foreach ( $banned_patterns as $pattern ) {
			if ( strpos( $name, $pattern ) !== false ) {
				$banned_found[] = $name;
			}
		}
	}

	$zip->close();

	if ( empty( $banned_found ) ) {
		cq_pass( "ZIP contains no dev/test files", $passed );
	} else {
		cq_fail( "Banned files in ZIP", implode( ', ', $banned_found ), $failed, $errors );
	}
} else {
	cq_pass( "ZIP check skipped (release ZIP not present in environment)", $passed );
}

/* ------------------------------------------------------------------ */
/* SUMMARY                                                             */
/* ------------------------------------------------------------------ */
echo "\n======================================================================\n";
echo " CODE QUALITY SUMMARY: $passed PASSED | $failed FAILED\n";
echo "======================================================================\n";

if ( ! empty( $errors ) ) {
	echo "\nFailed checks:\n";
	foreach ( $errors as $err ) {
		echo "  ✗ $err\n";
	}
}

// Return success/failure for the test runner
$GLOBALS['sentinelwp_test_result'] = ( $failed === 0 ) ? 'PASS' : 'FAIL';
