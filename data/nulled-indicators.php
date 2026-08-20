<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Nulled plugin/theme indicators. Filterable via sentinelwp_nulled_indicators.
 */
return apply_filters( 'sentinelwp_nulled_indicators', array(
	'malicious_files' => array(
		'class.theme-modules.php',
		'starter-developer.php',
		'starter-developer-starter.php',
		'developer-starter.php',
		'developer.starter.php',
		'developer_starter.php',
		'starter.developer.php',
		'starter_developer.php',
		'developer-starter-starter.php',
		'starter-developer-developer.php',
		'developer.developer.php',
		'starter.starter.php',
		'admin-control.php',
		'admin-core.php',
		'theme-core.php',
		'theme-verify.php',
		'plugin-verify.php',
		'class-wp-licence.php',
		'wp-verify-licence.php',
		'wp-check-licence.php',
		'verify-theme.php',
		'verify-plugin.php',
	),
	'nulled_domains' => array(
		'flavistarter.com',
		'developer-starter.com',
		'developer.starter.net',
		'gplclub.org',
		'themesfreedownload.com',
		'themeslide.com',
		'nulledpremium.com',
		'freenulled.com',
		'gpldl.com',
		'nulledscript.com',
		'crackthemes.com',
		'nulledfire.com',
		'downloadfreethemes.io',
		'nullclub.com',
		'wpgpl.com',
		'gplvault.com',
		'gplplugins.com',
		'wplocker.com',
		'nulled-scripts.com',
		'gplspring.com',
		'gplforest.com',
		'gplguru.com',
	),
	'license_bypass_patterns' => array(
		'/function\s+\w*(license|activ|valid|regist)\w*\s*\([^)]*\)\s*\{\s*return\s+true\s*;?\s*\}/i' => 'License validation function that always returns true',
		'/\/\/\s*(?:removed|nulled|cracked|patched|bypassed).*(?:license|activation|validation)/i' => 'Comment indicating license code was removed',
		'/update_option\(\s*[\'"][^\'"]*(?:license|key|activation|status)[^\'"]*[\'"]\s*,\s*[\'"](?:valid|active|true|1)[\'"]\s*\)/i' => 'Forcing valid license status via update_option',
		'/if\s*\(\s*(?:!|\s*not\s*)\w*(?:license|valid|activ).*\)\s*\{\s*return\s+true\s*;/i' => 'Inverted license check that returns true',
		'/[\'"](?:https?:\/\/.*api\..*|.*activate.*)[\'"]\s*=>\s*[\'"](?:http:\/\/localhost.*|http:\/\/127\.0\.0\.1.*)[\'"]/i' => 'Redirecting API or activation URL to localhost',
	),
) );
