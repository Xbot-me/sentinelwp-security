<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Magecart and checkout skimmer detection signatures. Filterable via sentinelwp_skimmer_signatures.
 */
return apply_filters( 'sentinelwp_skimmer_signatures', array(
	'/addEventListener\([\'"]submit[\'"].*(XMLHttpRequest|fetch|navigator\.sendBeacon)/s' => 'Form data capture targeting payment fields',
	'/querySelector\([\'"][^\'"]*(card|cc-num|cvv|cvc|expir|payment|billing)[^\'"]*[\'"]\)/is' => 'Credit card field selectors',
	'/(new\s+Image\(\)\.src|fetch\(|XMLHttpRequest).*?(?<!location\.)(https?:\/\/(?![\w\-]+\.(google-analytics\.com|googletagmanager\.com|facebook\.com|pinterest\.com|stripe\.com|paypal\.com))[\w\-\.]+)/i' => 'Data exfiltration to external domains',
	'/(?:btoa\([^\)]*\).*(card|payment|billing|checkout|cvv|cc-num)|(?:card|payment|billing|checkout|cvv|cc-num).*btoa\()/is' => 'Base64 exfiltration near payment fields',
	'/new\s+WebSocket\([\'"]wss?:\/\/(?![\w\-]+\.(pusher\.com|wp\.com))[\w\-\.]+[\'"]\)/i' => 'WebSocket exfiltration targeting non-standard domains',
	'/addEventListener\([\'"](keydown|keyup|input)[\'"].*(card|payment|billing|cc-num)/is' => 'Keylogger on payment fields',
	'/createElement\([\'"]form[\'"]\).*(card|payment|billing|cvv|cc-num)/is' => 'Fake form overlay injection',
	'/atob\(.*eval\(|Function\(.*atob\(/is' => 'atob() decoding combined with eval/Function constructor',
	'/document\.write\(.*(?:%[0-9a-f]{2}|\\\\x[0-9a-f]{2}|\\\\u[0-9a-f]{4}).*\)/is' => 'document.write with encoded script content on checkout pages',
	'/gtm\.js.*(eval\(|atob\(|btoa\()/is' => 'Fake GTM/analytics with suspicious patterns',
	'/querySelectorAll\([\'"]input[^\'"]*[\'"]\).*\.value.*(fetch|XMLHttpRequest|sendBeacon)/is' => 'Input field value harvesting and external sending',
	'/addEventListener\([\'"](copy|paste)[\'"]\)/i' => 'Clipboard hijacking on payment pages',
) );
