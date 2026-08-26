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
	// CloudSEK June 2026 Report: Targets DOM overlays injected alongside Stripe/WCPay payment containers.
	'/((?:wcpay-payment-element|StripeElement).{0,500}createElement\s*\(\s*[\'"](?:form|input)[\'"]|createElement\s*\(\s*[\'"](?:form|input)[\'"].{0,500}(?:wcpay-payment-element|StripeElement))/is' => 'Fake form or input overlay injected near payment container',
	// CloudSEK June 2026 Report: Targets client-side Google Analytics suppression used to avoid telemetry alarms.
	'/(?:window\[\s*[\'"]|\b)ga-disable-G-[A-Z0-9]{6,}/i' => 'Google Analytics tracking suppression flag (anti-telemetry)',
	// CloudSEK June 2026 Report: Targets obfuscator.io-style string array rotation coupled with payment keywords or decoders.
	'/(?:\bwhile\s*\(\s*--\s*[a-zA-Z0-9_$]+\s*\).*(?:push|shift|unshift)).*(?:atob\s*\(|btoa\s*\(|card|payment|billing|checkout|cvv|cc-num)|(?:atob\s*\(|btoa\s*\(|card|payment|billing|checkout|cvv|cc-num).*(?:\bwhile\s*\(\s*--\s*[a-zA-Z0-9_$]+\s*\).*(?:push|shift|unshift))/is' => 'Obfuscated string array rotation with payment or decoding keywords',
) );
