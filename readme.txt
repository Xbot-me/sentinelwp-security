=== SentinelGuard — Ecommerce & Checkout Protection ===
Contributors: mustafizurdev
Tags: security, woocommerce, malware scanner, firewall, checkout protection
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 0.4.5
Requires PHP: 7.4
License: GPL v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A security plugin built specifically for WooCommerce stores. It protects your checkout, scans for skimmers, and blocks card testing.

== Description ==

SentinelGuard focuses on the security issues that actually cost ecommerce stores money: card testing, checkout skimmers (Magecart), fake admin accounts, and unauthorized payment gateway changes.

While standard firewalls block basic attacks, SentinelGuard looks at order patterns, checkout behavior, and payment flows to spot abuse.

= Key Features =

* **Pre-Gateway Checks:** Scans checkout requests before they hit your payment processor, helping you avoid gateway penalty fees.
* **Smart Baselines:** Compares incoming orders against your store's normal 60-day averages instead of using strict, easily broken rules.
* **Observe Mode:** By default, it just logs suspicious activity without blocking real customers, so you can test it safely.
* **Skimmer Detection:** Scans your frontend JavaScript and database for payment field harvesting (`card`, `cvv`), keyloggers, and malicious eval scripts.
* **Card Testing Defense:** Tracks failed payments per IP and email to stop carding bots early.
* **Gateway Credential Alarms:** Alerts you immediately if someone changes your Stripe or PayPal payout keys.
* **Stealth Admin Scanning:** Checks the database directly to find hidden admin accounts that bypass the normal WordPress user list.
* **Safe Quarantine:** Suspicious files are safely isolated (base64 encoded) and can be restored with one click.
* **HPOS Ready:** Fully supports WooCommerce High-Performance Order Storage.

= External Services Disclosure =
This plugin uses third-party services to check for vulnerabilities and provide AI-assisted security summaries.

1. **WordPress.org APIs** (`api.wordpress.org`):
   - Data sent: WP version, plugin/theme slugs & versions.
   - When: During security scans to verify core checksums.
   - Terms & Privacy: https://wordpress.org/about/privacy/

2. **Patchstack Vulnerability Database** (`api.patchstack.com` — Optional):
   - Data sent: WP version, plugin/theme slugs.
   - When: Only if you enter your Patchstack API key in Settings.
   - Terms: https://patchstack.com/terms-and-conditions/
   - Privacy: https://patchstack.com/privacy-policy/

3. **WPScan Database** (`wpscan.com` — Optional):
   - Data sent: WP version, plugin/theme slugs.
   - When: Only if you enter your WPScan API key in Settings.
   - Terms: https://wpscan.com/terms/
   - Privacy: https://automattic.com/privacy/

4. **OpenAI API** (`api.openai.com` — Optional):
   - Data sent: Short, flagged code snippets (no user/store data).
   - When: Only if you enter your OpenAI API key to get plain-English explanations of findings.
   - Terms: https://openai.com/policies/terms-of-use/
   - Privacy: https://openai.com/policies/privacy-policy/

5. **Anthropic API** (`api.anthropic.com` — Optional):
   - Data sent: Short, flagged code snippets.
   - When: Only if you enter your Anthropic API key.
   - Terms: https://www.anthropic.com/legal/commercial-terms
   - Privacy: https://www.anthropic.com/legal/privacy

6. **Google Gemini API** (`generativelanguage.googleapis.com` — Optional):
   - Data sent: Short, flagged code snippets.
   - When: Only if you enter your Google Gemini API key.
   - Terms: https://ai.google.dev/gemini-api/terms
   - Privacy: https://policies.google.com/privacy

7. **Webhook Notifications** (Optional):
   - Data sent: Alerts (e.g., "Suspicious login detected").
   - When: Only if you configure a custom webhook URL (like Slack/Discord).

== Installation ==

1. Upload the `sentinelguard-ecommerce-protection` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to the new SentinelGuard menu to review your security dashboard.

== Frequently Asked Questions ==

= Does this replace my firewall (WAF)? =
No. SentinelGuard is designed to complement firewalls like Cloudflare or Wordfence. They handle basic perimeter defense, while SentinelGuard handles ecommerce-specific logic (orders, checkouts, payment hooks).

= Will this slow down checkout? =
No. The pre-gateway checks take milliseconds, and background tasks (like log purging) are scheduled via WP Cron so they don't impact shoppers. Memory footprint is typically under 2MB.

== Screenshots ==

1. SentinelGuard Dashboard - Real-time metrics on orders and blocks.
2. Store Security Scan - Checking core integrity and looking for skimmers.
3. Settings - Configure API keys and adjust alert thresholds.

== Changelog ==

= 0.4.5 =
* Transitioned quarantine storage completely to the database, eliminating code file storage on disk.
* Standardized path resolution and relative path helpers to use WordPress core APIs instead of internal constants.

= 0.4.4 =
* Ensured empty index.php directory listing guards in vault and languages directories.
* Standardized plugin directory path resolution with dynamic fallbacks.

= 0.4.3 =
* Rebranded to SentinelGuard and updated the plugin slug to sentinelguard-ecommerce-protection.
* Fixed broken "Scan Site Now" button (JS selector mismatch).
* Fixed skimmer and nulled-plugin findings not saving to the database.
* Replaced hardcoded directory paths with plugin_dir_path() and WP_CONTENT_DIR.
* Removed PHP execution headers from quarantine vault files.
* Added quarantine vault cleanup and missing options to uninstall.php.
* Fixed broken Patchstack terms URL and updated Tested up to value.
* Documented all external API services with working Terms and Privacy links.
* Simplified readme description and removed marketing fluff.

= 0.4.2 =
* Rebranded to SentinelGuard — Ecommerce & Checkout Protection.
* Updated contributor list and plugin URI.
* Documented all external API services with Terms and Privacy links.
* Simplified readme text.

= 0.4.1 =
* Removed AI rate limits to comply with WordPress.org trialware guidelines.
* Updated text domain and branding.
* Improved quarantine safety measures.

= 0.4.0 =
* Initial public release.
