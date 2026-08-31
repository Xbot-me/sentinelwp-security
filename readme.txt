=== SentinelGuard — Fraud & Checkout Protection for WooCommerce ===
Contributors: mustafizurdev
Tags: woocommerce, fraud protection, card testing, checkout security, skimmer
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 0.4.6
Requires PHP: 7.4
License: GPL v2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Stop WooCommerce card testing, block fake orders, and detect checkout skimmers. Essential fraud protection for your WooCommerce store.

== Description ==

SentinelGuard provides targeted fraud and checkout protection for WooCommerce. It stops automated carding bots, defends against Magecart checkout skimmers, detects unauthorized payment gateway tampering, and blocks fake orders before they trigger payment processor fines or account bans.

While general firewalls handle basic network probes, SentinelGuard inspects checkout velocity, payment failure spikes, and Store API endpoints to protect your revenue and checkout pipeline.

*Note: SentinelGuard is an application-level ecommerce defense layer. It is built to complement network-level edge WAFs (such as Cloudflare) and payment gateway fraud tools (such as Stripe Radar), not replace them.*

= Are you experiencing these attacks? =

* **Card Testing Bots:** Hundreds of rapid, small, or failed checkout attempts hitting Stripe, PayPal, or Authorize.Net.
* **Fake & Spam Orders:** Automated bot checkouts using fake names, sequential numbers, or disposable email addresses.
* **High Decline Penalties:** Warnings from payment gateways about elevated failure rates threatening your merchant account standing.
* **Checkout Script Tampering:** Malicious JavaScript or Magecart sniffers attempting to harvest cardholder details on payment forms.
* **Stealth Database Backdoors:** Rogue administrator accounts created directly in MySQL that stay invisible in the standard WordPress user list.

== Stop WooCommerce Card Testing & Fake Orders ==

* **Pre-Gateway Rate Limiting:** Evaluates payment velocity and failed attempt clusters before calls reach your payment gateway, eliminating unnecessary authorization fees.
* **Store API & REST Endpoint Security:** Hardens both classic WooCommerce checkout and modern headless/Block checkout endpoints (`/wc/store/v1/checkout`) against bot floods.
* **Disposable Email & Velocity Filters:** Flags temporary disposable inbox domains and enforces IP/email velocity limits during flash carding spikes.
* **Dynamic Store Baselines:** Evaluates checkout surges against your store's 60-day historical transaction volume instead of brittle rigid limits.

== Checkout Protection & Skimmer Detection ==

* **Magecart & Skimmer Scanning:** Continuously scans frontend scripts, database options, and active themes for card harvesting regexes, keylogger beacons, and suspicious `eval()` rotations.
* **Gateway Credential Integrity:** Real-time alarms alert store owners immediately if Stripe API keys, PayPal merchant emails, or payout settings are modified.
* **Stealth Admin Account Detection:** Queries the database directly to uncover shadow admin accounts that hide from the standard WordPress dashboard users screen.
* **Safe In-Database Quarantine:** Isolates suspicious code into encoded database records with one-click restore and zero executable file storage in `wp-content/uploads`.
* **Safe Observe Mode:** Ships in default Observe mode to record comprehensive threat telemetry without risking false positives on legitimate buyers.
* **HPOS & WooCommerce Blocks Ready:** Native compatibility with High-Performance Order Storage (HPOS) and the Cart/Checkout Blocks architecture.

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

= How do I stop WooCommerce card testing bots? =
Activate SentinelGuard and leave it in the default Observe mode for a few days to build a baseline of your store's normal checkout traffic. Once you're confident in the findings, switch to active enforcement and it will rate-limit and block card testing patterns before they reach your payment gateway.

= Does this detect Magecart and checkout skimmers? =
Yes. SentinelGuard continuously scans your frontend scripts, database options, and active theme for the code patterns and keylogger beacons associated with Magecart-style skimmers, and quarantines anything suspicious.

= Will this affect my payment gateway fees or decline rate? =
No, and it should help. By filtering obvious card testing attempts before they hit Stripe, PayPal, or Authorize.Net, SentinelGuard reduces the failed-authorization volume that drives up processor fees and decline-rate warnings.

= Does this work with WooCommerce Blocks and High-Performance Order Storage (HPOS)? =
Yes. SentinelGuard is built natively for both the classic checkout and the Cart/Checkout Blocks architecture, and it's fully compatible with HPOS.

= Do I need to configure anything, or does it work out of the box? =
It works out of the box in Observe mode, recording telemetry with no risk of blocking real customers. Optional integrations like Patchstack, WPScan, and AI-assisted explanations require you to add your own API key in Settings.

== Screenshots ==

1. SentinelGuard Dashboard - Real-time active threats, findings table, detection engines, and manual scan triggers.
2. General Settings - Protection levels, site role configuration, data retention, and baseline WordPress hardening toggles.
3. Scanning & Intelligence - Automated scan schedule, scan depth, path exclusion rules, and vulnerability database API keys.
4. Threat Detection Engines - Real-time status cards for skimmer scanning, card testing defense, and admin account monitoring.

== Changelog ==

= 0.4.6 =
* Updated plugin title and tags to lead with WooCommerce for better search visibility.
* Expanded the FAQ with common card testing, skimmer, and HPOS compatibility questions.

= 0.4.5 =
* Established Observe-First deployment lifecycle to protect stores against checkout false positives.
* Transitioned quarantine storage completely to the database, eliminating all code file storage on disk.
* Added server-level .htaccess and 0-byte index.php protection guards for quarantine vaults.
* Hardened classic and blocks checkout interception with exception halting to block rogue payment gateway continuation.
* Registered custom 7-day weekly interval for WP-Cron scan scheduling.
* Centralized all content and plugin directory path lookups in SentinelWP_Helper, eliminating direct WP_CONTENT_DIR and WP_PLUGIN_DIR constant access.
* Standardized root path resolution and relative path helpers to use WordPress core APIs instead of internal constants.
* Cleaned up obsolete vault initialization methods and sanitized session journey cookies.
* Synchronized webhook alert configuration and ensured admin assets load across all settings screens.

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
