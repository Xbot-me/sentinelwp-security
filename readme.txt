=== SentinelWP Security — Ecommerce & Checkout Protection ===
Contributors: sentinelwp
Tags: ecommerce, security, fraud prevention, malware scanner, firewall
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.4.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Dedicated security layer designed specifically to protect ecommerce revenue, checkout integrity, and payment flows.

== Description ==

SentinelWP Security is the dedicated security layer engineered to protect ecommerce revenue, checkout funnels, and customer payment data. Rather than competing as another generic WordPress firewall, SentinelWP laser-focuses on the threats that drain ecommerce store revenue: card testing attacks, Magecart checkout skimmers, stealth database administrators, fake order surges, and silent gateway credential changes.

= 1. Pre-Gateway Risk Engine & Store API Guard =
* **Pre-Gateway Evaluation** — Evaluates checkout requests before payment processor dispatch, preventing gateway API fees and merchant dispute penalties.
* **Multi-Signal Identity Clustering** — Combines session continuity, disposable email domains, cart SKU signatures, and IP subnet metrics into cluster tokens to defeat distributed residential proxy rotation.
* **Rolling 60-Day Percentile Baseline** — Evaluates order value anomalies against a rolling 60-day order-value percentile baseline based on the most recent 1,000 completed orders (p05, p50, p95) rather than rigid arbitrary thresholds.
* **Zero-Disruption OBSERVE Mode** — Default operating mode calculates risk and logs real-time attack telemetry while allowing 100% of live customer checkouts.

= 2. Magecart & Checkout Skimmer Defense =
* **JavaScript Payment Form Auditing** — Scans all frontend scripts for keyloggers, payment field harvesting (`card`, `cvv`, `expir`), and unauthorized exfiltration to external domains.
* **Fake Image Payload Detector** — Inspects `wp-content/uploads/` for counterfeit image files (`.png`, `.jpg`, `.svg`) containing disguised executable PHP/JS payloads.
* **Database Script Injection Scanner** — Audits `wp_options` and checkout page `post_content` for injected eval loaders, base64 strings, or unauthorized script tags.

= 3. Card Testing & Payment Abuse Prevention =
* **Rapid Card Testing Burst Detection** — Real-time tracking of failed payment attempts per IP and billing email to detect automated carding bots before gateway fees spike.
* **Canonical Payment Event Normalization** — Standardizes gateway lifecycle hooks (Stripe, PayPal, WooCommerce) into canonical payment events.
* **Order Velocity Monitoring** — HPOS-optimized database aggregations that identify order spikes from single IPs or disposable emails.
* **Temporary Disposable Email Filtering** — Flags checkout attempts originating from over 200+ known throwaway email services.

= 4. Store Configuration & Pricing Integrity =
* **Gateway Credential Change Alarms** — Real-time hashing of WooCommerce Stripe, PayPal, and checkout options to alert you immediately if payment routes or payout accounts change unexpectedly.
* **Price Zeroing & Coupon Abuse Detection** — Detects accidental or malicious product price reductions to $0.00 and high-percentage coupons created by non-admin accounts.
* **Refund Rate Spike Monitoring** — Tracks 7-day refund rates against baseline averages to surface unauthorized transaction waves early.

= 5. Stealth Admin & Privilege Elevation Guard =
* **Real-Time Role Elevation Monitor** — Intercepts user registrations and role modifications, immediately alerting on unauthorized admin creation.
* **Direct Database Stealth Admin Auditor** — Queries `wp_users` and `wp_usermeta` directly to uncover hidden admins that hook filters to hide from the standard users list.

= 6. Multi-Signal Attack Correlation Engine =
* **Active Incident Synthesis** — Synthesizes concurrent signals into unified high-confidence attack incidents (e.g. Card-Testing Attacks, Checkout Compromises, Store API Scraping Floods).
* **Non-Destructive Quarantine & Exact Rollback** — 2-phase atomic vault with SHA-256 integrity verification that allows 1-click quarantine and exact byte-for-byte restoration.
* **Automatic 30-Day History Purge** — Automatically purges scan history and request telemetry older than 30 days.

= 7. High-Performance Order Storage (HPOS) Native =
SentinelWP runs SQL database aggregations (`COUNT`, `SUM`, `AVG`, `GROUP BY`) compatible with both WooCommerce HPOS (`wc_orders`) and legacy `wp_posts`. It never loads orders in-memory, keeping memory usage `< 2MB` even on 500k+ order stores.

= External Services Disclosure =
This plugin connects to external services to provide specific security features:
1. **WordPress.org APIs** (`api.wordpress.org`): Used during scans to compare local WordPress core, plugin, and theme files/versions against official releases — specifically the Core Checksums API (`/core/checksums/1.0/`), Core Version Check API (`/core/version-check/1.7/`), and Plugins/Themes Info API (`/plugins/info/1.2/`, `/themes/info/1.2/`). No API key required; results are cached for 6–24 hours to minimize requests. Privacy policy: https://wordpress.org/about/privacy/
2. **Optional Patchstack Vulnerability Database** (`api.patchstack.com`): Only contacted if you enter your own Patchstack API key in Settings, to cross-reference installed plugins/themes/core against known CVEs. Privacy policy: https://patchstack.com/privacy-policy/
3. **Optional WPScan Vulnerability Database** (`wpscan.com`): Only contacted if you enter your own WPScan API key in Settings, for the same purpose as above. Privacy policy: https://wpscan.com/privacy-policy/
4. **Optional AI Triage Service** (OpenAI / Anthropic / Gemini): When you provide your own API key in Settings, flagged code snippets (never customer data or credentials) can be sent for plain-English remediation advice. Each provider's own privacy policy applies to data you choose to send.
5. **Your own alert webhook** (Pro): If you configure a webhook URL under Notifications, a short JSON alert summary (site name, severity, finding title) is sent to that URL when a new finding is recorded. This is a destination you control, not a SentinelWP-operated service.

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/sentinelwp-security`, or install through the WordPress Plugins screen.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Navigate to 'SentinelWP' in the admin menu to review the dashboard and run your first deep scan.

== Frequently Asked Questions ==

= Does SentinelWP slow down checkout? =
No. The risk engine is designed for <0.5ms overhead during checkout by avoiding unnecessary database writes and using memory-efficient fingerprinting.

= Does this replace my firewall? =
SentinelWP works perfectly alongside perimeter firewalls (WAFs) like Cloudflare. While WAFs block known malicious IPs, SentinelWP analyzes behavioral patterns and application-level intent that WAFs cannot see.

= Is this compatible with custom WooCommerce gateways? =
Yes. The plugin uses canonical payment event translation that hooks into standard WooCommerce core actions, making it compatible with Stripe, PayPal, Authorize.net, and most other gateways.

== Screenshots ==

1. The SentinelWP Security Dashboard showing active risk assessments.
2. Checkout protection mode configuration and risk thresholds.
3. Quarantine vault managing safely isolated suspicious files.
4. Comprehensive multi-engine security scan results with confidence metrics.
5. Multi-signal attack correlation and actionable threat mitigation.

== Changelog ==

= 0.4.1 =
* Fixed: Bulk "Quarantine file" action called a non-existent method and fataled — now correctly calls SentinelWP_Quarantine::quarantine_file().
* Added: Explicit WooCommerce HPOS (custom_order_tables) and Cart & Checkout Blocks compatibility declaration.
* Improved: Request-flood tracking now uses a single atomic query (down from two) on the no-object-cache fallback path, which runs on every front-end request.
* Added: `sentinelwp_rest_rate_limit_excluded_routes` filter so other plugins' REST namespaces can be exempted from the sitewide REST rate limiter if a conflict ever arises.
* Updated: External Services Disclosure now itemizes every third-party endpoint contacted (WordPress.org APIs, optional Patchstack, optional WPScan, optional AI providers, optional user-configured webhook).

= 0.4.0 =
* Added Pre-Gateway Risk Engine & Store API Guard with sub-millisecond route preflight.
* Implemented Multi-Signal Identity Clustering to counter distributed residential proxy attacks.
* Added Rolling 60-Day Order-Value Percentile Baseline (p05, p50, p95).
* Added Canonical Payment Event Adapter for uniform gateway lifecycle telemetry.
* Added Pre-Gateway Threat Response Policy with OBSERVE (Detection Only), PROTECT, and LOCKDOWN modes.
* Added Automatic 30-Day Scan History Purge routine.
* Hard-Negative verified against shared NAT IPs, bookmarked checkouts, $1.00 SKU purchases, and mobile carrier IP rotations.

= 0.3.0 =
* Added Active Correlated Incident Banner with 3-Pillar WooCommerce Attack Protection layout.
* Added persistent Scan History logging with per-phase millisecond execution timings.
* Added manual scan lock auto-clearance and Throwable PHP 8 exception safety.

= 0.2.0 =
* Added Magecart & JavaScript skimmer scanner.
* Added Nulled theme/plugin backdoor detector.
* Added Admin account guard for hidden database users.
* Added Form Shield honeypot and rate limiting.
* Added 2-phase non-destructive quarantine with byte-for-byte rollback.
