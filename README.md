# SentinelGuard — Ecommerce & Checkout Protection

A WordPress security plugin built specifically for WooCommerce stores. It focuses on the attack patterns that actually cost store owners money: card testing, checkout skimmers, fake admin accounts, and gateway tampering, instead of generic file-scanning that most WP security plugins already do.

[![CI Test Suite](https://github.com/Xbot-me/sentinelwp-security/actions/workflows/ci.yml/badge.svg)](https://github.com/Xbot-me/sentinelwp-security/actions/workflows/ci.yml)
[![PHP](https://img.shields.io/badge/PHP-7.4%20|%208.0%20|%208.1%20|%208.2%20|%208.3%20|%208.4-777bb4.svg)](https://php.net)
[![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759b.svg)](https://wordpress.org)
[![WooCommerce](https://img.shields.io/badge/WooCommerce-HPOS%20Ready-96588a.svg)](https://woocommerce.com)
[![License](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

## Table of contents

- [Why this exists](#why-this-exists)
- [What it does](#what-it-does)
- [How requests flow through it](#how-requests-flow-through-it)
- [Benchmarks](#benchmarks)
- [Installation](#installation)
- [Configuration](#configuration)
- [Testing](#testing)
- [External services and privacy](#external-services-and-privacy)
- [Contributing](#contributing)
- [Security policy](#security-policy)
- [License](#license)

## Why this exists

Most WordPress security plugins were built for blogs, not checkout flows. They catch brute-force logins and known malware signatures, but they have no concept of what a checkout looks like, so they miss card-testing bursts, skimmer scripts injected into checkout JS, and orders that come from a fraud ring rotating through residential proxies. I built SentinelGuard to sit in front of the payment gateway and catch that class of problem before it turns into chargebacks or a Stripe account review.

## What it does

**Pre-gateway risk scoring.** Checkout requests, both the classic `woocommerce_checkout_process` hook and the Store API's `/wc/store/v1/checkout` endpoint, get scored before the card is ever charged. The engine builds a 60-day rolling baseline of your store's own order values (p05/p50/p95) so a $5 order or a $2,000 VIP order doesn't get flagged just for being unusual in general. It also clusters session tokens, cart fingerprints, and billing details together, which catches coordinated attacks that rotate IPs but reuse the same session or cart pattern. You can run it in observe mode first and only switch to blocking once you trust the scores.

**Skimmer and Magecart detection.** Scans theme and plugin JS for listeners on card and CVV fields, base64-encoded eval loaders, and exfiltration beacons disguised as image requests. It also walks `wp-content/uploads/` looking for files with image extensions that actually contain PHP.

**Card-testing defense.** Tracks failed payment bursts per IP and per email cluster, normalizes events from WooCommerce core, Stripe, PayPal, Authorize.Net, and Braintree into one format, and checks against a list of 200+ disposable email domains, since a lot of card-testing traffic uses throwaway addresses.

**Configuration integrity.** Hashes your gateway settings, API keys, PayPal recipient, webhook secrets, so you get an alert the moment they change. Also flags $0.00 products and coupons created by anyone other than an admin, and watches refund volume against your own historical average.

**Hidden admin detection.** Hooks `user_register` and `set_user_role` to block unauthorized privilege escalation, and separately queries `wp_users`/`wp_usermeta` directly, which catches admin accounts created via a filter bypass that hides them from the normal WP admin UI.

**Attack correlation.** Individual signals (traffic spikes, failed cards, disposable emails, file changes) get merged into a single incident when they line up, rather than firing five separate alerts for one attack. Scan history older than 30 days is purged automatically.

**Quarantine with rollback.** Files get copied to a vault and checksummed before they're ever removed, not just deleted outright. Quarantine won't touch `wp-config.php`, `index.php`, or `.htaccess`, and can't be tricked into writing outside the WordPress root via `../` or symlinks. Rollback restores the original file, permissions included, and verifies the SHA-256 hash matches before calling it done.

## How requests flow through it

```
request → reverse proxy / IP resolution (Cloudflare-aware, strips spoofed XFF)
        → pre-gateway risk engine (clustering, AOV baseline, bot velocity)
        → observe / soft-block / protect
        → e-commerce guard (failed payment bursts, gateway hash check)
        → attack correlator (merges signals into one incident)
        → quarantine vault (two-phase commit, rollback available)
```

The continuous scanner (skimmer JS, fake image payloads, stealth admins, core/plugin CVE checks) runs on its own cron schedule, separate from the checkout path.

## Benchmarks

Tested against HPOS stores from 10,000 up to 500,000+ orders. Order aggregation queries stay under 0.015s, pre-gateway checkout scoring adds under 1.8ms, and peak memory during a fraud-pattern cron run stays under 2MB. These are the numbers I could reproduce consistently on my own test store; your mileage will vary with hosting and order volume.

## Installation

**WordPress admin:** download the latest `.zip` from [Releases](https://github.com/Xbot-me/sentinelwp-security/releases), then Plugins → Add New → Upload Plugin → Install → Activate.

**WP-CLI:**
```bash
wp plugin install https://github.com/Xbot-me/sentinelwp-security/archive/refs/heads/main.zip --activate
```

**Git:**
```bash
cd wp-content/plugins/
git clone https://github.com/Xbot-me/sentinelwp-security.git sentinelwp-security
```

## Configuration

Everything lives under **SentinelGuard** in the WP admin sidebar:

- **Dashboard** — live threat metrics, correlated incidents, recent scans.
- **Scanner** — run phased scans on demand (core checksums, CVE database, malware, JS skimmers, nulled code, stealth admins).
- **E-Commerce Guard** — set the risk engine to `observe` (I'd run this for at least a week before switching modes) or `protect`, tune failed-payment thresholds, toggle disposable email filtering, enable auto-hold on high-risk orders.
- **Quarantine Vault** — inspect quarantined files, check their SHA-256 state, roll back with one click.
- **Settings** — alert recipients, webhook endpoints (Slack, Discord, custom SIEM), and proxy resolution mode (Cloudflare, reverse proxy, or direct).

## Testing

15+ suites covering unit logic, integration, stress, and adversarial abuse cases.

```bash
# full suite
php tests/run-all-tests.php

# individual suites
php tests/test-risk-engine-phase1.php
php tests/test-attack-correlator.php
php tests/test-adversarial-abuse-suite.php
php tests/test-quarantine-rollback.php
php tests/test-corpus-benchmark.php
php tests/test-woocommerce-attacks-and-scalability.php
php tests/test-operational-chaos-suite.php
```

## External services and privacy

- `api.wordpress.org` is queried during scans to verify core, plugin, and theme checksums. No order or customer data goes out with those requests.
- Patchstack/WPScan vulnerability lookups only happen if you add your own API key in Settings.
- If you configure AI triage, flagged code snippets (never credentials or customer data) get sent out for plain-English remediation notes.
- Webhook alerts go straight to the endpoint you configure. Nothing routes through a third-party relay.

## Contributing

1. Fork the repo, branch off `feature/amazing-feature`.
2. Run `php tests/run-all-tests.php` before opening a PR.
3. Keep commits scoped and the message descriptive.
4. Open the PR against `main`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for more detail.

## Security policy

Found a vulnerability? Please don't open a public issue. Report it through [GitHub Security Advisories](https://github.com/Xbot-me/sentinelwp-security/security/advisories/new) or check [SECURITY.md](SECURITY.md) for other reporting options.

## License

GPL-2.0-or-later. See [LICENSE](https://www.gnu.org/licenses/gpl-2.0.html).
