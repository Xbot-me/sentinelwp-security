# Contributing to SentinelGuard

Thank you for your interest in contributing to **SentinelGuard**! We welcome bug fixes, documentation enhancements, feature proposals, and security improvements.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for all contributors and users. Please be respectful and constructive in all interactions.

---

## How Can I Contribute?

### 1. Reporting Bugs
- Before filing a new issue, search existing [GitHub Issues](https://github.com/Xbot-me/sentinelwp-security/issues) to see if it has already been reported.
- Use our [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md) with complete reproduction steps, environment details (WordPress, WooCommerce, HPOS status, PHP version), and logs.

### 2. Suggesting Enhancements
- Check [Open Issues](https://github.com/Xbot-me/sentinelwp-security/issues) to ensure your idea hasn't been proposed.
- Use our [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md) describing the motivation, architecture impact, and proposed implementation.

### 3. Submitting Pull Requests (PRs)
1. **Fork** the repository and clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/sentinelwp-security.git
   cd sentinelwp-security
   ```
2. **Create a topic branch**:
   ```bash
   git checkout -b feature/my-new-feature
   # or
   git checkout -b fix/issue-description
   ```
3. **Write clean, defensive PHP code** conforming to [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/php/):
   - Strict input validation and sanitization.
   - Nonce and capability verification for all privileged actions.
   - Escaping all outputs (`esc_html`, `esc_attr`, `esc_url`).
   - Prepared SQL queries via `$wpdb->prepare()`.
4. **Run the local test suite**:
   ```bash
   php tests/run-all-tests.php
   ```
   Ensure **100% of test suites pass** before opening a PR.
5. **Commit your changes** with clear, descriptive commit messages:
   ```bash
   git commit -m "feat(risk-engine): add velocity anomaly suppression for trusted webhooks"
   ```
6. **Push to your fork and submit a PR** against the `main` branch.

---

## Development & Testing Workflow

SentinelGuard includes a self-contained, high-performance mock testing harness that runs without requiring a full WordPress or database installation:

```bash
# Run all unit, integration, and security verification tests
php tests/run-all-tests.php

# Run individual test suites
php tests/test-risk-engine-phase1.php
php tests/test-attack-correlator.php
php tests/test-adversarial-abuse-suite.php
php tests/test-quarantine-rollback.php
php tests/test-corpus-benchmark.php
php tests/test-woocommerce-attacks-and-scalability.php
```

All Pull Requests trigger our GitHub Actions CI matrix across PHP 7.4 through PHP 8.4.

---

## Security Vulnerabilities

Please **do not** file public GitHub issues for security vulnerabilities. Review our [Security Policy](SECURITY.md) for private reporting instructions.
