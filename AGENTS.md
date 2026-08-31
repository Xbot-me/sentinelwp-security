# Agent Instructions & Deployment Protocol

Instructions for AI coding agents operating on the SentinelGuard repository.

## Release Invariants

Before packaging any distribution ZIP or committing changes to WordPress.org SVN (`trunk` or `tags/*`), you **MUST** run and pass both pre-flight checks:

### 1. Run Automated Test Suite
Execute the full test runner:
```bash
php tests/run-all-tests.php
```
**Completion Criterion**: All 12/12 test suites must pass with `0 Failed`. This validates:
- Version consistency across `readme.txt`, plugin header, and `SENTINELWP_VERSION`
- Database table references
- JS selectors ↔ Admin HTML sync
- Uninstaller cleanup completeness
- AbsPath security guards on all PHP files
- Static Plugin Check (PCP) sniffs for unescaped exceptions and i18n interpolation

### 2. Run Local WordPress Plugin Check (PCP)
Verify the production build using WP-CLI on the local site environment (`Bugged`):
```bash
# 1. Regenerate the clean distribution zip
python3 -c '
import zipfile, os
zip_dest = "/Users/xbot-me/Desktop/github-projects/sentinelguard-ecommerce-protection.zip"
repo_dir = "/Users/xbot-me/Desktop/github-projects/sentinelwp-security"
plugin_slug = "sentinelguard-ecommerce-protection"
include_files = [
    "admin/class-admin.php", "admin/css/admin.css", "admin/js/admin.js",
    "data/disposable-email-domains.php", "data/nulled-indicators.php", "data/skimmer-signatures.php",
    "includes/class-activator.php", "includes/class-admin-guard.php", "includes/class-ai-analyzer.php",
    "includes/class-alerts.php", "includes/class-attack-correlator.php", "includes/class-deactivator.php",
    "includes/class-ecommerce-guard.php", "includes/class-event-normalizer.php", "includes/class-flood-monitor.php",
    "includes/class-form-shield.php", "includes/class-freemium.php", "includes/class-hardening.php",
    "includes/class-helper.php", "includes/class-nulled-detector.php", "includes/class-payment-adapter.php",
    "includes/class-quarantine.php", "includes/class-risk-engine.php", "includes/class-scan-coordinator.php",
    "includes/class-scanner.php", "includes/class-settings.php", "includes/class-skimmer-detector.php",
    "includes/class-store-api-guard.php", "includes/class-vuln-db.php", "languages/index.php",
    "readme.txt", "sentinelguard-ecommerce-protection.php", "uninstall.php"
]
with zipfile.ZipFile(zip_dest, "w", zipfile.ZIP_DEFLATED) as z:
    for rel in include_files:
        z.write(os.path.join(repo_dir, rel), f"{plugin_slug}/{rel}")
'

# 2. Extract clean zip into the local site plugin directory
python3 -c '
import zipfile, shutil, os
dest = os.path.expanduser("~/Local Sites/bugged/app/public/wp-content/plugins/sentinelguard-ecommerce-protection")
if os.path.exists(dest):
    shutil.rmtree(dest)
with zipfile.ZipFile("/Users/xbot-me/Desktop/github-projects/sentinelguard-ecommerce-protection.zip", "r") as z:
    z.extractall(os.path.expanduser("~/Local Sites/bugged/app/public/wp-content/plugins/"))
'

# 3. Run official WordPress Plugin Check via WP-CLI with Local MySQL socket
php -d "mysqli.default_socket=/Users/xbot-me/Library/Application Support/Local/run/HO5xbvCzN/mysql/mysqld.sock" \
    /Applications/Local.app/Contents/Resources/extraResources/bin/wp-cli/wp-cli.phar \
    --path="$HOME/Local Sites/bugged/app/public" plugin check sentinelguard-ecommerce-protection
```
**Completion Criterion**: Must output:
`Success: Checks complete. No errors found.`

Only proceed with SVN commit once both criteria are satisfied.

## SVN Authentication Invariant
- **Username**: Must strictly be lowercase `mustafizurdev` (SVN pre-commit hooks reject uppercase).
- **Password**: Provided in active session credentials.
- **Always update both `trunk` and `tags/<version>`** synchronously.
