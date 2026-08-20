# SentinelWP Security — Implementation Plan

Plugin slug: `sentinelwp-security` · Prefix: `sentinelwp_` · Text domain: `sentinelwp-security`

## 1. What this plugin does

A freemium WordPress security plugin with three layers, in this order of trust:

1. **Hardening** — deterministic, always-on protections that need no data feed and no AI.
2. **Scanning** — matches what's installed against real vulnerability data and checks core file integrity against official checksums.
3. **AI analysis** — a second-opinion layer that looks at ambiguous findings (obfuscated code, unknown files, suspicious patterns) and explains them in plain language. AI never replaces the deterministic checks above; it only adds judgment on top of them, and every AI call has a non-AI fallback.

## 2. Vulnerability data sources (the part with no loopholes)

I'm not inventing a vulnerability feed — that would be the actual security hole. The plugin pulls from real, maintained sources and is explicit in the UI about which one is active:

| Source | What it gives us | Auth | Free tier | Role |
|---|---|---|---|---|
| **WordPress.org Core Checksums API** (`api.wordpress.org/core/checksums/1.0/`) | Official MD5 checksums for every core file, per version/locale | None | Unlimited | Core file integrity — detects tampered/backdoored core files. This is the free, always-on baseline and needs no third-party key at all. |
| **WordPress.org Plugins/Themes Info API** (`api.wordpress.org/plugins/info/1.2/`, `themes/info/1.2/`) | Latest stable version per plugin/theme slug | None | Unlimited | Outdated-plugin/theme detection even with zero vulnerability API configured. "You're 4 versions behind" is real signal on its own. |
| **Patchstack Vulnerability API** | CVE-backed plugin/theme/core vulnerability records, community-disclosed | Free API key (developer account) | Free tier, described by Patchstack as unlimited for the vuln lookup endpoint | Primary vulnerability match source |
| **WPScan Vulnerability Database API** (`wpscan.com/api`) | WordPress core/plugin/theme CVE database, 20k+ entries | Free API key | 25 requests/day on the free tier | Secondary/fallback vuln source, or primary if the user prefers it |

Design decision: **the vuln-data client is an interface, not a single vendor.** `class-vuln-db.php` defines `SentinelWP_Vuln_Source` with one method, `check( $type, $slug, $version )`, returning a normalized result. Patchstack and WPScan are two implementations. If neither API key is set, the plugin still runs on the two no-key WordPress.org endpoints — free users get real value with zero configuration, which is the whole point of a freemium plugin.

Rate limits are respected by caching every lookup in a transient keyed by `type:slug:version` for 12 hours, and by batching the daily cron scan so we don't reissue a request for a plugin that hasn't changed version since the last check.

## 3. Where "AI analysis" actually earns its place

AI is not asked to decide "is this site hacked" from nothing — that's unreliable and unauditable. It's scoped to three concrete jobs, each with a fallback that runs with zero AI:

1. **Obfuscated/suspicious code triage.** The deterministic scanner already flags files using signature patterns (see below). For flagged files, the AI is given the *matched snippet only* (not the whole file, not site data) and asked to classify: `malicious`, `suspicious-but-explainable` (e.g. a legit minifier), or `benign`, with a one-line reason. Fallback with no API key: the file is reported as "matched pattern X, needs manual review" — still actionable, just not triaged.
2. **Vulnerability plain-language summary.** When a CVE match comes back from Patchstack/WPScan, the AI turns the raw record into a two-sentence, non-jargon explanation of the risk and the fix. Fallback: show the raw CVE title, CVSS score, and "update to version X" — still complete, just less readable.
3. **Weekly digest.** Pro feature: summarizes the week's findings into one email. Fallback: a plain bullet list of what changed.

AI never gets: database credentials, full file contents beyond a capped snippet, site URLs beyond the bare domain, user PII, or write access to remediate anything on its own in the free tier (auto-remediation is a gated, human-in-the-loop Pro feature — see §6).

### Prompting and output contract

- Every AI call requests **strict JSON** matching a fixed schema (`verdict`, `confidence`, `reason`) and the response is validated against that schema before use; anything that doesn't parse is treated as a fallback case, not retried indefinitely.
- System prompt pins the model to a security-analyst role and explicitly forbids inventing CVE IDs or version numbers not present in the input — it's an explainer/classifier over data we already fetched, not a source of new vulnerability facts.
- Multi-provider: Claude, OpenAI, Gemini behind one `SentinelWP_AI_Provider` interface, selected in settings. No provider is hardcoded elsewhere in the codebase.
- Timeout capped (10s), single retry on transient failure, then fallback. Never blocks the admin UI — analysis runs via WP-Cron, not on page load.
- Every AI verdict is logged (model, timestamp, input hash, output) in the scan-log table for auditability, since auto-actions in Pro are gated behind these logs.

## 4. Detection mechanics (the actual scanning)

- **Core integrity**: fetch checksums for the exact running core version + locale, hash local files, diff. Any core file with a mismatched hash, or any unexpected `.php` file inside core directories, is flagged critical.
- **Plugin/theme version match**: enumerate `get_plugins()` / `wp_get_themes()`, compare against the vuln-data sources in §2.
- **Signature heuristics** (free, local, no API calls) on `wp-content/uploads`, `wp-content/mu-plugins`, and any `.php` file outside core/plugins/themes: known bad patterns — `eval(base64_decode(`, `eval(gzinflate(`, `assert($_POST`, `create_function` with dynamic input, suspicious `FilesMan`/`c99`/`r57`-style shell markers, PHP in files that should never contain PHP (e.g. inside `uploads`). This is pattern matching, not AI — it's fast, offline, and deterministic, and it's what feeds the AI triage step in §3.1.
- **Admin/user audit**: unexpected administrator accounts, accounts created outside normal registration flow, weak/default usernames like `admin`.
- Results are written to a custom table (`{$wpdb->prefix}sentinelwp_findings`) with severity, type, timestamp, and status (`new`/`acknowledged`/`resolved`), not to `wp_options`, since findings are structured records that need querying and pruning, not a single blob.

## 5. Security checklist (the "no loophole" requirement, made concrete)

Every item below is enforced in the scaffold I'm about to write, not left as a TODO:

- [x] Every AJAX/admin-post handler checks `current_user_can( 'manage_options' )` **and** verifies a nonce before touching anything.
- [x] Every DB query touching variable input uses `$wpdb->prepare()`. No string-concatenated SQL anywhere.
- [x] Every output to HTML uses `esc_html`/`esc_attr`/`esc_url`/`wp_kses_post` at the point of output, not "sanitized once on the way in and trusted forever."
- [x] Settings fields registered through the Settings API with explicit `sanitize_callback` per field — no raw `$_POST` writes to options.
- [x] API keys (Patchstack, WPScan, AI providers) stored via `autoload => false` options, never logged, never echoed back into the page (write-only field, masked).
- [x] Outbound requests (`wp_remote_get`/`wp_remote_post`) always set a timeout and check `is_wp_error()` / response code before touching the body.
- [x] No `eval`, `extract()` on user input, `unserialize()` on untrusted data, or dynamic `include`/`require` built from request data anywhere in the plugin's own code — the irony of a security scanner shipping the exact patterns it flags is the one bug this plan treats as non-negotiable.
- [x] File-integrity/signature scanning only *reads* files; it never writes to, deletes, or executes anything it finds. Any remediation (quarantine/delete) is a separate, explicitly confirmed, capability-checked, nonce-protected action — never automatic in the free tier.
- [x] Scan results and AI verdicts are logged locally; nothing about the site is sent anywhere except the minimal payload described in §3, and the AI settings screen states exactly what's sent, in plain text, before a key is even required.
- [x] `uninstall.php` removes options and custom tables only if the user opted into "remove data on uninstall" — no silent data loss, no orphaned data by default either.
- [x] Cron-based scanning only (`wp_schedule_event`), never on front-end requests, so an attacker can't trigger a heavy scan by hitting the site repeatedly.
- [x] Rate limiting on the plugin's own AJAX endpoints (transient-based counter) so an authenticated-but-low-privilege bug can't be turned into a resource-exhaustion vector.
- [x] All strings run through `__()`/`esc_html__()` with the plugin text domain — WP.org i18n requirement, not just a nice-to-have.

## 6. Free vs Pro split

**Free**: hardening toolkit, core-integrity + outdated-plugin detection (WordPress.org APIs, no key needed), signature-based malware heuristics, one vuln-data source (user supplies their own free Patchstack or WPScan key), email alerts, AI triage limited to N findings/month on a bring-your-own-key basis.

**Pro**: both vuln sources cross-checked simultaneously, unlimited AI analysis, human-in-the-loop auto-remediation (quarantine flagged files, one-click revert of a modified core file to the checksummed original), Slack/Discord/webhook alerts, multisite, scheduled PDF/email digest reports, historical trend data.

Gating lives in exactly one place: `SentinelWP_Freemium::can( $feature )`, called at each feature's entry point — never duplicated inline.

## 7. Build order (what I'm about to generate)

1. `sentinelwp-security.php` — bootstrap, constants, PSR-4-ish autoloader, activation/deactivation hooks.
2. `includes/class-activator.php` / `class-deactivator.php` — table creation, cron scheduling/clearing.
3. `includes/class-settings.php` — Settings API, sanitized fields, capability-gated save.
4. `includes/class-freemium.php` — single-source-of-truth gating.
5. `includes/class-hardening.php` — deterministic hardening toggles.
6. `includes/class-vuln-db.php` — Patchstack + WPScan + WP.org clients behind one interface, transient caching.
7. `includes/class-scanner.php` — orchestration: enumerate → check versions → checksum core → signature-scan files → write findings.
8. `includes/class-ai-analyzer.php` — provider abstraction, strict-JSON contract, fallback rules, logging.
9. `includes/class-alerts.php` — email (free) + webhook (Pro).
10. `admin/class-admin.php` + minimal CSS/JS — dashboard (status + findings list), settings page.
11. `uninstall.php`, `readme.txt`.

I'll generate all of this now as a working scaffold — not pseudocode — so it's a real starting point you can install on a staging site and iterate on.
