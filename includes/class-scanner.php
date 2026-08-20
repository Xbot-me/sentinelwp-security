<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Orchestrates a full scan: version/vulnerability checks, core file
 * integrity, and local signature heuristics. Runs only via WP-Cron —
 * never on a front-end or admin page load — so it can't be used to
 * exhaust server resources by hitting the site repeatedly.
 */
class SentinelWP_Scanner {

	private static $instance = null;

	/**
	 * Known-bad code patterns. Deliberately conservative (favors false
	 * positives that get reviewed over silently missing a real backdoor).
	 * Matched snippets — never full files — are what gets handed to the
	 * AI analyzer for triage.
	 */
	private $signatures = array(
		'/eval\s*\(\s*base64_decode\s*\(/i'        => 'eval(base64_decode()) obfuscation',
		'/eval\s*\(\s*gzinflate\s*\(/i'             => 'eval(gzinflate()) obfuscation',
		'/eval\s*\(\s*str_rot13\s*\(/i'             => 'eval(str_rot13()) obfuscation',
		'/assert\s*\(\s*\$_(POST|GET|REQUEST)/i'    => 'assert() executing request input',
		'/create_function\s*\(\s*[\'"].*\$_/i'      => 'dynamic create_function() from request input',
		'/preg_replace\s*\(.*\/e[\'"]/i'             => 'preg_replace() with deprecated /e eval modifier',
		'/\bFilesMan\b|\bc99shell\b|\br57shell\b|\bWSO\s*Shell\b/i' => 'known web-shell marker string',
		'/\$GLOBALS\[[^\]]+\]\s*\(\s*\$_(POST|GET|REQUEST)/i' => 'dynamic function call from request input',
		// Ecommerce-specific malware patterns.
		'/eval\s*\(\s*json_decode\s*\(/i'           => 'eval(json_decode()) obfuscation',
		'/\$_COOKIE\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\(/i' => 'cookie-based code execution',
		'/gtm\.js\?id=GTM-[A-Z0-9]+.*(?:atob|eval)/is' => 'fake Google Tag Manager with suspicious code',
		'/(?:sk_live_|rk_live_|pk_live_)[a-zA-Z0-9]{20,}/i' => 'hardcoded Stripe secret key in code',
		'/(?:visibility:\s*hidden|display:\s*none).*<iframe/is' => 'hidden iframe injection',
		'/wc-ajax[=\s]*checkout.*(?:eval|atob|fetch|XMLHttpRequest)/is' => 'WooCommerce checkout AJAX interception',
		'/file_put_contents\s*\(.*\$_(POST|GET|REQUEST|COOKIE)/i' => 'file_put_contents with user input',
		'/\bphp_uname\b|\bpassthru\b|\bshell_exec\b|\bpopen\b.*\$_(POST|GET|REQUEST)/i' => 'shell command execution from request input',
	);

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'sentinelwp_daily_scan', array( $this, 'run_full_scan' ) );
	}

	public function run_full_scan() {
		if ( class_exists( 'SentinelWP_Scan_Coordinator' ) ) {
			return SentinelWP_Scan_Coordinator::instance()->run_full_scan();
		}

		$this->scan_core_integrity();
		$this->scan_plugin_versions();
		$this->scan_theme_versions();
		$this->scan_uploads_for_php();
		$this->scan_mu_plugins();
		$this->scan_admin_accounts();

		// Ecommerce & Admin security scans.
		SentinelWP_Nulled_Detector::instance()->scan_all();
		SentinelWP_Skimmer_Detector::instance()->scan_all();
		SentinelWP_Admin_Guard::instance()->scan_for_hidden_admins();

		if ( class_exists( 'SentinelWP_Ecommerce_Guard' ) ) {
			SentinelWP_Ecommerce_Guard::instance()->cron_analyze_fraud_patterns();
			SentinelWP_Ecommerce_Guard::instance()->cron_monitor_complaint_patterns();
			SentinelWP_Ecommerce_Guard::instance()->cron_check_store_integrity();
		}

		do_action( 'sentinelwp_scan_complete' );
	}

	/**
	 * Compares live core files against WordPress.org's published MD5
	 * checksums for the exact running version + locale. This needs no
	 * API key and catches tampered/backdoored core files directly.
	 */
	public function scan_core_integrity() {
		global $wp_version;
		$locale = get_locale();

		$transient_key = 'sentinelwp_core_checksums_' . md5( $wp_version . '_' . $locale );
		$checksums     = get_transient( $transient_key );

		if ( false === $checksums || ! is_array( $checksums ) ) {
			$url  = add_query_arg(
				array(
					'version' => $wp_version,
					'locale'  => $locale,
				),
				'https://api.wordpress.org/core/checksums/1.0/'
			);
			$resp = wp_remote_get( $url, array( 'timeout' => 4 ) );

			if ( is_wp_error( $resp ) || 200 !== wp_remote_retrieve_response_code( $resp ) ) {
				return; // Don't report a false "all clear" — just skip this run.
			}

			$data = json_decode( wp_remote_retrieve_body( $resp ), true );
			if ( empty( $data['checksums'] ) || ! is_array( $data['checksums'] ) ) {
				return;
			}
			$checksums = $data['checksums'];
			set_transient( $transient_key, $checksums, DAY_IN_SECONDS );
		}

		$mismatches = array();
		foreach ( $checksums as $relative_path => $expected_md5 ) {
			// wp-content is user territory, never part of core checksums;
			// skip anything the API wouldn't list anyway as a safety net.
			if ( 0 === strpos( $relative_path, 'wp-content/' ) ) {
				continue;
			}
			$full_path = ABSPATH . $relative_path;
			if ( ! file_exists( $full_path ) ) {
				$mismatches[] = array( 'file' => $relative_path, 'issue' => 'missing' );
				continue;
			}
			if ( md5_file( $full_path ) !== $expected_md5 ) {
				$mismatches[] = array( 'file' => $relative_path, 'issue' => 'modified' );
			}
		}

		if ( ! empty( $mismatches ) ) {
			$this->record_finding(
				'core_integrity',
				'critical',
				'wordpress.org-checksums',
				sprintf(
					/* translators: %d: number of mismatched core files */
					_n( '%d WordPress core file differs from the official release', '%d WordPress core files differ from the official release', count( $mismatches ), 'sentinelwp-security' ),
					count( $mismatches )
				),
				wp_json_encode( array_slice( $mismatches, 0, 50 ) ),
				'confirmed',
				'core_checksums',
				__( 'Reinstall WordPress core files from the Updates screen to overwrite modified files.', 'sentinelwp-security' ),
				'low'
			);
		}
	}

	public function scan_plugin_versions() {
		if ( ! function_exists( 'get_plugins' ) && file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$vuln_db = new SentinelWP_Vuln_DB();
		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();

		foreach ( $plugins as $plugin_path => $plugin_data ) {
			$slug   = dirname( $plugin_path );
			if ( '.' === $slug ) {
				$slug = basename( $plugin_path, '.php' );
			}
			$result = $vuln_db->check( 'plugin', $slug, $plugin_data['Version'] );
			$this->record_vuln_result( 'plugin', $plugin_data['Name'], $result );
		}
	}

	public function scan_theme_versions() {
		$vuln_db = new SentinelWP_Vuln_DB();
		$themes  = wp_get_themes();

		foreach ( $themes as $slug => $theme ) {
			$result = $vuln_db->check( 'theme', $slug, $theme->get( 'Version' ) );
			$this->record_vuln_result( 'theme', $theme->get( 'Name' ), $result );
		}
	}

	private function record_vuln_result( $type, $name, SentinelWP_Vuln_Result $result ) {
		if ( $result->has_vulnerability ) {
			foreach ( $result->vulnerabilities as $vuln ) {
				$this->record_finding(
					$type . '_vulnerability',
					$this->normalize_severity( $vuln['severity'] ),
					$vuln['source'],
					sprintf( '%s: %s', $name, $vuln['title'] ),
					wp_json_encode( $vuln ),
					'likely',
					'vuln_db',
					__( 'Update this component immediately to the latest patched release.', 'sentinelwp-security' ),
					'low'
				);
			}
		} elseif ( $result->is_outdated ) {
			$this->record_finding(
				$type . '_outdated',
				'low',
				$result->source,
				sprintf(
					/* translators: 1: item name, 2: installed version, 3: latest version */
					__( '%1$s is outdated (%2$s installed, %3$s available)', 'sentinelwp-security' ),
					$name,
					$result->current_version,
					$result->latest_version
				),
				'',
				'confirmed',
				'version_checker',
				__( 'Update to the latest version to ensure security patches are applied.', 'sentinelwp-security' ),
				'low'
			);
		}
	}

	private function normalize_severity( $raw ) {
		$raw = strtolower( (string) $raw );
		if ( in_array( $raw, array( 'critical', 'high', 'medium', 'low' ), true ) ) {
			return $raw;
		}
		if ( is_numeric( $raw ) ) {
			$score = (float) $raw;
			if ( $score >= 9 ) return 'critical';
			if ( $score >= 7 ) return 'high';
			if ( $score >= 4 ) return 'medium';
			return 'low';
		}
		return 'medium';
	}

	/**
	 * Signature scan of locations that should never contain executable
	 * PHP under normal operation.
	 */
	public function scan_uploads_for_php() {
		$upload_dir = wp_upload_dir();
		$base       = $upload_dir['basedir'];

		if ( ! is_dir( $base ) ) {
			return;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST,
				RecursiveIteratorIterator::CATCH_GET_CHILD
			);
		} catch ( Exception $e ) {
			return;
		}

		$max_files_per_run = 5000;
		$checked           = 0;

		foreach ( $iterator as $file ) {
			if ( $checked >= $max_files_per_run ) {
				break;
			}
			if ( 'php' !== strtolower( $file->getExtension() ) ) {
				continue;
			}
			$checked++;

			$this->record_finding(
				'suspicious_file',
				'high',
				'filesystem_audit',
				sprintf(
					/* translators: %s: relative file path */
					__( 'PHP file found inside uploads directory: %s', 'sentinelwp-security' ),
					str_replace( ABSPATH, '', $file->getPathname() )
				),
				'',
				'likely',
				'filesystem_audit',
				__( 'PHP scripts should never exist in the media uploads folder. Inspect and quarantine the file.', 'sentinelwp-security' ),
				'low'
			);

			$this->signature_scan_file( $file->getPathname() );
		}
	}

	/**
	 * Runs the local signature list against a file and queues matched snippet.
	 */
	private function signature_scan_file( $path ) {
		if ( ! is_readable( $path ) || filesize( $path ) > 2 * MB_IN_BYTES ) {
			return;
		}
		$contents = file_get_contents( $path );
		if ( false === $contents ) {
			return;
		}

		foreach ( $this->signatures as $pattern => $label ) {
			if ( preg_match( $pattern, $contents, $matches, PREG_OFFSET_CAPTURE ) ) {
				$offset  = max( 0, $matches[0][1] - 80 );
				$snippet = substr( $contents, $offset, 240 );

				$finding_id = $this->record_finding(
					'malware_signature',
					'high',
					'local-heuristic',
					sprintf(
						/* translators: 1: signature label, 2: relative file path */
						__( 'Suspicious code pattern (%1$s) in %2$s', 'sentinelwp-security' ),
						$label,
						str_replace( ABSPATH, '', $path )
					),
					wp_json_encode( array( 'signature' => $label ) ),
					'suspicious',
					'local_heuristic',
					__( 'Review the flagged code snippet to verify whether it belongs to legitimate obfuscation or a web shell.', 'sentinelwp-security' ),
					'medium'
				);

				if ( $finding_id ) {
					SentinelWP_AI_Analyzer::instance()->queue_triage( $finding_id, $snippet, $label );
				}
			}
		}
	}

	public function scan_mu_plugins() {
		$mu_dir = WPMU_PLUGIN_DIR;
		if ( ! is_dir( $mu_dir ) ) {
			return;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $mu_dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST,
				RecursiveIteratorIterator::CATCH_GET_CHILD
			);
		} catch ( Exception $e ) {
			return;
		}

		$checked = 0;
		foreach ( $iterator as $file ) {
			if ( $checked >= 2000 ) {
				break;
			}
			if ( 'php' !== strtolower( $file->getExtension() ) ) {
				continue;
			}
			$checked++;
			$this->signature_scan_file( $file->getPathname() );
		}
	}

	public function scan_admin_accounts() {
		$admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID', 'user_login', 'user_registered' ) ) );

		foreach ( $admins as $admin ) {
			if ( 'admin' === strtolower( $admin->user_login ) ) {
				$this->record_finding(
					'weak_username',
					'medium',
					'admin_audit',
					__( 'Default administrator username "admin" detected', 'sentinelwp-security' ),
					wp_json_encode( array( 'user_id' => $admin->ID ) ),
					'heuristic',
					'admin_audit',
					__( 'Create a new admin user with a unique username and delete or downgrade the "admin" user.', 'sentinelwp-security' ),
					'low'
				);
			}
		}
	}

	/**
	 * Inserts finding with confidence, detector, remediation, and false-positive risk.
	 */
	public function record_finding( $type, $severity, $source, $title, $details, $confidence = 'likely', $detector = 'scanner', $remediation = '', $fp_risk = 'low' ) {
		global $wpdb;
		$table = $wpdb->prefix . 'sentinelwp_findings';

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE type = %s AND title = %s AND status != 'resolved' LIMIT 1",
				$type,
				$title
			)
		);

		if ( $existing ) {
			$wpdb->update(
				$table,
				array( 'updated_at' => current_time( 'mysql' ) ),
				array( 'id' => $existing ),
				array( '%s' ),
				array( '%d' )
			);
			return false;
		}

		$now = current_time( 'mysql' );
		$ok  = $wpdb->insert(
			$table,
			array(
				'type'                => $type,
				'severity'            => $severity,
				'confidence'          => $confidence,
				'detector'            => $detector,
				'source'              => $source,
				'title'               => $title,
				'details'             => $details,
				'remediation'         => $remediation,
				'false_positive_risk' => $fp_risk,
				'status'              => 'new',
				'created_at'          => $now,
				'updated_at'          => $now,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( $ok ) {
			$id = $wpdb->insert_id;
			do_action( 'sentinelwp_new_finding', $id, $type, $severity, $title );
			return $id;
		}
		return false;
	}
}
