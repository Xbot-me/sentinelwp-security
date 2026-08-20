<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SentinelWP_Quarantine class.
 *
 * Manages the secure file quarantine vault, state capture, path traversal defense,
 * durable two-phase quarantine invariant, and 1-click rollback.
 * Ensures zero accidental file loss and non-destructive remediation.
 */
class SentinelWP_Quarantine {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Get the absolute filesystem path to the quarantine vault directory.
	 *
	 * @return string
	 */
	public function get_vault_dir() {
		$upload_dir = wp_upload_dir();
		$vault_dir  = trailingslashit( $upload_dir['basedir'] ) . 'sentinelwp-quarantine';
		return $vault_dir;
	}

	/**
	 * Ensure the quarantine vault exists and is securely locked down.
	 *
	/**
	 * Get WP_Filesystem instance safely.
	 *
	 * @return \WP_Filesystem_Base|null
	 */
	private function get_filesystem() {
		global $wp_filesystem;
		if ( empty( $wp_filesystem ) ) {
			if ( ! function_exists( 'WP_Filesystem' ) && file_exists( ABSPATH . 'wp-admin/includes/file.php' ) ) {
				require_once ABSPATH . 'wp-admin/includes/file.php';
			}
			if ( function_exists( 'WP_Filesystem' ) ) {
				WP_Filesystem();
			}
		}
		return $wp_filesystem;
	}

	public function init_vault() {
		$vault_dir = $this->get_vault_dir();

		if ( ! file_exists( $vault_dir ) ) {
			wp_mkdir_p( $vault_dir );
		}

		if ( ! is_dir( $vault_dir ) || ! is_writable( $vault_dir ) ) {
			return false;
		}

		$fs = $this->get_filesystem();

		// 1. Write .htaccess to block direct HTTP access
		$htaccess_file = trailingslashit( $vault_dir ) . '.htaccess';
		if ( ! file_exists( $htaccess_file ) ) {
			$htaccess_content = "# SentinelWP Quarantine Vault - Deny All Access\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n";
			if ( $fs ) {
				$fs->put_contents( $htaccess_file, $htaccess_content, FS_CHMOD_FILE );
			} else {
				@file_put_contents( $htaccess_file, $htaccess_content );
			}
		}

		// 2. Write index.php to prevent directory listing
		$index_file = trailingslashit( $vault_dir ) . 'index.php';
		if ( ! file_exists( $index_file ) ) {
			$index_content = "<?php\n// Silence is golden.\nexit;\n";
			if ( $fs ) {
				$fs->put_contents( $index_file, $index_content, FS_CHMOD_FILE );
			} else {
				@file_put_contents( $index_file, $index_content );
			}
		}

		return true;
	}

	/**
	 * Quarantine a file using a Durable Two-Phase Commit:
	 * Phase 1: Copy to vault -> Verify SHA-256 Checksum -> Commit DB metadata.
	 * Phase 2: Unlink original only after Phase 1 is durably confirmed.
	 *
	 * @param int         $finding_id Finding ID in sentinelwp_findings table.
	 * @param string|null $file_path  Optional explicit file path.
	 * @return array Result array with success status, message, and quarantine_id.
	 */
	public function quarantine_file( $finding_id, $file_path = null ) {
		global $wpdb;

		if ( ! $this->init_vault() ) {
			return array(
				'success' => false,
				'message' => __( 'Unable to initialize quarantine vault directory (check filesystem permissions).', 'sentinelwp-security' ),
			);
		}

		$findings_table   = $wpdb->prefix . 'sentinelwp_findings';
		$quarantine_table = $wpdb->prefix . 'sentinelwp_quarantine';

		// Resolve file path from finding if not explicitly provided
		if ( empty( $file_path ) && $finding_id ) {
			$finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$findings_table} WHERE id = %d", $finding_id ) );
			if ( ! $finding ) {
				return array(
					'success' => false,
					'message' => __( 'Security finding not found.', 'sentinelwp-security' ),
				);
			}

			$file_path = $this->extract_path_from_finding( $finding );
		}

		// 1. Adversarial Path Validation (Anti-Path Traversal / Anti-Symlink)
		$validation_result = $this->validate_safe_path( $file_path );
		if ( ! $validation_result['safe'] ) {
			return array(
				'success' => false,
				'message' => $validation_result['error'],
			);
		}

		$canonical_path = $validation_result['canonical_path'];

		if ( ! file_exists( $canonical_path ) ) {
			return array(
				'success' => false,
				'message' => sprintf( __( 'File not found on filesystem: %s', 'sentinelwp-security' ), esc_html( (string) $file_path ) ),
			);
		}

		// 2. Prevent quarantining protected system files
		if ( $this->is_protected_system_file( $canonical_path ) ) {
			return array(
				'success' => false,
				'message' => __( 'Action blocked: Protected system file cannot be quarantined.', 'sentinelwp-security' ),
			);
		}

		$fs = $this->get_filesystem();
		$file_content = $fs ? $fs->get_contents( $canonical_path ) : @file_get_contents( $canonical_path );
		if ( false === $file_content || null === $file_content ) {
			return array(
				'success' => false,
				'message' => __( 'Failed to read source file for quarantine.', 'sentinelwp-security' ),
			);
		}

		$file_hash   = hash( 'sha256', (string) $file_content );
		$file_size   = filesize( $canonical_path );
		$perms       = substr( sprintf( '%o', fileperms( $canonical_path ) ), -4 );
		$unique_code = wp_generate_password( 16, false );
		$vault_name  = sanitize_file_name( basename( $canonical_path ) ) . '.' . $unique_code . '.quarantine';
		$vault_dest  = trailingslashit( $this->get_vault_dir() ) . $vault_name;

		// --- PHASE 1: Durable Copy & Checksum Verification ---
		$copied = $fs ? $fs->copy( $canonical_path, $vault_dest, true ) : @copy( $canonical_path, $vault_dest );
		if ( ! $copied || ! file_exists( $vault_dest ) ) {
			return array(
				'success' => false,
				'message' => __( 'Failed to write file into quarantine vault (possible disk full or permission error).', 'sentinelwp-security' ),
			);
		}

		$vault_content = $fs ? $fs->get_contents( $vault_dest ) : @file_get_contents( $vault_dest );
		if ( hash( 'sha256', (string) $vault_content ) !== $file_hash ) {
			if ( $fs ) {
				$fs->delete( $vault_dest );
			} else {
				@unlink( $vault_dest );
			}
			return array(
				'success' => false,
				'message' => __( 'Quarantine aborted: Checksum verification failed between source and vault artifact.', 'sentinelwp-security' ),
			);
		}

		// Commit metadata to database
		$now = current_time( 'mysql' );
		$db_ok = $wpdb->insert(
			$quarantine_table,
			array(
				'finding_id'          => (int) $finding_id,
				'original_path'       => $canonical_path,
				'quarantine_filename' => $vault_name,
				'file_hash'           => $file_hash,
				'file_size'           => (int) $file_size,
				'permissions'         => $perms,
				'status'              => 'quarantined',
				'created_at'          => $now,
			),
			array( '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
		);

		if ( ! $db_ok || empty( $wpdb->insert_id ) ) {
			if ( $fs ) {
				$fs->delete( $vault_dest );
			} else {
				@unlink( $vault_dest );
			}
			return array(
				'success' => false,
				'message' => __( 'Quarantine aborted: Failed to commit metadata record to database. Original file preserved.', 'sentinelwp-security' ),
			);
		}

		$quarantine_id = $wpdb->insert_id;

		// --- PHASE 2: Safe Unlink of Original File ---
		if ( $fs ) {
			$fs->delete( $canonical_path );
		} else {
			@unlink( $canonical_path );
		}

		if ( $finding_id ) {
			$wpdb->update(
				$findings_table,
				array(
					'status'     => 'quarantined',
					'updated_at' => $now,
				),
				array( 'id' => (int) $finding_id ),
				array( '%s', '%s' ),
				array( '%d' )
			);
		}

		return array(
			'success'       => true,
			'quarantine_id' => $quarantine_id,
			'message'       => __( 'File securely quarantined. State captured for 1-click rollback.', 'sentinelwp-security' ),
		);
	}

	/**
	 * Restore a quarantined file back to its exact original location and permissions.
	 * Preserves vault file if destination is unwritable or restore fails.
	 *
	 * @param int $quarantine_id Quarantine record ID.
	 * @return array Result array.
	 */
	public function restore_quarantine( $quarantine_id ) {
		global $wpdb;

		$quarantine_table = $wpdb->prefix . 'sentinelwp_quarantine';
		$findings_table   = $wpdb->prefix . 'sentinelwp_findings';

		$record = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$quarantine_table} WHERE id = %d", $quarantine_id ) );
		if ( ! $record ) {
			return array(
				'success' => false,
				'message' => __( 'Quarantine record not found.', 'sentinelwp-security' ),
			);
		}

		if ( 'quarantined' !== $record->status ) {
			return array(
				'success' => false,
				'message' => sprintf( __( 'File is not in quarantined state (current status: %s).', 'sentinelwp-security' ), $record->status ),
			);
		}

		// Validate restore path boundary
		$validation_result = $this->validate_safe_path( $record->original_path, true );
		if ( ! $validation_result['safe'] ) {
			return array(
				'success' => false,
				'message' => __( 'Action blocked: Restore path violates boundary policy.', 'sentinelwp-security' ),
			);
		}

		$fs = $this->get_filesystem();
		$vault_file = trailingslashit( $this->get_vault_dir() ) . $record->quarantine_filename;
		if ( ! file_exists( $vault_file ) ) {
			return array(
				'success' => false,
				'message' => __( 'Quarantined file missing from vault.', 'sentinelwp-security' ),
			);
		}

		// Verify vault file integrity against original hash
		$vault_content = $fs ? $fs->get_contents( $vault_file ) : @file_get_contents( $vault_file );
		if ( hash( 'sha256', (string) $vault_content ) !== $record->file_hash ) {
			return array(
				'success' => false,
				'message' => __( 'Quarantined file failed integrity hash check.', 'sentinelwp-security' ),
			);
		}

		// Ensure parent directory exists and is writable
		$orig_dir = dirname( $record->original_path );
		if ( ! file_exists( $orig_dir ) ) {
			wp_mkdir_p( $orig_dir );
		}

		if ( ! is_writable( $orig_dir ) ) {
			return array(
				'success' => false,
				'message' => sprintf( __( 'Restore destination directory is not writable (%s). Vault copy preserved.', 'sentinelwp-security' ), esc_html( $orig_dir ) ),
			);
		}

		// Restore file to original path
		$restored = $fs ? $fs->copy( $vault_file, $record->original_path, true ) : @copy( $vault_file, $record->original_path );
		if ( ! $restored || ! file_exists( $record->original_path ) ) {
			return array(
				'success' => false,
				'message' => __( 'Failed to restore file to original path (check filesystem permissions). Vault copy preserved.', 'sentinelwp-security' ),
			);
		}

		// Restore permissions
		if ( ! empty( $record->permissions ) ) {
			if ( $fs ) {
				$fs->chmod( $record->original_path, octdec( $record->permissions ) );
			} else {
				@chmod( $record->original_path, octdec( $record->permissions ) );
			}
		}

		// Remove from vault only after successful restore
		if ( $fs ) {
			$fs->delete( $vault_file );
		} else {
			@unlink( $vault_file );
		}

		// Update quarantine record
		$now = current_time( 'mysql' );
		$wpdb->update(
			$quarantine_table,
			array(
				'status'      => 'restored',
				'restored_at' => $now,
			),
			array( 'id' => (int) $quarantine_id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		// Update finding status
		if ( $record->finding_id ) {
			$wpdb->update(
				$findings_table,
				array(
					'status'     => 'resolved',
					'updated_at' => $now,
				),
				array( 'id' => (int) $record->finding_id ),
				array( '%s', '%s' ),
				array( '%d' )
			);
		}

		return array(
			'success' => true,
			'message' => __( 'File successfully restored to original location with original permissions.', 'sentinelwp-security' ),
		);
	}

	/**
	 * Permanently purge a quarantined file from the vault.
	 *
	 * @param int $quarantine_id Quarantine record ID.
	 * @return array Result array.
	 */
	public function purge_quarantine( $quarantine_id ) {
		global $wpdb;

		$quarantine_table = $wpdb->prefix . 'sentinelwp_quarantine';
		$record = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$quarantine_table} WHERE id = %d", $quarantine_id ) );

		if ( ! $record ) {
			return array(
				'success' => false,
				'message' => __( 'Quarantine record not found.', 'sentinelwp-security' ),
			);
		}

		$fs = $this->get_filesystem();
		$vault_file = trailingslashit( $this->get_vault_dir() ) . $record->quarantine_filename;
		if ( file_exists( $vault_file ) ) {
			if ( $fs ) {
				$fs->delete( $vault_file );
			} else {
				@unlink( $vault_file );
			}
		}

		$wpdb->update(
			$quarantine_table,
			array( 'status' => 'deleted' ),
			array( 'id' => (int) $quarantine_id ),
			array( '%s' ),
			array( '%d' )
		);

		return array(
			'success' => true,
			'message' => __( 'Quarantined file permanently purged.', 'sentinelwp-security' ),
		);
	}

	/**
	 * Adversarial Path Validation: Protects against path traversal and symlink hijacking.
	 *
	 * @param string $path
	 * @param bool   $is_restore
	 * @return array
	 */
	public function validate_safe_path( $path, $is_restore = false ) {
		if ( empty( $path ) || ! is_string( $path ) ) {
			return array( 'safe' => false, 'error' => __( 'Invalid or empty file path.', 'sentinelwp-security' ) );
		}

		// 1. Check for null byte injection
		if ( strpos( $path, "\0" ) !== false ) {
			return array( 'safe' => false, 'error' => __( 'Malicious null byte detected in file path.', 'sentinelwp-security' ) );
		}

		// 2. Normalize separators
		$normalized = wp_normalize_path( $path );

		// 3. Reject directory traversal sequences
		if ( strpos( $normalized, '../' ) !== false || strpos( $normalized, '..\\' ) !== false ) {
			return array( 'safe' => false, 'error' => __( 'Directory traversal sequence (../) detected in path.', 'sentinelwp-security' ) );
		}

		// 4. Resolve canonical realpath
		$abspath     = wp_normalize_path( strtolower( untrailingslashit( ABSPATH ) ) );
		$content_dir = wp_normalize_path( strtolower( untrailingslashit( WP_CONTENT_DIR ) ) );
		$norm_lower  = strtolower( $normalized );

		if ( ! $is_restore && file_exists( $normalized ) ) {
			$real = wp_normalize_path( realpath( $normalized ) );
			if ( false === $real ) {
				return array( 'safe' => false, 'error' => __( 'Unable to resolve canonical file path.', 'sentinelwp-security' ) );
			}

			$real_lower = strtolower( $real );

			// Reject symlinks pointing outside webroot
			if ( is_link( $normalized ) ) {
				if ( strpos( $real_lower, $abspath ) !== 0 && strpos( $real_lower, $content_dir ) !== 0 ) {
					return array( 'safe' => false, 'error' => __( 'Action blocked: Symlink points outside WordPress root.', 'sentinelwp-security' ) );
				}
			}

			$canonical       = $real;
			$canonical_lower = $real_lower;
		} else {
			$canonical       = $normalized;
			$canonical_lower = $norm_lower;
		}

		// 5. Enforce boundary containment inside ABSPATH or WP_CONTENT_DIR
		if ( strpos( $canonical_lower, $abspath ) !== 0 && strpos( $canonical_lower, $content_dir ) !== 0 ) {
			return array( 'safe' => false, 'error' => __( 'Action blocked: Path is outside allowed WordPress directory boundary.', 'sentinelwp-security' ) );
		}

		return array(
			'safe'           => true,
			'canonical_path' => $canonical,
		);
	}

	/**
	 * Extract file path from finding object.
	 *
	 * @param object $finding
	 * @return string|null
	 */
	private function extract_path_from_finding( $finding ) {
		if ( ! empty( $finding->title ) && file_exists( $finding->title ) ) {
			return $finding->title;
		}

		if ( ! empty( $finding->details ) ) {
			$details = json_decode( $finding->details, true );
			if ( is_array( $details ) ) {
				if ( ! empty( $details['file'] ) ) {
					return $details['file'];
				}
				if ( ! empty( $details['path'] ) ) {
					return $details['path'];
				}
			}
		}

		return null;
	}

	/**
	 * Check if file is a protected WordPress core system file.
	 *
	 * @param string $path
	 * @return bool
	 */
	public function is_protected_system_file( $path ) {
		$normalized = wp_normalize_path( strtolower( trim( $path ) ) );
		$basename   = basename( $normalized );

		$protected_basenames = array(
			'wp-config.php',
			'.htaccess',
			'index.php',
			'wp-settings.php',
			'wp-load.php',
			'wp-blog-header.php',
			'wp-cron.php',
			'xmlrpc.php',
		);

		if ( in_array( $basename, $protected_basenames, true ) ) {
			return true;
		}

		// Disallow any files directly under wp-admin or wp-includes
		$abspath     = wp_normalize_path( strtolower( untrailingslashit( ABSPATH ) ) );
		$content_dir = wp_normalize_path( strtolower( untrailingslashit( WP_CONTENT_DIR ) ) );
		if ( strpos( $normalized, $abspath . '/wp-admin/' ) === 0 || 
		     strpos( $normalized, $abspath . '/wp-includes/' ) === 0 || 
		     strpos( $normalized, $abspath . '/wp-admin' ) === 0 || 
		     strpos( $normalized, $abspath . '/wp-includes' ) === 0 ) {
			return true;
		}

				// Disallow quarantining our own plugin files (excluding uploads)
		$our_plugin_dir = wp_normalize_path( strtolower( untrailingslashit( plugin_dir_path( dirname( __FILE__ ) ) ) ) );
		if ( strpos( $normalized, $our_plugin_dir . '/' ) === 0 && strpos( $normalized, '/uploads/' ) === false ) {
			return true;
		}

		// Disallow quarantining main active plugin files
		$active_plugins = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active_plugins = array_merge( $active_plugins, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		
		foreach ( $active_plugins as $plugin_file ) {
			$plugin_path = wp_normalize_path( strtolower( WP_PLUGIN_DIR . '/' . $plugin_file ) );
			if ( $normalized === $plugin_path ) {
				return true;
			}
		}

		// Disallow quarantining active theme's functions.php and style.css
		$theme_dir = wp_normalize_path( strtolower( get_stylesheet_directory() ) );
		if ( $normalized === $theme_dir . '/functions.php' || $normalized === $theme_dir . '/style.css' ) {
			return true;
		}

		return false;
	}
}
