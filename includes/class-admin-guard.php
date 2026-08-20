<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SentinelWP_Admin_Guard class.
 * 
 * Monitors for unauthorized administrator account creation, privilege escalation,
 * and stealth/hidden administrator accounts in the database that bypass standard WP queries.
 */
class SentinelWP_Admin_Guard {

	/**
	 * Singleton instance.
	 *
	 * @var SentinelWP_Admin_Guard|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return SentinelWP_Admin_Guard
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor. Registers real-time hooks and scan actions.
	 */
	private function __construct() {
		// Real-time hooks for admin user creation and role changes
		add_action( 'user_register', array( $this, 'on_user_register' ), 10, 1 );
		add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 10, 3 );
		add_action( 'add_user_role', array( $this, 'on_add_user_role' ), 10, 2 );

		// Scheduled scan integration
		add_action( 'sentinelwp_daily_scan', array( $this, 'scan_for_hidden_admins' ), 15 );
	}

	/**
	 * Detects when a newly registered user is given administrator privileges.
	 *
	 * @param int $user_id Newly created user ID.
	 */
	public function on_user_register( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		if ( in_array( 'administrator', (array) $user->roles, true ) || user_can( $user_id, 'manage_options' ) ) {
			$this->analyze_admin_creation( $user, 'registration' );
		}
	}

	/**
	 * Detects when an existing user's role is set to administrator.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $role      New role.
	 * @param array  $old_roles Previous roles.
	 */
	public function on_set_user_role( $user_id, $role, $old_roles ) {
		if ( 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true ) ) {
			$user = get_userdata( $user_id );
			if ( $user ) {
				$this->analyze_admin_creation( $user, 'role_change' );
			}
		}
	}

	/**
	 * Detects when an administrator role is added to a user.
	 *
	 * @param int    $user_id User ID.
	 * @param string $role    Added role.
	 */
	public function on_add_user_role( $user_id, $role ) {
		if ( 'administrator' === $role ) {
			$user = get_userdata( $user_id );
			if ( $user ) {
				$this->analyze_admin_creation( $user, 'role_addition' );
			}
		}
	}

	/**
	 * Analyzes the context of an administrator creation or elevation.
	 *
	 * @param WP_User $user   User object.
	 * @param string  $action Type of action ('registration', 'role_change', 'role_addition').
	 */
	private function analyze_admin_creation( $user, $action ) {
		$current_user_id = get_current_user_id();
		$is_cli          = defined( 'WP_CLI' ) && WP_CLI;
		$is_valid_admin  = ( $current_user_id && current_user_can( 'create_users' ) ) || $is_cli;

		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';

		if ( ! $is_valid_admin ) {
			// CRITICAL: Admin created or elevated without a logged-in administrator (e.g. exploit / backdoor)
			$this->record_finding(
				'unauthorized_admin_creation',
				'critical',
				'admin-guard-realtime',
				sprintf(
					/* translators: 1: username, 2: action type */
					__( 'CRITICAL: Unauthorized administrator privilege escalation for user "%1$s" via %2$s', 'sentinelwp-security' ),
					$user->user_login,
					$action
				),
				wp_json_encode(
					array(
						'user_id'         => $user->ID,
						'user_login'      => $user->user_login,
						'user_email'      => $user->user_email,
						'action'          => $action,
						'acting_user_id'  => $current_user_id,
						'client_ip'       => $ip,
						'request_uri'     => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
						'detected_at'     => current_time( 'mysql' ),
					)
				)
			);
		} else {
			// Legitimate or authorized admin role grant — record as high-priority audit event
			$actor = get_userdata( $current_user_id );
			$actor_login = $actor ? $actor->user_login : ( $is_cli ? 'WP-CLI' : 'System' );

			$this->record_finding(
				'admin_role_granted',
				'high',
				'admin-guard-realtime',
				sprintf(
					/* translators: 1: username, 2: actor username */
					__( 'Administrator role assigned to user "%1$s" by "%2$s"', 'sentinelwp-security' ),
					$user->user_login,
					$actor_login
				),
				wp_json_encode(
					array(
						'user_id'        => $user->ID,
						'user_login'     => $user->user_login,
						'user_email'     => $user->user_email,
						'action'         => $action,
						'granted_by'     => $actor_login,
						'client_ip'      => $ip,
						'detected_at'    => current_time( 'mysql' ),
					)
				)
			);
		}
	}

	/**
	 * Deep scan for hidden or stealth administrator accounts directly in the database.
	 *
	 * Attackers often hide admin accounts from the standard WordPress UI/API by hooking
	 * filters such as `pre_get_users`, modifying `wp_capabilities` directly in raw SQL,
	 * or creating orphaned entries.
	 */
	public function scan_for_hidden_admins() {
		global $wpdb;

		$cap_key = $wpdb->get_blog_prefix() . 'capabilities';
		$lvl_key = $wpdb->get_blog_prefix() . 'user_level';

		// 1. Direct Raw Database Query (bypasses all WP filters and plugins)
		// Find all user IDs in the database that hold administrator capabilities or level 10
		$raw_db_admins = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DISTINCT u.ID, u.user_login, u.user_email, u.user_registered, m1.meta_value as capabilities, m2.meta_value as user_level
				FROM {$wpdb->users} u
				LEFT JOIN {$wpdb->usermeta} m1 ON u.ID = m1.user_id AND m1.meta_key = %s
				LEFT JOIN {$wpdb->usermeta} m2 ON u.ID = m2.user_id AND m2.meta_key = %s
				WHERE (m1.meta_value LIKE %s OR CAST(m2.meta_value AS UNSIGNED) >= 8)",
				$cap_key,
				$lvl_key,
				'%administrator%'
			)
		);

		// 2. Query administrators using standard WordPress API
		$wp_api_admin_users = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
			)
		);
		$wp_api_admin_ids = array_map( 'intval', (array) $wp_api_admin_users );

		// 3. Compare DB users vs WP API users to detect hidden/stealth accounts
		if ( ! empty( $raw_db_admins ) ) {
			foreach ( $raw_db_admins as $db_admin ) {
				$admin_id = (int) $db_admin->ID;

				// Check if this user is hidden from standard get_users() query
				if ( ! in_array( $admin_id, $wp_api_admin_ids, true ) ) {
					$this->record_finding(
						'hidden_admin_detected',
						'critical',
						'database-audit',
						sprintf(
							/* translators: 1: username, 2: user ID */
							__( 'CRITICAL: Hidden administrator account "%1$s" (ID: %2$d) detected in database but hidden from WordPress user list!', 'sentinelwp-security' ),
							$db_admin->user_login,
							$admin_id
						),
						wp_json_encode(
							array(
								'user_id'         => $admin_id,
								'user_login'      => $db_admin->user_login,
								'user_email'      => $db_admin->user_email,
								'user_registered' => $db_admin->user_registered,
								'capabilities'    => $db_admin->capabilities,
								'user_level'      => $db_admin->user_level,
								'reason'          => 'Account has administrator capabilities in database but is filtered or excluded from standard get_users() query.',
							)
						)
					);
				}

				// Check for suspicious administrator usernames (common stealth backdoor names)
				$suspicious_names = array(
					'root', 'system', 'system_admin', 'backup', 'backup_admin', 'wp_admin', 
					'support', 'wp_support', 'service', 'test', 'tester', '1', 'administrator_backup'
				);
				if ( in_array( strtolower( $db_admin->user_login ), $suspicious_names, true ) ) {
					$this->record_finding(
						'suspicious_admin_username',
						'high',
						'database-audit',
						sprintf(
							/* translators: %s: username */
							__( 'Suspicious administrator username "%s" found in database.', 'sentinelwp-security' ),
							$db_admin->user_login
						),
						wp_json_encode(
							array(
								'user_id'    => $admin_id,
								'user_login' => $db_admin->user_login,
								'user_email' => $db_admin->user_email,
							)
						)
					);
				}
			}
		}

		// 4. Scan for Orphaned Administrator Capabilities (meta pointing to non-existent users)
		$orphaned_caps = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT m.user_id, m.meta_value 
				FROM {$wpdb->usermeta} m 
				LEFT JOIN {$wpdb->users} u ON m.user_id = u.ID 
				WHERE m.meta_key = %s 
				AND m.meta_value LIKE %s 
				AND u.ID IS NULL",
				$cap_key,
				'%administrator%'
			)
		);

		if ( ! empty( $orphaned_caps ) ) {
			foreach ( $orphaned_caps as $orphan ) {
				$this->record_finding(
					'orphaned_admin_meta',
					'high',
					'database-audit',
					sprintf(
						/* translators: %d: orphaned user ID */
						__( 'Orphaned administrator capability found in database for deleted or ghost user ID %d.', 'sentinelwp-security' ),
						(int) $orphan->user_id
					),
					wp_json_encode(
						array(
							'orphaned_user_id' => (int) $orphan->user_id,
							'meta_value'       => $orphan->meta_value,
						)
					)
				);
			}
		}

		// 5. Audit global filters that might be hiding users from admin list table
		global $wp_filter;
		$user_filter_hooks = array( 'pre_get_users', 'users_list_table_query_args', 'views_users' );
		foreach ( $user_filter_hooks as $hook_name ) {
			if ( isset( $wp_filter[ $hook_name ] ) && ! empty( $wp_filter[ $hook_name ]->callbacks ) ) {
				foreach ( $wp_filter[ $hook_name ]->callbacks as $priority => $callbacks ) {
					foreach ( $callbacks as $cb_name => $cb_data ) {
						// Look for suspicious anonymous closures or callbacks from outside core
						if ( is_string( $cb_name ) && ( strpos( $cb_name, 'hide' ) !== false || strpos( $cb_name, 'stealth' ) !== false ) ) {
							$this->record_finding(
								'suspicious_user_filter',
								'high',
								'runtime-audit',
								sprintf(
									/* translators: 1: hook name, 2: callback name */
									__( 'Suspicious filter callback "%1$s" attached to hook "%2$s" that may hide users.', 'sentinelwp-security' ),
									$cb_name,
									$hook_name
								),
								wp_json_encode(
									array(
										'hook'     => $hook_name,
										'callback' => $cb_name,
										'priority' => $priority,
									)
								)
							);
						}
					}
				}
			}
		}
	}

	/**
	 * Records a security finding with de-duplication.
	 *
	 * @param string $type     Finding type identifier.
	 * @param string $severity Severity ('critical', 'high', 'medium', 'low').
	 * @param string $source   Detection source.
	 * @param string $title    Finding title.
	 * @param string $details  JSON details string.
	 * @return int|false Finding ID or false if duplicate.
	 */
	private function record_finding( $type, $severity, $source, $title, $details, $confidence = 'confirmed', $detector = 'admin_guard', $remediation = '', $fp_risk = 'low' ) {
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
