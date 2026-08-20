<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Deterministic hardening features. None of these depend on any API key
 * or AI call — they're the always-available free baseline.
 */
class SentinelWP_Hardening {

	private static $instance = null;
	private $options;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->options = get_option( 'sentinelwp_hardening', array() );
		$this->init();
	}

	private function enabled( $key ) {
		return ! empty( $this->options[ $key ] );
	}

	private function init() {
		if ( $this->enabled( 'disable_file_edit' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			// Can't force a constant at runtime that late plugins already
			// checked, but we can still block the theme/plugin editor
			// capability directly as a second line of defense.
			add_filter( 'map_meta_cap', array( $this, 'block_file_edit_cap' ), 10, 2 );
		}

		if ( $this->enabled( 'hide_wp_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', array( $this, 'strip_version_query' ), 9999 );
			add_filter( 'script_loader_src', array( $this, 'strip_version_query' ), 9999 );
		}

		if ( $this->enabled( 'disable_xmlrpc' ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
			add_filter( 'xmlrpc_methods', array( $this, 'strip_pingback_methods' ) );
		}

		if ( $this->enabled( 'disable_user_enum' ) ) {
			add_action( 'init', array( $this, 'block_author_scan' ) );
			add_filter( 'rest_endpoints', array( $this, 'restrict_users_rest_endpoint' ) );
		}

		if ( $this->enabled( 'login_attempt_limit' ) ) {
			add_action( 'wp_login_failed', array( $this, 'record_failed_login' ) );
			add_filter( 'authenticate', array( $this, 'block_if_locked_out' ), 30, 1 );
		}

		if ( $this->enabled( 'security_headers' ) ) {
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
		}
	}

	public function block_file_edit_cap( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_plugins', 'edit_themes', 'edit_files' ), true ) ) {
			$caps[] = 'do_not_allow';
		}
		return $caps;
	}

	public function strip_version_query( $src ) {
		if ( strpos( $src, 'ver=' . get_bloginfo( 'version' ) ) !== false ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	public function strip_pingback_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * Blocks the classic ?author=1 enumeration probe on the front end
	 * without touching legitimate author archive pages that already
	 * have pretty permalinks.
	 */
	public function block_author_scan() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( is_admin() || ! isset( $_GET['author'] ) ) {
			return;
		}
		if ( ! is_user_logged_in() ) {
			wp_safe_redirect( home_url( '/', 'relative' ), 302 );
			exit;
		}
	}

	public function restrict_users_rest_endpoint( $endpoints ) {
		if ( isset( $endpoints['/wp/v2/users'] ) && ! is_user_logged_in() ) {
			unset( $endpoints['/wp/v2/users'] );
		}
		return $endpoints;
	}

	/**
	 * Simple, self-contained login throttling using transients — no
	 * custom table needed for this. Locks an IP+username pair out for
	 * 15 minutes after 5 failed attempts within 10 minutes.
	 */
	public function record_failed_login( $username ) {
		$key   = 'sentinelwp_lf_' . md5( $this->client_ip() . '|' . $username );
		$count = (int) get_transient( $key );
		set_transient( $key, $count + 1, 10 * MINUTE_IN_SECONDS );

		if ( $count + 1 >= 5 ) {
			set_transient( 'sentinelwp_lock_' . md5( $this->client_ip() . '|' . $username ), 1, 15 * MINUTE_IN_SECONDS );
		}
	}

	public function block_if_locked_out( $user ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$username = isset( $_POST['log'] ) ? sanitize_user( wp_unslash( $_POST['log'] ) ) : '';
		if ( '' === $username ) {
			return $user;
		}

		$locked = get_transient( 'sentinelwp_lock_' . md5( $this->client_ip() . '|' . $username ) );
		if ( $locked ) {
			return new WP_Error(
				'sentinelwp_locked_out',
				__( 'Too many failed login attempts. Please try again in 15 minutes.', 'sentinelwp-security' )
			);
		}
		return $user;
	}

	private function client_ip() {
		// Deliberately does not trust X-Forwarded-For unless the site is
		// known to sit behind a proxy — spoofable header, would let an
		// attacker frame someone else's IP into a lockout.
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0.0.0.0';
	}

	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		// Deliberately no hardcoded CSP here — a wrong CSP breaks sites
		// silently, which is worse than not having one. CSP is a Pro
		// feature with a guided builder instead of a blind default.
	}
}
