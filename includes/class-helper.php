<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SentinelWP_Helper class.
 *
 * Provides shared utility methods: proxy-aware IP resolution,
 * cryptographic hashing, HPOS detection, and safe sanitizers.
 */
class SentinelWP_Helper {

	/**
	 * Get the real client IP address, safely handling trusted reverse proxies.
	 *
	 * @return string Validated IP address or fallback.
	 */
	public static function get_client_ip() {
		$allow_proxy_headers = (bool) get_option( 'sentinelwp_behind_proxy', false );

		if ( $allow_proxy_headers ) {
			// 1. Cloudflare header
			if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
				$raw_cf = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
				if ( strlen( $raw_cf ) <= 64 && strpos( $raw_cf, "\0" ) === false ) {
					if ( self::is_valid_ip( $raw_cf ) ) {
						return $raw_cf;
					}
				}
			}

			// 2. Standard X-Forwarded-For (leftmost public IP)
			if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				$raw_xff = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
				// Length & Character Guard: reject poisoned headers containing injection syntax
				if ( strlen( $raw_xff ) <= 512 && 
				     strpos( $raw_xff, "\0" ) === false && 
				     strpos( $raw_xff, ';' ) === false && 
				     strpos( $raw_xff, "'" ) === false && 
				     strpos( $raw_xff, '"' ) === false && 
				     strpos( $raw_xff, '<' ) === false && 
				     strpos( $raw_xff, '>' ) === false ) {
					$ips = explode( ',', $raw_xff );
					foreach ( $ips as $candidate ) {
						$candidate = trim( $candidate );
						if ( self::is_valid_ip( $candidate ) ) {
							return $candidate;
						}
					}
				}
			}

			// 3. X-Real-IP
			if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
				$raw_real = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
				if ( strlen( $raw_real ) <= 64 && strpos( $raw_real, "\0" ) === false ) {
					if ( self::is_valid_ip( $raw_real ) ) {
						return $raw_real;
					}
				}
			}
		}

		// Fallback to REMOTE_ADDR
		$remote_addr = ! empty( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( self::is_valid_ip( $remote_addr ) ) {
			return $remote_addr;
		}

		return '127.0.0.1';
	}

	/**
	 * Validate that a string is a valid IPv4 or IPv6 address.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_valid_ip( $ip ) {
		return false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Get the SHA-256 hash of a client IP address.
	 *
	 * @param string|null $ip Optional explicit IP. If omitted, uses get_client_ip().
	 * @return string SHA-256 hash string.
	 */
	public static function get_ip_hash( $ip = null ) {
		if ( null === $ip ) {
			$ip = self::get_client_ip();
		}
		return hash( 'sha256', (string) $ip );
	}

	/**
	 * Check if WooCommerce High-Performance Order Storage (HPOS) is active.
	 *
	 * @return bool
	 */
	public static function is_hpos_enabled() {
		$enabled = false;
		if ( class_exists( 'Automattic\WooCommerce\Utilities\OrderUtil' ) && method_exists( 'Automattic\WooCommerce\Utilities\OrderUtil', 'custom_orders_table_usage_is_enabled' ) ) {
			$enabled = Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled();
		}
		return (bool) apply_filters( 'sentinelwp_is_hpos_enabled', $enabled );
	}

	/**
	 * Get the WordPress root filesystem directory safely using WordPress core APIs.
	 *
	 * @return string Normalized root directory path with trailing slash.
	 */
	public static function get_home_directory() {
		$home = function_exists( 'get_home_path' ) ? get_home_path() : ( defined( 'ABSPATH' ) ? ABSPATH : '' );
		return trailingslashit( wp_normalize_path( $home ) );
	}

	/**
	 * Safely resolve a path relative to the WordPress root directory for display.
	 * Avoids direct string replacement on ABSPATH or WP_CONTENT_DIR.
	 *
	 * @param string $path Absolute or partial filesystem path.
	 * @return string Relative path or base filename.
	 */
	public static function get_relative_path( $path ) {
		if ( empty( $path ) || ! is_string( $path ) ) {
			return '';
		}

		$norm_path = wp_normalize_path( $path );
		$home_dir  = untrailingslashit( self::get_home_directory() );

		if ( ! empty( $home_dir ) && strpos( $norm_path, $home_dir ) === 0 ) {
			return ltrim( substr( $norm_path, strlen( $home_dir ) ), '/' );
		}

		return basename( $norm_path );
	}

	/**
	 * Get the WordPress content directory path safely.
	 *
	 * @return string Normalized content directory path without trailing slash.
	 */
	public static function get_content_directory() {
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			return untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
		}
		return untrailingslashit( self::get_home_directory() ) . '/wp-content';
	}

	/**
	 * Get the WordPress plugins directory path safely.
	 *
	 * @return string Normalized plugins directory path without trailing slash.
	 */
	public static function get_plugins_directory() {
		if ( defined( 'WP_PLUGIN_DIR' ) ) {
			return untrailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) );
		}
		return self::get_content_directory() . '/plugins';
	}
}
