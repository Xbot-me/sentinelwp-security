<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Normalized result of a vulnerability/version check.
 */
class SentinelWP_Vuln_Result {
	public $has_vulnerability = false;
	public $is_outdated       = false;
	public $current_version   = '';
	public $latest_version    = '';
	public $vulnerabilities   = array(); // array of ['title','cve','severity','fixed_in']
	public $source            = '';
}

/**
 * Fetches version/vulnerability data from real, maintained sources.
 *
 * - WordPress.org Plugins/Themes Info API and Core Checksums API need no
 *   API key and have no meaningful rate limit for a single site's daily
 *   scan, so they're always available as the free baseline.
 * - Patchstack and WPScan are optional, key-gated, and cached hard to
 *   respect their rate limits (WPScan's free tier is 25 req/day).
 *
 * Every lookup is cached in a transient for 12 hours keyed by
 * type:slug:version so a daily cron scan of even a large site issues at
 * most one request per installed item per day.
 */
class SentinelWP_Vuln_DB {

	const CACHE_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * @param string $type    'plugin' | 'theme' | 'core'
	 * @param string $slug    plugin/theme slug (ignored for core)
	 * @param string $version currently installed version
	 * @return SentinelWP_Vuln_Result
	 */
	public function check( $type, $slug, $version ) {
		$cache_key = 'sentinelwp_vdb_' . md5( $type . '|' . $slug . '|' . $version );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return $cached;
		}

		$result = $this->check_wordpress_org( $type, $slug, $version );

		$source = get_option( 'sentinelwp_vuln_source', 'wordpress_org' );

		if ( 'patchstack' === $source && $this->has_key( 'patchstack' ) ) {
			$this->merge_vulnerabilities( $result, $this->check_patchstack( $type, $slug, $version ) );
		} elseif ( 'wpscan' === $source && $this->has_key( 'wpscan' ) ) {
			$this->merge_vulnerabilities( $result, $this->check_wpscan( $type, $slug, $version ) );
		}

		// Pro: cross-check both sources instead of just one.
		if ( SentinelWP_Freemium::can( 'dual_vuln_source' ) ) {
			if ( 'patchstack' !== $source && $this->has_key( 'patchstack' ) ) {
				$this->merge_vulnerabilities( $result, $this->check_patchstack( $type, $slug, $version ) );
			}
			if ( 'wpscan' !== $source && $this->has_key( 'wpscan' ) ) {
				$this->merge_vulnerabilities( $result, $this->check_wpscan( $type, $slug, $version ) );
			}
		}

		set_transient( $cache_key, $result, self::CACHE_TTL );
		return $result;
	}

	private function has_key( $which ) {
		$option = 'patchstack' === $which ? 'sentinelwp_patchstack_key' : 'sentinelwp_wpscan_key';
		return '' !== trim( (string) get_option( $option, '' ) );
	}

	private function merge_vulnerabilities( SentinelWP_Vuln_Result $result, SentinelWP_Vuln_Result $extra ) {
		if ( ! $extra ) {
			return;
		}
		$existing_cves   = array_filter( wp_list_pluck( $result->vulnerabilities, 'cve' ) );
		$existing_titles = array_filter( wp_list_pluck( $result->vulnerabilities, 'title' ) );

		foreach ( $extra->vulnerabilities as $vuln ) {
			// De-dupe by CVE id if present, otherwise by title.
			$cve   = ! empty( $vuln['cve'] ) ? $vuln['cve'] : '';
			$title = ! empty( $vuln['title'] ) ? $vuln['title'] : '';

			$is_duplicate = false;
			if ( ! empty( $cve ) && in_array( $cve, $existing_cves, true ) ) {
				$is_duplicate = true;
			} elseif ( empty( $cve ) && ! empty( $title ) && in_array( $title, $existing_titles, true ) ) {
				$is_duplicate = true;
			}

			if ( ! $is_duplicate ) {
				$result->vulnerabilities[] = $vuln;
				if ( ! empty( $cve ) ) {
					$existing_cves[] = $cve;
				}
				if ( ! empty( $title ) ) {
					$existing_titles[] = $title;
				}
			}
		}
		if ( $extra->has_vulnerability ) {
			$result->has_vulnerability = true;
		}
	}

	/**
	 * No-key baseline: are we simply out of date? This alone catches a
	 * large share of real-world compromises, since most WordPress hacks
	 * exploit a known, already-patched bug in an old plugin.
	 */
	private function check_wordpress_org( $type, $slug, $version ) {
		$result                  = new SentinelWP_Vuln_Result();
		$result->current_version = $version;
		$result->source          = 'wordpress.org';

		if ( 'core' === $type ) {
			$latest = $this->get_cached_json(
				'sentinelwp_core_latest',
				'https://api.wordpress.org/core/version-check/1.7/',
				HOUR_IN_SECONDS * 6
			);
			if ( $latest && ! empty( $latest['offers'][0]['current'] ) ) {
				$result->latest_version = $latest['offers'][0]['current'];
			}
		} else {
			$action    = 'plugin' === $type ? 'plugin_information' : 'theme_information';
			$base      = 'plugin' === $type
				? 'https://api.wordpress.org/plugins/info/1.2/'
				: 'https://api.wordpress.org/themes/info/1.2/';
			$url       = add_query_arg(
				array(
					'action'        => $action,
					'request[slug]' => rawurlencode( $slug ),
				),
				$base
			);
			$info = $this->get_cached_json( 'sentinelwp_info_' . md5( $type . $slug ), $url, self::CACHE_TTL );
			if ( $info && ! empty( $info['version'] ) ) {
				$result->latest_version = $info['version'];
			}
		}

		if ( $result->latest_version && version_compare( $version, $result->latest_version, '<' ) ) {
			$result->is_outdated = true;
		}

		return $result;
	}

	private function check_patchstack( $type, $slug, $version ) {
		$result         = new SentinelWP_Vuln_Result();
		$result->source = 'patchstack';
		$key            = get_option( 'sentinelwp_patchstack_key', '' );

		$response = wp_remote_get(
			add_query_arg(
				array(
					'type' => $type,
					'slug' => rawurlencode( $slug ),
				),
				'https://api.patchstack.com/v1/vulnerability'
			),
			array(
				'timeout' => 10,
				'headers' => array( 'x-api-key' => $key ),
			)
		);

		return $this->parse_generic_vuln_response( $result, $response, $version, 'patchstack' );
	}

	private function check_wpscan( $type, $slug, $version ) {
		$result         = new SentinelWP_Vuln_Result();
		$result->source = 'wpscan';
		$key            = get_option( 'sentinelwp_wpscan_key', '' );

		$endpoint = 'core' === $type ? 'wordpresses' : ( 'plugin' === $type ? 'plugins' : 'themes' );
		$path     = 'core' === $type ? str_replace( '.', '', $version ) : $slug;

		$response = wp_remote_get(
			"https://wpscan.com/api/v3/{$endpoint}/" . rawurlencode( $path ),
			array(
				'timeout' => 10,
				'headers' => array( 'Authorization' => 'Token token=' . $key ),
			)
		);

		return $this->parse_wpscan_response( $result, $response, $version );
	}

	private function parse_generic_vuln_response( SentinelWP_Vuln_Result $result, $response, $version, $source ) {
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return $result; // fail closed to "no data", never fail open to "no vulnerabilities found".
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['vulnerabilities'] ) || ! is_array( $body['vulnerabilities'] ) ) {
			return $result;
		}

		foreach ( $body['vulnerabilities'] as $vuln ) {
			$fixed_in = isset( $vuln['fixed_in'] ) ? $vuln['fixed_in'] : '';
			$affects  = ( '' === $fixed_in ) || version_compare( $version, $fixed_in, '<' );
			if ( ! $affects ) {
				continue;
			}
			$result->has_vulnerability = true;
			$result->vulnerabilities[] = array(
				'title'    => isset( $vuln['title'] ) ? sanitize_text_field( $vuln['title'] ) : __( 'Unnamed vulnerability', 'sentinelguard-ecommerce-protection' ),
				'cve'      => isset( $vuln['cve'] ) ? sanitize_text_field( $vuln['cve'] ) : '',
				'severity' => isset( $vuln['severity'] ) ? sanitize_text_field( $vuln['severity'] ) : 'unknown',
				'fixed_in' => sanitize_text_field( $fixed_in ),
				'source'   => $source,
			);
		}

		return $result;
	}

	private function parse_wpscan_response( SentinelWP_Vuln_Result $result, $response, $version ) {
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return $result;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) ) {
			return $result;
		}

		// WPScan nests results under the slug/version key; take the first entry.
		$entry = reset( $body );
		if ( empty( $entry['vulnerabilities'] ) ) {
			return $result;
		}

		foreach ( $entry['vulnerabilities'] as $vuln ) {
			$fixed_in = isset( $vuln['fixed_in'] ) ? $vuln['fixed_in'] : '';
			$affects  = ( '' === $fixed_in ) || version_compare( $version, $fixed_in, '<' );
			if ( ! $affects ) {
				continue;
			}
			$cve = '';
			if ( ! empty( $vuln['references']['cve'][0] ) ) {
				$cve = 'CVE-' . sanitize_text_field( $vuln['references']['cve'][0] );
			}
			$result->has_vulnerability = true;
			$result->vulnerabilities[] = array(
				'title'    => isset( $vuln['title'] ) ? sanitize_text_field( $vuln['title'] ) : __( 'Unnamed vulnerability', 'sentinelguard-ecommerce-protection' ),
				'cve'      => $cve,
				'severity' => isset( $vuln['cvss']['rating'] ) ? sanitize_text_field( $vuln['cvss']['rating'] ) : 'unknown',
				'fixed_in' => sanitize_text_field( $fixed_in ),
				'source'   => 'wpscan',
			);
		}

		return $result;
	}

	/**
	 * GET + decode + cache helper for the no-key WordPress.org endpoints.
	 */
	private function get_cached_json( $cache_key, $url, $ttl ) {
		$cached = get_transient( $cache_key );
		if ( false !== $cached ) {
			return $cached;
		}

		$response = wp_remote_get( $url, array( 'timeout' => 10 ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			return false;
		}

		set_transient( $cache_key, $data, $ttl );
		return $data;
	}
}
