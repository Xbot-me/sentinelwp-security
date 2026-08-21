<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SentinelWP_Nulled_Detector {

	private static $instance = null;
	private $indicators = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	private function load_indicators() {
		if ( null !== $this->indicators ) {
			return $this->indicators;
		}

		$file = SENTINELWP_PATH . '/data/nulled-indicators.php';
		if ( file_exists( $file ) ) {
			$this->indicators = include $file;
		}

		if ( ! is_array( $this->indicators ) ) {
			$this->indicators = array(
				'malicious_files'         => array(),
				'nulled_domains'          => array(),
				'license_bypass_patterns' => array(),
			);
		}

		return $this->indicators;
	}

	private function record_finding( $type, $severity, $source, $title, $details, $confidence = 'confirmed', $detector = 'nulled_detector', $remediation = '', $fp_risk = 'low' ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'sentinelwp_findings';

		// De-duplicate check
		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table_name} WHERE type = %s AND title = %s AND status != 'resolved' LIMIT 1",
				$type,
				$title
			)
		);

		if ( $existing ) {
			$wpdb->update(
				$table_name,
				array( 'updated_at' => current_time( 'mysql' ) ),
				array( 'id' => $existing ),
				array( '%s' ),
				array( '%d' )
			);
			return false;
		}

		$data = array(
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
			'created_at'          => current_time( 'mysql' ),
			'updated_at'          => current_time( 'mysql' ),
		);

		$format = array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' );

		$ok = $wpdb->insert( $table_name, $data, $format );
		$id = $wpdb->insert_id;

		if ( $ok && $id ) {
			do_action( 'sentinelwp_new_finding', $id, $type, $severity, $title );
			return $id;
		}

		return false;
	}

	public function scan_all() {
		$this->scan_plugins();
		$this->scan_themes();
	}

	public function scan_plugins() {
		if ( ! function_exists( 'get_plugins' ) && file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();

		foreach ( $plugins as $plugin_file => $plugin_data ) {
			if ( strpos( $plugin_file, 'sentinelwp-security' ) !== false ) {
				continue;
			}

			$plugin_slug = dirname( $plugin_file );
			if ( '.' === $plugin_slug ) {
				$plugin_slug = $plugin_file;
				$plugin_dir  = WP_PLUGIN_DIR;
			} else {
				$plugin_dir = WP_PLUGIN_DIR . '/' . $plugin_slug;
			}

			if ( ! is_dir( $plugin_dir ) ) {
				continue;
			}

			$component_name = $plugin_data['Name'];

			$this->check_malicious_files( $plugin_dir, $component_name, 'plugin' );
			$this->check_license_bypass( $plugin_dir, $component_name );
			$this->check_update_suppression( $plugin_slug, 'plugin' );
			$this->check_wporg_mismatch( $plugin_slug, $plugin_data, 'plugin' );
			$this->check_phonehome_patterns( $plugin_dir, $component_name );
		}
	}

	public function scan_themes() {
		$themes = wp_get_themes();

		foreach ( $themes as $stylesheet => $theme ) {
			$theme_dir      = $theme->get_stylesheet_directory();
			$component_name = $theme->get( 'Name' );

			if ( ! is_dir( $theme_dir ) ) {
				continue;
			}

			$this->check_malicious_files( $theme_dir, $component_name, 'theme' );
			$this->check_license_bypass( $theme_dir, $component_name );
			$this->check_update_suppression( $stylesheet, 'theme' );
			$this->check_wporg_mismatch( $stylesheet, array(
				'Version'   => $theme->get( 'Version' ),
				'AuthorURI' => $theme->get( 'AuthorURI' ),
				'PluginURI' => $theme->get( 'ThemeURI' ), // Map to PluginURI for unified check
			), 'theme' );
			$this->check_phonehome_patterns( $theme_dir, $component_name );
		}
	}

	private function get_iterator( $dir ) {
		try {
			$flags    = RecursiveDirectoryIterator::SKIP_DOTS;
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, $flags ),
				RecursiveIteratorIterator::SELF_FIRST,
				RecursiveIteratorIterator::CATCH_GET_CHILD
			);
			return $iterator;
		} catch ( Exception $e ) {
			return false;
		}
	}

	public function check_malicious_files( $dir, $component_name, $type ) {
		$indicators = $this->load_indicators();
		$malicious  = isset( $indicators['malicious_files'] ) ? $indicators['malicious_files'] : array();
		
		$iterator = $this->get_iterator( $dir );
		if ( ! $iterator ) {
			return;
		}

		$count = 0;
		foreach ( $iterator as $file ) {
			if ( ++$count > 5000 ) {
				break;
			}

			if ( $file->isDir() ) {
				continue;
			}

			$filename = $file->getFilename();

			// Check against predefined list
			if ( in_array( $filename, $malicious, true ) ) {
				$this->record_finding(
					'nulled_malicious_file',
					'critical',
					$component_name,
					/* translators: %s: component name */
					sprintf( esc_html__( 'Malicious Nulled File Found in %s', 'sentinelwp-security' ), $component_name ),
					/* translators: %s: malicious filename */
					sprintf( esc_html__( 'File %s matches known malicious indicator.', 'sentinelwp-security' ), $filename )
				);
			}

			// Check against pattern
			if ( preg_match( '/nulled|cracked|gpl-?club|theme-?starter/i', $filename ) ) {
				$this->record_finding(
					'nulled_suspicious_filename',
					'critical',
					$component_name,
					/* translators: %s: component name */
					sprintf( esc_html__( 'Suspicious Filename Found in %s', 'sentinelwp-security' ), $component_name ),
					/* translators: %s: suspicious filename */
					sprintf( esc_html__( 'File %s indicates a potentially nulled component.', 'sentinelwp-security' ), $filename )
				);
			}
		}
	}

	public function check_license_bypass( $dir, $component_name ) {
		$indicators = $this->load_indicators();
		$patterns   = isset( $indicators['license_bypass_patterns'] ) ? $indicators['license_bypass_patterns'] : array();

		if ( empty( $patterns ) ) {
			return;
		}

		$iterator = $this->get_iterator( $dir );
		if ( ! $iterator ) {
			return;
		}

		$file_count = 0;
		$max_files  = 50;

		foreach ( $iterator as $file ) {
			if ( $file->isDir() || strtolower( $file->getExtension() ) !== 'php' ) {
				continue;
			}

			if ( ++$file_count > $max_files ) {
				break;
			}

			if ( $file->getSize() > 1048576 ) { // 1MB limit
				continue;
			}

			$content = @file_get_contents( $file->getPathname() );
			if ( false === $content ) {
				continue;
			}

			foreach ( $patterns as $pattern => $label ) {
				if ( preg_match( $pattern, $content ) ) {
					$this->record_finding(
						'nulled_license_bypass',
						'medium',
						$component_name,
						/* translators: %s: component name */
						sprintf( esc_html__( 'License Bypass Code in %s', 'sentinelwp-security' ), $component_name ),
						/* translators: 1: detection label, 2: filename */
						sprintf( esc_html__( '%1$s matched in file %2$s', 'sentinelwp-security' ), $label, $file->getFilename() )
					);
					break; // Found one pattern in this file, move to next file
				}
			}
		}
	}

	public function check_update_suppression( $slug, $type ) {
		global $wp_filter;
		$plugin_update_hook = implode( '_', array( 'pre', 'set', 'site', 'transient', 'update', 'plugins' ) );
		$theme_update_hook  = implode( '_', array( 'pre', 'set', 'site', 'transient', 'update', 'themes' ) );
		$hook = ( 'plugin' === $type ) ? $plugin_update_hook : $theme_update_hook;

		if ( ! isset( $wp_filter[ $hook ] ) ) {
			return;
		}

		// Check if a callback function from this component's directory is registered to the hook.
		$suspicious = false;
		
		foreach ( $wp_filter[ $hook ] as $priority => $callbacks ) {
			foreach ( $callbacks as $callback_data ) {
				$function = $callback_data['function'];
				if ( is_string( $function ) && function_exists( $function ) ) {
					$ref = new ReflectionFunction( $function );
					$file = $ref->getFileName();
					if ( $file && strpos( $file, $slug ) !== false ) {
						$suspicious = true;
						break 2;
					}
				} elseif ( is_array( $function ) && is_object( $function[0] ) ) {
					$ref = new ReflectionClass( $function[0] );
					$file = $ref->getFileName();
					if ( $file && strpos( $file, $slug ) !== false ) {
						$suspicious = true;
						break 2;
					}
				}
			}
		}

		if ( $suspicious ) {
			$this->record_finding(
				'nulled_update_suppression',
				'low',
				$slug,
				/* translators: %s: component slug */
				sprintf( esc_html__( 'Update Suppression Hook in %s', 'sentinelwp-security' ), $slug ),
				esc_html__( 'The component hooks into update transients, potentially suppressing updates.', 'sentinelwp-security' )
			);
		}
	}

	public function check_wporg_mismatch( $slug, $local_headers, $type ) {
		// Only applies to plugins/themes that are ostensibly from wp.org
		$api_url = ( 'plugin' === $type ) ? 'https://api.wordpress.org/plugins/info/1.2/' : 'https://api.wordpress.org/themes/info/1.2/';
		$action  = ( 'plugin' === $type ) ? 'plugin_information' : 'theme_information';
		
		$transient_key = 'sentinelwp_wporg_info_' . md5( $slug . $type );
		$info = get_transient( $transient_key );

		if ( false === $info ) {
			$request = wp_remote_post( $api_url, array(
				'timeout' => 3,
				'body'    => array(
					'action'  => $action,
					'request' => wp_json_encode( array( 'slug' => $slug ) ),
				),
			) );

			if ( is_wp_error( $request ) || 200 !== wp_remote_retrieve_response_code( $request ) ) {
				return;
			}

			$body = wp_remote_retrieve_body( $request );
			$info = json_decode( $body );
			
			if ( ! empty( $info ) && ! isset( $info->error ) ) {
				set_transient( $transient_key, $info, 12 * HOUR_IN_SECONDS );
			} else {
				// Component not on wp.org, so we can't check for mismatch
				set_transient( $transient_key, 'not_found', 12 * HOUR_IN_SECONDS );
				return;
			}
		}

		if ( 'not_found' === $info || empty( $info ) ) {
			return;
		}

		$mismatch = false;
		$details  = array();

		$official_author_uri = isset( $info->author_profile ) ? $info->author_profile : ( isset( $info->author ) ? wp_strip_all_tags( $info->author ) : '' );
		$official_plugin_uri = isset( $info->homepage ) ? $info->homepage : '';
		$official_version    = isset( $info->version ) ? $info->version : '0';

		$local_author_uri = isset( $local_headers['AuthorURI'] ) ? $local_headers['AuthorURI'] : '';
		$local_plugin_uri = isset( $local_headers['PluginURI'] ) ? $local_headers['PluginURI'] : '';
		$local_version    = isset( $local_headers['Version'] ) ? $local_headers['Version'] : '0';

		// Compare versions: if local is newer than official, it might be a fake version bump to prevent updates
		if ( version_compare( $local_version, $official_version, '>' ) ) {
			$mismatch = true;
			$details[] = sprintf( 'Local version (%1$s) is greater than official version (%2$s).', $local_version, $official_version );
		}

		$parsed_local_author = wp_parse_url( $local_author_uri, PHP_URL_HOST );
		if ( ! empty( $local_author_uri ) && ! empty( $official_author_uri ) && ! empty( $parsed_local_author ) && strpos( $official_author_uri, $parsed_local_author ) === false ) {
			$mismatch = true;
			$details[] = 'Author URI mismatch.';
		}

		if ( $mismatch ) {
			$this->record_finding(
				'nulled_wporg_mismatch',
				'medium',
				$slug,
				/* translators: %s: component slug */
				sprintf( esc_html__( 'WP.org Data Mismatch in %s', 'sentinelwp-security' ), $slug ),
				esc_html( implode( ' ', $details ) )
			);
		}
	}

	public function check_phonehome_patterns( $dir, $component_name ) {
		$indicators = $this->load_indicators();
		$domains    = isset( $indicators['nulled_domains'] ) ? $indicators['nulled_domains'] : array();

		if ( empty( $domains ) ) {
			return;
		}

		$iterator = $this->get_iterator( $dir );
		if ( ! $iterator ) {
			return;
		}

		$count = 0;
		foreach ( $iterator as $file ) {
			if ( $file->isDir() || strtolower( $file->getExtension() ) !== 'php' ) {
				continue;
			}

			if ( ++$count > 5000 ) {
				break;
			}

			if ( $file->getSize() > 1048576 ) { // 1MB limit
				continue;
			}

			$content = @file_get_contents( $file->getPathname() );
			if ( false === $content ) {
				continue;
			}

			// 1. Direct function calls to domains
			foreach ( $domains as $domain ) {
				if ( stripos( $content, $domain ) !== false ) {
					// Ensure it's likely a call
					if ( preg_match( '/(wp_remote_get|wp_remote_post|file_get_contents|curl_exec).*?[\'"](?:https?:)?\/\/[^\'"]*' . preg_quote( $domain, '/' ) . '/i', $content ) ) {
						$this->record_finding(
							'nulled_phonehome_call',
							'critical',
							$component_name,
							/* translators: %s: component name */
							sprintf( esc_html__( 'Suspicious Outbound Request in %s', 'sentinelwp-security' ), $component_name ),
							/* translators: 1: filename, 2: domain name */
							sprintf( esc_html__( 'File %1$s makes requests to known nulled domain: %2$s', 'sentinelwp-security' ), $file->getFilename(), $domain )
						);
					}
				}
			}

			// 2. Base64 encoded strings
			if ( preg_match_all( '/[\'"]([A-Za-z0-9+\/]{40,}=*)[\'"]/', $content, $matches ) ) {
				foreach ( $matches[1] as $b64 ) {
					$decoded = @base64_decode( $b64, true );
					if ( $decoded ) {
						foreach ( $domains as $domain ) {
							if ( stripos( $decoded, $domain ) !== false ) {
								$this->record_finding(
									'nulled_phonehome_base64',
									'critical',
									$component_name,
									/* translators: %s: component name */
									sprintf( esc_html__( 'Hidden Suspicious Domain in %s', 'sentinelwp-security' ), $component_name ),
									/* translators: 1: filename, 2: domain name */
									sprintf( esc_html__( 'File %1$s contains encoded reference to known nulled domain: %2$s', 'sentinelwp-security' ), $file->getFilename(), $domain )
								);
								break 2; // Move to next file
							}
						}
					}
				}
			}
		}
	}
}
