<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SentinelWP_Skimmer_Detector {

	private static $instance = null;
	private $signatures = null;

	public static function instance() {
		if ( is_null( self::$instance ) ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	public function scan_all() {
		$this->scan_js_files();
		$this->scan_fake_images();
		$this->scan_rogue_checkout_plugins();
		if ( class_exists( 'SentinelWP_Freemium' ) && SentinelWP_Freemium::can( 'skimmer_db_scan' ) ) {
			$this->scan_database_injections();
		}
	}

	private function load_signatures() {
		if ( is_null( $this->signatures ) ) {
			$sig_file = defined( 'SENTINELWP_PATH' ) ? SENTINELWP_PATH . 'data/skimmer-signatures.php' : '';
			if ( $sig_file && file_exists( $sig_file ) ) {
				$this->signatures = include $sig_file;
			}
			if ( ! is_array( $this->signatures ) ) {
				$this->signatures = array();
			}
		}
		return $this->signatures;
	}

	private function is_safe_directory( $path ) {
		$path      = wp_normalize_path( $path );
		$safe_dirs = array(
			'/wp-content/plugins/sentinelwp-security/',
			'/wp-content/plugins/woocommerce/',
			'/wp-content/plugins/jetpack/',
			'/node_modules/',
			'/vendor/'
		);
		foreach ( $safe_dirs as $dir ) {
			if ( strpos( $path, $dir ) !== false ) {
				return true;
			}
		}
		return false;
	}

	private function record_finding( $type, $severity, $source, $title, $details = '', $confidence = 'confirmed', $detector = 'skimmer_detector', $remediation = '', $fp_risk = 'low' ) {
		global $wpdb;

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$wpdb->prefix}sentinelwp_findings WHERE type = %s AND title = %s AND status != 'resolved' LIMIT 1",
				$type,
				$title
			)
		);
		
		if ( $existing ) {
			$wpdb->update(
				$wpdb->prefix . 'sentinelwp_findings',
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
		$wpdb->insert( $table_name, $data, $format );
		$finding_id = $wpdb->insert_id;

		if ( $finding_id ) {
			do_action( 'sentinelwp_new_finding', $finding_id, $type, $severity, $title );
			return $finding_id;
		}

		return false;
	}

	public function scan_js_files() {
		$dir = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
		if ( ! is_dir( $dir ) ) {
			return;
		}

		$signatures = $this->load_signatures();
		if ( empty( $signatures ) ) {
			return;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST,
				RecursiveIteratorIterator::CATCH_GET_CHILD
			);
		} catch ( Exception $e ) {
			return;
		}

		$count    = 0;
		foreach ( $iterator as $file ) {
			if ( $file->isDir() || strtolower( $file->getExtension() ) !== 'js' ) {
				continue;
			}
			$path = $file->getPathname();

			if ( $this->is_safe_directory( $path ) ) {
				continue;
			}

			$count++;
			if ( $count > 5000 ) {
				break;
			}

			if ( $file->getSize() > 2097152 ) { // 2MB limit
				continue;
			}

			$content = @file_get_contents( $path );
			if ( empty( $content ) ) {
				continue;
			}

			foreach ( $signatures as $pattern => $label ) {
				if ( preg_match( $pattern, $content, $matches, PREG_OFFSET_CAPTURE ) ) {
					$match_offset = $matches[0][1];
					
					$start   = max( 0, $match_offset - 80 );
					$snippet = substr( $content, $start, 240 );

					/* translators: %s: script file basename */
					$title      = sprintf( esc_html__( 'Magecart / card skimmer script detected in %s', 'sentinelguard-ecommerce-protection' ), basename( $path ) );
					$rel_path   = str_replace( ABSPATH, '', $path );
					$finding_id = $this->record_finding(
						'checkout_skimmer',
						'critical',
						$rel_path,
						$title,
						$label,
						'confirmed',
						'skimmer_detector',
						__( 'Quarantine or delete this script immediately to protect customer card details.', 'sentinelguard-ecommerce-protection' ),
						'low'
					);
					
					if ( $finding_id && class_exists( 'SentinelWP_AI_Analyzer' ) ) {
						SentinelWP_AI_Analyzer::instance()->queue_triage( $finding_id, $snippet, $label );
					}
					
					break;
				}
			}
		}
	}

	public function scan_fake_images() {
		$upload_dir_info = wp_upload_dir();
		$dir             = $upload_dir_info['basedir'];
		
		if ( ! is_dir( $dir ) ) {
			return;
		}

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST,
				RecursiveIteratorIterator::CATCH_GET_CHILD
			);
		} catch ( Exception $e ) {
			return;
		}

		$count      = 0;
		$extensions = array( 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'bmp', 'webp' );

		foreach ( $iterator as $file ) {
			if ( ! in_array( strtolower( $file->getExtension() ), $extensions, true ) ) {
				continue;
			}
			$path = $file->getPathname();

			$count++;
			if ( $count > 5000 ) {
				break;
			}

			$content = @file_get_contents( $path, false, null, 0, 8192 );
			if ( false !== $content && '' !== $content ) {
				if ( strpos( $content, '<?php' ) !== false || strpos( $content, '<script' ) !== false || strpos( $content, '<%' ) !== false ) {
					/* translators: %s: file basename */
					$title    = sprintf( esc_html__( 'Fake image payload detected: %s', 'sentinelguard-ecommerce-protection' ), basename( $path ) );
					$rel_path = str_replace( ABSPATH, '', $path );
					$this->record_finding(
						'fake_image_payload',
						'critical',
						$rel_path,
						$title,
						esc_html__( 'Image file contains executable PHP or JavaScript code signatures.', 'sentinelguard-ecommerce-protection' ),
						'confirmed',
						'fake_image_detector',
						__( 'Delete the counterfeit image file from wp-content/uploads.', 'sentinelguard-ecommerce-protection' ),
						'low'
					);
				}
			}
		}
	}

	public function scan_database_injections() {
		global $wpdb;

		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name NOT IN ('active_plugins', 'cron', 'rewrite_rules', 'widget_text') AND (option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s)",
				'%<script%',
				'%atob(%',
				'%eval(%',
				'%document.write(%'
			)
		);
		
		if ( $results ) {
			foreach ( $results as $row ) {
				/* translators: %s: database option name */
				$title = sprintf( esc_html__( 'Database script injection in option: %s', 'sentinelguard-ecommerce-protection' ), $row->option_name );
				$this->record_finding(
					'db_script_injection',
					'critical',
					'db_option:' . $row->option_name,
					$title,
					esc_html__( 'Option contains injected script tags or JavaScript execution code.', 'sentinelguard-ecommerce-protection' ),
					'confirmed',
					'db_injection_scanner',
					__( 'Inspect and sanitize the option value in wp_options.', 'sentinelguard-ecommerce-protection' ),
					'low'
				);
			}
		}

		$checkout_page_id = get_option( 'woocommerce_checkout_page_id' );
		if ( $checkout_page_id ) {
			$post = get_post( $checkout_page_id );
			if ( $post && ( strpos( $post->post_content, '<script' ) !== false || strpos( $post->post_content, 'atob(' ) !== false || strpos( $post->post_content, 'eval(' ) !== false || strpos( $post->post_content, 'document.write(' ) !== false ) ) {
				$title = esc_html__( 'Script injection detected on WooCommerce Checkout Page', 'sentinelguard-ecommerce-protection' );
				$this->record_finding(
					'db_script_injection',
					'critical',
					'db_post:' . $checkout_page_id,
					$title,
					esc_html__( 'Suspicious scripts or eval calls found in checkout page post_content.', 'sentinelguard-ecommerce-protection' ),
					'confirmed',
					'db_injection_scanner',
					__( 'Edit the Checkout page in the WordPress admin to remove injected script tags.', 'sentinelguard-ecommerce-protection' ),
					'low'
				);
			}
		}
	}

	public function scan_rogue_checkout_plugins() {
		$active_plugins = get_option( 'active_plugins', array() );
		if ( empty( $active_plugins ) || ! is_array( $active_plugins ) ) {
			return;
		}

		$checkout_hooks = array(
			'woocommerce_after_checkout_form',
			'woocommerce_review_order_after_submit',
			'woocommerce_checkout_order_processed',
			'woocommerce_thankyou'
		);

		foreach ( $active_plugins as $plugin_file ) {
			$full_path = WP_PLUGIN_DIR . '/' . $plugin_file;
			if ( ! file_exists( $full_path ) ) {
				continue;
			}

			$mtime = filemtime( $full_path );
			if ( ( time() - $mtime ) > 30 * DAY_IN_SECONDS ) {
				continue;
			}

			$content = file_get_contents( $full_path );
			if ( empty( $content ) ) {
				continue;
			}

			$has_checkout_hook = false;
			foreach ( $checkout_hooks as $hook ) {
				if ( strpos( $content, $hook ) !== false ) {
					$has_checkout_hook = true;
					break;
				}
			}
			
			if ( $has_checkout_hook ) {
				$has_other_wc_stuff = ( strpos( $content, 'WC_Product' ) !== false || strpos( $content, 'WC_Order' ) !== false || preg_match( '/add_action\(\s*[\'"](?:init|admin_menu|wp_enqueue_scripts|woocommerce_init)[\'"]/', $content ) );
				
				if ( ! $has_other_wc_stuff ) {
					/* translators: %s: plugin file basename */
					$title = sprintf( esc_html__( 'Unusual checkout hook handler in plugin: %s', 'sentinelguard-ecommerce-protection' ), $plugin_file );
					$this->record_finding(
						'rogue_checkout_plugin',
						'medium',
						$full_path,
						$title,
						esc_html__( 'Plugin exclusively registers WooCommerce checkout hooks and was recently installed.', 'sentinelguard-ecommerce-protection' ),
						'suspicious',
						'rogue_plugin_heuristic',
						__( 'Review the source code of this plugin to confirm if it was intentionally installed.', 'sentinelguard-ecommerce-protection' ),
						'high'
					);
				}
			}
		}
	}

	public function audit_checkout_hooks() {
		if ( ! class_exists( 'SentinelWP_Freemium' ) || ! SentinelWP_Freemium::can( 'checkout_hook_audit' ) ) {
			return array();
		}
		
		global $wp_filter;
		
		$checkout_hooks = array(
			'woocommerce_before_checkout_form',
			'woocommerce_checkout_before_customer_details',
			'woocommerce_checkout_after_customer_details',
			'woocommerce_checkout_before_order_review_heading',
			'woocommerce_checkout_before_order_review',
			'woocommerce_review_order_before_cart_contents',
			'woocommerce_review_order_after_cart_contents',
			'woocommerce_review_order_before_payment',
			'woocommerce_review_order_after_payment',
			'woocommerce_checkout_after_order_review',
			'woocommerce_after_checkout_form',
			'woocommerce_checkout_order_processed',
			'woocommerce_review_order_after_submit',
			'woocommerce_thankyou'
		);
		
		$registered_hooks = array();
		
		foreach ( $checkout_hooks as $hook ) {
			if ( isset( $wp_filter[ $hook ] ) ) {
				foreach ( $wp_filter[ $hook ] as $priority => $callbacks ) {
					foreach ( $callbacks as $callback_data ) {
						$callback = $callback_data['function'];
						$source   = 'unknown';
						$cb_name  = '';

						if ( is_string( $callback ) ) {
							$cb_name = $callback;
							if ( function_exists( $callback ) ) {
								$refl   = new ReflectionFunction( $callback );
								$source = $refl->getFileName();
							}
						} elseif ( is_array( $callback ) ) {
							if ( is_object( $callback[0] ) ) {
								$cb_name = get_class( $callback[0] ) . '->' . $callback[1];
								$refl    = new ReflectionClass( $callback[0] );
								$source  = $refl->getFileName();
							} elseif ( is_string( $callback[0] ) ) {
								$cb_name = $callback[0] . '::' . $callback[1];
								$refl    = new ReflectionClass( $callback[0] );
								$source  = $refl->getFileName();
							}
						} elseif ( $callback instanceof Closure ) {
							$cb_name = 'Closure';
							$refl    = new ReflectionFunction( $callback );
							$source  = $refl->getFileName();
						}
						
						if ( $source && strpos( $source, WP_CONTENT_DIR ) !== false ) {
							$source = str_replace( WP_CONTENT_DIR, '', $source );
						}

						$registered_hooks[] = array(
							'hook'     => $hook,
							'callback' => $cb_name,
							'source'   => $source,
							'priority' => $priority
						);
					}
				}
			}
		}
		
		return $registered_hooks;
	}
}
