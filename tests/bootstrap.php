<?php
/**
 * SentinelWP Security Test Suite Bootstrap.
 *
 * Provides a self-contained, lightweight mock WordPress & WooCommerce
 * execution environment so that unit, integration, and security test suites
 * can run in CI pipelines (e.g. GitHub Actions) or local CLI without a full
 * WordPress installation.
 */

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'WP_CONTENT_DIR' ) ) {
	define( 'WP_CONTENT_DIR', ABSPATH . 'wp-content' );
}

if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
	define( 'WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins' );
}

if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 86400 );
}

if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'HOUR_IN_SECONDS', 3600 );
}

if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
	define( 'MINUTE_IN_SECONDS', 60 );
}

if ( ! defined( 'ARRAY_A' ) ) {
	define( 'ARRAY_A', 'ARRAY_A' );
}

if ( ! defined( 'ARRAY_N' ) ) {
	define( 'ARRAY_N', 'ARRAY_N' );
}

if ( ! defined( 'OBJECT' ) ) {
	define( 'OBJECT', 'OBJECT' );
}

if ( ! defined( 'OBJECT_K' ) ) {
	define( 'OBJECT_K', 'OBJECT_K' );
}

if ( ! defined( 'FS_CHMOD_FILE' ) ) {
	define( 'FS_CHMOD_FILE', 0644 );
}

if ( ! defined( 'FS_CHMOD_DIR' ) ) {
	define( 'FS_CHMOD_DIR', 0755 );
}

if ( ! defined( 'SENTINELWP_VERSION' ) ) {
	define( 'SENTINELWP_VERSION', '0.4.1' );
}

if ( ! defined( 'SENTINELWP_PATH' ) ) {
	define( 'SENTINELWP_PATH', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'SENTINELWP_FILE' ) ) {
	define( 'SENTINELWP_FILE', SENTINELWP_PATH . 'sentinelwp-security.php' );
}

if ( ! defined( 'SENTINELWP_URL' ) ) {
	define( 'SENTINELWP_URL', 'https://example.com/wp-content/plugins/sentinelwp-security/' );
}

if ( ! defined( 'SENTINELWP_BASENAME' ) ) {
	define( 'SENTINELWP_BASENAME', 'sentinelwp-security/sentinelwp-security.php' );
}

// Global in-memory mock stores
global $mock_options, $mock_transients, $mock_filters, $mock_actions, $wpdb, $current_user, $wp_filesystem;
$mock_options    = array();
$mock_transients = array();
$mock_filters    = array();
$mock_actions    = array();

// Mock $wpdb
if ( ! isset( $wpdb ) ) {
	class MockWPDB {
		public $prefix = 'wp_';
		public $options = 'wp_options';
		public $users = 'wp_users';
		public $usermeta = 'wp_usermeta';
		public $posts = 'wp_posts';
		public $postmeta = 'wp_postmeta';
		public $comments = 'wp_comments';
		public $last_error = '';
		public $insert_id = 100;
		public $queries = array();
		public $tables = array();
		public $suppress_errors = false;

		public function __construct() {
			$this->init_tables();
		}

		public function init_tables() {
			$this->tables['wp_sentinelwp_findings']      = array();
			$this->tables['wp_sentinelwp_quarantine']    = array();
			$this->tables['wp_sentinelwp_request_rates'] = array();
			$this->tables['wp_sentinelwp_store_hashes']  = array();
			$this->tables['wp_wc_orders']                = array();
			$this->tables['wp_posts']                    = array();
			$this->tables['wp_postmeta']                 = array();
			$this->tables['wp_users']                    = array();
			$this->tables['wp_options']                  = array();
		}

		public function suppress_errors( $suppress = true ) {
			$this->suppress_errors = (bool) $suppress;
			return $this->suppress_errors;
		}

		public function get_charset_collate() {
			return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
		}

		public function get_blog_prefix() {
			return $this->prefix;
		}

		public function prepare( $query, ...$args ) {
			if ( empty( $args ) ) {
				return $query;
			}
			if ( is_array( $args[0] ) && count( $args ) === 1 ) {
				$args = $args[0];
			}
			$escaped_args = array_map( function( $arg ) {
				if ( is_int( $arg ) || is_float( $arg ) ) {
					return $arg;
				}
				return "'" . addslashes( (string) $arg ) . "'";
			}, $args );

			$query = str_replace( array( '%d', '%f', '%s' ), '%s', $query );
			return vsprintf( str_replace( '%s', '%s', $query ), $escaped_args );
		}

		public function query( $sql ) {
			$this->queries[] = $sql;
			
			// Handle TRUNCATE
			if ( preg_match( '/TRUNCATE\s+(?:TABLE\s+)?([a-zA-Z0-9_]+)/i', $sql, $m ) ) {
				$table = $m[1];
				$this->tables[ $table ] = array();
				return true;
			}

			// Handle DROP TABLE
			if ( preg_match( '/DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-zA-Z0-9_]+)/i', $sql, $m ) ) {
				$table = $m[1];
				unset( $this->tables[ $table ] );
				return true;
			}

			// Handle CREATE TABLE
			if ( preg_match( '/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)/i', $sql, $m ) ) {
				$table = $m[1];
				if ( ! isset( $this->tables[ $table ] ) ) {
					$this->tables[ $table ] = array();
				}
				return true;
			}

			// Handle DELETE FROM
			if ( preg_match( '/DELETE\s+FROM\s+([a-zA-Z0-9_]+)/i', $sql, $m ) ) {
				$table = $m[1];
				if ( isset( $this->tables[ $table ] ) ) {
					if ( strpos( $sql, "status = 'open'" ) !== false ) {
						foreach ( $this->tables[ $table ] as $id => $row ) {
							$status = is_object( $row ) ? ( isset( $row->status ) ? $row->status : '' ) : ( isset( $row['status'] ) ? $row['status'] : '' );
							if ( 'open' === $status ) {
								unset( $this->tables[ $table ][ $id ] );
							}
						}
					} elseif ( strpos( $sql, 'WHERE' ) === false ) {
						$this->tables[ $table ] = array();
					}
				}
				return true;
			}

			return 1;
		}

		public function get_var( $sql ) {
			$this->queries[] = $sql;

			// Handle SHOW TABLES LIKE
			if ( preg_match( "/SHOW\s+TABLES\s+LIKE\s+'([^']+)'/i", $sql, $m ) ) {
				$tbl = $m[1];
				return isset( $this->tables[ $tbl ] ) ? $tbl : null;
			}

			// Handle SELECT COUNT(*)
			if ( preg_match( '/SELECT\s+COUNT\(\*\)\s+FROM\s+([a-zA-Z0-9_]+)(?:\s+WHERE\s+(.+))?/i', $sql, $m ) ) {
				$table = $m[1];
				if ( ! isset( $this->tables[ $table ] ) ) {
					return 0;
				}
				$where = isset( $m[2] ) ? $m[2] : '';
				if ( empty( $where ) ) {
					return count( $this->tables[ $table ] );
				}
				$count = 0;
				foreach ( $this->tables[ $table ] as $row ) {
					$status   = is_object( $row ) ? ( isset( $row->status ) ? $row->status : '' ) : ( isset( $row['status'] ) ? $row['status'] : '' );
					$severity = is_object( $row ) ? ( isset( $row->severity ) ? $row->severity : '' ) : ( isset( $row['severity'] ) ? $row['severity'] : '' );
					
					if ( strpos( $where, "status = 'open'" ) !== false && 'open' !== $status ) {
						continue;
					}
					if ( strpos( $where, "severity = 'critical'" ) !== false && 'critical' !== $severity ) {
						continue;
					}
					$count++;
				}
				return $count;
			}

			if ( strpos( $sql, 'SELECT hit_count' ) !== false ) {
				return 1;
			}
			return 0;
		}

		public function get_row( $sql, $output = OBJECT ) {
			$this->queries[] = $sql;

			// Extract table and ID if present
			if ( preg_match( '/FROM\s+([a-zA-Z0-9_]+)\s+WHERE\s+id\s*=\s*(\d+)/i', $sql, $m ) ) {
				$table = $m[1];
				$id    = (int) $m[2];
				if ( isset( $this->tables[ $table ][ $id ] ) ) {
					$row = $this->tables[ $table ][ $id ];
					if ( OBJECT === $output ) {
						return is_object( $row ) ? $row : (object) $row;
					}
					return is_array( $row ) ? $row : (array) $row;
				}
			}

			if ( strpos( $sql, 'wp_sentinelwp_findings' ) !== false ) {
				if ( ! empty( $this->tables['wp_sentinelwp_findings'] ) ) {
					$last = end( $this->tables['wp_sentinelwp_findings'] );
					return OBJECT === $output ? ( is_object( $last ) ? $last : (object) $last ) : ( is_array( $last ) ? $last : (array) $last );
				}
				$default = array(
					'id'                  => 1,
					'type'                => 'suspicious_file',
					'severity'            => 'high',
					'confidence'          => 'confirmed',
					'detector'            => 'scanner',
					'source'              => 'wp-content/plugins/sample.php',
					'title'               => 'Suspicious PHP File',
					'details'             => 'eval(base64_decode())',
					'remediation'         => 'Remove file',
					'false_positive_risk' => 'low',
					'status'              => 'new',
					'created_at'          => date( 'Y-m-d H:i:s' ),
					'updated_at'          => date( 'Y-m-d H:i:s' ),
				);
				return OBJECT === $output ? (object) $default : $default;
			}

			if ( strpos( $sql, 'wp_sentinelwp_quarantine' ) !== false ) {
				if ( ! empty( $this->tables['wp_sentinelwp_quarantine'] ) ) {
					$last = end( $this->tables['wp_sentinelwp_quarantine'] );
					return OBJECT === $output ? ( is_object( $last ) ? $last : (object) $last ) : ( is_array( $last ) ? $last : (array) $last );
				}
				$default = array(
					'id'                  => 1,
					'finding_id'          => 1,
					'original_path'       => WP_CONTENT_DIR . '/uploads/quarantined-test.php',
					'quarantine_filename' => 'quarantined-test.php.12345.quarantine',
					'file_hash'           => hash( 'sha256', '<?php echo "malware";' ),
					'file_size'           => 20,
					'permissions'         => '0644',
					'status'              => 'quarantined',
					'created_at'          => date( 'Y-m-d H:i:s' ),
					'restored_at'         => null,
				);
				return OBJECT === $output ? (object) $default : $default;
			}

			return null;
		}

		public function get_col( $sql, $col = 0 ) {
			$this->queries[] = $sql;
			if ( strpos( $sql, 'DESCRIBE' ) !== false ) {
				return array( 'id', 'type', 'severity', 'confidence', 'detector', 'source', 'title', 'details', 'remediation', 'false_positive_risk', 'ai_verdict', 'ai_reason', 'status', 'created_at', 'updated_at' );
			}
			return array();
		}

		public function get_results( $sql, $output = OBJECT ) {
			$this->queries[] = $sql;

			// Handle custom orders table
			if ( strpos( $sql, 'wc_orders' ) !== false && isset( $this->tables['wp_wc_orders'] ) ) {
				$results = array();
				foreach ( $this->tables['wp_wc_orders'] as $row ) {
					$results[] = ( ARRAY_A === $output ) ? (array) $row : ( (object) $row );
				}
				return $results;
			}

			if ( strpos( $sql, 'wp_sentinelwp_findings' ) !== false ) {
				$findings = array();
				if ( isset( $this->tables['wp_sentinelwp_findings'] ) ) {
					foreach ( $this->tables['wp_sentinelwp_findings'] as $row ) {
						$status = is_object( $row ) ? ( isset( $row->status ) ? $row->status : '' ) : ( isset( $row['status'] ) ? $row['status'] : '' );
						if ( strpos( $sql, "status = 'open'" ) !== false && 'open' !== $status ) {
							continue;
						}
						if ( strpos( $sql, "status = 'new'" ) !== false && 'new' !== $status ) {
							continue;
						}
						$findings[] = ( ARRAY_A === $output ) ? (array) $row : ( (object) $row );
					}
				}
				return $findings;
			}

			return array();
		}

		public function insert( $table, $data, $format = null ) {
			$this->queries[] = "INSERT INTO $table";
			$this->insert_id++;
			$data['id'] = $this->insert_id;
			if ( ! isset( $this->tables[ $table ] ) ) {
				$this->tables[ $table ] = array();
			}
			$this->tables[ $table ][ $this->insert_id ] = (object) $data;
			return 1;
		}

		public function update( $table, $data, $where, $format = null, $where_format = null ) {
			$this->queries[] = "UPDATE $table";
			if ( isset( $this->tables[ $table ] ) ) {
				foreach ( $this->tables[ $table ] as $id => $row ) {
					$match = true;
					foreach ( $where as $wk => $wv ) {
						$row_val = is_object( $row ) ? ( isset( $row->$wk ) ? $row->$wk : null ) : ( isset( $row[ $wk ] ) ? $row[ $wk ] : null );
						if ( (string) $row_val !== (string) $wv ) {
							$match = false;
							break;
						}
					}
					if ( $match ) {
						foreach ( $data as $dk => $dv ) {
							if ( is_object( $this->tables[ $table ][ $id ] ) ) {
								$this->tables[ $table ][ $id ]->$dk = $dv;
							} else {
								$this->tables[ $table ][ $id ][ $dk ] = $dv;
							}
						}
					}
				}
			}
			return 1;
		}

		public function delete( $table, $where, $where_format = null ) {
			$this->queries[] = "DELETE FROM $table";
			$deleted = 0;
			if ( isset( $this->tables[ $table ] ) ) {
				foreach ( $this->tables[ $table ] as $id => $row ) {
					$match = true;
					foreach ( $where as $wk => $wv ) {
						$row_val = is_object( $row ) ? ( isset( $row->$wk ) ? $row->$wk : null ) : ( isset( $row[ $wk ] ) ? $row[ $wk ] : null );
						if ( (string) $row_val !== (string) $wv ) {
							$match = false;
							break;
						}
					}
					if ( $match ) {
						unset( $this->tables[ $table ][ $id ] );
						$deleted++;
					}
				}
			}
			return $deleted;
		}
	}
	$wpdb = new MockWPDB();
}

// Mock WordPress functions
if ( ! function_exists( 'get_option' ) ) {
	function get_option( $key, $default = false ) {
		global $mock_options;
		return array_key_exists( $key, $mock_options ) ? $mock_options[ $key ] : $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	function update_option( $key, $value, $autoload = null ) {
		global $mock_options;
		$mock_options[ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	function delete_option( $key ) {
		global $mock_options;
		unset( $mock_options[ $key ] );
		return true;
	}
}

if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( $key ) {
		global $mock_transients;
		return array_key_exists( $key, $mock_transients ) ? $mock_transients[ $key ] : false;
	}
}

if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( $key, $value, $expiration = 0 ) {
		global $mock_transients;
		$mock_transients[ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( $key ) {
		global $mock_transients;
		unset( $mock_transients[ $key ] );
		return true;
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		global $mock_filters;
		$mock_filters[ $hook ][] = array(
			'callback' => $callback,
			'priority' => $priority,
			'args'     => $accepted_args,
		);
		return true;
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( $hook, $value, ...$args ) {
		global $mock_filters;
		if ( ! empty( $mock_filters[ $hook ] ) ) {
			foreach ( $mock_filters[ $hook ] as $filter ) {
				$cb = $filter['callback'];
				if ( is_callable( $cb ) ) {
					$value = call_user_func( $cb, $value, ...$args );
				}
			}
		}
		return $value;
	}
}

if ( ! function_exists( 'remove_all_filters' ) ) {
	function remove_all_filters( $hook, $priority = false ) {
		global $mock_filters;
		if ( false === $priority ) {
			unset( $mock_filters[ $hook ] );
		} else {
			if ( ! empty( $mock_filters[ $hook ] ) ) {
				$mock_filters[ $hook ] = array_filter( $mock_filters[ $hook ], function( $f ) use ( $priority ) {
					return $f['priority'] !== $priority;
				} );
			}
		}
		return true;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		global $mock_actions;
		$mock_actions[ $hook ][] = array(
			'callback' => $callback,
			'priority' => $priority,
			'args'     => $accepted_args,
		);
		return true;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	function do_action( $hook, ...$args ) {
		global $mock_actions;
		if ( ! empty( $mock_actions[ $hook ] ) ) {
			foreach ( $mock_actions[ $hook ] as $action ) {
				$cb = $action['callback'];
				if ( is_callable( $cb ) ) {
					call_user_func( $cb, ...$args );
				}
			}
		}
	}
}

if ( ! function_exists( 'remove_all_actions' ) ) {
	function remove_all_actions( $hook, $priority = false ) {
		global $mock_actions;
		unset( $mock_actions[ $hook ] );
		return true;
	}
}

if ( ! function_exists( '__return_true' ) ) {
	function __return_true() {
		return true;
	}
}

if ( ! function_exists( '__return_false' ) ) {
	function __return_false() {
		return false;
	}
}

if ( ! function_exists( '__return_empty_array' ) ) {
	function __return_empty_array() {
		return array();
	}
}

if ( ! function_exists( 'wp_upload_dir' ) ) {
	function wp_upload_dir() {
		$dir = WP_CONTENT_DIR . '/uploads';
		wp_mkdir_p( $dir );
		return array(
			'path'    => $dir,
			'url'     => 'https://example.com/wp-content/uploads',
			'subdir'  => '',
			'basedir' => $dir,
			'baseurl' => 'https://example.com/wp-content/uploads',
			'error'   => false,
		);
	}
}

if ( ! function_exists( 'wp_list_pluck' ) ) {
	function wp_list_pluck( $list, $field ) {
		$res = array();
		foreach ( $list as $key => $value ) {
			if ( is_object( $value ) && isset( $value->$field ) ) {
				$res[ $key ] = $value->$field;
			} elseif ( is_array( $value ) && isset( $value[ $field ] ) ) {
				$res[ $key ] = $value[ $field ];
			}
		}
		return $res;
	}
}

if ( ! function_exists( 'wp_normalize_path' ) ) {
	function wp_normalize_path( $path ) {
		return str_replace( '\\', '/', (string) $path );
	}
}

if ( ! function_exists( 'untrailingslashit' ) ) {
	function untrailingslashit( $string ) {
		return rtrim( (string) $string, '/\\' );
	}
}

if ( ! function_exists( 'trailingslashit' ) ) {
	function trailingslashit( $string ) {
		return untrailingslashit( $string ) . '/';
	}
}

if ( ! function_exists( 'plugin_dir_path' ) ) {
	function plugin_dir_path( $file ) {
		return trailingslashit( dirname( $file ) );
	}
}

if ( ! function_exists( 'plugin_dir_url' ) ) {
	function plugin_dir_url( $file ) {
		return 'https://example.com/wp-content/plugins/' . basename( dirname( $file ) ) . '/';
	}
}

if ( ! function_exists( 'plugin_basename' ) ) {
	function plugin_basename( $file ) {
		return basename( dirname( $file ) ) . '/' . basename( $file );
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	function sanitize_text_field( $str ) {
		return trim( strip_tags( (string) $str ) );
	}
}

if ( ! function_exists( 'sanitize_key' ) ) {
	function sanitize_key( $key ) {
		return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
	}
}

if ( ! function_exists( 'sanitize_email' ) ) {
	function sanitize_email( $email ) {
		return filter_var( (string) $email, FILTER_VALIDATE_EMAIL ) ? (string) $email : '';
	}
}

if ( ! function_exists( 'sanitize_file_name' ) ) {
	function sanitize_file_name( $name ) {
		return preg_replace( '/[^a-zA-Z0-9_\.\-]/', '', (string) $name );
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $val ) {
		return is_string( $val ) ? stripslashes( $val ) : $val;
	}
}

if ( ! function_exists( 'is_email' ) ) {
	function is_email( $email ) {
		return (bool) filter_var( (string) $email, FILTER_VALIDATE_EMAIL );
	}
}

if ( ! function_exists( 'current_time' ) ) {
	function current_time( $type ) {
		return ( 'mysql' === $type ) ? date( 'Y-m-d H:i:s' ) : time();
	}
}

if ( ! function_exists( 'wp_rand' ) ) {
	function wp_rand( $min = 0, $max = 0 ) {
		return mt_rand( $min, $max );
	}
}

if ( ! function_exists( 'wp_generate_password' ) ) {
	function wp_generate_password( $length = 12, $special_chars = true ) {
		return bin2hex( random_bytes( (int) ceil( $length / 2 ) ) );
	}
}

if ( ! function_exists( 'wp_mkdir_p' ) ) {
	function wp_mkdir_p( $target ) {
		if ( is_dir( $target ) ) {
			return true;
		}
		return @mkdir( $target, 0777, true );
	}
}

if ( ! function_exists( 'wp_using_ext_object_cache' ) ) {
	function wp_using_ext_object_cache() {
		return false;
	}
}

if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	function esc_attr( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_url' ) ) {
	function esc_url( $url ) {
		return filter_var( (string) $url, FILTER_SANITIZE_URL );
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( $text, $domain = 'default' ) {
		return esc_html( $text );
	}
}

if ( ! function_exists( 'esc_textarea' ) ) {
	function esc_textarea( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'wp_kses_post' ) ) {
	function wp_kses_post( $text ) {
		return (string) $text;
	}
}

if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) {
		return $text;
	}
}

if ( ! function_exists( '_n' ) ) {
	function _n( $single, $plural, $number, $domain = 'default' ) {
		return 1 === $number ? $single : $plural;
	}
}

if ( ! function_exists( 'is_user_logged_in' ) ) {
	function is_user_logged_in() {
		return false;
	}
}

if ( ! function_exists( 'current_user_can' ) ) {
	function current_user_can( $capability ) {
		return true;
	}
}

if ( ! function_exists( 'get_current_user_id' ) ) {
	function get_current_user_id() {
		global $current_user;
		return ! empty( $current_user->ID ) ? (int) $current_user->ID : 0;
	}
}

if ( ! function_exists( 'wp_set_current_user' ) ) {
	function wp_set_current_user( $id ) {
		global $current_user;
		$current_user = (object) array(
			'ID'            => (int) $id,
			'user_login'    => 'admin',
			'user_email'    => 'admin@example.com',
			'display_name'  => 'Admin User',
			'roles'         => array( 'administrator' ),
		);
		return $current_user;
	}
}

if ( ! function_exists( 'get_user_by' ) ) {
	function get_user_by( $field, $value ) {
		return (object) array(
			'ID'            => 1,
			'user_login'    => 'admin',
			'user_email'    => 'admin@example.com',
			'display_name'  => 'Admin User',
			'roles'         => array( 'administrator' ),
		);
	}
}

if ( ! function_exists( 'wp_create_nonce' ) ) {
	function wp_create_nonce( $action = -1 ) {
		return substr( md5( 'nonce_' . $action ), 0, 10 );
	}
}

if ( ! function_exists( 'wp_verify_nonce' ) ) {
	function wp_verify_nonce( $nonce, $action = -1 ) {
		return ! empty( $nonce );
	}
}

if ( ! function_exists( 'check_admin_referer' ) ) {
	function check_admin_referer( $action = -1, $query_arg = '_wpnonce' ) {
		return 1;
	}
}

if ( ! function_exists( 'admin_url' ) ) {
	function admin_url( $path = '' ) {
		return 'https://example.com/wp-admin/' . ltrim( (string) $path, '/' );
	}
}

if ( ! function_exists( 'home_url' ) ) {
	function home_url( $path = '' ) {
		return 'https://example.com/' . ltrim( (string) $path, '/' );
	}
}

if ( ! function_exists( 'site_url' ) ) {
	function site_url( $path = '' ) {
		return 'https://example.com/' . ltrim( (string) $path, '/' );
	}
}

if ( ! function_exists( 'is_admin' ) ) {
	function is_admin() {
		return true;
	}
}

if ( ! function_exists( 'is_ssl' ) ) {
	function is_ssl() {
		return true;
	}
}

if ( ! function_exists( 'get_locale' ) ) {
	function get_locale() {
		return 'en_US';
	}
}

if ( ! function_exists( 'get_stylesheet_directory' ) ) {
	function get_stylesheet_directory() {
		return WP_CONTENT_DIR . '/themes/sentinel-mock-theme';
	}
}

if ( ! function_exists( 'wp_die' ) ) {
	function wp_die( $message = '', $title = '', $args = array() ) {
		throw new RuntimeException( 'wp_die: ' . ( is_string( $message ) ? $message : json_encode( $message ) ) );
	}
}

if ( ! function_exists( 'get_plugins' ) ) {
	function get_plugins() {
		return array(
			'sentinelwp-security/sentinelwp-security.php' => array(
				'Name'        => 'SentinelWP Security',
				'Version'     => '0.4.1',
				'PluginURI'   => 'https://github.com/Xbot-me/sentinelwp-security',
				'Author'      => 'SentinelWP Team',
				'Description' => 'Enterprise WooCommerce Fraud Prevention & Threat Defense.',
			),
		);
	}
}

if ( ! function_exists( 'dbDelta' ) ) {
	function dbDelta( $queries ) {
		global $wpdb;
		if ( ! is_array( $queries ) ) {
			$queries = explode( ';', (string) $queries );
		}
		foreach ( $queries as $query ) {
			$query = trim( $query );
			if ( ! empty( $query ) ) {
				$wpdb->query( $query );
			}
		}
		return array( 'wp_sentinelwp_findings' => 'Created table' );
	}
}

if ( ! function_exists( 'wp_remote_get' ) ) {
	function wp_remote_get( $url, $args = array() ) {
		$filtered = apply_filters( 'pre_http_request', false, $args, $url );
		if ( false !== $filtered ) {
			return $filtered;
		}
		return array(
			'response' => array( 'code' => 200, 'message' => 'OK' ),
			'body'     => json_encode( array( 'status' => 'ok' ) ),
		);
	}
}

if ( ! function_exists( 'wp_remote_post' ) ) {
	function wp_remote_post( $url, $args = array() ) {
		$filtered = apply_filters( 'pre_http_request', false, $args, $url );
		if ( false !== $filtered ) {
			return $filtered;
		}
		return array(
			'response' => array( 'code' => 200, 'message' => 'OK' ),
			'body'     => json_encode( array( 'status' => 'ok' ) ),
		);
	}
}

if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
	function wp_remote_retrieve_body( $response ) {
		if ( is_wp_error( $response ) || ! is_array( $response ) || ! isset( $response['body'] ) ) {
			return '';
		}
		return $response['body'];
	}
}

if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
	function wp_remote_retrieve_response_code( $response ) {
		if ( is_wp_error( $response ) || ! is_array( $response ) || ! isset( $response['response']['code'] ) ) {
			return 0;
		}
		return (int) $response['response']['code'];
	}
}

if ( ! function_exists( 'wp_safe_redirect' ) ) {
	function wp_safe_redirect( $location, $status = 302 ) {
		return true;
	}
}

if ( ! function_exists( 'wp_send_json_success' ) ) {
	function wp_send_json_success( $data = null ) {
		echo json_encode( array( 'success' => true, 'data' => $data ) );
	}
}

if ( ! function_exists( 'wp_send_json_error' ) ) {
	function wp_send_json_error( $data = null ) {
		echo json_encode( array( 'success' => false, 'data' => $data ) );
	}
}

if ( ! function_exists( 'wp_parse_args' ) ) {
	function wp_parse_args( $args, $defaults = array() ) {
		if ( is_object( $args ) ) {
			$r = get_object_vars( $args );
		} elseif ( is_array( $args ) ) {
			$r =& $args;
		} else {
			wp_parse_str( $args, $r );
		}
		return array_merge( $defaults, $r );
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) {
		return ( $thing instanceof WP_Error );
	}
}

if ( ! function_exists( 'wc_add_notice' ) ) {
	function wc_add_notice( $message, $type = 'error' ) {
		// Mock notice
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public $code;
		public $message;
		public $data;
		public function __construct( $code = '', $message = '', $data = '' ) {
			$this->code = $code;
			$this->message = $message;
			$this->data = $data;
		}
		public function get_error_message() {
			return $this->message;
		}
		public function get_error_code() {
			return $this->code;
		}
		public function add( $code, $message, $data = '' ) {
			$this->code = $code;
			$this->message = $message;
			$this->data = $data;
		}
	}
}

// Mock WP Filesystem
class MockFilesystem {
	public function put_contents( $file, $contents, $mode = false ) {
		$dir = dirname( $file );
		if ( ! file_exists( $dir ) ) {
			@mkdir( $dir, 0777, true );
		}
		return (bool) @file_put_contents( $file, $contents );
	}
	public function get_contents( $file ) {
		return file_exists( $file ) ? file_get_contents( $file ) : false;
	}
	public function exists( $file ) {
		return file_exists( $file );
	}
	public function is_file( $file ) {
		return is_file( $file );
	}
	public function is_dir( $path ) {
		return is_dir( $path );
	}
	public function is_writable( $path ) {
		return is_writable( $path );
	}
	public function chmod( $file, $mode = false, $recursive = false ) {
		return $mode ? @chmod( $file, $mode ) : true;
	}
	public function delete( $file, $recursive = false, $type = false ) {
		if ( is_file( $file ) ) {
			return @unlink( $file );
		}
		return true;
	}
	public function mkdir( $path, $chmod = false, $chown = false, $chgrp = false ) {
		return @mkdir( $path, $chmod ? $chmod : 0777, true );
	}
	public function move( $from, $to, $overwrite = false ) {
		if ( ! $overwrite && file_exists( $to ) ) {
			return false;
		}
		return @rename( $from, $to );
	}
	public function copy( $from, $to, $overwrite = false, $mode = false ) {
		if ( ! $overwrite && file_exists( $to ) ) {
			return false;
		}
		return @copy( $from, $to );
	}
}

if ( ! function_exists( 'WP_Filesystem' ) ) {
	function WP_Filesystem() {
		global $wp_filesystem;
		if ( empty( $wp_filesystem ) ) {
			$wp_filesystem = new MockFilesystem();
		}
		return true;
	}
}

global $wp_filesystem;
if ( empty( $wp_filesystem ) ) {
	$wp_filesystem = new MockFilesystem();
}

if ( ! function_exists( 'add_query_arg' ) ) {
	function add_query_arg( ...$args ) {
		return 'https://example.com/?mock_query_arg=1';
	}
}

if ( ! class_exists( 'WP_REST_Request' ) ) {
	class WP_REST_Request {
		private $headers = array();
		private $params  = array();
		public function __construct( $method = 'GET', $route = '' ) {}
		public function get_header( $key ) { return isset( $this->headers[ strtolower( $key ) ] ) ? $this->headers[ strtolower( $key ) ] : null; }
		public function set_header( $key, $value ) { $this->headers[ strtolower( $key ) ] = $value; }
		public function get_param( $key ) { return isset( $this->params[ $key ] ) ? $this->params[ $key ] : null; }
		public function set_param( $key, $value ) { $this->params[ $key ] = $value; }
		public function get_params() { return $this->params; }
	}
}

if ( ! class_exists( 'WooCommerce' ) ) {
	class WooCommerce {}
}

// Autoloader for SentinelWP classes
spl_autoload_register( function ( $class ) {
	if ( strpos( $class, 'SentinelWP_' ) !== 0 ) {
		return;
	}
	$relative = strtolower( str_replace( '_', '-', substr( $class, strlen( 'SentinelWP_' ) ) ) );
	$candidates = array(
		SENTINELWP_PATH . 'includes/class-' . $relative . '.php',
		SENTINELWP_PATH . 'admin/class-' . $relative . '.php',
	);
	foreach ( $candidates as $file ) {
		if ( file_exists( $file ) ) {
			require_once $file;
			return;
		}
	}
} );

