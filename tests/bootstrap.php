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

if ( ! defined( 'OBJECT' ) ) {
	define( 'OBJECT', 'OBJECT' );
}

if ( ! defined( 'OBJECT_K' ) ) {
	define( 'OBJECT_K', 'OBJECT_K' );
}

if ( ! defined( 'ARRAY_N' ) ) {
	define( 'ARRAY_N', 'ARRAY_N' );
}

if ( ! defined( 'SENTINELWP_VERSION' ) ) {
	define( 'SENTINELWP_VERSION', '0.4.1' );
}

if ( ! defined( 'SENTINELWP_FILE' ) ) {
	define( 'SENTINELWP_FILE', ABSPATH . 'sentinelguard-ecommerce-protection.php' );
}
if ( ! defined( 'SENTINELWP_PATH' ) ) {
	define( 'SENTINELWP_PATH', ABSPATH );
}
if ( ! defined( 'SENTINELWP_BASENAME' ) ) {
	define( 'SENTINELWP_BASENAME', 'sentinelguard-ecommerce-protection/sentinelguard-ecommerce-protection.php' );
}

if ( ! defined( 'SENTINELWP_URL' ) ) {
	define( 'SENTINELWP_URL', 'https://example.com/wp-content/plugins/sentinelwp-security/' );
}

// Global in-memory mock stores
global $mock_options, $mock_transients, $mock_filters, $mock_actions, $wpdb;
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
		public $created_tables = array();

		public function __construct() {
			$this->created_tables = array(
				'wp_sentinelwp_findings'      => true,
				'wp_sentinelwp_quarantine'    => true,
				'wp_sentinelwp_request_rates' => true,
				'wp_sentinelwp_store_hashes'  => true,
				'wp_sentinelwp_ai_log'        => true,
			);
			$this->tables['wp_sentinelwp_findings'] = array();
			$this->tables['wp_sentinelwp_quarantine'] = array();
			$this->tables['wp_sentinelwp_request_rates'] = array();
		}

		public function get_charset_collate() {
			return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
		}

		public function get_blog_prefix() {
			return $this->prefix;
		}

		public function suppress_errors( $suppress = true ) {
			return true;
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
			if ( preg_match( '/DROP TABLE IF EXISTS ([a-zA-Z0-9_]+)/i', $sql, $m ) ) {
				unset( $this->created_tables[ $m[1] ] );
				unset( $this->tables[ $m[1] ] );
			}
			if ( preg_match( '/CREATE TABLE ([a-zA-Z0-9_]+)/i', $sql, $m ) ) {
				$this->created_tables[ $m[1] ] = true;
			}
			if ( preg_match( '/DELETE FROM ([a-zA-Z0-9_]+)/i', $sql, $m ) ) {
				$this->tables[ $m[1] ] = array();
			}
			return 1;
		}

		public function get_var( $sql ) {
			$this->queries[] = $sql;
			if ( preg_match( "/SHOW TABLES LIKE '([^']+)'/i", $sql, $m ) ) {
				return isset( $this->created_tables[ $m[1] ] ) ? $m[1] : null;
			}
			if ( strpos( $sql, 'SELECT hit_count' ) !== false ) {
				return 1;
			}
			return 0;
		}

		public function get_row( $sql, $output = OBJECT ) {
			$this->queries[] = $sql;
			$row = null;
			if ( strpos( $sql, 'wp_sentinelwp_findings' ) !== false ) {
				if ( ! empty( $this->tables['wp_sentinelwp_findings'] ) ) {
					$row = end( $this->tables['wp_sentinelwp_findings'] );
				}
			} elseif ( strpos( $sql, 'wp_sentinelwp_quarantine' ) !== false ) {
				if ( ! empty( $this->tables['wp_sentinelwp_quarantine'] ) ) {
					$row = end( $this->tables['wp_sentinelwp_quarantine'] );
				}
			}

			if ( $row ) {
				return ( ARRAY_A === $output ) ? (array) $row : (object) $row;
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
			$results = array();
			if ( strpos( $sql, 'EXPLAIN' ) !== false ) {
				$results = array(
					(object) array(
						'table' => 'wp_wc_orders',
						'type'  => 'range',
						'key'   => 'date_created_gmt',
						'rows'  => 12,
					)
				);
			} elseif ( strpos( $sql, 'wp_sentinelwp_findings' ) !== false ) {
				if ( ! empty( $this->tables['wp_sentinelwp_findings'] ) ) {
					$results = array_values( $this->tables['wp_sentinelwp_findings'] );
				}
			}

			if ( ARRAY_A === $output ) {
				return array_map( function( $item ) {
					return is_object( $item ) ? (array) $item : $item;
				}, $results );
			}
			return array_map( function( $item ) {
				return is_array( $item ) ? (object) $item : $item;
			}, $results );
		}

		public function insert( $table, $data, $format = null ) {
			$this->queries[] = "INSERT INTO $table";
			if ( ! isset( $this->created_tables[ $table ] ) ) {
				return false;
			}
			$this->insert_id++;
			$data['id'] = $this->insert_id;
			$this->tables[$table][$this->insert_id] = (object) $data;
			return 1;
		}

		public function update( $table, $data, $where, $format = null, $where_format = null ) {
			$this->queries[] = "UPDATE $table";
			return 1;
		}

		public function delete( $table, $where, $where_format = null ) {
			$this->queries[] = "DELETE FROM $table";
			if ( isset( $where['id'] ) && isset( $this->tables[$table][$where['id']] ) ) {
				unset( $this->tables[$table][$where['id']] );
			}
			return 1;
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

if ( ! function_exists( 'get_site_transient' ) ) {
	function get_site_transient( $key ) {
		return get_transient( $key );
	}
}

if ( ! function_exists( 'set_site_transient' ) ) {
	function set_site_transient( $key, $val, $exp = 0 ) {
		return set_transient( $key, $val, $exp );
	}
}

if ( ! function_exists( 'delete_site_transient' ) ) {
	function delete_site_transient( $key ) {
		return delete_transient( $key );
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		global $mock_filters;
		$mock_filters[ $hook ][] = array(
			'callback' => $callback,
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
	function remove_all_filters( $hook ) {
		global $mock_filters;
		unset( $mock_filters[ $hook ] );
		return true;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		global $mock_actions;
		$mock_actions[ $hook ][] = array(
			'callback' => $callback,
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

if ( ! function_exists( 'wp_is_writable' ) ) {
	function wp_is_writable( $path ) {
		return is_writable( $path );
	}
}

if ( ! function_exists( 'wp_delete_file' ) ) {
	function wp_delete_file( $file ) {
		if ( file_exists( $file ) ) {
			@unlink( $file );
		}
	}
}

if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( $string, $remove_breaks = false ) {
		$string = preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', $string );
		$string = strip_tags( $string );
		if ( $remove_breaks ) {
			$string = preg_replace( '/[\r\n\t ]+/', ' ', $string );
		}
		return trim( $string );
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( $url, $component );
	}
}

if ( ! function_exists( 'wp_kses_post' ) ) {
	function wp_kses_post( $data ) {
		return $data;
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
		return 1;
	}
}

if ( ! function_exists( 'is_multisite' ) ) {
	function is_multisite() {
		return false;
	}
}

if ( ! function_exists( 'get_locale' ) ) {
	function get_locale() {
		return 'en_US';
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $options = 0, $depth = 512 ) {
		return json_encode( $data, $options, $depth );
	}
}

if ( ! function_exists( 'add_query_arg' ) ) {
	function add_query_arg( ...$args ) {
		return 'https://api.wordpress.org/core/checksums/1.0/?version=6.6.1&locale=en_US';
	}
}

if ( ! function_exists( 'dbDelta' ) ) {
	function dbDelta( $queries ) {
		global $wpdb;
		if ( is_string( $queries ) ) {
			$queries = explode( ';', $queries );
		}
		foreach ( $queries as $q ) {
			$q = trim( $q );
			if ( ! empty( $q ) ) {
				$wpdb->query( $q );
			}
		}
		return array();
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

if ( ! function_exists( 'wc_add_notice' ) ) {
	function wc_add_notice( $message, $type = 'error' ) {
		// Mock notice
	}
}

if ( ! function_exists( 'get_plugins' ) ) {
	function get_plugins() {
		return array(
			'sentinelwp-security/sentinelwp-security.php' => array(
				'Name'        => 'SentinelWP Security',
				'Version'     => '0.4.1',
				'Author'      => 'SentinelWP Security',
				'AuthorURI'   => 'https://sentinelwp.io',
				'PluginURI'   => 'https://sentinelwp.io',
				'TextDomain'  => 'sentinelguard-ecommerce-protection',
			),
		);
	}
}

if ( ! function_exists( 'wp_get_themes' ) ) {
	function wp_get_themes() {
		return array();
	}
}

if ( ! function_exists( 'wp_remote_get' ) ) {
	function wp_remote_get( $url, $args = array() ) {
		return array(
			'response' => array( 'code' => 200, 'message' => 'OK' ),
			'body'     => '{"checksums":{"6.6.1":{"wp-login.php":"mockhash"}}}',
		);
	}
}

if ( ! function_exists( 'wp_remote_post' ) ) {
	function wp_remote_post( $url, $args = array() ) {
		return array(
			'response' => array( 'code' => 200, 'message' => 'OK' ),
			'body'     => '{"verdict":"clean"}',
		);
	}
}

if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
	function wp_remote_retrieve_response_code( $response ) {
		return is_array( $response ) && isset( $response['response']['code'] ) ? (int) $response['response']['code'] : 0;
	}
}

if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
	function wp_remote_retrieve_body( $response ) {
		return is_array( $response ) && isset( $response['body'] ) ? $response['body'] : '';
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
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

if ( ! class_exists( 'WP_REST_Request' ) ) {
	class WP_REST_Request {
		protected $route = '';
		protected $params = array();
		protected $headers = array();
		public function __construct( $method = 'GET', $route = '' ) {
			$this->route = $route;
		}
		public function get_route() {
			return $this->route;
		}
		public function set_route( $route ) {
			$this->route = $route;
		}
		public function get_param( $key ) {
			return isset( $this->params[ $key ] ) ? $this->params[ $key ] : null;
		}
		public function set_param( $key, $val ) {
			$this->params[ $key ] = $val;
		}
		public function get_params() {
			return $this->params;
		}
		public function get_header( $header ) {
			return isset( $this->headers[ $header ] ) ? $this->headers[ $header ] : '';
		}
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
