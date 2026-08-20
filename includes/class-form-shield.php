<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SentinelWP_Form_Shield {

	private static $instance = null;

	public static function instance() {
		if ( is_null( self::$instance ) ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		if ( ! get_option( 'sentinelwp_form_shield_enabled', 1 ) ) {
			return;
		}

		add_action( 'pre_comment_on_post', array( $this, 'rate_limit_comments' ), 1, 1 );
		add_action( 'comment_form_after_fields', array( $this, 'inject_honeypot' ), 99 );
		add_filter( 'preprocess_comment', array( $this, 'check_honeypot' ), 1, 1 );
		add_filter( 'registration_errors', array( $this, 'rate_limit_registration' ), 10, 3 );
		add_action( 'woocommerce_checkout_process', array( $this, 'rate_limit_checkout' ), 1 );
		add_filter( 'rest_pre_dispatch', array( $this, 'rate_limit_rest' ), 1, 3 );
		add_action( 'login_init', array( $this, 'rate_limit_login_page' ), 1 );
	}

	public function rate_limit_comments( $post_id ) {
		if ( $this->check_rate( 'comment', 5, 600 ) ) {
			wp_die( esc_html__( 'Too many comments. Please try again later.', 'sentinelwp-security' ), '', array( 'response' => 429 ) );
		}
	}

	public function inject_honeypot() {
		?>
		<p style="position:absolute;left:-9999px;" aria-hidden="true">
			<label for="sentinelwp_hp_field"><?php esc_html_e( 'Leave this empty', 'sentinelwp-security' ); ?></label>
			<input type="text" name="sentinelwp_hp_field" id="sentinelwp_hp_field" value="" tabindex="-1" autocomplete="off" />
		</p>
		<?php
	}

	public function check_honeypot( $comment_data ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['sentinelwp_hp_field'] ) && ! empty( $_POST['sentinelwp_hp_field'] ) ) {
			wp_die( esc_html__( 'Spam detected.', 'sentinelwp-security' ), '', array( 'response' => 403 ) );
		}
		return $comment_data;
	}

	public function rate_limit_registration( $errors, $sanitized_user_login, $user_email ) {
		if ( $this->check_rate( 'register', 3, 3600 ) ) {
			$errors->add( 'sentinelwp_rate_limit', __( 'Too many registration attempts. Please try again later.', 'sentinelwp-security' ) );
		}
		return $errors;
	}

	public function rate_limit_checkout() {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return;
		}

		if ( $this->check_rate( 'checkout', 10, 1800 ) ) {
			wc_add_notice( __( 'Too many checkout attempts. Please try again later.', 'sentinelwp-security' ), 'error' );
		}
	}

	public function rate_limit_rest( $result, $server, $request ) {
		if ( current_user_can( 'edit_posts' ) ) {
			return $result;
		}

		/**
		 * REST routes to exempt from the sitewide rate limit, e.g. another
		 * plugin's own polling/webhook endpoint. Route strings are matched
		 * against the request route with strpos(), so a prefix like
		 * '/my-plugin/v1/' excludes that entire namespace.
		 *
		 * @param string[] $excluded_routes
		 * @param WP_REST_Request $request
		 */
		$excluded_routes = (array) apply_filters( 'sentinelwp_rest_rate_limit_excluded_routes', array(), $request );
		$route            = method_exists( $request, 'get_route' ) ? $request->get_route() : '';
		foreach ( $excluded_routes as $excluded_route ) {
			if ( '' !== $excluded_route && false !== strpos( $route, $excluded_route ) ) {
				return $result;
			}
		}

		if ( $this->check_rate( 'rest', 60, 60 ) ) {
			return new WP_Error( 'sentinelwp_rate_limit', __( 'Too many requests.', 'sentinelwp-security' ), array( 'status' => 429 ) );
		}
		return $result;
	}

	public function rate_limit_login_page() {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'GET' === strtoupper( $method ) ) {
			if ( $this->check_rate( 'login', 20, 600 ) ) {
				wp_die( esc_html__( 'Too many requests. Please try again later.', 'sentinelwp-security' ), '', array( 'response' => 429 ) );
			}
		}
	}

	private function check_rate( $action, $limit, $window_seconds ) {
		$ip_hash = $this->get_ip_hash();
		if ( empty( $ip_hash ) ) {
			return false;
		}

		$transient_key = 'sentinelwp_rl_' . $action . '_' . $ip_hash;
		$count = get_transient( $transient_key );

		if ( false === $count ) {
			$count = 0;
		}

		if ( $count >= $limit ) {
			return true;
		}

		set_transient( $transient_key, $count + 1, $window_seconds );
		return false;
	}

	private function get_ip_hash() {
		if ( class_exists( 'SentinelWP_Helper' ) ) {
			return SentinelWP_Helper::get_ip_hash();
		}
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return ! empty( $ip ) ? hash( 'sha256', $ip ) : '';
	}
}
