<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Notification dispatch. Email is the free-tier channel; webhooks
 * (Slack/Discord/generic) are Pro-gated via SentinelWP_Freemium.
 */
class SentinelWP_Alerts {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'sentinelwp_new_finding', array( $this, 'maybe_email' ), 10, 4 );
		add_action( 'sentinelwp_new_finding', array( $this, 'maybe_webhook' ), 10, 4 );
		add_action( 'sentinelwp_daily_digest', array( $this, 'send_digest' ) );
		if ( ! wp_next_scheduled( 'sentinelwp_daily_digest' ) ) {
			wp_schedule_event( strtotime( 'tomorrow 08:00:00' ), 'daily', 'sentinelwp_daily_digest' );
		}
	}

	/**
	 * Get list of valid recipient email addresses.
	 *
	 * @return array
	 */
	public function get_recipients() {
		$raw = get_option( 'sentinelwp_alert_recipients', '' );
		if ( empty( $raw ) ) {
			$raw = get_option( 'sentinelwp_alert_email', get_option( 'admin_email' ) );
		}

		$lines = preg_split( '/[\r\n,]+/', (string) $raw );
		$emails = array();
		foreach ( $lines as $line ) {
			$clean = sanitize_email( trim( $line ) );
			if ( is_email( $clean ) && ! in_array( $clean, $emails, true ) ) {
				$emails[] = $clean;
			}
		}

		if ( empty( $emails ) ) {
			$admin = get_option( 'admin_email' );
			if ( is_email( $admin ) ) {
				$emails[] = $admin;
			}
		}

		return $emails;
	}

	public function maybe_email( $id, $type, $severity, $title ) {
		$threshold = get_option( 'sentinelwp_alert_threshold', 'high' );
		$allowed_severities = array();

		switch ( $threshold ) {
			case 'critical':
				$allowed_severities = array( 'critical' );
				break;
			case 'high':
				$allowed_severities = array( 'critical', 'high' );
				break;
			case 'medium':
				$allowed_severities = array( 'critical', 'high', 'medium' );
				break;
			case 'low':
			default:
				$allowed_severities = array( 'critical', 'high', 'medium', 'low' );
				break;
		}

		if ( ! in_array( strtolower( (string) $severity ), $allowed_severities, true ) ) {
			return;
		}

		$digest_mode = get_option( 'sentinelwp_alert_digest', 'instant' );
		// If digest is daily and finding is not critical/high, queue for the daily digest email
		if ( 'daily' === $digest_mode && ! in_array( strtolower( (string) $severity ), array( 'critical', 'high' ), true ) ) {
			$queue = get_option( 'sentinelwp_digest_queue', array() );
			if ( ! is_array( $queue ) ) {
				$queue = array();
			}
			$queue[] = array(
				'id'       => (int) $id,
				'title'    => (string) $title,
				'severity' => (string) $severity,
				'time'     => current_time( 'mysql' ),
			);
			update_option( 'sentinelwp_digest_queue', array_slice( $queue, -100 ), false );
			return;
		}

		$recipients = $this->get_recipients();
		if ( empty( $recipients ) ) {
			return;
		}

		$subject = sprintf(
			/* translators: 1: site name, 2: severity */
			__( '[%1$s] SentinelGuard: %2$s security finding', 'sentinelguard-ecommerce-protection' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			ucfirst( $severity )
		);

		$body = sprintf(
			"%s\n\n%s\n\n%s",
			sanitize_text_field( $title ),
			sprintf(
				/* translators: %s: admin URL */
				__( 'Review it here: %s', 'sentinelguard-ecommerce-protection' ),
				esc_url_raw( admin_url( 'admin.php?page=sentinelguard-ecommerce-protection&finding=' . (int) $id ) )
			),
			__( 'This is an automated alert from SentinelGuard.', 'sentinelguard-ecommerce-protection' )
		);

		foreach ( $recipients as $to ) {
			wp_mail( $to, $subject, $body );
		}
	}

	/**
	 * Dispatches aggregated daily digest email.
	 */
	public function send_digest() {
		$queue = get_option( 'sentinelwp_digest_queue', array() );
		if ( empty( $queue ) || ! is_array( $queue ) ) {
			return;
		}

		$recipients = $this->get_recipients();
		if ( empty( $recipients ) ) {
			return;
		}

		/* translators: %s: site name */
		$subject = sprintf( __( '[%s] SentinelGuard Daily Security Digest', 'sentinelguard-ecommerce-protection' ), get_bloginfo( 'name' ) );
		$items = array();
		foreach ( $queue as $item ) {
			$items[] = sprintf( '- [%s] %s', strtoupper( $item['severity'] ), $item['title'] );
		}

		$body = sprintf(
			/* translators: 1: finding count, 2: list of findings, 3: dashboard URL */
			__( "SentinelGuard Daily Security Digest\n\n%1\$d findings recorded:\n\n%2\$s\n\nReview dashboard: %3\$s", 'sentinelguard-ecommerce-protection' ),
			count( $queue ),
			implode( "\n", $items ),
			esc_url_raw( admin_url( 'admin.php?page=sentinelguard-ecommerce-protection' ) )
		);

		foreach ( $recipients as $to ) {
			wp_mail( $to, $subject, $body );
		}

		delete_option( 'sentinelwp_digest_queue' );
	}

	public function maybe_webhook( $id, $type, $severity, $title ) {
		if ( ! SentinelWP_Freemium::can( 'webhook_alerts' ) ) {
			return;
		}

		$webhook_url = get_option( 'sentinelwp_alert_webhook', '' );
		if ( empty( $webhook_url ) ) {
			$webhook_url = get_option( 'sentinelwp_webhook_url', '' );
		}
		if ( ! $webhook_url || ! wp_http_validate_url( $webhook_url ) ) {
			return;
		}

		wp_remote_post(
			$webhook_url,
			array(
				'timeout' => 8,
				'headers' => array( 'content-type' => 'application/json' ),
				'body'    => wp_json_encode(
					array(
						'text' => sprintf( '[%s] %s: %s', get_bloginfo( 'name' ), ucfirst( $severity ), $title ),
					)
				),
			)
		);
	}
}
