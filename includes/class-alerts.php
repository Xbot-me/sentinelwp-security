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
	}

	public function maybe_email( $id, $type, $severity, $title ) {
		if ( ! in_array( $severity, array( 'critical', 'high' ), true ) ) {
			return; // don't spam an inbox with every "outdated" note; digest covers those.
		}

		$to = get_option( 'sentinelwp_alert_email', get_option( 'admin_email' ) );
		if ( ! is_email( $to ) ) {
			return;
		}

		$subject = sprintf(
			/* translators: 1: site name, 2: severity */
			__( '[%1$s] SentinelWP: %2$s security finding', 'sentinelwp-security' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			ucfirst( $severity )
		);

		$body = sprintf(
			"%s\n\n%s\n\n%s",
			sanitize_text_field( $title ),
			sprintf(
				/* translators: %s: admin URL */
				__( 'Review it here: %s', 'sentinelwp-security' ),
				esc_url_raw( admin_url( 'admin.php?page=sentinelwp-security&finding=' . (int) $id ) )
			),
			__( 'This is an automated alert from SentinelWP Security.', 'sentinelwp-security' )
		);

		wp_mail( $to, $subject, $body );
	}

	public function maybe_webhook( $id, $type, $severity, $title ) {
		if ( ! SentinelWP_Freemium::can( 'webhook_alerts' ) ) {
			return;
		}

		$webhook_url = get_option( 'sentinelwp_webhook_url', '' );
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
