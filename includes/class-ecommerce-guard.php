<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SentinelWP_Ecommerce_Guard class.
 *
 * Scalable, HPOS-compatible security engine designed specifically to protect
 * WooCommerce revenue, checkout integrity, payment flows, and store configuration.
 *
 * Completely avoids in-memory full table scans (no wc_get_orders limit => -1).
 * Uses indexed database aggregations (COUNT, SUM, AVG, GROUP BY) scaling
 * gracefully to 100k–1M+ order stores.
 */
class SentinelWP_Ecommerce_Guard {

	private static $instance = null;

	public static function instance() {
		if ( is_null( self::$instance ) ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		if ( ! class_exists( 'WooCommerce' ) || ! get_option( 'sentinelwp_ecommerce_guard_enabled', 1 ) ) {
			return;
		}

		add_action( 'woocommerce_checkout_order_processed', array( $this, 'check_order_velocity' ), 10, 1 );
		add_action( 'woocommerce_checkout_process', array( $this, 'check_disposable_email' ), 10 );
		add_action( 'woocommerce_order_status_failed', array( $this, 'check_payment_failure' ), 10, 1 );
		add_action( 'sentinelwp_daily_scan', array( $this, 'cron_analyze_fraud_patterns' ), 20 );
		add_action( 'sentinelwp_daily_scan', array( $this, 'cron_monitor_complaint_patterns' ), 25 );
		add_action( 'sentinelwp_daily_scan', array( $this, 'cron_check_store_integrity' ), 30 );
	}

	/**
	 * Real-time order velocity checks on order creation.
	 */
	public function check_order_velocity( $order_id ) {
		if ( ! function_exists( 'wc_get_order' ) ) {
			return;
		}

		$order = wc_get_order( $order_id );
		if ( ! $order ) {
			return;
		}

		$ip_hash = $this->get_order_ip_hash( $order );
		$ip_count = 0;
		if ( $ip_hash ) {
			$ip_transient_key = 'sentinelwp_ord_vel_ip_' . $ip_hash;
			$ip_count = (int) get_transient( $ip_transient_key );
			$ip_count++;
			set_transient( $ip_transient_key, $ip_count, HOUR_IN_SECONDS );

			if ( $ip_count > 5 ) {
				$this->record_finding(
					'order_velocity',
					'high',
					'ecommerce_guard',
					__( 'High order velocity from single IP detected', 'sentinelwp-security' ),
					sprintf( __( 'More than 5 orders from client IP hash %s in 1 hour.', 'sentinelwp-security' ), esc_html( substr( $ip_hash, 0, 12 ) . '...' ) ),
					'likely',
					'ecommerce_guard',
					__( 'Review customer orders from this IP and consider enabling checkout rate limits.', 'sentinelwp-security' ),
					'low'
				);
			}
		}

		$email = $order->get_billing_email();
		$email_count = 0;
		if ( ! empty( $email ) ) {
			$email_hash = md5( strtolower( trim( $email ) ) );
			$email_transient_key = 'sentinelwp_ord_vel_email_' . $email_hash;
			$email_count = (int) get_transient( $email_transient_key );
			$email_count++;
			set_transient( $email_transient_key, $email_count, HOUR_IN_SECONDS );

			if ( $email_count > 3 ) {
				$this->record_finding(
					'order_velocity',
					'high',
					'ecommerce_guard',
					__( 'High order velocity from single email detected', 'sentinelwp-security' ),
					sprintf( __( 'More than 3 orders from same email in 1 hour (Order #%d).', 'sentinelwp-security' ), (int) $order_id ),
					'likely',
					'ecommerce_guard',
					__( 'Verify order legitimacy before fulfillment.', 'sentinelwp-security' ),
					'low'
				);
			}
		}

		$is_fraud_auto_hold_enabled = get_option( 'sentinelwp_fraud_auto_hold', false );
		if ( $is_fraud_auto_hold_enabled ) {
			if ( ( $ip_hash && $ip_count > 5 ) || ( ! empty( $email ) && $email_count > 3 ) ) {
				$order->update_status( 'on-hold', __( 'SentinelWP Security: Order automatically placed on hold due to high order velocity.', 'sentinelwp-security' ) );
			}
		}
	}

	/**
	 * Real-time card testing burst detector on payment failure.
	 */
	public function check_payment_failure( $order_id ) {
		if ( ! function_exists( 'wc_get_order' ) ) {
			return;
		}

		$order = wc_get_order( $order_id );
		if ( ! $order ) {
			return;
		}

		$ip_hash = $this->get_order_ip_hash( $order );
		if ( $ip_hash ) {
			$ip_transient_key = 'sentinelwp_pay_fail_' . $ip_hash;
			$ip_count = (int) get_transient( $ip_transient_key );
			$ip_count++;
			set_transient( $ip_transient_key, $ip_count, 10 * MINUTE_IN_SECONDS );

			if ( $ip_count > 3 ) {
				$this->record_finding(
					'card_testing',
					'critical',
					'ecommerce_guard',
					__( 'Card testing attack detected via IP', 'sentinelwp-security' ),
					sprintf( __( 'More than 3 rapid payment failures from IP hash %s in 10 minutes.', 'sentinelwp-security' ), esc_html( substr( $ip_hash, 0, 12 ) . '...' ) ),
					'confirmed',
					'ecommerce_guard',
					__( 'Investigate payment gateway logs for card testing activity and enable CAPTCHA / gateway velocity rules.', 'sentinelwp-security' ),
					'low'
				);
			}
		}

		$email = $order->get_billing_email();
		if ( ! empty( $email ) ) {
			$email_hash = md5( strtolower( trim( $email ) ) );
			$email_transient_key = 'sentinelwp_pay_fail_email_' . $email_hash;
			$email_count = (int) get_transient( $email_transient_key );
			$email_count++;
			set_transient( $email_transient_key, $email_count, HOUR_IN_SECONDS );

			if ( $email_count > 5 ) {
				$this->record_finding(
					'card_testing',
					'high',
					'ecommerce_guard',
					__( 'Card testing attack detected via email', 'sentinelwp-security' ),
					sprintf( __( 'More than 5 payment failures from same billing email in 1 hour (Order #%d).', 'sentinelwp-security' ), (int) $order_id ),
					'likely',
					'ecommerce_guard',
					__( 'Review payment attempts for stolen card pattern.', 'sentinelwp-security' ),
					'low'
				);
			}
		}
	}

	/**
	 * Real-time disposable email domain check during checkout.
	 */
	public function check_disposable_email() {
		$is_enabled = get_option( 'sentinelwp_disposable_email_check', true );
		if ( ! $is_enabled ) {
			return;
		}

		if ( isset( $_POST['billing_email'] ) ) {
			$billing_email = sanitize_email( wp_unslash( $_POST['billing_email'] ) );
			if ( empty( $billing_email ) ) {
				return;
			}

			$parts = explode( '@', $billing_email );
			if ( count( $parts ) === 2 ) {
				$domain = strtolower( trim( $parts[1] ) );
				$disposable_domains = $this->load_disposable_domains();
				
				if ( in_array( $domain, $disposable_domains, true ) ) {
					$this->record_finding(
						'disposable_email',
						'medium',
						'ecommerce_guard',
						__( 'Order placed using temporary disposable email domain', 'sentinelwp-security' ),
						sprintf( __( 'Domain "%s" is on the known disposable email list.', 'sentinelwp-security' ), esc_html( $domain ) ),
						'likely',
						'ecommerce_guard',
						__( 'Verify customer identity before dispatching high-value items.', 'sentinelwp-security' ),
						'medium'
					);
				}
			}
		}
	}

	/**
	 * Scalable, HPOS-compatible database aggregation for 24h/30d fraud analysis.
	 * Runs via cron or manual deep scan without memory blowups.
	 */
	public function cron_analyze_fraud_patterns() {
		global $wpdb;

		$is_hpos = class_exists( 'SentinelWP_Helper' ) && SentinelWP_Helper::is_hpos_enabled();
		$orders_table = $wpdb->prefix . 'wc_orders';
		$hpos_table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $orders_table ) ) === $orders_table;

		$one_day_ago = date( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$thirty_days_ago = date( 'Y-m-d H:i:s', time() - 30 * DAY_IN_SECONDS );

		if ( $is_hpos && $hpos_table_exists ) {
			// 1. HPOS Mode: 24h Order Velocity by Email Aggregation
			$email_spikes = $wpdb->get_results( $wpdb->prepare(
				"SELECT billing_email, COUNT(*) as order_count 
				FROM {$orders_table} 
				WHERE date_created_gmt >= %s 
				AND status NOT IN ('wc-cancelled', 'wc-trash')
				AND billing_email != ''
				GROUP BY billing_email 
				HAVING order_count > 10 
				LIMIT 20",
				$one_day_ago
			) );

			if ( ! empty( $email_spikes ) ) {
				foreach ( $email_spikes as $row ) {
					$this->record_finding(
						'order_anomaly',
						'high',
						'ecommerce_guard',
						__( 'High 24h order volume from single email', 'sentinelwp-security' ),
						sprintf( __( 'Email "%s" placed %d orders in the last 24 hours.', 'sentinelwp-security' ), esc_html( $row->billing_email ), (int) $row->order_count ),
						'likely',
						'ecommerce_guard',
						__( 'Review customer orders for automated purchasing scripts or card testing.', 'sentinelwp-security' ),
						'low'
					);
				}
			}

			// 2. HPOS Mode: 24h Order Velocity by IP Aggregation
			$ip_spikes = $wpdb->get_results( $wpdb->prepare(
				"SELECT ip_address, COUNT(*) as order_count 
				FROM {$orders_table} 
				WHERE date_created_gmt >= %s 
				AND status NOT IN ('wc-cancelled', 'wc-trash')
				AND ip_address != ''
				GROUP BY ip_address 
				HAVING order_count > 10 
				LIMIT 20",
				$one_day_ago
			) );

			if ( ! empty( $ip_spikes ) ) {
				foreach ( $ip_spikes as $row ) {
					$this->record_finding(
						'order_anomaly',
						'high',
						'ecommerce_guard',
						__( 'High 24h order volume from single IP', 'sentinelwp-security' ),
						sprintf( __( 'IP "%s" placed %d orders in the last 24 hours.', 'sentinelwp-security' ), esc_html( $row->ip_address ), (int) $row->order_count ),
						'likely',
						'ecommerce_guard',
						__( 'Inspect IP for proxy or bot network activity.', 'sentinelwp-security' ),
						'low'
					);
				}
			}

			// 3. HPOS Mode: 30-day Average Order Value SQL Aggregation
			$aov_data = $wpdb->get_row( $wpdb->prepare(
				"SELECT AVG(total_amount) as avg_val, COUNT(*) as total_orders 
				FROM {$orders_table} 
				WHERE date_created_gmt >= %s 
				AND status IN ('wc-completed', 'wc-processing')",
				$thirty_days_ago
			) );

			if ( $aov_data && (int) $aov_data->total_orders > 10 && (float) $aov_data->avg_val > 0 ) {
				$avg_order_value = (float) $aov_data->avg_val;
				$spike_threshold = $avg_order_value * 5;

				$large_orders = $wpdb->get_results( $wpdb->prepare(
					"SELECT id, total_amount 
					FROM {$orders_table} 
					WHERE date_created_gmt >= %s 
					AND status IN ('wc-completed', 'wc-processing') 
					AND total_amount > %f 
					LIMIT 10",
					$one_day_ago,
					$spike_threshold
				) );

				if ( ! empty( $large_orders ) ) {
					foreach ( $large_orders as $ord ) {
						$this->record_finding(
							'order_anomaly',
							'medium',
							'ecommerce_guard',
							__( 'Anomalous order amount or customer purchase spike', 'sentinelwp-security' ),
							sprintf( __( 'Order #%d total ($%s) is more than 5x the 30-day average order value ($%s).', 'sentinelwp-security' ), (int) $ord->id, number_format( (float) $ord->total_amount, 2 ), number_format( $avg_order_value, 2 ) ),
							'suspicious',
							'ecommerce_guard',
							__( 'Verify high-value payment authorization with customer before shipping.', 'sentinelwp-security' ),
							'medium'
						);
					}
				}
			}

		} else {
			// Legacy Post-Meta Mode: SQL Aggregations on wp_posts & wp_postmeta
			$email_spikes = $wpdb->get_results( $wpdb->prepare(
				"SELECT pm.meta_value as billing_email, COUNT(p.ID) as order_count 
				FROM {$wpdb->posts} p 
				INNER JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
				WHERE p.post_type = 'shop_order' 
				AND p.post_date_gmt >= %s 
				AND p.post_status NOT IN ('wc-cancelled', 'wc-trash')
				AND pm.meta_key = '_billing_email'
				AND pm.meta_value != ''
				GROUP BY pm.meta_value 
				HAVING order_count > 10 
				LIMIT 20",
				$one_day_ago
			) );

			if ( ! empty( $email_spikes ) ) {
				foreach ( $email_spikes as $row ) {
					$this->record_finding(
						'order_anomaly',
						'high',
						'ecommerce_guard',
						__( 'High 24h order volume from single email', 'sentinelwp-security' ),
						sprintf( __( 'Email "%s" placed %d orders in the last 24 hours.', 'sentinelwp-security' ), esc_html( $row->billing_email ), (int) $row->order_count ),
						'likely',
						'ecommerce_guard',
						__( 'Review customer orders for automated purchasing scripts.', 'sentinelwp-security' ),
						'low'
					);
				}
			}

			// Legacy Average Order Value
			$aov_data = $wpdb->get_row( $wpdb->prepare(
				"SELECT AVG(CAST(pm.meta_value AS DECIMAL(10,2))) as avg_val, COUNT(p.ID) as total_orders 
				FROM {$wpdb->posts} p 
				INNER JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
				WHERE p.post_type = 'shop_order' 
				AND p.post_date_gmt >= %s 
				AND p.post_status IN ('wc-completed', 'wc-processing')
				AND pm.meta_key = '_order_total'",
				$thirty_days_ago
			) );

			if ( $aov_data && (int) $aov_data->total_orders > 10 && (float) $aov_data->avg_val > 0 ) {
				$avg_order_value = (float) $aov_data->avg_val;
				$spike_threshold = $avg_order_value * 5;

				$large_orders = $wpdb->get_results( $wpdb->prepare(
					"SELECT p.ID as id, CAST(pm.meta_value AS DECIMAL(10,2)) as total_amount 
					FROM {$wpdb->posts} p 
					INNER JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id 
					WHERE p.post_type = 'shop_order' 
					AND p.post_date_gmt >= %s 
					AND p.post_status IN ('wc-completed', 'wc-processing') 
					AND pm.meta_key = '_order_total' 
					AND CAST(pm.meta_value AS DECIMAL(10,2)) > %f 
					LIMIT 10",
					$one_day_ago,
					$spike_threshold
				) );

				if ( ! empty( $large_orders ) ) {
					foreach ( $large_orders as $ord ) {
						$this->record_finding(
							'order_anomaly',
							'medium',
							'ecommerce_guard',
							__( 'Anomalous order amount or customer purchase spike', 'sentinelwp-security' ),
							sprintf( __( 'Order #%d total ($%s) is more than 5x the 30-day average order value ($%s).', 'sentinelwp-security' ), (int) $ord->id, number_format( (float) $ord->total_amount, 2 ), number_format( $avg_order_value, 2 ) ),
							'suspicious',
							'ecommerce_guard',
							__( 'Verify high-value payment authorization with customer before shipping.', 'sentinelwp-security' ),
							'medium'
						);
					}
				}
			}
		}

		// Bounded cursor sampling for nonsensical names (checks max 25 recent orders)
		$recent_sample_orders = $wpdb->get_results( $wpdb->prepare(
			"SELECT p.ID, 
				(SELECT meta_value FROM {$wpdb->postmeta} WHERE post_id = p.ID AND meta_key = '_billing_first_name' LIMIT 1) as fn,
				(SELECT meta_value FROM {$wpdb->postmeta} WHERE post_id = p.ID AND meta_key = '_billing_last_name' LIMIT 1) as ln
			FROM {$wpdb->posts} p 
			WHERE p.post_type = 'shop_order' 
			AND p.post_date_gmt >= %s 
			ORDER BY p.ID DESC 
			LIMIT 25",
			$one_day_ago
		) );

		if ( ! empty( $recent_sample_orders ) ) {
			foreach ( $recent_sample_orders as $ord ) {
				$first_name = (string) $ord->fn;
				$last_name  = (string) $ord->ln;
				if ( ( is_numeric( $first_name ) && is_numeric( $last_name ) ) || ( strlen( $first_name ) === 1 && strlen( $last_name ) === 1 && $first_name !== '' ) ) {
					$this->record_finding(
						'order_anomaly',
						'medium',
						'ecommerce_guard',
						__( 'Nonsensical billing data detected', 'sentinelwp-security' ),
						sprintf( __( 'Order #%d contains suspicious numeric or single-character billing name "%s %s".', 'sentinelwp-security' ), (int) $ord->ID, esc_html( $first_name ), esc_html( $last_name ) ),
						'suspicious',
						'ecommerce_guard',
						__( 'Inspect order for automated testing before processing.', 'sentinelwp-security' ),
						'medium'
					);
				}
			}
		}
	}

	/**
	 * Scalable 7-day refund rate aggregation and chargeback keyword monitoring.
	 */
	public function cron_monitor_complaint_patterns() {
		global $wpdb;

		$seven_days_ago = date( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS );
		$is_hpos = class_exists( 'SentinelWP_Helper' ) && SentinelWP_Helper::is_hpos_enabled();
		$orders_table = $wpdb->prefix . 'wc_orders';
		$hpos_table_exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $orders_table ) ) === $orders_table;

		if ( $is_hpos && $hpos_table_exists ) {
			$refund_stats = $wpdb->get_row( $wpdb->prepare(
				"SELECT 
					COUNT(*) as total_orders,
					COUNT(CASE WHEN status = 'wc-refunded' THEN 1 END) as refunded_orders 
				FROM {$orders_table} 
				WHERE date_created_gmt >= %s",
				$seven_days_ago
			) );
		} else {
			$refund_stats = $wpdb->get_row( $wpdb->prepare(
				"SELECT 
					COUNT(*) as total_orders,
					COUNT(CASE WHEN post_status = 'wc-refunded' THEN 1 END) as refunded_orders 
				FROM {$wpdb->posts} 
				WHERE post_type = 'shop_order' 
				AND post_date_gmt >= %s",
				$seven_days_ago
			) );
		}

		if ( $refund_stats && (int) $refund_stats->total_orders > 20 ) {
			$total_7d    = (int) $refund_stats->total_orders;
			$refunded_7d = (int) $refund_stats->refunded_orders;
			$rate        = (float) ( $refunded_7d / $total_7d );

			// If refund rate exceeds 25% across >20 orders
			if ( $rate > 0.25 ) {
				$this->record_finding(
					'refund_spike',
					'high',
					'ecommerce_guard',
					__( 'Spike in refunded orders', 'sentinelwp-security' ),
					sprintf( __( 'The 7-day refund rate is %s%% (%d of %d orders refunded).', 'sentinelwp-security' ), number_format( $rate * 100, 1 ), $refunded_7d, $total_7d ),
					'likely',
					'ecommerce_guard',
					__( 'Examine recent refunds for unauthorized transactions or disputed charges.', 'sentinelwp-security' ),
					'medium'
				);
			}
		}

		// Order note chargeback / dispute keywords query
		$keywords = array( 'fraud', 'unauthorized', 'chargeback', 'stolen', 'dispute', 'not recognized', 'did not order' );
		$like_clauses = array();
		foreach ( $keywords as $kw ) {
			$like_clauses[] = $wpdb->prepare( 'comment_content LIKE %s', '%' . $wpdb->esc_like( $kw ) . '%' );
		}
		
		$query = "SELECT COUNT(*) FROM {$wpdb->comments} 
			WHERE comment_type = 'order_note' 
			AND comment_date_gmt >= %s 
			AND (" . implode( ' OR ', $like_clauses ) . ")";
			
		$suspicious_notes_count = (int) $wpdb->get_var( $wpdb->prepare( $query, $seven_days_ago ) );

		if ( $suspicious_notes_count > 3 ) {
			$this->record_finding(
				'complaint_pattern',
				'critical',
				'ecommerce_guard',
				__( 'Suspicious customer complaint pattern detected', 'sentinelwp-security' ),
				sprintf( __( 'Found %d order notes containing fraud or chargeback keywords in the last 7 days.', 'sentinelwp-security' ), $suspicious_notes_count ),
				'likely',
				'ecommerce_guard',
				__( 'Check merchant gateway account for active chargeback disputes.', 'sentinelwp-security' ),
				'low'
			);
		}
	}

	/**
	 * Daily store configuration and product pricing integrity audits.
	 */
	public function cron_check_store_integrity() {
		global $wpdb;

		$monitored_options = array(
			'woocommerce_stripe_settings',
			'woocommerce_paypal_settings',
			'woocommerce_checkout_page_id',
			'woocommerce_cart_page_id',
			'woocommerce_currency',
			'woocommerce_default_country'
		);
		
		$hashes_table = $wpdb->prefix . 'sentinelwp_store_hashes';

		foreach ( $monitored_options as $option_name ) {
			$value = get_option( $option_name );
			$hash_value = hash( 'sha256', maybe_serialize( $value ) );

			$existing_hash = $wpdb->get_var( $wpdb->prepare(
				"SELECT hash_value FROM {$hashes_table} WHERE option_name = %s",
				$option_name
			) );

			if ( ! is_null( $existing_hash ) && $existing_hash !== $hash_value ) {
				$this->record_finding(
					'store_config_changed',
					'high',
					'ecommerce_guard',
					__( 'Payment gateway or critical store configuration changed', 'sentinelwp-security' ),
					sprintf( __( 'The WooCommerce setting "%s" was modified.', 'sentinelwp-security' ), esc_html( $option_name ) ),
					'confirmed',
					'ecommerce_guard',
					__( 'Verify that payment gateway API keys and payout accounts point to your official accounts.', 'sentinelwp-security' ),
					'low'
				);
			}

			if ( is_null( $existing_hash ) ) {
				$wpdb->insert(
					$hashes_table,
					array(
						'option_name' => $option_name,
						'hash_value'  => $hash_value,
						'updated_at'  => current_time( 'mysql' ),
					)
				);
			} else if ( $existing_hash !== $hash_value ) {
				$wpdb->update(
					$hashes_table,
					array(
						'hash_value' => $hash_value,
						'updated_at' => current_time( 'mysql' ),
					),
					array( 'option_name' => $option_name )
				);
			}
		}

		// Check for zero-priced products with bounded limit 50
		$recent_zero_products = $wpdb->get_results(
			"SELECT p.ID, p.post_title FROM {$wpdb->posts} p
			INNER JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id
			WHERE p.post_type IN ('product', 'product_variation')
			AND p.post_status = 'publish'
			AND pm.meta_key = '_price'
			AND (pm.meta_value = '0' OR pm.meta_value = '0.00' OR pm.meta_value = '0.01')
			LIMIT 50"
		);

		if ( ! empty( $recent_zero_products ) ) {
			foreach ( $recent_zero_products as $product ) {
				$regular_price = get_post_meta( $product->ID, '_regular_price', true );
				if ( (float) $regular_price > 0.01 ) {
					$this->record_finding(
						'store_config_changed',
						'high',
						'ecommerce_guard',
						__( 'Suspicious product price zeroing detected', 'sentinelwp-security' ),
						sprintf( __( 'Product "%s" (#%d) is priced at $0.00 but has a regular price of $%s.', 'sentinelwp-security' ), esc_html( $product->post_title ), (int) $product->ID, esc_html( $regular_price ) ),
						'likely',
						'ecommerce_guard',
						__( 'Verify product price in WooCommerce products catalog.', 'sentinelwp-security' ),
						'low'
					);
				}
			}
		}
		
		// Check for suspicious coupons created in last 24h
		$one_day_ago = date( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$coupons = $wpdb->get_results( $wpdb->prepare(
			"SELECT ID, post_author, post_title FROM {$wpdb->posts} 
			WHERE post_type = 'shop_coupon' 
			AND post_date_gmt >= %s 
			LIMIT 50",
			$one_day_ago
		) );
		
		foreach ( $coupons as $coupon ) {
			$author_id = (int) $coupon->post_author;
			$author_meta = get_userdata( $author_id );
			$is_admin = false;
			if ( $author_meta && in_array( 'administrator', (array) $author_meta->roles, true ) ) {
				$is_admin = true;
			}
			
			if ( ! $is_admin ) {
				$coupon_type = get_post_meta( $coupon->ID, 'discount_type', true );
				$coupon_amount = (float) get_post_meta( $coupon->ID, 'coupon_amount', true );
				
				if ( 'percent' === $coupon_type && $coupon_amount > 50 ) {
					$this->record_finding(
						'store_config_changed',
						'high',
						'ecommerce_guard',
						__( 'Suspicious high-value coupon created by non-admin', 'sentinelwp-security' ),
						sprintf( __( 'Coupon "%s" with >50%% discount was created by non-administrator user #%d.', 'sentinelwp-security' ), esc_html( $coupon->post_title ), $author_id ),
						'likely',
						'ecommerce_guard',
						__( 'Inspect coupon settings and revoke unauthorized user permissions.', 'sentinelwp-security' ),
						'low'
					);
				}
			}
		}
	}

	/**
	 * Record finding with full confidence, severity, detector, and remediation metadata.
	 */
	public function record_finding( $type, $severity, $source, $title, $details, $confidence = 'likely', $detector = 'ecommerce_guard', $remediation = '', $fp_risk = 'low' ) {
		global $wpdb;

		$findings_table = $wpdb->prefix . 'sentinelwp_findings';

		$existing_id = $wpdb->get_var( $wpdb->prepare(
			"SELECT id FROM {$findings_table} WHERE type = %s AND title = %s AND status != 'resolved' LIMIT 1",
			$type,
			$title
		) );

		if ( $existing_id ) {
			$wpdb->update(
				$findings_table,
				array( 'updated_at' => current_time( 'mysql' ) ),
				array( 'id' => $existing_id ),
				array( '%s' ),
				array( '%d' )
			);
			return false;
		}

		$inserted = $wpdb->insert(
			$findings_table,
			array(
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
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( $inserted ) {
			$finding_id = $wpdb->insert_id;
			do_action( 'sentinelwp_new_finding', $finding_id, $type, $severity, $title );
			return $finding_id;
		}

		return false;
	}

	private function get_order_ip_hash( $order ) {
		$ip_address = $order->get_customer_ip_address();
		if ( empty( $ip_address ) && class_exists( 'SentinelWP_Helper' ) ) {
			$ip_address = SentinelWP_Helper::get_client_ip();
		}
		if ( empty( $ip_address ) ) {
			return false;
		}
		return hash( 'sha256', (string) $ip_address );
	}

	private function load_disposable_domains() {
		$domains = array();
		if ( defined( 'SENTINELWP_PATH' ) ) {
			$file_path = SENTINELWP_PATH . 'data/disposable-email-domains.php';
			if ( file_exists( $file_path ) ) {
				$domains_data = include $file_path;
				if ( is_array( $domains_data ) ) {
					$domains = $domains_data;
				}
			}
		}
		return $domains;
	}
}
