<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin UI. Every state-changing action here checks capability +
 * nonce before touching anything, per the plan's security checklist.
 */
class SentinelWP_Admin {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_sentinelwp_run_scan_now', array( $this, 'ajax_run_scan_now' ) );
		add_action( 'wp_ajax_sentinelwp_resolve_finding', array( $this, 'ajax_resolve_finding' ) );
		add_action( 'wp_ajax_sentinelwp_unresolve_finding', array( $this, 'ajax_unresolve_finding' ) );
		add_action( 'wp_ajax_sentinelwp_bulk_action', array( $this, 'ajax_bulk_action' ) );
		add_action( 'wp_ajax_sentinelwp_test_email', array( $this, 'ajax_test_email' ) );
		add_action( 'wp_ajax_sentinelwp_dismiss_flood_alert', array( $this, 'ajax_dismiss_flood_alert' ) );
		add_action( 'wp_ajax_sentinelwp_quarantine_finding', array( $this, 'ajax_quarantine_finding' ) );
		add_action( 'wp_ajax_sentinelwp_restore_quarantine', array( $this, 'ajax_restore_quarantine' ) );
		add_action( 'wp_ajax_sentinelwp_purge_quarantine', array( $this, 'ajax_purge_quarantine' ) );
		add_action( 'wp_ajax_sentinelwp_reset_settings', array( $this, 'ajax_reset_settings' ) );
		add_action( 'wp_ajax_sentinelwp_purge_history', array( $this, 'ajax_purge_history' ) );
		add_action( 'wp_ajax_sentinelwp_clear_scan_history', array( $this, 'ajax_clear_scan_history' ) );
		add_action( 'wp_ajax_sentinelwp_delete_scan_run', array( $this, 'ajax_delete_scan_run' ) );
	}

	public function register_menu() {
		add_menu_page(
			__( 'SentinelWP Security', 'sentinelguard-ecommerce-protection' ),
			__( 'SentinelWP', 'sentinelguard-ecommerce-protection' ),
			'manage_options',
			'sentinelguard-ecommerce-protection',
			array( $this, 'render_dashboard' ),
			'dashicons-shield',
			80
		);

		add_submenu_page(
			'sentinelguard-ecommerce-protection',
			__( 'Dashboard', 'sentinelguard-ecommerce-protection' ),
			__( 'Dashboard', 'sentinelguard-ecommerce-protection' ),
			'manage_options',
			'sentinelguard-ecommerce-protection',
			array( $this, 'render_dashboard' )
		);

		add_submenu_page(
			'sentinelguard-ecommerce-protection',
			__( 'Settings', 'sentinelguard-ecommerce-protection' ),
			__( 'Settings', 'sentinelguard-ecommerce-protection' ),
			'manage_options',
			'sentinelwp-security-settings',
			array( $this, 'render_settings' )
		);
	}

	public function enqueue_assets( $hook ) {
		if ( strpos( $hook, 'sentinelguard-ecommerce-protection' ) === false ) {
			return;
		}
		wp_enqueue_style( 'sentinelwp-admin', SENTINELWP_URL . 'admin/css/admin.css', array(), SENTINELWP_VERSION );
		wp_enqueue_script( 'sentinelwp-admin', SENTINELWP_URL . 'admin/js/admin.js', array( 'jquery' ), SENTINELWP_VERSION, true );
		wp_localize_script(
			'sentinelwp-admin',
			'SentinelWPAdmin',
			array(
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				'nonce'      => wp_create_nonce( 'sentinelwp_admin_action' ),
				'scanning'   => __( 'Scanning…', 'sentinelguard-ecommerce-protection' ),
				'confirmMsg' => __( 'This won\'t remove the file. Mark as resolved anyway?', 'sentinelguard-ecommerce-protection' ),
			)
		);
	}

	/* -------------------------------------------------------------- */
	/* Dashboard View                                                  */
	/* -------------------------------------------------------------- */

	public function render_dashboard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'sentinelguard-ecommerce-protection' ) );
		}		global $wpdb;

		// All open findings
		$findings = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}sentinelwp_findings WHERE status != 'resolved' ORDER BY FIELD(severity,'critical','high','medium','low'), created_at DESC LIMIT 200" );
		
		// Resolved count
		$resolved_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sentinelwp_findings WHERE status = 'resolved'" );

		$counts = array(
			'all'      => count( $findings ),
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
			'resolved' => $resolved_count,
		);

		foreach ( $findings as $f ) {
			$sev = strtolower( $f->severity );
			if ( isset( $counts[ $sev ] ) ) {
				$counts[ $sev ]++;
			}
		}

		$crit_count = $counts['critical'];
		$high_count = $counts['high'];
		$med_count  = $counts['medium'];
		$low_count  = $counts['low'];
		$total_open = $crit_count + $high_count + $med_count + $low_count;

		$last_scan_time     = (int) get_option( 'sentinelwp_last_scan_time', 0 );
		$relative_last_scan = $last_scan_time ? $this->get_relative_time( $last_scan_time ) : __( 'Never', 'sentinelguard-ecommerce-protection' );
		$engines_online     = 6;

		?>
		<div class="wrap sentinelwp-wrap sentinelwp-dashboard" id="sentinelwp-dashboard">
			<!-- Top Action Header -->
			<div class="head sentinelwp-head">
				<div class="sentinelwp-head-left">
					<h1><?php esc_html_e( 'SentinelWP Security', 'sentinelguard-ecommerce-protection' ); ?></h1>
					<p class="meta sentinelwp-meta">
						<span class="dot sentinelwp-dot"></span>Last scan <b><?php echo esc_html( $relative_last_scan ); ?></b> &middot; <?php 
						/* translators: %d: active engine count */
						echo esc_html( sprintf( __( '%d engines online', 'sentinelguard-ecommerce-protection' ), $engines_online ) ); 
						?> &middot; <?php esc_html_e( 'next auto-scan in ~6h', 'sentinelguard-ecommerce-protection' ); ?>
					</p>
				</div>
				<div class="actions sentinelwp-actions">
					<button type="button" class="btn btn-primary sentinelwp-btn sentinelwp-btn-primary" id="sentinelwp-btn-scan">
						<span class="dashicons dashicons-shield"></span>
						<span class="btn-text"><?php esc_html_e( 'Scan Site Now', 'sentinelguard-ecommerce-protection' ); ?></span>
					</button>
				</div>
			</div>

			<!-- Scan Progress Bar (Revealed during scan) -->
			<div class="sentinelwp-progress-bar" id="sentinelwp-progress-bar" style="display:none;" aria-live="polite" role="progressbar">
				<div class="sentinelwp-progress-fill" id="sentinelwp-progress-fill"></div>
				<div class="sentinelwp-progress-label" id="sentinelwp-progress-label"><?php esc_html_e( 'Initializing scan engines…', 'sentinelguard-ecommerce-protection' ); ?></div>
			</div>

			<!-- Transient Notice Container for Undo / Alert notices -->
			<div id="sentinelwp-transient-notice-area"></div>

			<!-- Active Correlated Attack Incidents -->
			<?php
			$incidents = class_exists( 'SentinelWP_Attack_Correlator' ) ? SentinelWP_Attack_Correlator::instance()->get_active_incidents() : array();
			if ( ! empty( $incidents ) ) :
				foreach ( $incidents as $incident ) :
					?>
					<div class="sentinelwp-incident-banner <?php echo esc_attr( 'incident-' . $incident['severity'] ); ?>">
						<div class="sentinelwp-incident-header">
							<span class="sentinelwp-incident-pill">
								<span class="sentinelwp-pulse-dot"></span>
								<?php esc_html_e( 'ACTIVE ATTACK CORRELATED', 'sentinelguard-ecommerce-protection' ); ?>
							</span>
							<span class="sentinelwp-incident-confidence"><?php echo esc_html( $incident['confidence_label'] ); ?></span>
						</div>
						<h3 class="sentinelwp-incident-title"><?php echo esc_html( $incident['title'] ); ?></h3>
						<p class="sentinelwp-incident-summary"><?php echo esc_html( $incident['summary'] ); ?></p>
						
						<?php if ( ! empty( $incident['signals'] ) ) : ?>
							<div class="sentinelwp-incident-signals">
								<strong><?php esc_html_e( 'Correlated Attack Signals:', 'sentinelguard-ecommerce-protection' ); ?></strong>
								<ul>
									<?php foreach ( $incident['signals'] as $sig ) : ?>
										<li><?php echo esc_html( $sig ); ?></li>
									<?php endforeach; ?>
								</ul>
							</div>
						<?php endif; ?>
						
						<div class="sentinelwp-incident-action">
							<span class="dashicons dashicons-shield"></span>
							<strong><?php esc_html_e( 'Actionable Defense:', 'sentinelguard-ecommerce-protection' ); ?></strong>
							<span><?php echo esc_html( $incident['recommended_action'] ); ?></span>
						</div>
					</div>
					<?php
				endforeach;
			endif;
			?>

			<!-- One Alarm Block (with inline severity counts) -->
			<?php 
			if ( $total_open > 0 ) : 
				if ( $crit_count > 0 ) {
					$alarm_class = 'alarm-crit';
					$alarm_icon  = '!';
					/* translators: %d: critical finding count */
					$alarm_title = sprintf( _n( '%d critical finding needs action', '%d critical findings need action', $crit_count, 'sentinelguard-ecommerce-protection' ), $crit_count );
					/* translators: %d: open finding count */
					$alarm_sub   = sprintf( _n( '%d open finding detected. Critical items indicate active compromise, skimmers, or backdoors requiring immediate containment.', '%d open findings detected. Critical items indicate active compromise, skimmers, or backdoors requiring immediate containment.', $total_open, 'sentinelguard-ecommerce-protection' ), $total_open );
				} elseif ( $high_count > 0 ) {
					$alarm_class = 'alarm-high';
					$alarm_icon  = '!';
					/* translators: %d: high threat count */
					$alarm_title = sprintf( _n( '%d high threat needs action', '%d high threats need action', $high_count, 'sentinelguard-ecommerce-protection' ), $high_count );
					/* translators: %d: open finding count */
					$alarm_sub   = sprintf( _n( '%d open finding detected. High-priority items indicate suspicious accounts, order velocity bursts, or altered store settings.', '%d open findings detected. High-priority items indicate suspicious accounts, order velocity bursts, or altered store settings.', $total_open, 'sentinelguard-ecommerce-protection' ), $total_open );
				} else {
					$alarm_class = 'alarm-med';
					$alarm_icon  = 'i';
					/* translators: %d: security recommendation count */
					$alarm_title = sprintf( _n( '%d security recommendation requires review', '%d security recommendations require review', $total_open, 'sentinelguard-ecommerce-protection' ), $total_open );
					/* translators: %d: open recommendation count */
					$alarm_sub   = sprintf( _n( '%d open recommendation. Medium and low severity items are hardening best-practices and version update advisories.', '%d open recommendations. Medium and low severity items are hardening best-practices and version update advisories.', $total_open, 'sentinelguard-ecommerce-protection' ), $total_open );
				}
				?>
				<div class="alarm sentinelwp-alarm <?php echo esc_attr( $alarm_class ); ?>" id="sentinelwp-alarm-box">
					<div class="icon sentinelwp-alarm-icon"><?php echo esc_html( $alarm_icon ); ?></div>
					<div>
						<div class="t sentinelwp-alarm-title" id="sentinelwp-alarm-title">
							<?php echo esc_html( $alarm_title ); ?>
						</div>
						<div class="s sentinelwp-alarm-sub" id="sentinelwp-alarm-sub">
							<?php echo esc_html( $alarm_sub ); ?>
						</div>
					</div>
					<div class="num sentinelwp-alarm-num">
						<div class="sentinelwp-alarm-filter" data-filter="critical" style="cursor:pointer;" title="<?php esc_attr_e( 'Filter critical findings', 'sentinelguard-ecommerce-protection' ); ?>">
							<div class="k"><?php esc_html_e( 'Critical', 'sentinelguard-ecommerce-protection' ); ?></div>
							<div class="v crit" id="sentinelwp-strip-crit"><?php echo (int) $crit_count; ?></div>
						</div>
						<div class="sentinelwp-alarm-filter" data-filter="high" style="cursor:pointer;" title="<?php esc_attr_e( 'Filter high findings', 'sentinelguard-ecommerce-protection' ); ?>">
							<div class="k"><?php esc_html_e( 'High', 'sentinelguard-ecommerce-protection' ); ?></div>
							<div class="v high" id="sentinelwp-strip-high"><?php echo (int) $high_count; ?></div>
						</div>
						<div class="sentinelwp-alarm-filter" data-filter="medium" style="cursor:pointer;" title="<?php esc_attr_e( 'Filter medium findings', 'sentinelguard-ecommerce-protection' ); ?>">
							<div class="k"><?php esc_html_e( 'Medium', 'sentinelguard-ecommerce-protection' ); ?></div>
							<div class="v med" id="sentinelwp-strip-med"><?php echo (int) $med_count; ?></div>
						</div>
					</div>
				</div>
			<?php else : ?>
				<div class="alarm ok sentinelwp-alarm sentinelwp-alarm-ok" id="sentinelwp-alarm-box">
					<div class="icon sentinelwp-alarm-icon">&#10003;</div>
					<div>
						<div class="t sentinelwp-alarm-title"><?php esc_html_e( 'All security checks passing', 'sentinelguard-ecommerce-protection' ); ?></div>
						<div class="s sentinelwp-alarm-sub"><?php esc_html_e( 'No active malware, skimmers, backdoor accounts, or vulnerabilities detected.', 'sentinelguard-ecommerce-protection' ); ?></div>
					</div>
					<div class="num sentinelwp-alarm-num">
						<div>
							<div class="k"><?php esc_html_e( 'Critical', 'sentinelguard-ecommerce-protection' ); ?></div>
							<div class="v" id="sentinelwp-strip-crit">0</div>
						</div>
						<div>
							<div class="k"><?php esc_html_e( 'High', 'sentinelguard-ecommerce-protection' ); ?></div>
							<div class="v" id="sentinelwp-strip-high">0</div>
						</div>
						<div>
							<div class="k"><?php esc_html_e( 'Medium', 'sentinelguard-ecommerce-protection' ); ?></div>
							<div class="v" id="sentinelwp-strip-med">0</div>
						</div>
					</div>
				</div>
			<?php endif; ?>

			<!-- Active Findings Section Header -->
			<div class="sec-head sentinelwp-sec-head">
				<h2><?php esc_html_e( 'Active findings', 'sentinelguard-ecommerce-protection' ); ?></h2>
				<p><?php esc_html_e( 'Sorted by severity, then detection time.', 'sentinelguard-ecommerce-protection' ); ?></p>
			</div>

			<!-- Subsubsub Filter Links -->
			<ul class="subsub sentinelwp-subsub">
				<li class="cur">
					<a href="#all" class="sentinelwp-tab-filter" data-filter="all"><?php esc_html_e( 'All', 'sentinelguard-ecommerce-protection' ); ?></a> <span>(<span id="sentinelwp-cnt-all"><?php echo (int) $counts['all']; ?></span>)</span>
				</li>
				<li>
					<a href="#critical" class="sentinelwp-tab-filter" data-filter="critical"><?php esc_html_e( 'Critical', 'sentinelguard-ecommerce-protection' ); ?></a> <span>(<span id="sentinelwp-cnt-critical"><?php echo (int) $counts['critical']; ?></span>)</span>
				</li>
				<li>
					<a href="#high" class="sentinelwp-tab-filter" data-filter="high"><?php esc_html_e( 'High', 'sentinelguard-ecommerce-protection' ); ?></a> <span>(<span id="sentinelwp-cnt-high"><?php echo (int) $counts['high']; ?></span>)</span>
				</li>
				<li>
					<a href="#medium" class="sentinelwp-tab-filter" data-filter="medium"><?php esc_html_e( 'Medium', 'sentinelguard-ecommerce-protection' ); ?></a> <span>(<span id="sentinelwp-cnt-medium"><?php echo (int) $counts['medium']; ?></span>)</span>
				</li>
				<li>
					<a href="#low" class="sentinelwp-tab-filter" data-filter="low"><?php esc_html_e( 'Low', 'sentinelguard-ecommerce-protection' ); ?></a> <span>(<span id="sentinelwp-cnt-low"><?php echo (int) $counts['low']; ?></span>)</span>
				</li>
				<li>
					<a href="#resolved" class="sentinelwp-tab-filter" data-filter="resolved"><?php esc_html_e( 'Resolved', 'sentinelguard-ecommerce-protection' ); ?></a> <span>(<span id="sentinelwp-cnt-resolved"><?php echo (int) $counts['resolved']; ?></span>)</span>
				</li>
			</ul>

			<!-- Tablenav Controls -->
			<div class="tablenav sentinelwp-tablenav">
				<select id="bulk-action-selector-top" name="action">
					<option value="-1"><?php esc_html_e( 'Bulk actions', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="resolve"><?php esc_html_e( 'Mark resolved', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="false_positive"><?php esc_html_e( 'Ignore', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="quarantine"><?php esc_html_e( 'Quarantine file', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="export_csv"><?php esc_html_e( 'Export CSV', 'sentinelguard-ecommerce-protection' ); ?></option>
				</select>
				<button type="button" class="btn btn-sec sentinelwp-btn-sec" id="sentinelwp-doaction"><?php esc_html_e( 'Apply', 'sentinelguard-ecommerce-protection' ); ?></button>

				<select id="sentinelwp-engine-filter">
					<option value=""><?php esc_html_e( 'All engines', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="local-heuristic"><?php esc_html_e( 'local-heuristic', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="database-audit"><?php esc_html_e( 'database-audit', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="magecart-guard"><?php esc_html_e( 'magecart-guard', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="nulled-detector"><?php esc_html_e( 'nulled-detector', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="ecommerce-guard"><?php esc_html_e( 'ecommerce-guard', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="flood-monitor"><?php esc_html_e( 'flood-monitor', 'sentinelguard-ecommerce-protection' ); ?></option>
				</select>

				<input type="search" id="sentinelwp-search-input" placeholder="<?php esc_attr_e( 'Search findings…', 'sentinelguard-ecommerce-protection' ); ?>" />
				<span class="count sentinelwp-count" id="sentinelwp-displaying-num"><?php 
				/* translators: %d: open item count */
				echo esc_html( sprintf( _n( '%d item', '%d items', $total_open, 'sentinelguard-ecommerce-protection' ), $total_open ) ); 
				?></span>
			</div>

			<!-- Findings List Table -->
			<div class="sentinelwp-table-responsive">
			<table class="sentinelwp-findings-table" id="sentinelwp-table">
				<thead>
					<tr>
						<th class="c-check"><input type="checkbox" id="cb-select-all-1"></th>
						<th class="c-sev"><?php esc_html_e( 'Severity', 'sentinelguard-ecommerce-protection' ); ?></th>
						<th><?php esc_html_e( 'Finding', 'sentinelguard-ecommerce-protection' ); ?></th>
						<th class="c-when"><?php esc_html_e( 'Detected', 'sentinelguard-ecommerce-protection' ); ?></th>
						<th class="c-status"><?php esc_html_e( 'Status', 'sentinelguard-ecommerce-protection' ); ?></th>
					</tr>
				</thead>
				<tbody id="the-list">
				<?php if ( empty( $findings ) ) : ?>
					<tr class="sentinelwp-empty-row">
						<td colspan="5" style="text-align:center; padding: 24px; color: var(--ink-3);">
							<?php esc_html_e( 'No open findings.', 'sentinelguard-ecommerce-protection' ); ?>
							<?php if ( $resolved_count > 0 ) : ?>
								<a href="#resolved" class="sentinelwp-tab-filter" data-filter="resolved" style="margin-left: 8px; color: var(--wp-blue);">
									<?php 
									/* translators: %d: resolved findings count */
									echo esc_html( sprintf( __( 'View %d resolved findings &rsaquo;', 'sentinelguard-ecommerce-protection' ), $resolved_count ) ); 
									?>
								</a>
							<?php endif; ?>
						</td>
					</tr>
				<?php endif; ?>

				<?php foreach ( $findings as $finding ) :
					$sev = strtolower( $finding->severity );
					$pill_class = 'p-' . $sev;
					$relative_detected = $this->get_relative_time( strtotime( $finding->created_at ) );
					$iso_date = mysql2date( 'Y-m-d H:i:s', $finding->created_at );
					$engine_tag = ! empty( $finding->source ) ? $finding->source : 'scanner';
					$human_title = $this->format_human_title( $finding->type, $finding->title, $finding->source );
					$human_path  = $this->format_human_path( $finding->type, $finding->source, $finding->title );
					$engine_slug = $this->format_engine_slug( $finding->type, $finding->source );
					$module_key  = $this->get_module_for_type( $finding->type );
					?>
					<tr class="sentinelwp-finding-row" data-id="<?php echo esc_attr( $finding->id ); ?>" data-severity="<?php echo esc_attr( $sev ); ?>" data-source="<?php echo esc_attr( $finding->source ); ?>" data-type="<?php echo esc_attr( $finding->type ); ?>" data-engine="<?php echo esc_attr( $engine_slug ); ?>" data-module="<?php echo esc_attr( $module_key ); ?>" data-status="open">
						<td class="c-check">
							<input type="checkbox" name="finding_ids[]" value="<?php echo esc_attr( $finding->id ); ?>" />
						</td>
						<td class="c-sev">
							<span class="pill <?php echo esc_attr( $pill_class ); ?>">
								<?php echo esc_html( ucfirst( $sev ) ); ?>
							</span>
						</td>
						<td>
							<span class="title">
								<a href="#" class="sentinelwp-disclosure-toggle" aria-expanded="false">
									<?php echo esc_html( $human_title ); ?>
								</a>
							</span>
							<?php if ( ! empty( $human_path ) ) : ?>
								<code class="path"><?php echo esc_html( $human_path ); ?></code>
							<?php endif; ?>
							<span class="src"><?php echo esc_html( $engine_slug ); ?></span>
							<div class="rowact sentinelwp-rowact">
								<a href="#" class="sentinelwp-disclosure-toggle"><?php esc_html_e( 'View details', 'sentinelguard-ecommerce-protection' ); ?></a>
								<span>|</span>
								<a href="#" class="sentinelwp-action-quarantine" data-id="<?php echo esc_attr( $finding->id ); ?>"><?php esc_html_e( 'Quarantine', 'sentinelguard-ecommerce-protection' ); ?></a>
								<span>|</span>
								<a href="#" class="sentinelwp-action-resolve" data-id="<?php echo esc_attr( $finding->id ); ?>"><?php esc_html_e( 'Mark resolved', 'sentinelguard-ecommerce-protection' ); ?></a>
								<span>|</span>
								<a href="#" class="sentinelwp-action-fp" data-id="<?php echo esc_attr( $finding->id ); ?>"><?php esc_html_e( 'Ignore', 'sentinelguard-ecommerce-protection' ); ?></a>
							</div>
						</td>
						<td class="c-when" title="<?php echo esc_attr( $iso_date ); ?>">
							<?php echo esc_html( $relative_detected ); ?>
						</td>
						<td class="c-status">
							<span class="status open"><?php esc_html_e( 'Open', 'sentinelguard-ecommerce-protection' ); ?></span>
						</td>
					</tr>

					<!-- Expandable Inline Detail Panel Row -->
					<tr class="sentinelwp-detail-row" id="detail-<?php echo esc_attr( $finding->id ); ?>" style="display: none;">
						<td colspan="5">
							<div class="sentinelwp-detail-box">
								<div class="sentinelwp-detail-grid">
									<div class="sentinelwp-detail-col">
										<h4><?php esc_html_e( 'Evidence & Detection Match', 'sentinelguard-ecommerce-protection' ); ?></h4>
										<?php if ( ! empty( $finding->details ) ) : ?>
											<pre class="sentinelwp-code-block"><code><?php echo esc_html( $finding->details ); ?></code></pre>
										<?php else : ?>
											<p style="color:var(--ink-3); font-size:12px; margin:0 0 10px;"><?php esc_html_e( 'Heuristic pattern matched during file traversal.', 'sentinelguard-ecommerce-protection' ); ?></p>
										<?php endif; ?>

										<?php if ( ! empty( $finding->ai_verdict ) ) : ?>
											<div class="sentinelwp-ai-verdict-box">
												<strong><?php esc_html_e( 'AI Security Verdict:', 'sentinelguard-ecommerce-protection' ); ?></strong>
												<span><?php echo esc_html( ucfirst( $finding->ai_verdict ) ); ?> &mdash; <?php echo esc_html( $finding->ai_reason ); ?></span>
											</div>
										<?php endif; ?>
									</div>

									<div class="sentinelwp-detail-col">
										<h4><?php esc_html_e( 'Context & Remediation', 'sentinelguard-ecommerce-protection' ); ?></h4>
										<table class="sentinelwp-meta-mini-table">
											<tr>
												<th><?php esc_html_e( 'Confidence', 'sentinelguard-ecommerce-protection' ); ?>:</th>
												<td>
													<span class="sentinelwp-conf-badge conf-<?php echo esc_attr( ! empty( $finding->confidence ) ? $finding->confidence : 'likely' ); ?>">
														<?php echo esc_html( ucfirst( ! empty( $finding->confidence ) ? $finding->confidence : 'Likely' ) ); ?>
													</span>
												</td>
											</tr>
											<tr>
												<th><?php esc_html_e( 'Detector', 'sentinelguard-ecommerce-protection' ); ?>:</th>
												<td><code><?php echo esc_html( ! empty( $finding->detector ) ? $finding->detector : $engine_slug ); ?></code></td>
											</tr>
											<tr>
												<th><?php esc_html_e( 'Type', 'sentinelguard-ecommerce-protection' ); ?>:</th>
												<td><code><?php echo esc_html( $finding->type ); ?></code></td>
											</tr>
											<tr>
												<th><?php esc_html_e( 'Source', 'sentinelguard-ecommerce-protection' ); ?>:</th>
												<td><code><?php echo esc_html( $finding->source ); ?></code></td>
											</tr>
											<tr>
												<th><?php esc_html_e( 'Detected', 'sentinelguard-ecommerce-protection' ); ?>:</th>
												<td><?php echo esc_html( $iso_date ); ?></td>
											</tr>
										</table>

										<?php if ( ! empty( $finding->remediation ) ) : ?>
											<div class="sentinelwp-remediation-box" style="margin: 10px 0; padding: 10px; background: var(--bg); border-left: 3px solid var(--wp-blue); font-size: 12px;">
												<strong><?php esc_html_e( 'Recommended Action:', 'sentinelguard-ecommerce-protection' ); ?></strong>
												<p style="margin: 4px 0 0;"><?php echo esc_html( $finding->remediation ); ?></p>
											</div>
										<?php endif; ?>

										<div class="sentinelwp-detail-actions">
											<button type="button" class="btn btn-primary sentinelwp-action-resolve" data-id="<?php echo esc_attr( $finding->id ); ?>">
												<?php esc_html_e( 'Mark resolved', 'sentinelguard-ecommerce-protection' ); ?>
											</button>
											<button type="button" class="btn btn-sec sentinelwp-action-quarantine" data-id="<?php echo esc_attr( $finding->id ); ?>">
												<?php esc_html_e( 'Quarantine file', 'sentinelguard-ecommerce-protection' ); ?>
											</button>
											<button type="button" class="btn btn-sec sentinelwp-action-fp" data-id="<?php echo esc_attr( $finding->id ); ?>">
												<?php esc_html_e( 'Ignore', 'sentinelguard-ecommerce-protection' ); ?>
											</button>
										</div>
									</div>
								</div>
							</div>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			</div>

			<!-- Tablenav Bottom -->
			<div class="tablenav bottom sentinelwp-tablenav sentinelwp-tablenav-bottom">
				<select id="bulk-action-selector-bottom" name="action2">
					<option value="-1"><?php esc_html_e( 'Bulk actions', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="resolve"><?php esc_html_e( 'Mark resolved', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="false_positive"><?php esc_html_e( 'Ignore', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="quarantine"><?php esc_html_e( 'Quarantine file', 'sentinelguard-ecommerce-protection' ); ?></option>
					<option value="export_csv"><?php esc_html_e( 'Export CSV', 'sentinelguard-ecommerce-protection' ); ?></option>
				</select>
				<button type="button" class="btn btn-sec sentinelwp-btn-sec" id="sentinelwp-doaction2"><?php esc_html_e( 'Apply', 'sentinelguard-ecommerce-protection' ); ?></button>
				<span class="count sentinelwp-count" id="sentinelwp-bottom-item-count"><?php /* translators: %d: open finding count */ echo esc_html( sprintf( _n( '%d item', '%d items', $total_open, 'sentinelguard-ecommerce-protection' ), $total_open ) ); ?></span>
			</div>

			<!-- Threat Protection Modules Section -->
			<?php $this->render_ecommerce_dashboard(); ?>

			<!-- Footer Meta -->
			<footer>
				<span><?php /* translators: %s: plugin version string */ echo esc_html( sprintf( __( 'SentinelWP Security v%s', 'sentinelguard-ecommerce-protection' ), SENTINELWP_VERSION ) ); ?></span> &middot;
				<span><?php esc_html_e( 'Definitions 2026.08-rev1', 'sentinelguard-ecommerce-protection' ); ?></span> &middot;
				<a href="https://sentinelwp.io/docs" target="_blank"><?php esc_html_e( 'Documentation', 'sentinelguard-ecommerce-protection' ); ?></a> &middot;
				<a href="https://sentinelwp.io/support" target="_blank"><?php esc_html_e( 'Support', 'sentinelguard-ecommerce-protection' ); ?></a>
			</footer>
		</div>
		<?php
	}

	/**
	 * Threat Protection Modules Grid (Threat Detection Modules).
	 */
	private function render_ecommerce_dashboard() {
		global $wpdb;
		$table = $wpdb->prefix . 'sentinelwp_findings';

		$modules_raw = array(
			'fraud' => array(
				'title' => __( 'Checkout & Card-Testing Defense', 'sentinelguard-ecommerce-protection' ),
				'desc'  => __( 'Monitors failed payment bursts, card testing attacks, rapid order velocity, and disposable emails.', 'sentinelguard-ecommerce-protection' ),
				'types' => array( 'order_velocity', 'card_testing', 'disposable_email', 'order_anomaly', 'refund_spike', 'complaint_pattern' ),
			),
			'skimmer' => array(
				'title' => __( 'Magecart & Checkout Script Guard', 'sentinelguard-ecommerce-protection' ),
				'desc'  => __( 'Continuous static & runtime scanning of JavaScript for credit card harvesting and checkout form hijacking.', 'sentinelguard-ecommerce-protection' ),
				'types' => array( 'checkout_skimmer', 'fake_image_payload', 'db_script_injection' ),
			),
			'flood' => array(
				'title' => __( 'Store API & Bot Traffic Defense', 'sentinelguard-ecommerce-protection' ),
				'desc'  => __( 'Sliding-window rate limiting on /checkout and Store API endpoints with proxy-aware IP enforcement.', 'sentinelguard-ecommerce-protection' ),
				'types' => array( 'flood_detected' ),
			),
			'integrity' => array(
				'title' => __( 'Store Gateway & Config Integrity', 'sentinelguard-ecommerce-protection' ),
				'desc'  => __( 'Detects unauthorized gateway credential changes, checkout page tampering, and modified core files.', 'sentinelguard-ecommerce-protection' ),
				'types' => array( 'store_config_changed', 'suspicious_file', 'malware_signature', 'core_integrity' ),
			),
			'admin' => array(
				'title' => __( 'Admin Account & Backdoor Guard', 'sentinelguard-ecommerce-protection' ),
				'desc'  => __( 'Real-time role-elevation detection, hidden database administrator auditor, and rogue capability checks.', 'sentinelguard-ecommerce-protection' ),
				'types' => array( 'hidden_admin_detected', 'unauthorized_admin_creation', 'admin_role_granted', 'suspicious_admin_username', 'orphaned_admin_meta', 'suspicious_user_filter', 'weak_username' ),
			),
			'nulled' => array(
				'title' => __( 'Nulled Plugin & Theme Detector', 'sentinelguard-ecommerce-protection' ),
				'desc'  => __( 'Identifies pirated software distributions, backdoor files, phone-home beacons, and license bypass routines.', 'sentinelguard-ecommerce-protection' ),
				'types' => array( 'nulled_plugin', 'nulled_malicious_file', 'nulled_license_bypass', 'nulled_wporg_mismatch', 'nulled_phonehome_call', 'nulled_phonehome_base64', 'nulled_suspicious_filename' ),
			),
		);

		// Calculate count for sorting directly from in-memory $findings
		$modules = array();
		$active_module_count = 0;
		foreach ( $modules_raw as $k => $mod ) {
			$types = $mod['types'];
			$count = 0;
			if ( ! empty( $findings ) ) {
				foreach ( $findings as $f ) {
					if ( in_array( $f->type, $types, true ) ) {
						$count++;
					}
				}
			}
			$mod['count']  = $count;
			$modules[ $k ] = $mod;
			$active_module_count++;
		}

		// Sort: issue count descending, then alphabetically by title
		uasort( $modules, function ( $a, $b ) {
			if ( $a['count'] === $b['count'] ) {
				return strcmp( $a['title'], $b['title'] );
			}
			return $b['count'] - $a['count'];
		} );

		?>
		<div class="sec-head sentinelwp-sec-head" style="margin-top: 28px;">
			<h2><?php esc_html_e( 'Threat Detection Modules', 'sentinelguard-ecommerce-protection' ); ?></h2>
			<p><?php /* translators: 1: active module count, 2: total module count */ echo esc_html( sprintf( __( 'Active security engine status &middot; %1$d of %2$d active engines', 'sentinelguard-ecommerce-protection' ), $active_module_count, count( $modules_raw ) ) ); ?></p>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinelwp-security-settings&tab=modules' ) ); ?>">
				<?php esc_html_e( 'Manage in settings ›', 'sentinelguard-ecommerce-protection' ); ?>
			</a>
		</div>

		<div class="grid sentinelwp-grid">
			<?php foreach ( $modules as $key => $mod ) :
				$count = $mod['count'];
				$has_issues = $count > 0;
				?>
				<div class="card sentinelwp-card">
					<div class="top">
						<span class="nm"><?php echo esc_html( $mod['title'] ); ?></span>
						<?php if ( $has_issues ) : ?>
							<span class="chip bad">
								<?php /* translators: %d: findings count */ echo esc_html( sprintf( _n( '%d finding', '%d findings', $count, 'sentinelguard-ecommerce-protection' ), $count ) ); ?>
							</span>
						<?php else : ?>
							<span class="chip ok"><?php esc_html_e( 'Clear', 'sentinelguard-ecommerce-protection' ); ?></span>
						<?php endif; ?>
					</div>
					<p><?php echo esc_html( $mod['desc'] ); ?></p>
					<div class="foot">
						<span><?php esc_html_e( 'Last run 5m ago', 'sentinelguard-ecommerce-protection' ); ?></span>
						<?php if ( $has_issues ) : ?>
							<a href="#sentinelwp-table" class="sentinelwp-module-view-findings" data-module="<?php echo esc_attr( $key ); ?>">
								<?php esc_html_e( 'View findings ›', 'sentinelguard-ecommerce-protection' ); ?>
							</a>
						<?php else : ?>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinelwp-security-settings&tab=modules' ) ); ?>">
								<?php esc_html_e( 'Configure ›', 'sentinelguard-ecommerce-protection' ); ?>
							</a>
						<?php endif; ?>
					</div>
				</div>
			<?php endforeach; ?>
		</div>

		<?php
		// Checkout hook audit — Pro + WooCommerce only
		if ( SentinelWP_Freemium::can( 'checkout_hook_audit' ) && class_exists( 'WooCommerce' ) ) :
			$hooks = SentinelWP_Skimmer_Detector::instance()->audit_checkout_hooks();
			if ( ! empty( $hooks ) ) :
				?>
				<div class="sec-head sentinelwp-sec-head" style="margin-top: 24px;">
					<h2><?php esc_html_e( 'WooCommerce checkout hook audit', 'sentinelguard-ecommerce-protection' ); ?></h2>
					<p><?php esc_html_e( 'Live inventory of callbacks registered on checkout actions.', 'sentinelguard-ecommerce-protection' ); ?></p>
				</div>
				<table class="sentinelwp-findings-table">
					<thead>
						<tr>
							<th style="width: 240px;"><?php esc_html_e( 'Action Hook', 'sentinelguard-ecommerce-protection' ); ?></th>
							<th><?php esc_html_e( 'Registered Callback', 'sentinelguard-ecommerce-protection' ); ?></th>
							<th style="width: 180px;"><?php esc_html_e( 'Origin Source', 'sentinelguard-ecommerce-protection' ); ?></th>
							<th style="width: 80px;"><?php esc_html_e( 'Priority', 'sentinelguard-ecommerce-protection' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $hooks as $hook_info ) : ?>
						<tr>
							<td><code><?php echo esc_html( $hook_info['hook'] ); ?></code></td>
							<td><code><?php echo esc_html( $hook_info['callback'] ); ?></code></td>
							<td><span class="src"><?php echo esc_html( $hook_info['source'] ); ?></span></td>
							<td><?php echo esc_html( $hook_info['priority'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<?php
			endif;
		endif;
	}

	/* -------------------------------------------------------------- */
	/* 6. Settings Screen (nav-tab-wrapper + 5 Tabs)                   */
	/* -------------------------------------------------------------- */

	public function render_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'sentinelguard-ecommerce-protection' ) );
		}

		$current_tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'general';
		$valid_tabs  = array( 'general', 'scanning', 'modules', 'notifications', 'advanced' );
		if ( ! in_array( $current_tab, $valid_tabs, true ) ) {
			$current_tab = 'general';
		}
		?>
		<div class="wrap sentinelwp-wrap sentinelwp-settings-wrap">
			<h1 class="wp-heading-inline"><?php esc_html_e( 'SentinelWP Settings', 'sentinelguard-ecommerce-protection' ); ?></h1>
			<hr class="wp-header-end">

			<nav class="nav-tab-wrapper sentinelwp-nav-tab-wrapper" aria-label="<?php esc_attr_e( 'Settings Tabs', 'sentinelguard-ecommerce-protection' ); ?>">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinelwp-security-settings&tab=general' ) ); ?>" class="nav-tab <?php echo 'general' === $current_tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'General', 'sentinelguard-ecommerce-protection' ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinelwp-security-settings&tab=scanning' ) ); ?>" class="nav-tab <?php echo 'scanning' === $current_tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Scanning', 'sentinelguard-ecommerce-protection' ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinelwp-security-settings&tab=modules' ) ); ?>" class="nav-tab <?php echo 'modules' === $current_tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Modules', 'sentinelguard-ecommerce-protection' ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinelwp-security-settings&tab=notifications' ) ); ?>" class="nav-tab <?php echo 'notifications' === $current_tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Notifications', 'sentinelguard-ecommerce-protection' ); ?>
				</a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=sentinelwp-security-settings&tab=advanced' ) ); ?>" class="nav-tab <?php echo 'advanced' === $current_tab ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e( 'Advanced', 'sentinelguard-ecommerce-protection' ); ?>
				</a>
			</nav>

			<form method="post" action="options.php" id="sentinelwp-settings-form">
				<?php
				settings_fields( 'sentinelwp_settings' );

				switch ( $current_tab ) {
					case 'scanning':
						$this->render_tab_scanning();
						break;
					case 'modules':
						$this->render_tab_modules();
						break;
					case 'notifications':
						$this->render_tab_notifications();
						break;
					case 'advanced':
						$this->render_tab_advanced();
						break;
					case 'general':
					default:
						$this->render_tab_general();
						break;
				}
				?>

				<!-- Sticky Save Bar (appears when form is modified) -->
				<div class="sentinelwp-sticky-save" id="sentinelwp-sticky-save">
					<div class="sentinelwp-sticky-save-inner">
						<span class="sentinelwp-dirty-text"><?php esc_html_e( 'You have unsaved changes.', 'sentinelguard-ecommerce-protection' ); ?></span>
						<div class="sentinelwp-save-actions">
							<a href="" class="sentinelwp-link-muted" id="sentinelwp-discard-changes"><?php esc_html_e( 'Discard', 'sentinelguard-ecommerce-protection' ); ?></a>
							<?php submit_button( __( 'Save Changes', 'sentinelguard-ecommerce-protection' ), 'primary', 'submit', false ); ?>
						</div>
					</div>
				</div>
			</form>
		</div>
		<?php
	}

	/* Tab 1: General */
	private function render_tab_general() {
		$prot_level = get_option( 'sentinelwp_protection_level', 'balanced' );
		$site_role  = get_option( 'sentinelwp_site_role', class_exists( 'WooCommerce' ) ? 'woocommerce' : 'standard' );
		$retention  = (int) get_option( 'sentinelwp_data_retention', 90 );
		$hardening  = get_option( 'sentinelwp_hardening', array() );
		?>
		<div class="postbox sentinelwp-postbox">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'General Protection Profile', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<table class="form-table sentinelwp-form-table">
					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Protection Level', 'sentinelguard-ecommerce-protection' ); ?></label>
							<p class="description"><?php esc_html_e( 'Controls scan strictness and real-time response posture.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<fieldset class="sentinelwp-segmented-control">
								<label class="sentinelwp-seg-option <?php echo 'monitor' === $prot_level ? 'is-selected' : ''; ?>">
									<input type="radio" name="sentinelwp_protection_level" value="monitor" <?php checked( $prot_level, 'monitor' ); ?> />
									<?php esc_html_e( 'Monitor only', 'sentinelguard-ecommerce-protection' ); ?>
								</label>
								<label class="sentinelwp-seg-option <?php echo 'balanced' === $prot_level ? 'is-selected' : ''; ?>">
									<input type="radio" name="sentinelwp_protection_level" value="balanced" <?php checked( $prot_level, 'balanced' ); ?> />
									<?php esc_html_e( 'Balanced (Recommended)', 'sentinelguard-ecommerce-protection' ); ?>
								</label>
								<label class="sentinelwp-seg-option <?php echo 'aggressive' === $prot_level ? 'is-selected' : ''; ?>">
									<input type="radio" name="sentinelwp_protection_level" value="aggressive" <?php checked( $prot_level, 'aggressive' ); ?> />
									<?php esc_html_e( 'Aggressive', 'sentinelguard-ecommerce-protection' ); ?>
								</label>
							</fieldset>
							<p class="description sentinelwp-helper-line">
								<?php esc_html_e( 'Balanced mode enforces core checksum validation, standard rate tracking, and daily Magecart scans.', 'sentinelguard-ecommerce-protection' ); ?>
							</p>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Site Role & Commerce Mode', 'sentinelguard-ecommerce-protection' ); ?></label>
							<p class="description"><?php esc_html_e( 'Enables checkout protection and fraud detection.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<select name="sentinelwp_site_role" class="regular-text">
								<option value="standard" <?php selected( $site_role, 'standard' ); ?>><?php esc_html_e( 'Standard Content Site (Blog / Business)', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="woocommerce" <?php selected( $site_role, 'woocommerce' ); ?>><?php esc_html_e( 'WooCommerce Store (Full Commerce Guard)', 'sentinelguard-ecommerce-protection' ); ?></option>
							</select>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Findings Data Retention', 'sentinelguard-ecommerce-protection' ); ?></label>
						</th>
						<td>
							<select name="sentinelwp_data_retention">
								<option value="30" <?php selected( $retention, 30 ); ?>><?php esc_html_e( '30 days', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="90" <?php selected( $retention, 90 ); ?>><?php esc_html_e( '90 days (Default)', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="365" <?php selected( $retention, 365 ); ?>><?php esc_html_e( '365 days', 'sentinelguard-ecommerce-protection' ); ?></option>
							</select>
							<p class="description"><?php esc_html_e( 'Resolved and acknowledged findings older than this period are automatically pruned.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<div class="postbox sentinelwp-postbox">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'Baseline WordPress Hardening', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<table class="form-table sentinelwp-form-table">
					<?php
					$toggles = array(
						'disable_file_edit'   => __( 'Disable theme/plugin file editor (DISALLOW_FILE_EDIT)', 'sentinelguard-ecommerce-protection' ),
						'hide_wp_version'     => __( 'Hide WordPress generator meta tag from public HTML', 'sentinelguard-ecommerce-protection' ),
						'disable_xmlrpc'      => __( 'Disable XML-RPC pingback methods against brute force', 'sentinelguard-ecommerce-protection' ),
						'disable_user_enum'   => __( 'Block author-scan user enumeration (?author=N query)', 'sentinelguard-ecommerce-protection' ),
						'login_attempt_limit' => __( 'Limit failed login attempts (5 failures &rarr; 15m lockout)', 'sentinelguard-ecommerce-protection' ),
						'security_headers'    => __( 'Send baseline security headers (X-Frame-Options, X-Content-Type-Options)', 'sentinelguard-ecommerce-protection' ),
					);
					foreach ( $toggles as $key => $label ) :
						?>
						<tr>
							<th scope="row"><?php echo esc_html( $label ); ?></th>
							<td>
								<label class="sentinelwp-switch">
									<input type="checkbox" name="sentinelwp_hardening[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( ! empty( $hardening[ $key ] ) ); ?> />
									<span class="sentinelwp-slider"></span>
								</label>
							</td>
						</tr>
					<?php endforeach; ?>
				</table>
			</div>
		</div>
		<?php
	}

	/* Tab 2: Scanning */
	private function render_tab_scanning() {
		$schedule    = get_option( 'sentinelwp_scan_schedule', 'daily' );
		$scan_time   = get_option( 'sentinelwp_scan_time', '03:00' );
		$depth       = get_option( 'sentinelwp_scan_depth', 'standard' );
		$exclusions  = get_option( 'sentinelwp_path_exclusions', '' );
		$duration    = (int) get_option( 'sentinelwp_max_scan_duration', 300 );
		$vuln_source = get_option( 'sentinelwp_vuln_source', 'wordpress_org' );
		?>
		<div class="postbox sentinelwp-postbox">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'Scan Schedule & Depth', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<table class="form-table sentinelwp-form-table">
					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Automated Scan Frequency', 'sentinelguard-ecommerce-protection' ); ?></label>
							<p class="description"><?php /* translators: %s: site timezone string */ echo esc_html( sprintf( __( 'Site timezone: %s', 'sentinelguard-ecommerce-protection' ), wp_timezone_string() ) ); ?></p>
						</th>
						<td>
							<select name="sentinelwp_scan_schedule">
								<option value="off" <?php selected( $schedule, 'off' ); ?>><?php esc_html_e( 'Off (Manual only)', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="daily" <?php selected( $schedule, 'daily' ); ?>><?php esc_html_e( 'Daily (Recommended)', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="twicedaily" <?php selected( $schedule, 'twicedaily' ); ?>><?php esc_html_e( 'Twice Daily', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="weekly" <?php selected( $schedule, 'weekly' ); ?>><?php esc_html_e( 'Weekly', 'sentinelguard-ecommerce-protection' ); ?></option>
							</select>
							<input type="text" name="sentinelwp_scan_time" value="<?php echo esc_attr( $scan_time ); ?>" class="small-text" placeholder="03:00" />
							<span class="description"><?php esc_html_e( 'Preferred run time (24h format)', 'sentinelguard-ecommerce-protection' ); ?></span>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Scan Depth', 'sentinelguard-ecommerce-protection' ); ?></label>
						</th>
						<td>
							<select name="sentinelwp_scan_depth">
								<option value="quick" <?php selected( $depth, 'quick' ); ?>><?php esc_html_e( 'Quick (~10s) — Core checksums & DB admins only', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="standard" <?php selected( $depth, 'standard' ); ?>><?php esc_html_e( 'Standard (~45s) — Full plugin, theme, and skimmer scan', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="deep" <?php selected( $depth, 'deep' ); ?>><?php esc_html_e( 'Deep (~2m) — Full upload tree and database options audit', 'sentinelguard-ecommerce-protection' ); ?></option>
							</select>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Path Exclusions', 'sentinelguard-ecommerce-protection' ); ?></label>
							<p class="description"><?php esc_html_e( 'One glob path per line to ignore from file scans.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<textarea name="sentinelwp_path_exclusions" rows="4" cols="50" class="large-text code sentinelwp-mono-input" placeholder="wp-content/uploads/cache/*&#10;wp-content/backup-*"><?php echo esc_textarea( $exclusions ); ?></textarea>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Resource Guard (Max Duration)', 'sentinelguard-ecommerce-protection' ); ?></label>
						</th>
						<td>
							<input type="number" name="sentinelwp_max_scan_duration" value="<?php echo esc_attr( $duration ); ?>" min="60" max="1800" class="small-text" />
							<span class="description"><?php esc_html_e( 'Seconds before a scan safely yields to prevent timeouts.', 'sentinelguard-ecommerce-protection' ); ?></span>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<div class="postbox sentinelwp-postbox">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'Vulnerability Intelligence Feeds', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<table class="form-table sentinelwp-form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Vulnerability Source', 'sentinelguard-ecommerce-protection' ); ?></th>
						<td>
							<select name="sentinelwp_vuln_source">
								<option value="wordpress_org" <?php selected( $vuln_source, 'wordpress_org' ); ?>><?php esc_html_e( 'WordPress.org Official API (No key needed)', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="patchstack" <?php selected( $vuln_source, 'patchstack' ); ?>><?php esc_html_e( 'Patchstack Database', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="wpscan" <?php selected( $vuln_source, 'wpscan' ); ?>><?php esc_html_e( 'WPScan Vulnerability Database', 'sentinelguard-ecommerce-protection' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="sentinelwp_patchstack_key"><?php esc_html_e( 'Patchstack API Key', 'sentinelguard-ecommerce-protection' ); ?></label></th>
						<td><input type="password" id="sentinelwp_patchstack_key" name="sentinelwp_patchstack_key" value="<?php echo esc_attr( $this->mask_key( get_option( 'sentinelwp_patchstack_key', '' ) ) ); ?>" class="regular-text" autocomplete="off" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="sentinelwp_wpscan_key"><?php esc_html_e( 'WPScan API Key', 'sentinelguard-ecommerce-protection' ); ?></label></th>
						<td><input type="password" id="sentinelwp_wpscan_key" name="sentinelwp_wpscan_key" value="<?php echo esc_attr( $this->mask_key( get_option( 'sentinelwp_wpscan_key', '' ) ) ); ?>" class="regular-text" autocomplete="off" /></td>
					</tr>
				</table>
			</div>
		</div>

		<!-- Recent Scan Run History -->
		<div class="postbox sentinelwp-postbox" id="sentinelwp-scan-history-box">
			<?php $history = SentinelWP_Scan_Coordinator::instance()->get_scan_history(); ?>
			<div class="postbox-header" style="display:flex; justify-content:space-between; align-items:center; padding-right:12px;">
				<h2>
					<?php esc_html_e( 'Recent Scan Run History', 'sentinelguard-ecommerce-protection' ); ?>
					<span style="font-size:12px; font-weight:normal; color:#646970; margin-left:8px;"><?php esc_html_e( '(Automatic 30-day purge active)', 'sentinelguard-ecommerce-protection' ); ?></span>
				</h2>
				<?php if ( ! empty( $history ) ) : ?>
					<button type="button" class="button button-secondary" id="sentinelwp-btn-clear-scan-history" style="font-size:12px; height:28px; line-height:26px;">
						<span class="dashicons dashicons-trash" style="font-size:14px; line-height:26px; vertical-align:middle;"></span>
						<?php esc_html_e( 'Clear Scan History', 'sentinelguard-ecommerce-protection' ); ?>
					</button>
				<?php endif; ?>
			</div>
			<div class="inside">
				<?php if ( empty( $history ) ) : ?>
					<p class="description"><?php esc_html_e( 'No previous scan runs recorded yet. Click "Run deep scan" on the dashboard to generate your first scan run report.', 'sentinelguard-ecommerce-protection' ); ?></p>
				<?php else : ?>
					<table class="wp-list-table widefat fixed striped sentinelwp-history-table">
						<thead>
							<tr>
								<th style="width: 170px;"><?php esc_html_e( 'Date & Time', 'sentinelguard-ecommerce-protection' ); ?></th>
								<th style="width: 110px;"><?php esc_html_e( 'Status', 'sentinelguard-ecommerce-protection' ); ?></th>
								<th style="width: 90px;"><?php esc_html_e( 'Duration', 'sentinelguard-ecommerce-protection' ); ?></th>
								<th style="width: 100px;"><?php esc_html_e( 'Peak Memory', 'sentinelguard-ecommerce-protection' ); ?></th>
								<th style="width: 130px;"><?php esc_html_e( 'Open Findings', 'sentinelguard-ecommerce-protection' ); ?></th>
								<th><?php esc_html_e( 'Engine Phases & Timings', 'sentinelguard-ecommerce-protection' ); ?></th>
								<th style="width: 60px; text-align:center;"><?php esc_html_e( 'Action', 'sentinelguard-ecommerce-protection' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $history as $run ) : 
								$status_class = ( 'completed' === ( $run['status'] ?? '' ) ) ? 'resolved' : 'open';
								$status_label = ucfirst( $run['status'] ?? 'Completed' );
								$run_id       = isset( $run['id'] ) ? (int) $run['id'] : 0;
								?>
								<tr data-run-id="<?php echo esc_attr( $run_id ); ?>">
									<td>
										<strong><?php echo esc_html( $run['timestamp'] ?? 'N/A' ); ?></strong>
									</td>
									<td>
										<span class="status <?php echo esc_attr( $status_class ); ?>"><?php echo esc_html( $status_label ); ?></span>
									</td>
									<td>
										<?php echo esc_html( sprintf( '%.2fs', $run['total_time'] ?? 0 ) ); ?>
									</td>
									<td>
										<?php echo esc_html( sprintf( '%.1f MB', $run['peak_memory'] ?? 0 ) ); ?>
									</td>
									<td>
										<?php if ( ! empty( $run['critical_count'] ) ) : ?>
											<span class="badge badge-critical" style="font-size:11px; padding:2px 6px;"><?php echo esc_html( $run['critical_count'] . ' Critical' ); ?></span>
										<?php endif; ?>
										<span><?php /* translators: %d: open finding count */ echo esc_html( sprintf( __( '%d open', 'sentinelguard-ecommerce-protection' ), $run['open_findings'] ?? 0 ) ); ?></span>
									</td>
									<td>
										<?php
										if ( ! empty( $run['phases'] ) && is_array( $run['phases'] ) ) {
											$phase_badges = array();
											foreach ( $run['phases'] as $pkey => $pdata ) {
												$dur = isset( $pdata['duration'] ) ? sprintf( '%.2fs', $pdata['duration'] ) : '';
												$phase_badges[] = '<code style="font-size:11px; margin-right:4px;">' . esc_html( ucfirst( $pkey ) . ': ' . $dur ) . '</code>';
											}
											echo wp_kses_post( implode( ' ', $phase_badges ) );
										} else {
											esc_html_e( 'All 6 core phases completed', 'sentinelguard-ecommerce-protection' );
										}
										?>
									</td>
									<td style="text-align:center;">
										<button type="button" class="button-link-delete sentinelwp-delete-scan-run" data-id="<?php echo esc_attr( $run_id ); ?>" title="<?php esc_attr_e( 'Delete this scan run', 'sentinelguard-ecommerce-protection' ); ?>" style="cursor:pointer; border:none; background:none; color:#a00;">
											<span class="dashicons dashicons-trash" style="font-size:16px;"></span>
										</button>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/* Tab 3: Modules */
	private function render_tab_modules() {
		$flood_enabled  = (bool) get_option( 'sentinelwp_flood_enabled', true );
		$form_enabled   = (bool) get_option( 'sentinelwp_form_shield_enabled', true );
		$ecom_enabled   = (bool) get_option( 'sentinelwp_ecommerce_guard_enabled', true );
		$fraud_hold     = (bool) get_option( 'sentinelwp_fraud_auto_hold', false );
		$disp_email     = (bool) get_option( 'sentinelwp_disposable_email_check', true );
		$threshold      = (int) get_option( 'sentinelwp_flood_threshold', 120 );
		$operating_mode = class_exists( 'SentinelWP_Risk_Engine' ) ? SentinelWP_Risk_Engine::instance()->get_mode() : 'observe';
		?>
		<div class="postbox sentinelwp-postbox" style="border-left: 4px solid #2271b1;">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'Pre-Gateway Threat Response Policy (Operating Mode)', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<p class="description" style="margin-bottom:14px; font-size:13px;">
					<?php esc_html_e( 'Controls how SentinelWP responds when high-confidence card testing or distributed bot clusters are detected at the Store API preflight gate.', 'sentinelguard-ecommerce-protection' ); ?>
				</p>
				<table class="form-table sentinelwp-form-table">
					<tr>
						<th scope="row">
							<strong><?php esc_html_e( 'Operating Mode', 'sentinelguard-ecommerce-protection' ); ?></strong>
						</th>
						<td>
							<fieldset>
								<label style="display:block; margin-bottom:10px;">
									<input type="radio" name="sentinelwp_operating_mode" value="observe" <?php checked( 'observe', $operating_mode ); ?> />
									<strong><?php esc_html_e( 'OBSERVE (Detection Only — Recommended)', 'sentinelguard-ecommerce-protection' ); ?></strong>
									<br><span class="description" style="margin-left:24px; display:block;"><?php esc_html_e( 'Risk scores and reason codes are calculated and logged into the Threat Timeline in real time. Zero customer checkout attempts will be blocked.', 'sentinelguard-ecommerce-protection' ); ?></span>
								</label>
								<label style="display:block; margin-bottom:10px;">
									<input type="radio" name="sentinelwp_operating_mode" value="protect" <?php checked( 'protect', $operating_mode ); ?> />
									<strong><?php esc_html_e( 'PROTECT (Adaptive Shield)', 'sentinelguard-ecommerce-protection' ); ?></strong>
									<br><span class="description" style="margin-left:24px; display:block;"><?php esc_html_e( 'Challenges or soft-throttles high-confidence carding clusters and repeated payment failure bursts (>75% risk).', 'sentinelguard-ecommerce-protection' ); ?></span>
								</label>
								<label style="display:block;">
									<input type="radio" name="sentinelwp_operating_mode" value="lockdown" <?php checked( 'lockdown', $operating_mode ); ?> />
									<strong><?php esc_html_e( 'LOCKDOWN (Under Active Attack)', 'sentinelguard-ecommerce-protection' ); ?></strong>
									<br><span class="description" style="margin-left:24px; display:block;"><?php esc_html_e( 'Strictly blocks confirmed attack clusters (>85% risk with corroborating failure velocity). Recommended during active high-volume card testing campaigns.', 'sentinelguard-ecommerce-protection' ); ?></span>
								</label>
							</fieldset>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<div class="postbox sentinelwp-postbox">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'Active Threat Engines (12 Core Engines)', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<table class="form-table sentinelwp-form-table">
					<tr>
						<th scope="row">
							<strong><?php esc_html_e( 'Magecart & JavaScript Skimmer Engine', 'sentinelguard-ecommerce-protection' ); ?></strong>
							<p class="description"><?php esc_html_e( 'Scans JavaScript files and fake images for payment field scraping.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<span class="sentinelwp-chip sentinelwp-chip-active"><?php esc_html_e( 'Always Active', 'sentinelguard-ecommerce-protection' ); ?></span>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<strong><?php esc_html_e( 'Nulled Software & Backdoor Scanner', 'sentinelguard-ecommerce-protection' ); ?></strong>
							<p class="description"><?php esc_html_e( 'Flags pirated themes, phonehome domains, and license bypass routines.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<span class="sentinelwp-chip sentinelwp-chip-active"><?php esc_html_e( 'Always Active', 'sentinelguard-ecommerce-protection' ); ?></span>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<strong><?php esc_html_e( 'Admin Role & Hidden Database User Guard', 'sentinelguard-ecommerce-protection' ); ?></strong>
							<p class="description"><?php esc_html_e( 'Monitors unauthorized admin additions and hidden database accounts.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<span class="sentinelwp-chip sentinelwp-chip-active"><?php esc_html_e( 'Always Active', 'sentinelguard-ecommerce-protection' ); ?></span>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label for="sentinelwp_flood_enabled"><strong><?php esc_html_e( 'Application-Layer Flood & DDoS Monitor', 'sentinelguard-ecommerce-protection' ); ?></strong></label>
							<p class="description"><?php esc_html_e( 'Tracks per-IP request rates without database bloat.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<label class="sentinelwp-switch">
								<input type="checkbox" id="sentinelwp_flood_enabled" name="sentinelwp_flood_enabled" value="1" <?php checked( $flood_enabled ); ?> />
								<span class="sentinelwp-slider"></span>
							</label>
							<div class="sentinelwp-inline-settings">
								<label><?php esc_html_e( 'Alert Threshold (req/min):', 'sentinelguard-ecommerce-protection' ); ?></label>
								<input type="number" name="sentinelwp_flood_threshold" value="<?php echo esc_attr( $threshold ); ?>" min="30" max="600" class="small-text" />
							</div>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label for="sentinelwp_form_shield_enabled"><strong><?php esc_html_e( 'Form Shield & Honeypot Protection', 'sentinelguard-ecommerce-protection' ); ?></strong></label>
							<p class="description"><?php esc_html_e( 'Rate-limits comment, registration, and login page requests.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<label class="sentinelwp-switch">
								<input type="checkbox" id="sentinelwp_form_shield_enabled" name="sentinelwp_form_shield_enabled" value="1" <?php checked( $form_enabled ); ?> />
								<span class="sentinelwp-slider"></span>
							</label>
						</td>
					</tr>

					<?php if ( class_exists( 'WooCommerce' ) ) : ?>
					<tr>
						<th scope="row">
							<label for="sentinelwp_ecommerce_guard_enabled"><strong><?php esc_html_e( 'WooCommerce Fraud & Card Testing Guard', 'sentinelguard-ecommerce-protection' ); ?></strong></label>
							<p class="description"><?php esc_html_e( 'Detects high-velocity checkout bursts and failed card attempts.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<label class="sentinelwp-switch">
								<input type="checkbox" id="sentinelwp_ecommerce_guard_enabled" name="sentinelwp_ecommerce_guard_enabled" value="1" <?php checked( $ecom_enabled ); ?> />
								<span class="sentinelwp-slider"></span>
							</label>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label for="sentinelwp_fraud_auto_hold"><strong><?php esc_html_e( 'Auto-Hold High-Velocity Orders', 'sentinelguard-ecommerce-protection' ); ?></strong></label>
							<p class="description"><?php esc_html_e( 'Sets suspicious orders to on-hold status for manual verification.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<label class="sentinelwp-switch">
								<input type="checkbox" id="sentinelwp_fraud_auto_hold" name="sentinelwp_fraud_auto_hold" value="1" <?php checked( $fraud_hold ); ?> />
								<span class="sentinelwp-slider"></span>
							</label>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label for="sentinelwp_disposable_email_check"><strong><?php esc_html_e( 'Disposable Email Domain Filter', 'sentinelguard-ecommerce-protection' ); ?></strong></label>
							<p class="description"><?php esc_html_e( 'Flags orders created using temporary disposable email providers.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<label class="sentinelwp-switch">
								<input type="checkbox" id="sentinelwp_disposable_email_check" name="sentinelwp_disposable_email_check" value="1" <?php checked( $disp_email ); ?> />
								<span class="sentinelwp-slider"></span>
							</label>
						</td>
					</tr>
					<?php endif; ?>
				</table>
			</div>
		</div>
		<?php
	}

	/* Tab 4: Notifications */
	private function render_tab_notifications() {
		$threshold  = get_option( 'sentinelwp_alert_threshold', 'high' );
		$recipients = get_option( 'sentinelwp_alert_recipients', get_option( 'admin_email' ) );
		$digest     = get_option( 'sentinelwp_alert_digest', 'instant' );
		$webhook    = get_option( 'sentinelwp_alert_webhook', '' );
		?>
		<div class="postbox sentinelwp-postbox">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'Email & Webhook Alerts', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<table class="form-table sentinelwp-form-table">
					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Notification Severity Threshold', 'sentinelguard-ecommerce-protection' ); ?></label>
							<p class="description"><?php esc_html_e( 'Only notify when findings meet or exceed this level.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<select name="sentinelwp_alert_threshold">
								<option value="critical" <?php selected( $threshold, 'critical' ); ?>><?php esc_html_e( 'Critical Only', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="high" <?php selected( $threshold, 'high' ); ?>><?php esc_html_e( 'High & Critical (Recommended)', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="medium" <?php selected( $threshold, 'medium' ); ?>><?php esc_html_e( 'Medium, High & Critical', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="low" <?php selected( $threshold, 'low' ); ?>><?php esc_html_e( 'All Findings (Including Low)', 'sentinelguard-ecommerce-protection' ); ?></option>
							</select>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Recipient Email Addresses', 'sentinelguard-ecommerce-protection' ); ?></label>
							<p class="description"><?php esc_html_e( 'One email per line.', 'sentinelguard-ecommerce-protection' ); ?></p>
						</th>
						<td>
							<textarea name="sentinelwp_alert_recipients" rows="3" cols="50" class="regular-text"><?php echo esc_textarea( $recipients ); ?></textarea>
							<div style="margin-top: 8px;">
								<button type="button" class="button button-secondary" id="sentinelwp-send-test-email">
									<?php esc_html_e( 'Send test email', 'sentinelguard-ecommerce-protection' ); ?>
								</button>
								<span id="sentinelwp-test-email-status" class="sentinelwp-inline-status"></span>
							</div>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label><?php esc_html_e( 'Alert Digest Mode', 'sentinelguard-ecommerce-protection' ); ?></label>
						</th>
						<td>
							<label style="margin-right: 16px;">
								<input type="radio" name="sentinelwp_alert_digest" value="instant" <?php checked( $digest, 'instant' ); ?> />
								<?php esc_html_e( 'Instant Alert (As soon as detected)', 'sentinelguard-ecommerce-protection' ); ?>
							</label>
							<label>
								<input type="radio" name="sentinelwp_alert_digest" value="daily" <?php checked( $digest, 'daily' ); ?> />
								<?php esc_html_e( 'Daily Summary Digest', 'sentinelguard-ecommerce-protection' ); ?>
							</label>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label for="sentinelwp_alert_webhook"><?php esc_html_e( 'Webhook URL (Slack / Discord / SIEM)', 'sentinelguard-ecommerce-protection' ); ?></label>
						</th>
						<td>
							<input type="url" id="sentinelwp_alert_webhook" name="sentinelwp_alert_webhook" value="<?php echo esc_attr( $webhook ); ?>" class="large-text" placeholder="https://hooks.slack.com/services/..." />
						</td>
					</tr>
				</table>
			</div>
		</div>
		<?php
	}

	/* Tab 5: Advanced */
	private function render_tab_advanced() {
		$debug       = (bool) get_option( 'sentinelwp_debug_logging', false );
		$channel     = get_option( 'sentinelwp_update_channel', 'stable' );
		$ai_provider = get_option( 'sentinelwp_ai_provider', '' );
		$uninstall   = (bool) get_option( 'sentinelwp_remove_data_on_uninstall', false );
		?>
		<div class="postbox sentinelwp-postbox">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'AI Code Analysis Configuration', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<p class="description">
					<?php esc_html_e( 'Optional second opinion layer. Code snippets (never credentials or PII) are evaluated to provide plain-language explanations.', 'sentinelguard-ecommerce-protection' ); ?>
				</p>
				<table class="form-table sentinelwp-form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'AI Provider', 'sentinelguard-ecommerce-protection' ); ?></th>
						<td>
							<select name="sentinelwp_ai_provider">
								<option value="" <?php selected( $ai_provider, '' ); ?>><?php esc_html_e( 'Disabled (Heuristic only)', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="claude" <?php selected( $ai_provider, 'claude' ); ?>>Claude (Anthropic)</option>
								<option value="openai" <?php selected( $ai_provider, 'openai' ); ?>>OpenAI (GPT-4o)</option>
								<option value="gemini" <?php selected( $ai_provider, 'gemini' ); ?>>Google Gemini</option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="sentinelwp_ai_api_key"><?php esc_html_e( 'AI Provider API Key', 'sentinelguard-ecommerce-protection' ); ?></label></th>
						<td>
							<input type="password" id="sentinelwp_ai_api_key" name="sentinelwp_ai_api_key" value="<?php echo esc_attr( $this->mask_key( get_option( 'sentinelwp_ai_api_key', '' ) ) ); ?>" class="regular-text" autocomplete="off" />
						</td>
					</tr>
				</table>
			</div>
		</div>

		<div class="postbox sentinelwp-postbox">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'Diagnostics & Updates', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<table class="form-table sentinelwp-form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Debug Logging', 'sentinelguard-ecommerce-protection' ); ?></th>
						<td>
							<label class="sentinelwp-switch">
								<input type="checkbox" name="sentinelwp_debug_logging" value="1" <?php checked( $debug ); ?> />
								<span class="sentinelwp-slider"></span>
							</label>
							<span class="description"><?php esc_html_e( 'Log detailed scanner execution traces to wp-content/debug.log.', 'sentinelguard-ecommerce-protection' ); ?></span>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Definitions Update Channel', 'sentinelguard-ecommerce-protection' ); ?></th>
						<td>
							<select name="sentinelwp_update_channel">
								<option value="stable" <?php selected( $channel, 'stable' ); ?>><?php esc_html_e( 'Stable (Tested production definitions)', 'sentinelguard-ecommerce-protection' ); ?></option>
								<option value="beta" <?php selected( $channel, 'beta' ); ?>><?php esc_html_e( 'Beta (Early access signatures)', 'sentinelguard-ecommerce-protection' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Data Removal on Uninstall', 'sentinelguard-ecommerce-protection' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="sentinelwp_remove_data_on_uninstall" value="1" <?php checked( $uninstall ); ?> />
								<?php esc_html_e( 'Delete all SentinelWP database tables and options on plugin deletion', 'sentinelguard-ecommerce-protection' ); ?>
							</label>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<!-- Danger Zone -->
		<div class="postbox sentinelwp-postbox sentinelwp-danger-zone">
			<div class="postbox-header">
				<h2><?php esc_html_e( 'Danger Zone', 'sentinelguard-ecommerce-protection' ); ?></h2>
			</div>
			<div class="inside">
				<div class="sentinelwp-danger-row">
					<div>
						<strong><?php esc_html_e( 'Reset all plugin settings', 'sentinelguard-ecommerce-protection' ); ?></strong>
						<p class="description"><?php esc_html_e( 'Restores all hardening, scanning, and threshold options to their defaults.', 'sentinelguard-ecommerce-protection' ); ?></p>
					</div>
					<div>
						<input type="text" class="regular-text" id="sentinelwp-confirm-reset" placeholder="<?php esc_attr_e( 'Type RESET to confirm', 'sentinelguard-ecommerce-protection' ); ?>" />
						<button type="button" class="button button-secondary" id="sentinelwp-btn-reset-settings" disabled>
							<?php esc_html_e( 'Reset Settings', 'sentinelguard-ecommerce-protection' ); ?>
						</button>
					</div>
				</div>

				<div class="sentinelwp-danger-row" style="margin-top: 16px;">
					<div>
						<strong><?php esc_html_e( 'Purge all scan findings history', 'sentinelguard-ecommerce-protection' ); ?></strong>
						<p class="description"><?php esc_html_e( 'Permanently clears all recorded findings, logs, and rate history.', 'sentinelguard-ecommerce-protection' ); ?></p>
					</div>
					<div>
						<input type="text" class="regular-text" id="sentinelwp-confirm-purge" placeholder="<?php esc_attr_e( 'Type PURGE to confirm', 'sentinelguard-ecommerce-protection' ); ?>" />
						<button type="button" class="button button-secondary" id="sentinelwp-btn-purge-history" disabled>
							<?php esc_html_e( 'Purge History', 'sentinelguard-ecommerce-protection' ); ?>
						</button>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/* -------------------------------------------------------------- */
	/* Helper & Formatting Methods                                     */
	/* -------------------------------------------------------------- */

	private function mask_key( $key ) {
		if ( '' === $key ) {
			return '';
		}
		return str_repeat( '•', 8 ) . substr( $key, -4 );
	}

	private function get_relative_time( $timestamp ) {
		if ( empty( $timestamp ) ) {
			return __( 'Never', 'sentinelguard-ecommerce-protection' );
		}
		$diff = time() - $timestamp;
		if ( $diff < 60 ) {
			return __( 'Just now', 'sentinelguard-ecommerce-protection' );
		} elseif ( $diff < 3600 ) {
			$mins = round( $diff / 60 );
			/* translators: %d: elapsed minutes */
			return sprintf( _n( '%d minute ago', '%d minutes ago', $mins, 'sentinelguard-ecommerce-protection' ), $mins );
		} elseif ( $diff < 86400 ) {
			$hours = round( $diff / 3600 );
			/* translators: %d: elapsed hours */
			return sprintf( _n( '%d hour ago', '%d hours ago', $hours, 'sentinelguard-ecommerce-protection' ), $hours );
		} else {
			$days = round( $diff / 86400 );
			/* translators: %d: elapsed days */
			return sprintf( _n( '%d day ago', '%d days ago', $days, 'sentinelguard-ecommerce-protection' ), $days );
		}
	}

	public function format_human_title( $type, $title, $source ) {
		switch ( $type ) {
			case 'checkout_skimmer':
				return __( 'Card skimmer script detected in active plugin', 'sentinelguard-ecommerce-protection' );
			case 'fake_image_payload':
				return __( 'Executable script payload hidden inside image file', 'sentinelguard-ecommerce-protection' );
			case 'db_script_injection':
				return __( 'Unauthorized script injection in database option', 'sentinelguard-ecommerce-protection' );
			case 'nulled_malicious_file':
				if ( preg_match( '/found in ([^:]+):/i', $title, $m ) ) {
					/* translators: %s: component name */
					return sprintf( __( 'Nulled theme file found in %s', 'sentinelguard-ecommerce-protection' ), $m[1] );
				}
				if ( ! empty( $source ) && false === strpos( $source, '/' ) ) {
					/* translators: %s: component source path */
					return sprintf( __( 'Nulled theme/plugin backdoor file in %s', 'sentinelguard-ecommerce-protection' ), $source );
				}
				return __( 'Nulled theme or plugin backdoor file found', 'sentinelguard-ecommerce-protection' );
			case 'nulled_license_bypass':
				return __( 'License verification bypass routine detected', 'sentinelguard-ecommerce-protection' );
			case 'nulled_phonehome_call':
			case 'nulled_phonehome_base64':
				return __( 'Phonehome connection to known pirated distribution network', 'sentinelguard-ecommerce-protection' );
			case 'nulled_wporg_mismatch':
				return __( 'Plugin metadata mismatch with official WordPress.org release', 'sentinelguard-ecommerce-protection' );
			case 'hidden_admin_detected':
			case 'orphaned_admin_meta':
				return __( 'Stealth administrator account found in database', 'sentinelguard-ecommerce-protection' );
			case 'unauthorized_admin_creation':
			case 'admin_role_granted':
				return __( 'Unauthorized administrator privilege elevation detected', 'sentinelguard-ecommerce-protection' );
			case 'suspicious_admin_username':
				if ( preg_match( '/"([^"]+)"/', $title, $m ) ) {
					/* translators: %s: administrator username */
					return sprintf( __( 'Unrecognised administrator account “%s”', 'sentinelguard-ecommerce-protection' ), $m[1] );
				}
				return __( 'Unrecognised administrator account in database', 'sentinelguard-ecommerce-protection' );
			case 'weak_username':
				return __( 'Administrator uses the default username “admin”', 'sentinelguard-ecommerce-protection' );
			case 'suspicious_user_filter':
				return __( 'Hidden admin user query filter detected in active theme/plugin', 'sentinelguard-ecommerce-protection' );
			case 'malware_signature':
				if ( preg_match( '/Pattern match \((.*)\) in/i', $title, $m ) ) {
					/* translators: %s: malware pattern name */
					return sprintf( __( 'Obfuscated backdoor — %s', 'sentinelguard-ecommerce-protection' ), $m[1] );
				}
				return __( 'Obfuscated backdoor — eval(base64_decode()) pattern', 'sentinelguard-ecommerce-protection' );
			case 'suspicious_file':
				return __( 'Executable PHP inside the uploads directory', 'sentinelguard-ecommerce-protection' );
			case 'core_integrity':
				return __( 'WordPress core checksum mismatch (tampered core file)', 'sentinelguard-ecommerce-protection' );
			case 'store_config_changed':
				return __( 'Payment gateway or critical store configuration changed', 'sentinelguard-ecommerce-protection' );
			case 'order_velocity':
				return __( 'Rapid checkout order velocity burst from single IP', 'sentinelguard-ecommerce-protection' );
			case 'card_testing':
				return __( 'Multiple rapid payment failures (Card testing detected)', 'sentinelguard-ecommerce-protection' );
			case 'disposable_email':
				return __( 'Order placed using temporary disposable email domain', 'sentinelguard-ecommerce-protection' );
			case 'order_anomaly':
				return __( 'Anomalous order amount or customer purchase spike', 'sentinelguard-ecommerce-protection' );
			case 'flood_detected':
				return __( 'Application-layer request flood threshold exceeded', 'sentinelguard-ecommerce-protection' );
			default:
				if ( ! empty( $source ) ) {
					$base = basename( $source );
					$clean = str_replace( array( " in {$source}", " in {$base}", " ({$source})", " ({$base})" ), '', $title );
					return $clean;
				}
				return $title;
		}
	}

	public function format_human_path( $type, $source, $title ) {
		if ( 'suspicious_admin_username' === $type || 'hidden_admin_detected' === $type || 'weak_username' === $type ) {
			if ( 'weak_username' === $type ) {
				return 'wp_users · ID 1';
			}
			if ( preg_match( '/"([^"]+)"/', $title, $m ) ) {
				return "wp_users · user: {$m[1]}";
			}
			return 'wp_users (database table)';
		}
		if ( 'store_config_changed' === $type || 'db_script_injection' === $type ) {
			return 'wp_options · ' . ( ! empty( $source ) ? $source : 'option_value' );
		}
		if ( preg_match( '/(wp-content\/[^\s:]+)/', $title, $m ) ) {
			return $m[1];
		}
		if ( ! empty( $source ) && false !== strpos( $source, '/' ) ) {
			return $source;
		}
		return '';
	}

	public function format_engine_slug( $type, $source ) {
		if ( 0 === strpos( $type, 'nulled' ) ) {
			return 'nulled-detector';
		}
		if ( 'checkout_skimmer' === $type || 'fake_image_payload' === $type || 'db_script_injection' === $type ) {
			return 'magecart-guard';
		}
		if ( 0 === strpos( $type, 'admin' ) || 'suspicious_admin_username' === $type || 'hidden_admin_detected' === $type || 'orphaned_admin_meta' === $type || 'suspicious_user_filter' === $type ) {
			return 'database-audit';
		}
		if ( 'order_velocity' === $type || 'card_testing' === $type || 'disposable_email' === $type || 'order_anomaly' === $type || 'refund_spike' === $type || 'store_config_changed' === $type ) {
			return 'ecommerce-guard';
		}
		if ( 'flood_detected' === $type ) {
			return 'flood-monitor';
		}
		return ! empty( $source ) && false === strpos( $source, '/' ) ? $source : 'local-heuristic';
	}

	public function get_module_for_type( $type ) {
		$map = array(
			'hidden_admin_detected'      => 'admin',
			'unauthorized_admin_creation'=> 'admin',
			'admin_role_granted'         => 'admin',
			'suspicious_admin_username'  => 'admin',
			'orphaned_admin_meta'        => 'admin',
			'suspicious_user_filter'     => 'admin',
			'weak_username'              => 'admin',
			'store_config_changed'       => 'integrity',
			'suspicious_file'            => 'integrity',
			'malware_signature'          => 'integrity',
			'core_integrity'             => 'integrity',
			'checkout_skimmer'           => 'skimmer',
			'fake_image_payload'         => 'skimmer',
			'db_script_injection'        => 'skimmer',
			'nulled_plugin'              => 'nulled',
			'nulled_malicious_file'      => 'nulled',
			'nulled_license_bypass'      => 'nulled',
			'nulled_wporg_mismatch'      => 'nulled',
			'nulled_phonehome_call'      => 'nulled',
			'nulled_phonehome_base64'    => 'nulled',
			'nulled_suspicious_filename' => 'nulled',
			'flood_detected'             => 'flood',
			'order_velocity'             => 'fraud',
			'card_testing'               => 'fraud',
			'disposable_email'           => 'fraud',
			'order_anomaly'              => 'fraud',
			'refund_spike'               => 'fraud',
			'complaint_pattern'          => 'fraud',
		);
		return isset( $map[ $type ] ) ? $map[ $type ] : 'integrity';
	}

	/* -------------------------------------------------------------- */
	/* AJAX Handlers                                                   */
	/* -------------------------------------------------------------- */

	public function ajax_run_scan_now() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		delete_transient( 'sentinelwp_manual_scan_lock' );
		delete_transient( 'sentinelwp_active_scan_lock' );
		update_option( 'sentinelwp_last_scan_time', time() );

		try {
			$results = SentinelWP_Scan_Coordinator::instance()->run_full_scan();
			wp_send_json_success( array(
				'message' => __( 'Scan complete.', 'sentinelguard-ecommerce-protection' ),
				'results' => $results,
			) );
		} catch ( Throwable $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ), 500 );
		}
	}

	public function ajax_resolve_finding() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$id = isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0;
		if ( ! $id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid finding.', 'sentinelguard-ecommerce-protection' ) ), 400 );
		}

		global $wpdb;
		$wpdb->update(
			$wpdb->prefix . 'sentinelwp_findings',
			array( 'status' => 'resolved', 'updated_at' => current_time( 'mysql' ) ),
			array( 'id' => $id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		wp_send_json_success();
	}

	public function ajax_unresolve_finding() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$id = isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0;
		if ( ! $id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid finding.', 'sentinelguard-ecommerce-protection' ) ), 400 );
		}

		global $wpdb;
		$wpdb->update(
			$wpdb->prefix . 'sentinelwp_findings',
			array( 'status' => 'new', 'updated_at' => current_time( 'mysql' ) ),
			array( 'id' => $id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		wp_send_json_success();
	}

	public function ajax_bulk_action() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$bulk_action = isset( $_POST['bulk_action'] ) ? sanitize_key( $_POST['bulk_action'] ) : '';
		$ids         = isset( $_POST['ids'] ) && is_array( $_POST['ids'] ) ? array_map( 'absint', $_POST['ids'] ) : array();

		if ( empty( $ids ) || empty( $bulk_action ) ) {
			wp_send_json_error( array( 'message' => __( 'No items selected.', 'sentinelguard-ecommerce-protection' ) ), 400 );
		}

		global $wpdb;
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );

		if ( 'resolve' === $bulk_action ) {
			$wpdb->query(
				$wpdb->prepare(
					"UPDATE {$wpdb->prefix}sentinelwp_findings SET status = 'resolved', updated_at = %s WHERE id IN ($placeholders)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					array_merge( array( current_time( 'mysql' ) ), $ids )
				)
			);
		} elseif ( 'false_positive' === $bulk_action || 'ignore' === $bulk_action ) {
			$wpdb->query(
				$wpdb->prepare(
					"UPDATE {$wpdb->prefix}sentinelwp_findings SET status = 'acknowledged', updated_at = %s WHERE id IN ($placeholders)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					array_merge( array( current_time( 'mysql' ) ), $ids )
				)
			);
		} elseif ( 'quarantine' === $bulk_action ) {
			if ( class_exists( 'SentinelWP_Quarantine' ) ) {
				$quarantine = SentinelWP_Quarantine::instance();
				foreach ( $ids as $id ) {
					$quarantine->quarantine_file( $id );
				}
			}
		}

		wp_send_json_success();
	}

	public function ajax_test_email() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$to = get_option( 'sentinelwp_alert_email', get_option( 'admin_email' ) );
		/* translators: %s: site name */
		$subject = sprintf( __( '[%s] SentinelWP Security Test Notification', 'sentinelguard-ecommerce-protection' ), get_bloginfo( 'name' ) );
		$body = __( "This is a test notification from SentinelWP Security.\n\nYour alert dispatch channel is operational.", 'sentinelguard-ecommerce-protection' );

		$sent = wp_mail( $to, $subject, $body );

		if ( $sent ) {
			/* translators: %s: recipient email address */
			wp_send_json_success( array( 'message' => sprintf( __( 'Test email sent to %s', 'sentinelguard-ecommerce-protection' ), $to ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'wp_mail() returned false. Check mail server configuration.', 'sentinelguard-ecommerce-protection' ) ) );
		}
	}

	public function ajax_dismiss_flood_alert() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$id = isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0;
		if ( ! $id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid finding.', 'sentinelguard-ecommerce-protection' ) ), 400 );
		}

		global $wpdb;
		$wpdb->update(
			$wpdb->prefix . 'sentinelwp_findings',
			array( 'status' => 'acknowledged', 'updated_at' => current_time( 'mysql' ) ),
			array( 'id' => $id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		wp_send_json_success();
	}

	public function ajax_quarantine_finding() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$id = isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0;
		if ( ! $id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid finding ID.', 'sentinelguard-ecommerce-protection' ) ), 400 );
		}

		$res = SentinelWP_Quarantine::instance()->quarantine_file( $id );
		if ( $res['success'] ) {
			wp_send_json_success( $res );
		} else {
			wp_send_json_error( $res, 400 );
		}
	}

	public function ajax_restore_quarantine() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$quarantine_id = isset( $_POST['quarantine_id'] ) ? absint( $_POST['quarantine_id'] ) : 0;
		$finding_id    = isset( $_POST['finding_id'] ) ? absint( $_POST['finding_id'] ) : 0;

		if ( ! $quarantine_id && $finding_id ) {
			global $wpdb;
			$quarantine_id = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$wpdb->prefix}sentinelwp_quarantine WHERE finding_id = %d ORDER BY id DESC LIMIT 1", $finding_id ) );
		}

		if ( ! $quarantine_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid quarantine ID.', 'sentinelguard-ecommerce-protection' ) ), 400 );
		}

		$res = SentinelWP_Quarantine::instance()->restore_quarantine( $quarantine_id );
		if ( $res['success'] ) {
			wp_send_json_success( $res );
		} else {
			wp_send_json_error( $res, 400 );
		}
	}

	public function ajax_purge_quarantine() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$quarantine_id = isset( $_POST['quarantine_id'] ) ? absint( $_POST['quarantine_id'] ) : 0;
		if ( ! $quarantine_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid quarantine ID.', 'sentinelguard-ecommerce-protection' ) ), 400 );
		}

		$res = SentinelWP_Quarantine::instance()->purge_quarantine( $quarantine_id );
		if ( $res['success'] ) {
			wp_send_json_success( $res );
		} else {
			wp_send_json_error( $res, 400 );
		}
	}

	public function ajax_reset_settings() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$options_to_reset = array(
			'sentinelwp_hardening'               => array(),
			'sentinelwp_vuln_source'             => 'wordpress_org',
			'sentinelwp_alert_email'              => get_option( 'admin_email' ),
			'sentinelwp_flood_enabled'           => true,
			'sentinelwp_flood_threshold'         => 120,
			'sentinelwp_flood_block'             => false,
			'sentinelwp_form_shield_enabled'     => true,
			'sentinelwp_ecommerce_guard_enabled' => true,
			'sentinelwp_fraud_auto_hold'         => false,
			'sentinelwp_disposable_email_check'  => true,
			'sentinelwp_protection_level'        => 'balanced',
			'sentinelwp_site_role'               => class_exists( 'WooCommerce' ) ? 'woocommerce' : 'standard',
			'sentinelwp_data_retention'          => 90,
			'sentinelwp_scan_schedule'           => 'daily',
			'sentinelwp_scan_time'               => '03:00',
			'sentinelwp_scan_depth'              => 'standard',
			'sentinelwp_path_exclusions'         => '',
			'sentinelwp_max_scan_duration'       => 300,
			'sentinelwp_alert_threshold'         => 'high',
			'sentinelwp_alert_recipients'        => get_option( 'admin_email' ),
			'sentinelwp_alert_digest'            => 'instant',
			'sentinelwp_alert_webhook'           => '',
			'sentinelwp_debug_logging'           => false,
			'sentinelwp_update_channel'          => 'stable',
		);

		foreach ( $options_to_reset as $opt => $val ) {
			update_option( $opt, $val );
		}

		wp_send_json_success( array( 'message' => __( 'All plugin settings have been successfully reset to defaults.', 'sentinelguard-ecommerce-protection' ) ) );
	}

	public function ajax_purge_history() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		global $wpdb;
		$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinelwp_findings" );
		$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinelwp_request_rates" );
		$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinelwp_quarantine" );
		$wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinelwp_store_hashes" );

		delete_option( 'sentinelwp_scan_history_log' );
		delete_option( 'sentinelwp_last_scan_summary' );
		delete_option( 'sentinelwp_last_scan_time' );
		delete_transient( 'sentinelwp_scan_coordinator_state' );

		wp_send_json_success( array( 'message' => __( 'All scan history, findings, and logs have been permanently purged.', 'sentinelguard-ecommerce-protection' ) ) );
	}

	public function ajax_clear_scan_history() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		SentinelWP_Scan_Coordinator::instance()->clear_scan_history();
		wp_send_json_success( array( 'message' => __( 'Scan run history has been cleared.', 'sentinelguard-ecommerce-protection' ) ) );
	}

	public function ajax_delete_scan_run() {
		check_ajax_referer( 'sentinelwp_admin_action', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'sentinelguard-ecommerce-protection' ) ), 403 );
		}

		$id = isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0;
		if ( ! $id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid run ID.', 'sentinelguard-ecommerce-protection' ) ), 400 );
		}

		SentinelWP_Scan_Coordinator::instance()->delete_scan_run( $id );
		wp_send_json_success( array( 'message' => __( 'Scan record removed.', 'sentinelguard-ecommerce-protection' ) ) );
	}
}
