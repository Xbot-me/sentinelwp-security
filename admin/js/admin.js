( function ( $ ) {
	'use strict';

	$( function () {
		/* ---------------------------------------------------------- */
		/* 1. Deep Scan Trigger & Progress Bar Animation              */
		/* ---------------------------------------------------------- */
		$( '#sentinelwp-btn-scan' ).on( 'click', function ( e ) {
			e.preventDefault();
			var $btn      = $( this );
			var $btnText  = $btn.find( '.btn-text' );
			var $bar      = $( '#sentinelwp-progress-bar' );
			var $fill     = $( '#sentinelwp-progress-fill' );
			var $label    = $( '#sentinelwp-progress-label' );

			$btn.prop( 'disabled', true ).addClass( 'sentinelwp-scanning' );
			$fill.css( { 'width': '8%', 'background': '' } );
			$label.text( 'Initializing security engines…' );
			$btnText.text( 'Scanning…' );
			$bar.stop( true, true ).slideDown( 180 );

			var steps = [
				{ pct: 20, text: 'Phase 1/6: Verifying WordPress core integrity…' },
				{ pct: 38, text: 'Phase 2/6: Auditing plugin & theme vulnerabilities…' },
				{ pct: 56, text: 'Phase 3/6: Scanning scripts for Magecart payment skimmers…' },
				{ pct: 72, text: 'Phase 4/6: Inspecting nulled distribution indicators…' },
				{ pct: 86, text: 'Phase 5/6: Auditing admin database & stealth accounts…' },
				{ pct: 95, text: 'Phase 6/6: Analyzing ecommerce fraud & store hashes…' }
			];

			var stepIdx = 0;
			var interval = setInterval( function () {
				if ( stepIdx < steps.length ) {
					var s = steps[ stepIdx ];
					$fill.css( 'width', s.pct + '%' );
					$label.text( s.text );
					$btnText.text( 'Scanning… ' + s.pct + '%' );
					stepIdx++;
				}
			}, 850 );

			$.ajax( {
				url: SentinelWPAdmin.ajaxUrl,
				type: 'POST',
				data: {
					action: 'sentinelwp_run_scan_now',
					nonce: SentinelWPAdmin.nonce
				},
				timeout: 120000
			} ).done( function ( response ) {
				clearInterval( interval );
				if ( response && response.success ) {
					$fill.css( 'width', '100%' );
					$label.text( 'Scan complete! Refreshing dashboard…' );
					$btnText.text( 'Scan Complete' );
					setTimeout( function () {
						window.location.reload();
					}, 500 );
				} else {
					var err = ( response && response.data && response.data.message ) || 'Scan was interrupted.';
					$fill.css( 'background', '#d63638' );
					$label.text( err );
					$btn.prop( 'disabled', false ).removeClass( 'sentinelwp-scanning' );
					$btnText.text( 'Run Deep Scan' );
				}
			} ).fail( function ( xhr, textStatus ) {
				clearInterval( interval );
				var msg = 'Scan request failed.';
				if ( xhr.status === 403 || xhr.responseText === '-1' ) {
					msg = 'Security session expired. Refreshing page…';
					setTimeout( function () { window.location.reload(); }, 1500 );
				} else if ( textStatus === 'timeout' ) {
					msg = 'Scan request timed out on server.';
				} else if ( xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message ) {
					msg = xhr.responseJSON.data.message;
				}
				$fill.css( 'background', '#d63638' );
				$label.text( msg );
				$btn.prop( 'disabled', false ).removeClass( 'sentinelwp-scanning' );
				$btnText.text( 'Run Deep Scan' );
				setTimeout( function () {
					$bar.slideUp( 250, function () {
						$fill.css( { 'width': '0%', 'background': '' } );
					} );
				}, 4500 );
			} );
		} );

		/* ---------------------------------------------------------- */
		/* 2. Subsubsub Severity Filters, Module Clicks & Smooth Scroll*/
		/* ---------------------------------------------------------- */
		var activeModuleFilter = '';

		function applyTableFilters() {
			var activeFilter = $( '.subsub li.cur .sentinelwp-tab-filter' ).data( 'filter' ) || 'all';
			var engineFilter = $( '#sentinelwp-engine-filter' ).val() || '';
			var searchTerm   = $( '#sentinelwp-search-input' ).val().toLowerCase().trim();

			var visibleCount = 0;

			$( '.sentinelwp-finding-row' ).each( function () {
				var $row      = $( this );
				var id        = $row.data( 'id' );
				var severity  = $row.data( 'severity' );
				var source    = ( $row.data( 'source' ) || '' ).toLowerCase();
				var engine    = ( $row.data( 'engine' ) || '' ).toLowerCase();
				var module    = ( $row.data( 'module' ) || '' ).toLowerCase();
				var title     = $row.find( '.title a' ).text().toLowerCase();
				var path      = $row.find( '.path' ).text().toLowerCase();
				var status    = $row.data( 'status' ) || 'open';
				var $detail   = $( '#detail-' + id );

				var matchesSeverity = ( activeFilter === 'all' && status === 'open' ) ||
				                      ( activeFilter === 'resolved' && status === 'resolved' ) ||
				                      ( activeFilter === severity && status === 'open' );

				var matchesEngine = ! engineFilter || engine === engineFilter.toLowerCase() || source.indexOf( engineFilter.toLowerCase() ) !== -1;
				var matchesModule = ! activeModuleFilter || module === activeModuleFilter.toLowerCase();
				var matchesSearch = ! searchTerm || title.indexOf( searchTerm ) !== -1 || source.indexOf( searchTerm ) !== -1 || path.indexOf( searchTerm ) !== -1;

				if ( matchesSeverity && matchesEngine && matchesModule && matchesSearch ) {
					$row.show();
					visibleCount++;
				} else {
					$row.hide();
					if ( $detail.length ) {
						$detail.hide();
					}
				}
			} );

			$( '#sentinelwp-displaying-num, #sentinelwp-bottom-item-count' ).text( visibleCount + ' item' + ( visibleCount === 1 ? '' : 's' ) );
		}

		// Module Cards: "View findings ›" click handler
		$( document ).on( 'click', '.sentinelwp-module-view-findings', function ( e ) {
			e.preventDefault();
			var moduleKey = $( this ).data( 'module' );
			activeModuleFilter = moduleKey;

			// Reset severity tab to All
			$( '.subsub li' ).removeClass( 'cur' );
			$( '.sentinelwp-tab-filter[data-filter="all"]' ).closest( 'li' ).addClass( 'cur' );
			$( '#sentinelwp-search-input' ).val( '' );
			$( '#sentinelwp-engine-filter' ).val( '' );

			applyTableFilters();

			// Smooth scroll to table
			var $table = $( '#sentinelwp-table' );
			if ( $table.length ) {
				$( 'html, body' ).animate( {
					scrollTop: $table.offset().top - 120
				}, 350 );
			}
		} );

		// Alarm Severity Blocks: Click to filter & scroll
		$( document ).on( 'click', '.sentinelwp-alarm-filter', function ( e ) {
			e.preventDefault();
			var filter = $( this ).data( 'filter' );
			activeModuleFilter = '';

			$( '.subsub li' ).removeClass( 'cur' );
			$( '.sentinelwp-tab-filter[data-filter="' + filter + '"]' ).closest( 'li' ).addClass( 'cur' );
			$( '#sentinelwp-search-input' ).val( '' );
			$( '#sentinelwp-engine-filter' ).val( '' );

			applyTableFilters();

			var $table = $( '#sentinelwp-table' );
			if ( $table.length ) {
				$( 'html, body' ).animate( {
					scrollTop: $table.offset().top - 120
				}, 350 );
			}
		} );

		// Subsubsub Severity Tabs
		$( document ).on( 'click', '.sentinelwp-tab-filter', function ( e ) {
			e.preventDefault();
			activeModuleFilter = '';
			var filter = $( this ).data( 'filter' );
			$( '.subsub li' ).removeClass( 'cur' );
			$( '.sentinelwp-tab-filter[data-filter="' + filter + '"]' ).closest( 'li' ).addClass( 'cur' );

			applyTableFilters();
		} );

		// Engine Dropdown & Search Input
		$( '#sentinelwp-engine-filter, #sentinelwp-search-input' ).on( 'input change', function () {
			activeModuleFilter = '';
			applyTableFilters();
		} );

		/* ---------------------------------------------------------- */
		/* 3. Inline Expandable Row Accordion                          */
		/* ---------------------------------------------------------- */
		$( document ).on( 'click', '.sentinelwp-disclosure-toggle', function ( e ) {
			e.preventDefault();
			var $row    = $( this ).closest( '.sentinelwp-finding-row' );
			var id      = $row.data( 'id' );
			var $detail = $( '#detail-' + id );
			var $toggle = $row.find( '.sentinelwp-disclosure-toggle' );

			if ( $detail.is( ':visible' ) ) {
				$detail.hide();
				$toggle.attr( 'aria-expanded', 'false' );
			} else {
				$( '.sentinelwp-detail-row' ).hide();
				$( '.sentinelwp-disclosure-toggle' ).attr( 'aria-expanded', 'false' );

				$detail.show();
				$toggle.attr( 'aria-expanded', 'true' );
			}
		} );

		/* ---------------------------------------------------------- */
		/* 4. Optimistic Resolve, Ignore & Quarantine Actions          */
		/* ---------------------------------------------------------- */
		var undoTimeouts = {};

		function showUndoNotice( id, title, labelText ) {
			var label = labelText || 'marked as resolved';
			var noticeHtml = '<div class="notice notice-success is-dismissible sentinelwp-undo-notice" id="sentinelwp-undo-notice-' + id + '" style="margin: 12px 0 16px;">' +
				'<p>Finding <strong>' + $( '<div>' ).text( title ).html() + '</strong> ' + label + '. ' +
				'<button type="button" class="button-link sentinelwp-undo-btn" data-id="' + id + '">Undo</button>' +
				'</p></div>';

			$( '#sentinelwp-transient-notice-area' ).prepend( noticeHtml );

			undoTimeouts[ id ] = setTimeout( function () {
				$( '#sentinelwp-undo-notice-' + id ).fadeOut( 200, function () { $( this ).remove(); } );
				delete undoTimeouts[ id ];
			}, 10000 );
		}

		$( document ).on( 'click', '.sentinelwp-action-resolve', function ( e ) {
			e.preventDefault();
			var id   = $( this ).data( 'id' );
			var $row = $( '.sentinelwp-finding-row[data-id="' + id + '"]' );
			var title = $row.find( '.title a' ).text();
			var $detail = $( '#detail-' + id );

			// Optimistic UI update
			$row.addClass( 'is-resolved' ).data( 'status', 'resolved' );
			$row.find( '.status' ).removeClass( 'open' ).addClass( 'resolved' ).text( 'Resolved' );
			$detail.hide();

			showUndoNotice( id, title, 'marked as resolved' );

			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_resolve_finding',
				id: id,
				nonce: SentinelWPAdmin.nonce
			} );

			var openCount = $( '.sentinelwp-finding-row[data-status="open"]' ).length;
			$( '#sentinelwp-cnt-all' ).text( openCount );
			var resCount = parseInt( $( '#sentinelwp-cnt-resolved' ).text(), 10 ) || 0;
			$( '#sentinelwp-cnt-resolved' ).text( resCount + 1 );
		} );

		$( document ).on( 'click', '.sentinelwp-action-fp', function ( e ) {
			e.preventDefault();
			var id   = $( this ).data( 'id' );
			var $row = $( '.sentinelwp-finding-row[data-id="' + id + '"]' );
			var title = $row.find( '.title a' ).text();
			var $detail = $( '#detail-' + id );

			$row.fadeOut( 200 );
			$detail.hide();

			showUndoNotice( id, title, 'ignored (false positive)' );

			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_resolve_finding',
				id: id,
				nonce: SentinelWPAdmin.nonce
			} );
		} );

		$( document ).on( 'click', '.sentinelwp-action-quarantine', function ( e ) {
			e.preventDefault();
			var id   = $( this ).data( 'id' );
			var $row = $( '.sentinelwp-finding-row[data-id="' + id + '"]' );
			var title = $row.find( '.title a' ).text();
			var $detail = $( '#detail-' + id );

			$row.addClass( 'is-quarantined' ).data( 'status', 'quarantined' ).fadeOut( 200 );
			$detail.hide();

			showUndoNotice( id, title, 'quarantined into safe vault' );

			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_quarantine_finding',
				id: id,
				nonce: SentinelWPAdmin.nonce
			} );

			var openCount = $( '.sentinelwp-finding-row[data-status="open"]' ).length;
			$( '#sentinelwp-cnt-all' ).text( Math.max( 0, openCount - 1 ) );
		} );

		$( document ).on( 'click', '.sentinelwp-undo-btn', function ( e ) {
			e.preventDefault();
			var id = $( this ).data( 'id' );
			var $row = $( '.sentinelwp-finding-row[data-id="' + id + '"]' );
			var $notice = $( '#sentinelwp-undo-notice-' + id );

			if ( undoTimeouts[ id ] ) {
				clearTimeout( undoTimeouts[ id ] );
				delete undoTimeouts[ id ];
			}

			$notice.remove();

			$row.removeClass( 'is-resolved is-quarantined' ).data( 'status', 'open' ).show();
			$row.find( '.status' ).removeClass( 'resolved quarantined' ).addClass( 'open' ).text( 'Open' );

			// Restore finding and rollback any quarantined file
			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_restore_quarantine',
				finding_id: id,
				nonce: SentinelWPAdmin.nonce
			} );

			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_unresolve_finding',
				id: id,
				nonce: SentinelWPAdmin.nonce
			} );

			var openCount = $( '.sentinelwp-finding-row[data-status="open"]' ).length;
			$( '#sentinelwp-cnt-all' ).text( openCount );
		} );

		/* ---------------------------------------------------------- */
		/* 5. Bulk Actions & CSV Export                                */
		/* ---------------------------------------------------------- */
		$( '#cb-select-all-1' ).on( 'change', function () {
			var isChecked = $( this ).is( ':checked' );
			$( 'input[name="finding_ids[]"]:visible' ).prop( 'checked', isChecked );
		} );

		$( '#sentinelwp-doaction, #sentinelwp-doaction2' ).on( 'click', function ( e ) {
			e.preventDefault();
			var action = $( this ).siblings( 'select' ).val();
			if ( action === '-1' ) {
				return;
			}

			var selectedIds = [];
			$( 'input[name="finding_ids[]"]:checked' ).each( function () {
				selectedIds.push( $( this ).val() );
			} );

			if ( ! selectedIds.length ) {
				alert( 'Please select at least one finding.' );
				return;
			}

			if ( action === 'export_csv' ) {
				// Export CSV
				var csvContent = 'data:text/csv;charset=utf-8,ID,Severity,Title,Source\n';
				selectedIds.forEach( function ( id ) {
					var $row = $( '.sentinelwp-finding-row[data-id="' + id + '"]' );
					csvContent += id + ',' +
					              $row.data( 'severity' ) + ',"' +
					              $row.find( '.title a, .title' ).first().text().trim().replace( /"/g, '""' ) + '","' +
					              $row.data( 'source' ) + '"\n';
				} );
				var encodedUri = encodeURI( csvContent );
				var link = document.createElement( 'a' );
				link.setAttribute( 'href', encodedUri );
				link.setAttribute( 'download', 'sentinelguard-findings.csv' );
				document.body.appendChild( link );
				link.click();
				document.body.removeChild( link );
				return;
			}

			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_bulk_action',
				bulk_action: action,
				ids: selectedIds,
				nonce: SentinelWPAdmin.nonce
			} ).done( function () {
				window.location.reload();
			} );
		} );

		/* ---------------------------------------------------------- */
		/* 6. Settings Screen: Segmented Controls & Dirty Save Bar    */
		/* ---------------------------------------------------------- */
		$( '.sentinelwp-seg-option input[type="radio"]' ).on( 'change', function () {
			$( this ).closest( '.sentinelwp-segmented-control' )
				.find( '.sentinelwp-seg-option' )
				.removeClass( 'is-selected' );
			$( this ).closest( '.sentinelwp-seg-option' ).addClass( 'is-selected' );
		} );

		// Sticky Save Bar on dirty form
		var $settingsForm = $( '#sentinelwp-settings-form' );
		var $stickySave   = $( '#sentinelwp-sticky-save' );

		if ( $settingsForm.length ) {
			$settingsForm.on( 'change input', 'input, select, textarea', function () {
				$stickySave.addClass( 'is-visible' );
			} );

			$( '#sentinelwp-discard-changes' ).on( 'click', function ( e ) {
				e.preventDefault();
				window.location.reload();
			} );
		}

		/* ---------------------------------------------------------- */
		/* 7. Danger Zone Confirmations & Actions                     */
		/* ---------------------------------------------------------- */
		$( '#sentinelwp-confirm-reset' ).on( 'input', function () {
			$( '#sentinelwp-btn-reset-settings' ).prop( 'disabled', $( this ).val().trim() !== 'RESET' );
		} );

		$( '#sentinelwp-btn-reset-settings' ).on( 'click', function ( e ) {
			e.preventDefault();
			var $btn = $( this );
			if ( $( '#sentinelwp-confirm-reset' ).val().trim() !== 'RESET' ) {
				return;
			}
			$btn.prop( 'disabled', true ).text( 'Resetting…' );
			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_reset_settings',
				nonce: SentinelWPAdmin.nonce
			} ).done( function ( resp ) {
				alert( resp.data.message || 'Settings reset successfully.' );
				window.location.reload();
			} ).fail( function ( xhr ) {
				alert( ( xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message ) || 'Reset failed.' );
				$btn.prop( 'disabled', false ).text( 'Reset Settings' );
			} );
		} );

		$( '#sentinelwp-confirm-purge' ).on( 'input', function () {
			$( '#sentinelwp-btn-purge-history' ).prop( 'disabled', $( this ).val().trim() !== 'PURGE' );
		} );

		$( '#sentinelwp-btn-purge-history' ).on( 'click', function ( e ) {
			e.preventDefault();
			var $btn = $( this );
			if ( $( '#sentinelwp-confirm-purge' ).val().trim() !== 'PURGE' ) {
				return;
			}
			$btn.prop( 'disabled', true ).text( 'Purging…' );
			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_purge_history',
				nonce: SentinelWPAdmin.nonce
			} ).done( function ( resp ) {
				alert( resp.data.message || 'History purged successfully.' );
				window.location.reload();
			} ).fail( function ( xhr ) {
				alert( ( xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message ) || 'Purge failed.' );
				$btn.prop( 'disabled', false ).text( 'Purge History' );
			} );
		} );

		// Clear Scan History only (from Scan History table)
		$( '#sentinelwp-btn-clear-scan-history' ).on( 'click', function ( e ) {
			e.preventDefault();
			if ( ! confirm( 'Are you sure you want to clear the scan run history log?' ) ) {
				return;
			}
			var $btn = $( this );
			$btn.prop( 'disabled', true );
			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_clear_scan_history',
				nonce: SentinelWPAdmin.nonce
			} ).done( function ( resp ) {
				window.location.reload();
			} ).fail( function ( xhr ) {
				alert( ( xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message ) || 'Failed to clear history.' );
				$btn.prop( 'disabled', false );
			} );
		} );

		// Delete single scan run
		$( document ).on( 'click', '.sentinelwp-delete-scan-run', function ( e ) {
			e.preventDefault();
			var runId = $( this ).data( 'id' );
			var $row  = $( this ).closest( 'tr' );

			if ( ! runId ) {
				return;
			}

			$row.css( 'opacity', '0.4' );
			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_delete_scan_run',
				id: runId,
				nonce: SentinelWPAdmin.nonce
			} ).done( function () {
				$row.fadeOut( 250, function () {
					$row.remove();
					if ( $( '.sentinelwp-history-table tbody tr' ).length === 0 ) {
						window.location.reload();
					}
				} );
			} ).fail( function () {
				$row.css( 'opacity', '1' );
				alert( 'Failed to delete scan record.' );
			} );
		} );

		/* ---------------------------------------------------------- */
		/* 8. Send Test Email AJAX Trigger                            */
		/* ---------------------------------------------------------- */
		$( '#sentinelwp-send-test-email' ).on( 'click', function ( e ) {
			e.preventDefault();
			var $btn = $( this );
			var $status = $( '#sentinelwp-test-email-status' );

			$btn.prop( 'disabled', true );
			$status.text( 'Sending…' );

			$.post( SentinelWPAdmin.ajaxUrl, {
				action: 'sentinelwp_test_email',
				nonce: SentinelWPAdmin.nonce
			} ).done( function ( resp ) {
				$btn.prop( 'disabled', false );
				if ( resp.success ) {
					$status.css( 'color', '#007017' ).text( resp.data.message );
				} else {
					$status.css( 'color', '#b32d2e' ).text( resp.data.message );
				}
			} ).fail( function () {
				$btn.prop( 'disabled', false );
				$status.css( 'color', '#b32d2e' ).text( 'Request failed.' );
			} );
		} );

		/* ---------------------------------------------------------- */
		/* 9. Keyboard Shortcuts (j / k / Enter / r / x)              */
		/* ---------------------------------------------------------- */
		var currentFocusIndex = -1;
		$( document ).on( 'keydown', function ( e ) {
			if ( $( e.target ).is( 'input, textarea, select' ) ) {
				return;
			}

			var $rows = $( '.sentinelwp-finding-row:visible' );
			if ( ! $rows.length ) {
				return;
			}

			if ( e.key === 'j' ) { // Next row
				currentFocusIndex = Math.min( $rows.length - 1, currentFocusIndex + 1 );
				$rows.removeClass( 'keyboard-focused' );
				$rows.eq( currentFocusIndex ).addClass( 'keyboard-focused' ).focus();
			} else if ( e.key === 'k' ) { // Prev row
				currentFocusIndex = Math.max( 0, currentFocusIndex - 1 );
				$rows.removeClass( 'keyboard-focused' );
				$rows.eq( currentFocusIndex ).addClass( 'keyboard-focused' ).focus();
			} else if ( e.key === 'Enter' && currentFocusIndex >= 0 ) { // Toggle detail
				$rows.eq( currentFocusIndex ).find( '.sentinelwp-disclosure-toggle' ).trigger( 'click' );
			} else if ( e.key === 'r' && currentFocusIndex >= 0 ) { // Resolve
				$rows.eq( currentFocusIndex ).find( '.sentinelwp-action-resolve' ).trigger( 'click' );
			} else if ( e.key === 'x' && currentFocusIndex >= 0 ) { // Check
				var $chk = $rows.eq( currentFocusIndex ).find( 'input[name="finding_ids[]"]' );
				$chk.prop( 'checked', ! $chk.prop( 'checked' ) );
			}
		} );
	} );
} )( jQuery );

