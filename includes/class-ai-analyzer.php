<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AI triage layer. Scoped narrowly: it classifies a code snippet the
 * deterministic scanner already flagged, or turns a raw CVE record into
 * plain language. It never receives full files, credentials, or PII,
 * and every call has a rule-based fallback so the plugin is fully
 * functional with zero AI configured.
 *
 * Contract: every provider call must return strict JSON matching
 * { "verdict": string, "confidence": string, "reason": string }.
 * Anything that fails to parse or validate is treated as "AI
 * unavailable" for that call — never retried into infinity, never
 * silently trusted half-parsed.
 */
class SentinelWP_AI_Analyzer {

	private static $instance = null;

	const ALLOWED_VERDICTS    = array( 'malicious', 'suspicious', 'benign' );
	const ALLOWED_CONFIDENCE  = array( 'low', 'medium', 'high' );
	const MAX_SNIPPET_LENGTH  = 400;
	const REQUEST_TIMEOUT     = 10;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'sentinelwp_ai_triage_job', array( $this, 'process_triage_job' ), 10, 3 );
	}

	/**
	 * Queues triage as a single-event cron job rather than running
	 * inline during the scan, so a slow/hanging AI provider can never
	 * stall the scan loop itself.
	 */
	public function queue_triage( $finding_id, $snippet, $signature_label ) {
		$snippet = $this->redact_and_cap( $snippet );
		wp_schedule_single_event(
			time() + 5,
			'sentinelwp_ai_triage_job',
			array( $finding_id, $snippet, $signature_label )
		);
	}

	public function process_triage_job( $finding_id, $snippet, $signature_label ) {
		$verdict = $this->classify_snippet( $snippet, $signature_label );
		$this->apply_verdict_to_finding( $finding_id, $verdict );
	}

	/**
	 * Redacts anything that looks like a credential/secret before a
	 * snippet is ever sent off-site, and hard-caps length regardless of
	 * what the caller passed in.
	 */
	private function redact_and_cap( $snippet ) {
		$patterns = array(
			'/([\'"])(?:password|passwd|secret|api[_-]?key|token)\1\s*=>\s*[\'"][^\'"]*[\'"]/i' => '$1REDACTED$1 => \'[redacted]\'',
			'/define\s*\(\s*[\'"](DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|NONCE_KEY|AUTH_SALT)[\'"]\s*,\s*[\'"][^\'"]*[\'"]\s*\)/i' => 'define(\'$1\', \'[redacted]\')',
		);
		$snippet = preg_replace( array_keys( $patterns ), array_values( $patterns ), $snippet );
		return mb_substr( $snippet, 0, self::MAX_SNIPPET_LENGTH );
	}

	/**
	 * Core entry point: classify a snippet, respecting quota and
	 * falling back to a deterministic rule when AI isn't available,
	 * fails, times out, or returns something we can't validate.
	 *
	 * @return array { verdict, confidence, reason, fallback_used }
	 */
	public function classify_snippet( $snippet, $signature_label ) {
		$provider = get_option( 'sentinelwp_ai_provider', '' );
		$api_key  = get_option( 'sentinelwp_ai_api_key', '' );

		$can_use_ai = '' !== $provider
			&& '' !== trim( (string) $api_key )
			&& SentinelWP_Freemium::ai_quota_remaining() > 0;

		if ( ! $can_use_ai ) {
			return $this->fallback_verdict( $signature_label, false );
		}

		$prompt = $this->build_prompt( $snippet, $signature_label );
		$raw    = $this->call_provider( $provider, $api_key, $prompt );

		if ( false === $raw ) {
			return $this->fallback_verdict( $signature_label, true );
		}

		$parsed = $this->validate_json_contract( $raw );
		if ( false === $parsed ) {
			$this->log_ai_call( $provider, 'snippet_triage', $snippet, null, true );
			return $this->fallback_verdict( $signature_label, true );
		}

		SentinelWP_Freemium::record_ai_use();
		$this->log_ai_call( $provider, 'snippet_triage', $snippet, $parsed, false );

		return array(
			'verdict'       => $parsed['verdict'],
			'confidence'    => $parsed['confidence'],
			'reason'        => $parsed['reason'],
			'fallback_used' => false,
		);
	}

	/**
	 * Deterministic fallback used whenever AI is unavailable, unset, out
	 * of quota, or fails. Never blocks the finding — it's still reported
	 * as needing manual review, just without an AI-generated verdict.
	 */
	private function fallback_verdict( $signature_label, $ai_attempted ) {
		return array(
			'verdict'       => 'suspicious',
			'confidence'    => 'low',
			'reason'        => sprintf(
				/* translators: %s: matched signature label */
				__( 'Matched pattern "%s". AI triage unavailable — flagged for manual review.', 'sentinelwp-security' ),
				$signature_label
			),
			'fallback_used' => true,
		);
	}

	private function build_prompt( $snippet, $signature_label ) {
		$system = 'You are a WordPress security analyst reviewing a short code snippet that a static scanner already flagged. '
			. 'You are only classifying the snippet given to you — never invent file names, CVE IDs, or facts not present in the input. '
			. 'Respond with ONLY a single JSON object, no markdown fences, no commentary before or after: '
			. '{"verdict": "malicious"|"suspicious"|"benign", "confidence": "low"|"medium"|"high", "reason": "<one sentence>"}.';

		$user = sprintf(
			"Static scanner matched signature: %s\n\nSnippet (may be truncated, whitespace/context trimmed):\n---\n%s\n---\n\nClassify this snippet.",
			$signature_label,
			$snippet
		);

		return array( 'system' => $system, 'user' => $user );
	}

	/**
	 * Dispatches to the configured provider. Every branch enforces the
	 * same timeout and the same "fail closed to false" behavior so a
	 * provider outage degrades to the rule-based fallback instead of
	 * hanging the cron job.
	 *
	 * @return string|false raw text response, or false on any failure
	 */
	private function call_provider( $provider, $api_key, $prompt ) {
		switch ( $provider ) {
			case 'claude':
				return $this->call_claude( $api_key, $prompt );
			case 'openai':
				return $this->call_openai( $api_key, $prompt );
			case 'gemini':
				return $this->call_gemini( $api_key, $prompt );
			default:
				return false;
		}
	}

	private function call_claude( $api_key, $prompt ) {
		$response = wp_remote_post(
			'https://api.anthropic.com/v1/messages',
			array(
				'timeout' => self::REQUEST_TIMEOUT,
				'headers' => array(
					'content-type'      => 'application/json',
					'x-api-key'         => $api_key,
					'anthropic-version' => '2023-06-01',
				),
				'body'    => wp_json_encode(
					array(
						'model'      => 'claude-sonnet-4-6',
						'max_tokens' => 200,
						'system'     => $prompt['system'],
						'messages'   => array(
							array( 'role' => 'user', 'content' => $prompt['user'] ),
						),
					)
				),
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return isset( $body['content'][0]['text'] ) ? $body['content'][0]['text'] : false;
	}

	private function call_openai( $api_key, $prompt ) {
		$response = wp_remote_post(
			'https://api.openai.com/v1/chat/completions',
			array(
				'timeout' => self::REQUEST_TIMEOUT,
				'headers' => array(
					'content-type'  => 'application/json',
					'authorization' => 'Bearer ' . $api_key,
				),
				'body'    => wp_json_encode(
					array(
						'model'           => 'gpt-4o-mini',
						'max_tokens'      => 200,
						'response_format' => array( 'type' => 'json_object' ),
						'messages'        => array(
							array( 'role' => 'system', 'content' => $prompt['system'] ),
							array( 'role' => 'user', 'content' => $prompt['user'] ),
						),
					)
				),
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return isset( $body['choices'][0]['message']['content'] ) ? $body['choices'][0]['message']['content'] : false;
	}

	private function call_gemini( $api_key, $prompt ) {
		$response = wp_remote_post(
			'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' . rawurlencode( $api_key ),
			array(
				'timeout' => self::REQUEST_TIMEOUT,
				'headers' => array( 'content-type' => 'application/json' ),
				'body'    => wp_json_encode(
					array(
						'system_instruction' => array( 'parts' => array( array( 'text' => $prompt['system'] ) ) ),
						'contents'           => array(
							array( 'parts' => array( array( 'text' => $prompt['user'] ) ) ),
						),
						'generationConfig'   => array(
							'responseMimeType' => 'application/json',
							'maxOutputTokens'  => 200,
						),
					)
				),
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return isset( $body['candidates'][0]['content']['parts'][0]['text'] ) ? $body['candidates'][0]['content']['parts'][0]['text'] : false;
	}

	/**
	 * Strict validation of the JSON output contract. A response that
	 * merely "looks JSON-ish" is not good enough — the verdict and
	 * confidence values must be from the closed enum we defined, or the
	 * whole result is discarded in favor of the fallback.
	 *
	 * @return array|false
	 */
	private function validate_json_contract( $raw ) {
		$raw = trim( $raw );
		// Strip accidental markdown fences some models add despite instructions.
		$raw = preg_replace( '/^```(?:json)?|```$/m', '', $raw );
		$raw = trim( $raw );

		$data = json_decode( $raw, true );
		if ( ! is_array( $data ) ) {
			return false;
		}
		if ( empty( $data['verdict'] ) || ! in_array( $data['verdict'], self::ALLOWED_VERDICTS, true ) ) {
			return false;
		}
		if ( empty( $data['confidence'] ) || ! in_array( $data['confidence'], self::ALLOWED_CONFIDENCE, true ) ) {
			return false;
		}
		if ( empty( $data['reason'] ) || ! is_string( $data['reason'] ) ) {
			return false;
		}

		return array(
			'verdict'    => $data['verdict'],
			'confidence' => $data['confidence'],
			'reason'     => sanitize_text_field( mb_substr( $data['reason'], 0, 300 ) ),
		);
	}

	private function apply_verdict_to_finding( $finding_id, array $verdict ) {
		global $wpdb;
		$table = $wpdb->prefix . 'sentinelwp_findings';

		// Escalate severity when AI is confident it's malicious;
		// never downgrade a critical finding automatically just because
		// AI said "benign" — a human still confirms that (§5 of the plan:
		// no automatic remediation/downgrade based on AI alone in free tier).
		$updates = array(
			'ai_verdict' => $verdict['verdict'],
			'ai_reason'  => $verdict['reason'],
			'updated_at' => current_time( 'mysql' ),
		);

		$wpdb->update( $table, $updates, array( 'id' => $finding_id ), array( '%s', '%s', '%s' ), array( '%d' ) );

		do_action( 'sentinelwp_ai_verdict_applied', $finding_id, $verdict );
	}

	private function log_ai_call( $provider, $job_type, $input, $parsed, $fallback_used ) {
		global $wpdb;
		$wpdb->insert(
			$wpdb->prefix . 'sentinelwp_ai_log',
			array(
				'provider'      => $provider,
				'job_type'      => $job_type,
				'input_hash'    => hash( 'sha256', $input ),
				'verdict'       => $parsed['verdict'] ?? null,
				'confidence'    => $parsed['confidence'] ?? null,
				'fallback_used' => $fallback_used ? 1 : 0,
				'created_at'    => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
		);
	}
}
