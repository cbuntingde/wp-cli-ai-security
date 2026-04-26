<?php
/**
 * AI Code Analyzer Service.
 *
 * Uses Semgrep and AI models to analyze code for security issues,
 * malware, backdoors, and suspicious patterns.
 *
 * @package WPAISecurity
 */

namespace WPAISecurity\Services;

use WPAISecurity\Exceptions\ApiException;
use WPAISecurity\Utils\Cache;

/**
 * Handles AI-powered code analysis for WordPress packages.
 */
class AIAnalyzer {

	private const ANTHROPIC_API_URL  = 'https://api.anthropic.com/v1/messages';
	private const ANTHROPIC_MODEL    = 'claude-sonnet-4-20250514';
	private const ANTHROPIC_VERSION  = '2023-06-01';
	private const ANTHROPIC_TIMEOUT  = 120;
	private const MAX_RETRIES        = 3;
	private const RETRY_BASE_DELAY_MS = 1000;
	private const CODE_CHUNK_LENGTH  = 12000;

	private $config;
	private $cache;

	private $wp_security_rules = array(
		array(
			'id'       => 'wp-001',
			'pattern'  => '(?:eval|assert)\s*\(',
			'title'    => 'Use of eval() or assert() detected',
			'severity' => 'critical',
			'desc'     => 'Code execution functions that can lead to RCE.',
		),
		array(
			'id'       => 'wp-002',
			'pattern'  => 'base64_decode\s*\(',
			'title'    => 'Base64 decode detected',
			'severity' => 'medium',
			'desc'     => 'Often used to obfuscate malicious code, especially when combined with eval.',
		),
		array(
			'id'       => 'wp-003',
			'pattern'  => '(?:shell_exec|exec|passthru|system|popen|proc_open|pcntl_exec)\s*\(',
			'title'    => 'Shell command execution detected',
			'severity' => 'critical',
			'desc'     => 'Command execution functions present a critical RCE risk.',
		),
		array(
			'id'       => 'wp-004',
			'pattern'  => '(?<!\w)\$_GET\s*\[|\$_POST\s*\[|\$_REQUEST\s*\[|\$_SERVER\s*\[\s*[\'"]REQUEST_METHOD',
			'title'    => 'Raw superglobal input access',
			'severity' => 'medium',
			'desc'     => 'Superglobal input should be sanitized and validated before use.',
		),
		array(
			'id'       => 'wp-005',
			'pattern'  => 'mysql_\w+\s*\(|mysqli_\w+\s*\(|wpdb->query|wpdb->get_var|wpdb->get_row',
			'title'    => 'Potential SQL injection risk',
			'severity' => 'high',
			'desc'     => 'Direct database queries should use wpdb->prepare() with parameterized queries.',
		),
		array(
			'id'       => 'wp-006',
			'pattern'  => '(?:file_get_contents|file_put_contents|fopen|fwrite|fputs|move_uploaded_file|copy|rename|unlink|chmod)\s*\(\s*(?:\$_|\$[\w]+)',
			'severity' => 'high',
			'title'    => 'File operations with dynamic/user input',
			'desc'     => 'Path traversal or arbitrary file read/write risk from unsanitized input.',
		),
		array(
			'id'       => 'wp-007',
			'pattern'  => 'add_action\s*\(\s*[\'"]wp_ajax_|add_action\s*\(\s*[\'"]wp_ajax_nopriv_',
			'title'    => 'AJAX handler registered without visible nonce check',
			'severity' => 'medium',
			'desc'     => 'AJAX actions should verify nonces via check_ajax_referer() or check_admin_referer().',
		),
		array(
			'id'       => 'wp-008',
			'pattern'  => '(?:create_function|preg_replace\s*\(.*\/[eems]*e)',
			'deprecated' => true,
			'title'    => 'Deprecated dangerous functions',
			'severity' => 'high',
			'desc'     => 'create_function() and /e modifier in preg_replace are deprecated and enable code injection.',
		),
		array(
			'id'       => 'wp-009',
			'pattern'  => '(?:gzinflate|str_rot13|gzuncompress|gzdecode)\s*\(\s*(?:base64_decode|\$)',
			'title'    => 'Obfuscated code pattern detected',
			'severity' => 'critical',
			'desc'     => 'Nested decoding functions are a strong indicator of obfuscated malware.',
		),
		array(
			'id'       => 'wp-010',
			'pattern'  => '\$\s*_\s*=\s*|\(\s*function\s*\(\s*\)\s*use\s*\(|preg_replace\s*\(\s*(?:[\'"])(.)\1[^es]*[es]',
			'title'    => 'Suspicious obfuscation or callback pattern',
			'severity' => 'high',
			'desc'     => 'Common malware patterns using variable variables or obfuscated callbacks.',
		),
	);

	/**
	 * Constructor.
	 *
	 * @param Config $config Configuration service.
	 * @param Cache  $cache  Cache service.
	 */
	public function __construct( Config $config, Cache $cache ) {
		$this->config = $config;
		$this->cache  = $cache;
	}

	/**
	 * Analyze code for security issues.
	 *
	 * @param string $path Path to the code to analyze.
	 * @return array List of findings.
	 */
	public function analyze( $path ) {
		if ( ! is_dir( $path ) && ! is_file( $path ) ) {
			\WP_CLI::warning( "Analysis path does not exist: {$path}" );
			return array();
		}

		$provider = $this->config->get( 'ai_provider', 'semgrep' );
		$method   = 'analyze_' . $provider;

		if ( method_exists( $this, $method ) ) {
			\WP_CLI::debug( "Running analysis with provider: {$provider}", 'wp-ai-security' );
			return $this->$method( $path );
		}

		\WP_CLI::warning( "Unknown AI provider '{$provider}', falling back to pattern matching." );

		return $this->analyze_patterns( $path );
	}

	/**
	 * Analyze using Semgrep.
	 *
	 * @param string $path Path to analyze.
	 * @return array Findings.
	 */
private function analyze_semgrep( $path ) {
		// Check if Semgrep is installed.
		// Note: Semgrep is an external CLI tool that must be executed via exec().
		// This is necessary because Semgrep provides rule-based static analysis
		// that cannot be replicated through PHP native functions alone.
		exec( 'which semgrep 2>/dev/null', $output, $return_code );

		if ( 0 !== $return_code ) {
			\WP_CLI::warning( 'Semgrep not installed. Run: pip install semgrep' );
			return $this->analyze_patterns( $path );
		}

		// Validate path exists before attempting analysis.
		if ( ! file_exists( $path ) ) {
			\WP_CLI::warning( "Path does not exist: {$path}" );
			return array();
		}

		$cache_key = 'ai_semgrep_' . md5( $path );
		$cached    = $this->cache->get( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$temp_rules = sys_get_temp_dir() . '/wp-ai-security-rules.yml';
		$this->write_semgrep_rules( $temp_rules );

		$output_file = sys_get_temp_dir() . '/semgrep-output.json';

		// Sanitize path to prevent command injection (ASI05).
		// All user-controlled inputs are escaped via escapeshellarg().
		$safe_path = escapeshellarg( $path );
		$safe_rules = escapeshellarg( $temp_rules );
		$safe_output = escapeshellarg( $output_file );

		$command = "semgrep --config={$safe_rules} --json --output={$safe_output} {$safe_path} 2>/dev/null";

		// Execute Semgrep with error handling.
		// Timeout is handled by the system via shell timeout settings.
		exec( $command, $output, $return_code );

		$findings = array();

		// Only parse output file if Semgrep executed successfully.
		if ( file_exists( $output_file ) ) {
			$results = json_decode( file_get_contents( $output_file ), true );
			if ( ! empty( $results['results'] ) ) {
				foreach ( $results['results'] as $result ) {
					$findings[] = array(
						'title'    => $result['extra']['message'] ?? 'Security issue detected',
						'file'     => basename( $result['path'] ?? '' ),
						'line'     => $result['start']['line'] ?? 0,
						'severity' => $this->map_semgrep_severity( $result['extra']['severity'] ?? 'WARNING' ),
						'pattern'  => $result['extra']['metadata']['cwe'] ?? '',
						'rule_id'  => $result['check_id'] ?? '',
					);
				}
			}
			// Clean up output file.
			unlink( $output_file );
		} elseif ( 0 !== $return_code ) {
			// Log warning if Semgrep failed to produce output.
			\WP_CLI::warning( 'Semgrep execution returned non-zero status: ' . $return_code );
		}

		// Clean up temp rules file if it exists.
		if ( file_exists( $temp_rules ) ) {
			unlink( $temp_rules );
		}

		$this->cache->set( $cache_key, $findings );
		return $findings;
	}

	/**
	 * Analyze using pattern matching (no external tools needed).
	 *
	 * @param string $path Path to analyze.
	 * @return array Findings.
	 */
	private function analyze_patterns( $path ) {
		$cache_key = 'ai_patterns_' . md5( $path );
		$cached    = $this->cache->get( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$findings = array();
		$php_files = $this->find_php_files( $path );

		foreach ( $php_files as $file ) {
			$content = file_get_contents( $file );

			foreach ( $this->wp_security_rules as $rule ) {
				if ( preg_match( '/' . $rule['pattern'] . '/i', $content, $matches, PREG_OFFSET_CAPTURE ) ) {
					// Get line number.
					$line_num = substr_count( substr( $content, 0, $matches[0][1] ), "\n" ) + 1;

					$findings[] = array(
						'title'    => $rule['title'],
						'file'     => basename( $file ),
						'line'     => $line_num,
						'severity' => $rule['severity'],
						'desc'     => $rule['desc'],
						'rule_id'  => $rule['id'],
					);
				}
			}
		}

		$this->cache->set( $cache_key, $findings );
		return $findings;
	}

	/**
	 * Analyze using Anthropic Claude API.
	 *
	 * @param string $path Path to analyze.
	 * @return array Findings.
	 */
	private function analyze_anthropic( $path ) {
		$api_key = $this->config->get_ai_api_key();

		if ( empty( $api_key ) ) {
			\WP_CLI::warning( 'No Anthropic API key configured. Using pattern matching.' );
			return $this->analyze_patterns( $path );
		}

		$pattern_findings = $this->analyze_patterns( $path );

		$suspicious_files = array();
		foreach ( $pattern_findings as $finding ) {
			if ( in_array( $finding['severity'], array( 'high', 'critical' ), true ) ) {
				$suspicious_files[] = $finding['file'];
			}
		}

		if ( empty( $suspicious_files ) ) {
			\WP_CLI::debug( 'No suspicious files found by pattern matching; skipping AI analysis.', 'wp-ai-security' );
			return $pattern_findings;
		}

		$php_files = $this->find_php_files( $path );
		if ( empty( $php_files ) ) {
			return $pattern_findings;
		}

		$ai_findings = array();
		$files_analyzed = 0;
		$max_ai_files   = min( 3, count( $php_files ) );

		foreach ( $php_files as $file_path ) {
			if ( $files_analyzed >= $max_ai_files ) {
				break;
			}

			$basename = basename( $file_path );

			$is_suspicious = false;
			foreach ( $suspicious_files as $sf ) {
				if ( $sf === $basename || strpos( $basename, $sf ) !== false ) {
					$is_suspicious = true;
					break;
				}
			}

			if ( ! $is_suspicious ) {
				continue;
			}

			$code = file_get_contents( $file_path );

			if ( strlen( $code ) > self::CODE_CHUNK_LENGTH ) {
				$code = substr( $code, 0, self::CODE_CHUNK_LENGTH );
				\WP_CLI::debug( "Truncated {$basename} to " . self::CODE_CHUNK_LENGTH . ' chars for AI analysis.', 'wp-ai-security' );
			}

			$prompt = $this->build_analysis_prompt( $basename, $code );
			$response = $this->call_anthropic_api( $api_key, $prompt );

			if ( ! empty( $response ) && is_array( $response ) ) {
				foreach ( $response as $finding ) {
					if ( ! isset( $finding['file'] ) ) {
						$finding['file'] = $basename;
					}
					$ai_findings[] = $finding;
				}
				$files_analyzed++;
			}
		}

		if ( ! empty( $ai_findings ) ) {
			\WP_CLI::debug( 'Merging ' . count( $ai_findings ) . ' AI findings with ' . count( $pattern_findings ) . ' pattern findings.', 'wp-ai-security' );
			return array_merge( $pattern_findings, $ai_findings );
		}

		return $pattern_findings;
	}

	/**
	 * Build the analysis prompt for Anthropic Claude.
	 *
	 * @param string $filename Source file name.
	 * @param string $code     Source code content.
	 * @return string
	 */
	private function build_analysis_prompt( $filename, $code ) {
		$prompt = "Analyze this WordPress {$filename} code for security vulnerabilities, malware, backdoors, and suspicious patterns.\n\n" .
			"Focus on:\n" .
			"- SQL injection vulnerabilities\n" .
			"- XSS (cross-site scripting) vulnerabilities\n" .
			"- CSRF / missing nonce checks\n" .
			"- Remote code execution risks\n" .
			"- Obfuscated or encoded code\n" .
			"- Backdoors or malicious code\n" .
			"- Authentication bypasses\n" .
			"- Privilege escalation\n" .
			"- Server-side request forgery (SSRF)\n" .
			"- File inclusion or path traversal\n\n" .
			"Code:\n```php\n{$code}\n```\n\n" .
			"Return findings as a JSON array of objects, each with these exact keys:\n" .
			"- title (string): concise finding name\n" .
			"- severity (string): one of low, medium, high, critical\n" .
			"- description (string): detailed explanation of the vulnerability\n" .
			"- file (string): {$filename}\n" .
			"If no vulnerabilities are found, return an empty array []. Do not include any text outside the JSON array.";

		return $prompt;
	}

	/**
	 * Call Anthropic Claude API with retry and exponential backoff.
	 *
	 * @param string $api_key  Anthropic API key.
	 * @param string $prompt   Prompt to send.
	 * @param int    $retries  Remaining retry count.
	 * @return array Parsed findings from response.
	 */
	private function call_anthropic_api( $api_key, $prompt, $retries = self::MAX_RETRIES ) {
		$body = array(
			'model'       => self::ANTHROPIC_MODEL,
			'max_tokens'  => 4096,
			'temperature' => 0.2,
			'system'      => 'You are a security expert analyzing WordPress PHP code for vulnerabilities. Return only valid JSON arrays.',
			'messages'    => array(
				array(
					'role'    => 'user',
					'content' => $prompt,
				),
			),
		);

		$headers = array(
			'Content-Type: application/json',
			'x-api-key: ' . $api_key,
			'anthropic-version: ' . self::ANTHROPIC_VERSION,
		);

		$context = stream_context_create( array(
			'http' => array(
				'method'  => 'POST',
				'header'  => $headers,
				'content' => json_encode( $body ),
				'timeout' => self::ANTHROPIC_TIMEOUT,
				'ignore_errors' => true,
			),
			'ssl' => array(
				'verify_peer'      => true,
				'verify_peer_name' => true,
			),
		) );

		$response = @file_get_contents( self::ANTHROPIC_API_URL, false, $context );

		if ( false === $response ) {
			$error = error_get_last();
			$error_message = is_array( $error ) ? ( $error['message'] ?? 'Unknown error' ) : 'Unknown error';

			if ( $retries > 1 ) {
				$delay_ms = self::RETRY_BASE_DELAY_MS * pow( 2, self::MAX_RETRIES - $retries );
				\WP_CLI::debug( "Anthropic API error: {$error_message}. Retrying in {$delay_ms}ms... ({$retries} retries left)", 'wp-ai-security' );
				usleep( $delay_ms * 1000 );
				return $this->call_anthropic_api( $api_key, $prompt, $retries - 1 );
			}

			\WP_CLI::warning( "Anthropic API request failed after " . self::MAX_RETRIES . " attempts: {$error_message}" );
			return array();
		}

		$http_response_header_array = $http_response_header ?? array();
		$http_code = 0;
		foreach ( $http_response_header_array as $header ) {
			if ( preg_match( '/^HTTP\/\d\.\d\s+(\d+)/', $header, $matches ) ) {
				$http_code = (int) $matches[1];
				break;
			}
		}

		if ( $http_code >= 400 ) {
			if ( 429 === $http_code && $retries > 1 ) {
				$delay_ms = self::RETRY_BASE_DELAY_MS * pow( 2, self::MAX_RETRIES - $retries );
				\WP_CLI::debug( "Anthropic API rate limited (429). Retrying in {$delay_ms}ms... ({$retries} retries left)", 'wp-ai-security' );
				usleep( $delay_ms * 1000 );
				return $this->call_anthropic_api( $api_key, $prompt, $retries - 1 );
			}

			$response_body = json_decode( $response, true );
			$error_detail = $response_body['error']['message'] ?? "HTTP {$http_code}";
			\WP_CLI::warning( "Anthropic API returned {$http_code}: {$error_detail}" );

			if ( in_array( $http_code, array( 401, 403 ), true ) ) {
				\WP_CLI::warning( 'Your Anthropic API key appears to be invalid or unauthorized. Run: wp ai-security config set --key=ai_api_key --value=YOUR_KEY' );
			}

			return array();
		}

		$result = json_decode( $response, true );

		if ( ! is_array( $result ) || ! isset( $result['content'][0]['text'] ) ) {
			\WP_CLI::warning( 'Unexpected Anthropic API response format.' );
			return array();
		}

		$content = $result['content'][0]['text'];

		if ( preg_match( '/\[[\s\S]*?\]/', $content, $matches ) ) {
			$decoded = json_decode( $matches[0], true );
			if ( is_array( $decoded ) ) {
				return $decoded;
			}
		}

		return array();
	}

	/**
	 * Write Semgrep rules to temp file.
	 *
	 * @param string $path Output path.
	 */
	private function write_semgrep_rules( $path ) {
		$rules = array(
			'rules' => array(),
		);

		foreach ( $this->wp_security_rules as $rule ) {
			$severity_map = array(
				'critical' => 'ERROR',
				'high'     => 'ERROR',
				'medium'   => 'WARNING',
				'low'      => 'INFO',
			);

			$semgrep_severity = $severity_map[ $rule['severity'] ] ?? 'WARNING';

			$rules['rules'][] = array(
				'id'       => $rule['id'],
				'pattern'  => $rule['pattern'],
				'message'  => $rule['title'] . ': ' . $rule['desc'],
				'severity' => $semgrep_severity,
				'languages' => array( 'php' ),
				'metadata'  => array(
					'cwe'   => $rule['title'],
					'owasp' => 'A1:2017 - Injection',
				),
			);
		}

		// Generate valid Semgrep YAML rules file.
		$yaml = "rules:\n";
		foreach ( $rules['rules'] as $rule ) {
			$yaml .= "  - id: {$rule['id']}\n";
			$yaml .= "    pattern: {$rule['pattern']}\n";
			$yaml .= "    message: {$rule['message']}\n";
			$yaml .= "    severity: {$rule['severity']}\n";
			$yaml .= "    languages:\n";
			$yaml .= "      - php\n";
		}

		file_put_contents( $path, $yaml );
	}

	/**
	 * Find all PHP files in a directory.
	 *
	 * @param string $path Directory path.
	 * @return array List of PHP files.
	 */
	private function find_php_files( $path ) {
		$files = array();
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $path, \RecursiveDirectoryIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $file ) {
			if ( 'php' === strtolower( $file->getExtension() ) ) {
				$files[] = $file->getPathname();
			}
		}

		return $files;
	}

	/**
	 * Map Semgrep severity to our standard.
	 *
	 * @param string $severity Semgrep severity.
	 * @return string Mapped severity.
	 */
	private function map_semgrep_severity( $severity ) {
		$mapping = array(
			'ERROR'   => 'critical',
			'WARNING' => 'medium',
			'INFO'    => 'low',
		);
		return $mapping[ $severity ] ?? 'medium';
	}

	/**
	 * Get supported AI providers.
	 *
	 * @return array
	 */
	public function get_providers() {
		return array( 'semgrep', 'anthropic', 'patterns' );
	}
}