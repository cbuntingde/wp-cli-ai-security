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

use WPAISecurity\Utils\Cache;

/**
 * Handles AI-powered code analysis for WordPress packages.
 */
class AIAnalyzer {

	/**
	 * Configuration service.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Cache service.
	 *
	 * @var Cache
	 */
	private $cache;

	/**
	 * WordPress security patterns to check.
	 *
	 * @var array
	 */
	private $wp_security_rules = array(
		array(
			'id'       => 'wp-001',
			'pattern'  => 'eval\s*\(',
			'title'    => 'Use of eval() detected',
			'severity' => 'high',
			'desc'     => 'eval() is dangerous and can lead to code injection.',
		),
		array(
			'id'       => 'wp-002',
			'pattern'  => 'base64_decode\s*\(',
			'title'    => 'Base64 decode detected',
			'severity' => 'medium',
			'desc'     => 'Often used to obfuscate malicious code.',
		),
		array(
			'id'       => 'wp-003',
			'pattern'  => 'shell_exec\s*\(|exec\s*\(|passthru\s*\(|system\s*\(',
			'title'    => 'Shell command execution detected',
			'severity' => 'high',
			'desc'     => 'Potential command injection vulnerability.',
		),
		array(
			'id'       => 'wp-004',
			'pattern'  => '\$_GET\s*\[|\$_POST\s*\[|\$_REQUEST\s*\[',
			'title'    => 'Raw user input access',
			'severity' => 'medium',
			'desc'     => 'User input should be sanitized before use.',
		),
		array(
			'id'       => 'wp-005',
			'pattern'  => 'mysql_\$|mysqli_\$|wpdb->prepare.*%',
			'title'    => 'Potential SQL injection risk',
			'severity' => 'high',
			'desc'     => 'SQL queries should use prepared statements.',
		),
		array(
			'id'       => 'wp-006',
			'pattern'  => 'file_get_contents\s*\(\s*\$_|file_put_contents\s*\(\s*\$_|fopen\s*\(\s*\$_',
			'severity' => 'high',
			'title'    => 'File operations with user input',
			'desc'     => 'Path traversal or arbitrary file read/write risk.',
		),
		array(
			'id'       => 'wp-007',
			'pattern'  => 'wp_ajax_\$|wp_ajax_nopriv_\$',
			'title'    => 'AJAX handler without nonce check',
			'severity' => 'medium',
			'desc'     => 'AJAX actions should verify nonces for security.',
		),
		array(
			'id'       => 'wp-008',
			'pattern'  => 'create_function\s*\(|preg_replace.*\/e',
			'deprecated' => true,
			'title'    => 'Deprecated dangerous functions',
			'severity' => 'medium',
			'desc'     => 'These functions are deprecated and potentially dangerous.',
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
		$provider = $this->config->get( 'ai_provider', 'semgrep' );
		$method   = 'analyze_' . $provider;

		if ( method_exists( $this, $method ) ) {
			return $this->$method( $path );
		}

		// Fallback to pattern matching.
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
		exec( 'which semgrep 2>/dev/null', $output, $return_code );

		if ( 0 !== $return_code ) {
			\WP_CLI::warning( 'Semgrep not installed. Run: pip install semgrep' );
			return $this->analyze_patterns( $path );
		}

		$cache_key = 'ai_semgrep_' . md5( $path );
		$cached    = $this->cache->get( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$temp_rules = sys_get_temp_dir() . '/wp-ai-security-rules.yml';
		$this->write_semgrep_rules( $temp_rules );

		$output_file = sys_get_temp_dir() . '/semgrep-output.json';

		// Sanitize path to prevent command injection (ASI05)
		$safe_path = escapeshellarg( $path );
		$safe_rules = escapeshellarg( $temp_rules );
		$safe_output = escapeshellarg( $output_file );

		$command = "semgrep --config={$safe_rules} --json --output={$safe_output} {$safe_path} 2>/dev/null";

		exec( $command, $output, $return_code );

		$findings = array();
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
			unlink( $output_file );
		}

		unlink( $temp_rules );
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
	 * Analyze using OpenAI API.
	 *
	 * @param string $path Path to analyze.
	 * @return array Findings.
	 */
	private function analyze_openai( $path ) {
		$api_key = $this->config->get_ai_api_key();

		if ( empty( $api_key ) ) {
			\WP_CLI::warning( 'No OpenAI API key configured. Using pattern matching.' );
			return $this->analyze_patterns( $path );
		}

		// First run pattern matching for quick results.
		$pattern_findings = $this->analyze_patterns( $path );

		// Then use OpenAI for deeper analysis on suspicious files.
		$suspicious_files = array();
		foreach ( $pattern_findings as $finding ) {
			if ( in_array( $finding['severity'], array( 'high', 'critical' ) ) ) {
				$suspicious_files[] = $finding['file'];
			}
		}

		if ( empty( $suspicious_files ) ) {
			return $pattern_findings;
		}

		// Get first suspicious file for AI analysis.
		$first_file = $this->find_php_files( $path )[0] ?? '';
		if ( empty( $first_file ) ) {
			return $pattern_findings;
		}

		$code = substr( file_get_contents( $first_file ), 0, 8000 ); // Limit to first 8000 chars.

		$prompt = "Analyze this WordPress plugin code for security vulnerabilities, malware, backdoors, and suspicious patterns. Focus on:\n" .
			"- SQL injection vulnerabilities\n" .
			"- XSS (cross-site scripting) vulnerabilities\n" .
			"- CSRF vulnerabilities\n" .
			"- Remote code execution risks\n" .
			"- Obfuscated code\n" .
			"- Backdoors or malicious code\n" .
			"- Authentication bypasses\n\n" .
			"Code:\n```php\n{$code}\n```\n\n" .
			"Return a JSON array of findings, each with: title, severity (low/medium/high/critical), description, and file.";

		$response = $this->call_openai_api( $api_key, $prompt );

		if ( ! empty( $response ) ) {
			// Merge AI findings with pattern findings.
			return array_merge( $pattern_findings, $response );
		}

		return $pattern_findings;
	}

	/**
	 * Call OpenAI API.
	 *
	 * @param string $api_key API key.
	 * @param string $prompt  Prompt to send.
	 * @return array Response.
	 */
	private function call_openai_api( $api_key, $prompt ) {
		$url = 'https://api.openai.com/v1/chat/completions';

		$data = array(
			'model'       => 'gpt-4o-mini',
			'messages'    => array(
				array(
					'role'    => 'system',
					'content' => 'You are a security expert analyzing WordPress plugins for vulnerabilities.',
				),
				array(
					'role'    => 'user',
					'content' => $prompt,
				),
			),
			'temperature' => 0.2,
		);

		$context = stream_context_create( array(
			'http' => array(
				'method'  => 'POST',
				'header'  => array(
					'Content-Type: application/json',
					'Authorization: Bearer ' . $api_key,
				),
				'content' => json_encode( $data ),
				'timeout' => 60,
			),
			'ssl' => array(
				'verify_peer'      => true,
				'verify_peer_name' => true,
			),
		) );

		$response = @file_get_contents( $url, false, $context );

		if ( false === $response ) {
			return array();
		}

		$result = json_decode( $response, true );
		$content = $result['choices'][0]['message']['content'] ?? '';

		// Try to extract JSON from response.
		if ( preg_match( '/\[[\s\S]*\]/', $content, $matches ) ) {
			return json_decode( $matches[0], true ) ?: array();
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
			$rules['rules'][] = array(
				'id'     => $rule['id'],
				'pattern' => $rule['pattern'],
				'message' => $rule['desc'],
				'severity' => 'WARNING',
				'languages' => array( 'php' ),
				'metadata'  => array(
					'cwe'  => $rule['title'],
					'owasp' => 'A1:2017 - Injection',
				),
			);
		}

		// Convert to YAML-like format for Semgrep.
		$yaml = "rules:\n";
		foreach ( $rules['rules'] as $rule ) {
			$yaml .= "  - id: {$rule['id']}\n";
			$yaml .= "    pattern: \$X = {$rule['pattern']}\n";
			$yaml .= "    message: {$rule['message']}\n";
			$yaml .= "    severity: WARNING\n";
			$yaml .= "    languages:\n      - php\n";
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
		return array( 'semgrep', 'openai', 'patterns' );
	}
}