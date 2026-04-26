<?php
/**
 * Configuration service for AI Security.
 *
 * @package WPAISecurity
 */

namespace WPAISecurity\Services;

/**
 * Handles configuration management for the AI Security package.
 */
class Config {

	/**
	 * Configuration file path.
	 *
	 * @var string
	 */
	private $config_file;

	/**
	 * Configuration data.
	 *
	 * @var array
	 */
	private $data;

	/**
	 * Default configuration values.
	 *
	 * @var array
	 */
	private $defaults = array(
		'api_provider'     => 'wpscan',  // wpscan, patchstack, or nvd
		'api_key'          => '',
		'ai_enabled'       => false,
		'ai_provider'      => 'semgrep', // semgrep, anthropic, or patterns
		'ai_api_key'       => '',
		'cache_dir'        => '',
		'cache_ttl'        => 86400,     // 24 hours in seconds
		'strict_mode'      => false,     // Block installation on any finding
		'ignore_cves'      => array(),   // List of CVEs to ignore
		'min_severity'     => 'low',     // Minimum severity to report
		'auto_audit'       => false,     // Auto-audit after install
		'log_audits'       => true,
	);

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->config_file = $this->get_config_file_path();
		$this->data        = $this->load();
	}

	/**
	 * Get the configuration file path.
	 *
	 * @return string
	 */
	private function get_config_file_path() {
		$home = getenv( 'HOME' ) ?: getenv( 'USERPROFILE' ) ?: sys_get_temp_dir();
		$dir  = $home . '/.wp-ai-security';

		if ( ! is_dir( $dir ) ) {
			mkdir( $dir, 0700, true );
		}

		return $dir . '/config.json';
	}

	/**
	 * Load configuration from file.
	 *
	 * @return array
	 */
	private function load() {
		if ( file_exists( $this->config_file ) ) {
			$content = file_get_contents( $this->config_file );
			$data    = json_decode( $content, true );
			return is_array( $data ) ? array_merge( $this->defaults, $data ) : $this->defaults;
		}
		return $this->defaults;
	}

	/**
	 * Save configuration to file.
	 */
	private function save() {
		file_put_contents(
			$this->config_file,
			json_encode( $this->data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES )
		);
	}

	/**
	 * Get a configuration value.
	 *
	 * @param string $key     Configuration key.
	 * @param mixed  $default Default value if key not found.
	 * @return mixed
	 */
	public function get( $key, $default = null ) {
		$value = $this->data[ $key ] ?? $this->defaults[ $key ] ?? $default;

		// Apply dynamic defaults.
		if ( 'cache_dir' === $key && empty( $value ) ) {
			$value = sys_get_temp_dir() . '/wp-ai-security';
		}

		return $value;
	}

	/**
	 * Set a configuration value.
	 *
	 * @param string $key   Configuration key.
	 * @param mixed  $value Value to set.
	 */
	public function set( $key, $value ) {
		$this->data[ $key ] = $value;
		$this->save();
	}

	/**
	 * Get all configuration.
	 *
	 * @return array
	 */
	public function all() {
		return $this->data;
	}

	/**
	 * Check if AI is properly configured.
	 *
	 * @return bool
	 */
	public function is_ai_configured() {
		if ( ! $this->get( 'ai_enabled' ) ) {
			return false;
		}

		$provider = $this->get( 'ai_provider' );

		if ( 'semgrep' === $provider ) {
			// Check if semgrep is installed.
			exec( 'which semgrep 2>/dev/null', $output, $return_code );
			return 0 === $return_code;
		}

		// For Anthropic/API-based providers, check for API key.
		return ! empty( $this->get( 'ai_api_key' ) );
	}

	/**
	 * Check if vulnerability scanning is configured.
	 *
	 * @return bool
	 */
	public function is_vuln_scanning_configured() {
		$provider = $this->get( 'api_provider' );

		if ( 'wpscan' === $provider || 'patchstack' === $provider ) {
			return ! empty( $this->get( 'api_key' ) );
		}

		// NVD doesn't require API key but has rate limits.
		return true;
	}

	/**
	 * Get API key for the configured provider.
	 *
	 * @return string
	 */
	public function get_api_key() {
		return $this->get( 'api_key', '' );
	}

	/**
	 * Get AI API key.
	 *
	 * @return string
	 */
	public function get_ai_api_key() {
		return $this->get( 'ai_api_key', '' );
	}
}