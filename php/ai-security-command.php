<?php
/**
 * AI Security Command for WP-CLI
 *
 * Provides AI-powered security scanning for WordPress plugins and themes.
 * Supports pre-install scanning and post-install auditing.
 *
 * @package WPAISecurity
 */

if ( ! class_exists( 'WP_CLI' ) ) {
	return;
}

require_once __DIR__ . '/Commands/BaseCommand.php';
require_once __DIR__ . '/Commands/PluginScan.php';
require_once __DIR__ . '/Commands/ThemeScan.php';
require_once __DIR__ . '/Commands/Audit.php';
require_once __DIR__ . '/Exceptions/WPAISecurityException.php';
require_once __DIR__ . '/Exceptions/ApiException.php';
require_once __DIR__ . '/Exceptions/DownloadException.php';
require_once __DIR__ . '/Exceptions/ScanException.php';
require_once __DIR__ . '/Services/VulnerabilityScanner.php';
require_once __DIR__ . '/Services/AIAnalyzer.php';
require_once __DIR__ . '/Services/Config.php';
require_once __DIR__ . '/Utils/AuditLogger.php';
require_once __DIR__ . '/Utils/Cache.php';
require_once __DIR__ . '/Utils/Downloader.php';

// Register commands
WP_CLI::add_command( 'ai-plugin', 'WPAISecurity\\Commands\\PluginScan' );
WP_CLI::add_command( 'ai-theme', 'WPAISecurity\\Commands\\ThemeScan' );
WP_CLI::add_command( 'ai-audit', 'WPAISecurity\\Commands\\Audit' );
WP_CLI::add_command( 'ai-security', 'WPAISecurity\\Commands\\BaseCommand' );

/**
 * Main AI Security command group.
 *
 * ## EXAMPLES
 *
 *     # Scan a plugin before installation
 *     wp ai-plugin scan woocommerce
 *
 *     # Install plugin with security check
 *     wp ai-plugin install woocommerce --scan
 *
 *     # Audit all installed plugins
 *     wp ai-audit plugins
 *
 *     # Scan a theme
 *     wp ai-theme scan astra
 */
class WPAISecurity_Command {
	/**
	 * Shows AI Security help and status.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format - table, json, or yaml.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-security status
	 *
	 * @when after_wp_load
	 */
	public function status( $args, $assoc_args ) {
		$format = isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table';

		$config      = new \WPAISecurity\Services\Config();
		$cache       = new \WPAISecurity\Utils\Cache( $config );
		$audit_logger = new \WPAISecurity\Utils\AuditLogger( $config );

		$data = array(
			'cache_dir'       => $config->get( 'cache_dir', sys_get_temp_dir() . '/wp-ai-security' ),
			'api_provider'    => $config->get( 'api_provider', 'wpscan' ),
			'cache_ttl'       => $config->get( 'cache_ttl', 86400 ),
			'ai_enabled'     => $config->get( 'ai_enabled', false ),
			'semgrep_installed' => $this->check_semgrep(),
			'cached_audits'   => $cache->get_count(),
			'total_audits'    => $audit_logger->get_count(),
		);

		if ( 'json' === $format ) {
			WP_CLI::line( json_encode( $data, JSON_PRETTY_PRINT ) );
			return;
		}

		WP_CLI::success( 'AI Security Status' );
		WP_CLI::line( '' );

		foreach ( $data as $key => $value ) {
			$label = ucwords( str_replace( '_', ' ', $key ) );
			$value = is_bool( $value ) ? ( $value ? 'Yes' : 'No' ) : $value;
			WP_CLI::line( sprintf( '%s: %s', $label, $value ) );
		}
	}

	/**
	 * Check if Semgrep is installed.
	 *
	 * @return bool
	 */
	private function check_semgrep() {
		exec( 'which semgrep 2>/dev/null', $output, $return_code );
		return 0 === $return_code;
	}

	/**
	 * Configure AI Security settings.
	 *
	 * ## OPTIONS
	 *
	 * <key> <value>
	 * : Configuration key and value.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-security config set api_key YOUR_API_KEY
	 *     wp ai-security config set ai_enabled true
	 *
	 * @when after_wp_load
	 */
	public function config( $args, $assoc_args ) {
		list( $action ) = $args;

		if ( 'set' === $action && isset( $assoc_args['key'] ) && isset( $assoc_args['value'] ) ) {
			$config = new \WPAISecurity\Services\Config();
			$config->set( $assoc_args['key'], $assoc_args['value'] );
			WP_CLI::success( "Configuration updated: {$assoc_args['key']} = {$assoc_args['value']}" );
		} elseif ( 'get' === $action && isset( $assoc_args['key'] ) ) {
			$config = new \WPAISecurity\Services\Config();
			$value  = $config->get( $assoc_args['key'] );
			WP_CLI::line( $value );
		} else {
			WP_CLI::error( 'Usage: wp ai-security config set --key=KEY --value=VALUE' );
		}
	}

	/**
	 * Clear the security scan cache.
	 *
	 * ## OPTIONS
	 *
	 * [--all]
	 * : Clear all cache including audit history.
	 *
	 * ## EXAMPLES
 *
	 *     wp ai-security cache clear
	 *     wp ai-security cache clear --all
	 *
	 * @when after_wp_load
	 */
	public function clear_cache( $args, $assoc_args ) {
		$config = new \WPAISecurity\Services\Config();
		$cache  = new \WPAISecurity\Utils\Cache( $config );

		if ( isset( $assoc_args['all'] ) ) {
			$cache->clear_all();
			$audit_logger = new \WPAISecurity\Utils\AuditLogger( $config );
			$audit_logger->clear();
			WP_CLI::success( 'All cache and audit history cleared.' );
		} else {
			$cache->clear();
			WP_CLI::success( 'Security scan cache cleared.' );
		}
	}
}

WP_CLI::add_command( 'ai-security', 'WPAISecurity_Command' );