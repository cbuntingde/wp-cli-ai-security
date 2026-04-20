<?php
/**
 * AI Plugin Scan Command for WP-CLI.
 *
 * Provides AI-powered security scanning for WordPress plugins.
 *
 * @package WPAISecurity
 */

namespace WPAISecurity\Commands;

/**
 * AI-powered plugin security scanning command.
 */
class PluginScan extends BaseCommand {

	/**
	 * Package type.
	 *
	 * @return string
	 */
	protected function get_package_type() {
		return 'plugin';
	}

	/**
	 * Scan a plugin for security issues without installing.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : Plugin slug (from wordpress.org) or URL to plugin zip.
	 *
	 * [--force]
	 * : Force re-scan even if cached.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-plugin scan woocommerce
	 *     wp ai-plugin scan woocommerce --force
	 *
	 * @when after_wp_load
	 */
	public function scan( $args, $assoc_args ) {
		list( $slug ) = $args;
		$force = isset( $assoc_args['force'] );

		\WP_CLI::line( "Scanning plugin: {$slug}" );
		\WP_CLI::line( str_repeat( '-', 40 ) );

		$options = array();
		if ( $force ) {
			$options['force'] = true;
		}

		$results = $this->run_security_scan( $slug, $options );

		\WP_CLI::line( '' );
		if ( $results['safe'] ) {
			\WP_CLI::success( 'No security issues found!' );
		} else {
			\WP_CLI::warning( 'Security issues detected!' );
		}

		if ( $results['cache_hit'] ) {
			\WP_CLI::line( '(Results from cache)' );
		}
	}

	/**
	 * Install a plugin with security scanning.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : Plugin slug (from wordpress.org) or URL to plugin zip.
	 *
	 * [--scan]
	 * : Run security scan before installing (recommended).
	 *
	 * [--force]
	 * : Force re-scan even if cached.
	 *
	 * [--activate]
	 * : Activate the plugin after installation.
	 *
	 * [--skip-scan]
	 * : Skip security scan (not recommended).
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-plugin install woocommerce --scan
	 *     wp ai-plugin install woocommerce --scan --activate
	 *     wp ai-plugin install https://example.com/plugin.zip --scan
	 *
	 * @when after_wp_load
	 */
	public function install( $args, $assoc_args ) {
		list( $slug ) = $args;

		$do_scan       = isset( $assoc_args['scan'] ) || ! isset( $assoc_args['skip-scan'] );
		$force         = isset( $assoc_args['force'] );
		$activate      = isset( $assoc_args['activate'] );
		$strict_mode   = $this->config->get( 'strict_mode', false );

		if ( $do_scan ) {
			\WP_CLI::line( "Installing plugin with security scan: {$slug}" );
			\WP_CLI::line( str_repeat( '-', 40 ) );

			$options = array();
			if ( $force ) {
				$options['force'] = true;
			}

			$results = $this->run_security_scan( $slug, $options );

			\WP_CLI::line( '' );

			// Decide whether to block installation.
			if ( ! $results['safe'] ) {
				if ( $strict_mode ) {
					\WP_CLI::error( 'Installation blocked due to security issues. Use --skip-scan to bypass (not recommended).' );
					return;
				}

				\WP_CLI::warning( 'Security issues detected, but continuing with installation...' );
				\WP_CLI::line( 'Use --skip-scan in the future to skip scanning.' );
				\WP_CLI::line( 'Set strict_mode=true to block installation on security findings.' );
			} else {
				\WP_CLI::success( 'Security check passed!' );
			}
		} else {
			\WP_CLI::warning( 'Skipping security scan!' );
			\WP_CLI::line( 'Make sure you trust this plugin before installing.' );
		}

		// Now install the plugin using WP-CLI's built-in command.
		\WP_CLI::line( '' );
		\WP_CLI::line( 'Installing plugin...' );

		$install_args = array( $slug );
		$install_assoc = array();

		if ( $activate ) {
			$install_assoc['activate'] = true;
		}

		try {
			\WP_CLI::run_command( $install_args, $install_assoc );
			\WP_CLI::success( "Plugin {$slug} installed successfully." );
		} catch ( \Exception $e ) {
			\WP_CLI::error( "Failed to install plugin: " . $e->getMessage() );
		}
	}

	/**
	 * List all installed plugins with their security status.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format - table, json, or csv.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-plugin list
	 *     wp ai-plugin list --format=json
	 *
	 * @when after_wp_load
	 */
	public function list_plugins( $args, $assoc_args ) {
		$format = isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table';

		// Get installed plugins.
		$plugins = get_plugins();
		$rows    = array();

		foreach ( $plugins as $plugin_file => $plugin_data ) {
			$slug = dirname( $plugin_file );
			if ( '.' === $slug ) {
				$slug = basename( $plugin_file, '.php' );
			}

			// Check cache for security status.
			$cached = $this->cache->get( 'scan_' . $slug );

			$rows[] = array(
				'name'     => $plugin_data['Name'],
				'slug'     => $slug,
				'version'  => $plugin_data['Version'],
				'status'   => is_plugin_active( $plugin_file ) ? 'Active' : 'Inactive',
				'vulns'    => $cached ? count( $cached['vulnerabilities'] ) : '-',
				'ai_issues' => $cached ? count( $cached['ai_findings'] ) : '-',
			);
		}

		\WP_CLI::success( 'Installed Plugins Security Status' );

		if ( 'json' === $format ) {
			\WP_CLI::line( json_encode( $rows, JSON_PRETTY_PRINT ) );
			return;
		}

		// Format as table.
		$table = new \cli\Table();
		$table->setHeaders( array( 'Name', 'Slug', 'Version', 'Status', 'Vulns', 'AI Issues' ) );
		$table->setRows( $rows );
		$table->display();
	}
}