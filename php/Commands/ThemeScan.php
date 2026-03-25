<?php
/**
 * AI Theme Scan Command for WP-CLI.
 *
 * Provides AI-powered security scanning for WordPress themes.
 *
 * @package WPAISecurity
 */

namespace WPAISecurity\Commands;

/**
 * AI-powered theme security scanning command.
 */
class ThemeScan extends BaseCommand {

	/**
	 * Package type.
	 *
	 * @return string
	 */
	protected function get_package_type() {
		return 'theme';
	}

	/**
	 * Scan a theme for security issues without installing.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : Theme slug (from wordpress.org) or URL to theme zip.
	 *
	 * [--force]
	 * : Force re-scan even if cached.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-theme scan astra
	 *     wp ai-theme scan astra --force
	 *
	 * @when after_wp_load
	 */
	public function scan( $args, $assoc_args ) {
		list( $slug ) = $args;
		$force = isset( $assoc_args['force'] );

		\WP_CLI::line( "Scanning theme: {$slug}" );
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
	 * Install a theme with security scanning.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : Theme slug (from wordpress.org) or URL to theme zip.
	 *
	 * [--scan]
	 * : Run security scan before installing (recommended).
	 *
	 * [--force]
	 * : Force re-scan even if cached.
	 *
	 * [--activate]
	 * : Activate the theme after installation.
	 *
	 * [--skip-scan]
	 * : Skip security scan (not recommended).
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-theme install astra --scan
	 *     wp ai-theme install astra --scan --activate
	 *     wp ai-theme install https://example.com/theme.zip --scan
	 *
	 * @when after_wp_load
	 */
	public function install( $args, $assoc_args ) {
		list( $slug ) = $args;

		$do_scan     = isset( $assoc_args['scan'] ) || ! isset( $assoc_args['skip-scan'] );
		$force       = isset( $assoc_args['force'] );
		$activate    = isset( $assoc_args['activate'] );
		$strict_mode = $this->config->get( 'strict_mode', false );

		if ( $do_scan ) {
			\WP_CLI::line( "Installing theme with security scan: {$slug}" );
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
			\WP_CLI::line( 'Make sure you trust this theme before installing.' );
		}

		// Now install the theme using WP-CLI's built-in command.
		\WP_CLI::line( '' );
		\WP_CLI::line( 'Installing theme...' );

		$install_args = array( $slug );
		$install_assoc = array();

		if ( $activate ) {
			$install_assoc['activate'] = true;
		}

		// Show what would be run (prototype).
		$cmd = 'wp theme install ' . implode( ' ', array_map( 'escapeshellarg', $install_args ) );
		foreach ( $install_assoc as $key => $value ) {
			if ( true === $value ) {
				$cmd .= ' --' . $key;
			}
		}

		\WP_CLI::line( "Running: {$cmd}" );
		\WP_CLI::line( '' );
		\WP_CLI::success( 'Theme installation would proceed here.' );
		\WP_CLI::line( 'Note: This is a prototype. Full implementation would call wp theme install.' );
	}

	/**
	 * List all installed themes with their security status.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format - table, json, or csv.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-theme list
	 *     wp ai-theme list --format=json
	 *
	 * @when after_wp_load
	 */
	public function list_themes( $args, $assoc_args ) {
		$format = isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table';

		// Get installed themes.
		$themes = wp_get_themes();
		$rows   = array();

		foreach ( $themes as $theme ) {
			$slug = $theme->get_stylesheet();

			// Check cache for security status.
			$cached = $this->cache->get( 'scan_' . $slug );

			$rows[] = array(
				'name'     => $theme->get( 'Name' ),
				'slug'     => $slug,
				'version'  => $theme->get( 'Version' ),
				'status'   => get_stylesheet() === $slug ? 'Active' : 'Inactive',
				'vulns'    => $cached ? count( $cached['vulnerabilities'] ) : '-',
				'ai_issues' => $cached ? count( $cached['ai_findings'] ) : '-',
			);
		}

		\WP_CLI::success( 'Installed Themes Security Status' );

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