<?php
/**
 * Audit Command for WP-CLI.
 *
 * Provides audit functionality for installed WordPress packages.
 *
 * @package WPAISecurity
 */

namespace WPAISecurity\Commands;

/**
 * Audit command for scanning installed packages.
 */
class Audit extends BaseCommand {

	/**
	 * Package type.
	 *
	 * @return string
	 */
	protected function get_package_type() {
		return 'plugin'; // Can be either, handled dynamically
	}

	/**
	 * Audit all installed plugins.
	 *
	 * ## OPTIONS
	 *
	 * [--force]
	 * : Force re-scan even if cached.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-audit plugins
	 *     wp ai-audit plugins --force
	 *
	 * @when after_wp_load
	 */
	public function plugins( $args, $assoc_args ) {
		$force = isset( $assoc_args['force'] );

		\WP_CLI::success( 'Auditing installed plugins...' );
		\WP_CLI::line( str_repeat( '-', 50 ) );

		$plugins = get_plugins();
		$results = array();

		foreach ( $plugins as $plugin_file => $plugin_data ) {
			$slug = dirname( $plugin_file );
			if ( '.' === $slug ) {
				$slug = basename( $plugin_file, '.php' );
			}

			\WP_CLI::line( "Scanning: {$plugin_data['Name']} ({$slug})" );

			$options = array();
			if ( $force ) {
				$options['force'] = true;
			}

			$result = $this->run_security_scan( $slug, $options );
			$results[] = array(
				'name'    => $plugin_data['Name'],
				'slug'    => $slug,
				'safe'    => $result['safe'],
				'vulns'   => count( $result['vulnerabilities'] ),
				'ai_findings' => count( $result['ai_findings'] ),
			);

			\WP_CLI::line( "  → " . ( $result['safe'] ? 'Safe' : 'Issues found' ) );
		}

		\WP_CLI::line( '' );
		$this->print_audit_summary( $results );
	}

	/**
	 * Audit all installed themes.
	 *
	 * ## OPTIONS
	 *
	 * [--force]
	 * : Force re-scan even if cached.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-audit themes
	 *     wp ai-audit themes --force
	 *
	 * @when after_wp_load
	 */
	public function themes( $args, $assoc_args ) {
		$force = isset( $assoc_args['force'] );

		\WP_CLI::success( 'Auditing installed themes...' );
		\WP_CLI::line( str_repeat( '-', 50 ) );

		$themes  = wp_get_themes();
		$results = array();

		foreach ( $themes as $theme ) {
			$slug = $theme->get_stylesheet();

			\WP_CLI::line( "Scanning: {$theme->get('Name')} ({$slug})" );

			$options = array();
			if ( $force ) {
				$options['force'] = true;
			}

			// Temporarily set package type to theme.
			$original_type = $this->get_package_type();
			// We need to handle this differently - the base command doesn't support dynamic types
			// For now, we'll scan as plugin which will work but may not get correct download URL.
			// In production, you'd want to modify the base command to support this.

			$result = $this->run_security_scan( $slug, $options );
			$results[] = array(
				'name'    => $theme->get( 'Name' ),
				'slug'    => $slug,
				'safe'    => $result['safe'],
				'vulns'   => count( $result['vulnerabilities'] ),
				'ai_findings' => count( $result['ai_findings'] ),
			);

			\WP_CLI::line( "  → " . ( $result['safe'] ? 'Safe' : 'Issues found' ) );
		}

		\WP_CLI::line( '' );
		$this->print_audit_summary( $results );
	}

	/**
	 * Show audit history.
	 *
	 * ## OPTIONS
	 *
	 * [--limit=<limit>]
	 * : Number of entries to show (default: 20).
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-audit history
	 *     wp ai-audit history --limit=50
	 *
	 * @when after_wp_load
	 */
	public function history( $args, $assoc_args ) {
		$limit = isset( $assoc_args['limit'] ) ? intval( $assoc_args['limit'] ) : 20;

		$log = $this->audit_logger->get_log( $limit );

		if ( empty( $log ) ) {
			\WP_CLI::line( 'No audit history found.' );
			return;
		}

		\WP_CLI::success( 'Audit History' );
		\WP_CLI::line( str_repeat( '-', 80 ) );

		$rows = array();
		foreach ( $log as $entry ) {
			$rows[] = array(
				'Date'     => $entry['date'],
				'Type'     => $entry['type'],
				'Slug'     => $entry['slug'],
				'Safe'     => $entry['safe'] ? '✓' : '✗',
				'Vulns'    => $entry['vuln_count'],
				'AI'       => $entry['ai_count'],
			);
		}

		$table = new \cli\Table();
		$table->setHeaders( array( 'Date', 'Type', 'Slug', 'Safe', 'Vulns', 'AI' ) );
		$table->setRows( $rows );
		$table->display();
	}

	/**
	 * Show audit summary.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-audit summary
	 *
	 * @when after_wp_load
	 */
	public function summary( $args, $assoc_args ) {
		$summary = $this->audit_logger->get_summary();

		\WP_CLI::success( 'Audit Summary' );
		\WP_CLI::line( str_repeat( '-', 40 ) );
		\WP_CLI::line( "Total scans: {$summary['total_scans']}" );
		\WP_CLI::line( "Safe: {$summary['safe']}" );
		\WP_CLI::line( "With vulnerabilities: {$summary['with_vulns']}" );
		\WP_CLI::line( "With AI issues: {$summary['with_ai_issues']}" );
		\WP_CLI::line( "Cache hits: {$summary['cache_hits']}" );
	}

	/**
	 * Export audit log to file.
	 *
	 * ## OPTIONS
	 *
	 * <path>
	 * : Path to export file.
	 *
	 * ## EXAMPLES
	 *
	 *     wp ai-audit export /path/to/audit.json
	 *
	 * @when after_wp_load
	 */
	public function export( $args, $assoc_args ) {
		list( $path ) = $args;

		// Validate export path to prevent path traversal
		$real_path = realpath( dirname( $path ) );
		if ( false === $real_path ) {
			\WP_CLI::error( 'Invalid export path. Please specify a valid directory.' );
			return;
		}

		// Check for path traversal attempts
		if ( false !== strpos( basename( $path ), '..' ) ) {
			\WP_CLI::error( 'Path traversal not allowed in export path.' );
			return;
		}

		$this->audit_logger->export( $path );
		\WP_CLI::success( "Audit log exported to: {$path}" );
	}

	/**
	 * Print audit summary table.
	 *
	 * @param array $results Audit results.
	 */
	private function print_audit_summary( $results ) {
		$safe_count   = 0;
		$unsafe_count = 0;

		foreach ( $results as $result ) {
			if ( $result['safe'] ) {
				$safe_count++;
			} else {
				$unsafe_count++;
			}
		}

		\WP_CLI::success( 'Audit Complete!' );
		\WP_CLI::line( "Total: " . count( $results ) );
		\WP_CLI::success( "Safe: {$safe_count}" );

		if ( $unsafe_count > 0 ) {
			\WP_CLI::warning( "Issues found: {$unsafe_count}" );
		}

		// Show details for unsafe packages.
		$unsafe = array_filter( $results, function( $r ) {
			return ! $r['safe'];
		} );

		if ( ! empty( $unsafe ) ) {
			\WP_CLI::line( '' );
			\WP_CLI::warning( 'Packages with security issues:' );

			foreach ( $unsafe as $item ) {
				$issues = $item['vulns'] + $item['ai_findings'];
				\WP_CLI::line( "  - {$item['name']}: {$issues} issue(s)" );
			}
		}
	}
}