<?php
/**
 * Audit Logger utility for AI Security.
 *
 * @package WPAISecurity
 */

namespace WPAISecurity\Utils;

use WPAISecurity\Services\Config;

/**
 * Handles logging of security scans and audit trails.
 */
class AuditLogger {

	/**
	 * Configuration service.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Log file path.
	 *
	 * @var string
	 */
	private $log_file;

	/**
	 * Constructor.
	 *
	 * @param Config $config Configuration service.
	 */
	public function __construct( Config $config ) {
		$this->config   = $config;
		$this->log_file = $config->get( 'cache_dir', sys_get_temp_dir() ) . '/wp-ai-security/audit.json';

		$dir = dirname( $this->log_file );
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir, 0755, true );
		}
	}

	/**
	 * Log a security scan.
	 *
	 * @param string $slug     Package slug.
	 * @param string $type     Package type (plugin/theme).
	 * @param array  $results  Scan results.
	 */
	public function log( $slug, $type, $results ) {
		if ( ! $this->config->get( 'log_audits', true ) ) {
			return;
		}

		$log = $this->get_log();

		$entry = array(
			'id'          => uniqid( 'audit_' ),
			'timestamp'   => time(),
			'date'        => date( 'Y-m-d H:i:s' ),
			'slug'        => $slug,
			'type'        => $type,
			'safe'        => $results['safe'] ?? true,
			'vuln_count'  => count( $results['vulnerabilities'] ?? array() ),
			'ai_count'    => count( $results['ai_findings'] ?? array() ),
			'cache_hit'   => $results['cache_hit'] ?? false,
		);

		$log[] = $entry;

		// Keep only last 1000 entries.
		if ( count( $log ) > 1000 ) {
			$log = array_slice( $log, -1000 );
		}

		file_put_contents( $this->log_file, json_encode( $log, JSON_PRETTY_PRINT ) );
	}

	/**
	 * Get audit log entries.
	 *
	 * @param int $limit Number of entries to return.
	 * @return array
	 */
	public function get_log( $limit = 100 ) {
		if ( ! file_exists( $this->log_file ) ) {
			return array();
		}

		$content = file_get_contents( $this->log_file );
		$log     = json_decode( $content, true );

		if ( ! is_array( $log ) ) {
			return array();
		}

		return array_slice( $log, -$limit );
	}

	/**
	 * Get count of audit entries.
	 *
	 * @return int
	 */
	public function get_count() {
		$log = $this->get_log( 10000 );
		return count( $log );
	}

	/**
	 * Clear audit log.
	 */
	public function clear() {
		if ( file_exists( $this->log_file ) ) {
			unlink( $this->log_file );
		}
	}

	/**
	 * Get audit summary.
	 *
	 * @return array
	 */
	public function get_summary() {
		$log = $this->get_log( 10000 );

		$summary = array(
			'total_scans'   => count( $log ),
			'safe'          => 0,
			'unsafe'        => 0,
			'with_vulns'    => 0,
			'with_ai_issues' => 0,
			'cache_hits'    => 0,
		);

		foreach ( $log as $entry ) {
			if ( $entry['safe'] ) {
				$summary['safe']++;
			} else {
				$summary['unsafe']++;
			}

			if ( $entry['vuln_count'] > 0 ) {
				$summary['with_vulns']++;
			}

			if ( $entry['ai_count'] > 0 ) {
				$summary['with_ai_issues']++;
			}

			if ( $entry['cache_hit'] ) {
				$summary['cache_hits']++;
			}
		}

		return $summary;
	}

	/**
	 * Export audit log to file.
	 *
	 * @param string $path Export path.
	 */
	public function export( $path ) {
		$log = $this->get_log( 10000 );
		file_put_contents( $path, json_encode( $log, JSON_PRETTY_PRINT ) );
	}

	/**
	 * Get log file path.
	 *
	 * @return string
	 */
	public function get_log_file() {
		return $this->log_file;
	}
}