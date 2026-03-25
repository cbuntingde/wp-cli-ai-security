<?php
/**
 * Base Command class for AI Security commands.
 *
 * @package WPAISecurity
 */

namespace WPAISecurity\Commands;

use WPAISecurity\Services\VulnerabilityScanner;
use WPAISecurity\Services\AIAnalyzer;
use WPAISecurity\Services\Config;
use WPAISecurity\Utils\Cache;
use WPAISecurity\Utils\AuditLogger;
use WPAISecurity\Utils\Downloader;

/**
 * Base class providing common functionality for all AI Security commands.
 */
abstract class BaseCommand {

	/**
	 * Configuration service.
	 *
	 * @var Config
	 */
	protected $config;

	/**
	 * Vulnerability scanner service.
	 *
	 * @var VulnerabilityScanner
	 */
	protected $vuln_scanner;

	/**
	 * AI analyzer service.
	 *
	 * @var AIAnalyzer
	 */
	protected $ai_analyzer;

	/**
	 * Cache service.
	 *
	 * @var Cache
	 */
	protected $cache;

	/**
	 * Audit logger.
	 *
	 * @var AuditLogger
	 */
	protected $audit_logger;

	/**
	 * Downloader utility.
	 *
	 * @var Downloader
	 */
	protected $downloader;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->config         = new Config();
		$this->cache          = new Cache( $this->config );
		$this->audit_logger   = new AuditLogger( $this->config );
		$this->vuln_scanner   = new VulnerabilityScanner( $this->config, $this->cache );
		$this->ai_analyzer    = new AIAnalyzer( $this->config, $this->cache );
		$this->downloader     = new Downloader( $this->config );
	}

	/**
	 * Run full security scan on a package.
	 *
	 * @param string $slug    Package slug (plugin or theme).
	 * @param array  $options Scan options.
	 * @return array Scan results.
	 */
	protected function run_security_scan( $slug, $options = array() ) {
		$results = array(
			'slug'         => $slug,
			'timestamp'    => time(),
			'vulnerabilities' => array(),
			'ai_findings'  => array(),
			'safe'         => true,
			'cache_hit'    => false,
		);

		// Check cache first.
		$cached = $this->cache->get( 'scan_' . $slug );
		if ( false !== $cached && ! isset( $options['force'] ) ) {
			$results            = $cached;
			$results['cache_hit'] = true;
			return $results;
		}

		// Step 1: Download package for analysis.
		\WP_CLI::line( "Downloading {$slug} for analysis..." );
		$download_path = $this->downloader->download_package( $slug, $this->get_package_type() );

		if ( ! $download_path ) {
			\WP_CLI::error( "Failed to download {$slug}. Please check the slug and try again." );
			return $results;
		}

		// Step 2: Run vulnerability scan.
		\WP_CLI::line( 'Checking for known vulnerabilities...' );
		$vulns = $this->vuln_scanner->scan( $slug, $download_path );
		$results['vulnerabilities'] = $vulns;

		if ( ! empty( $vulns ) ) {
			$results['safe'] = false;
			$this->print_vulnerabilities( $vulns );
		}

		// Step 3: Run AI code analysis (if enabled).
		if ( $this->config->get( 'ai_enabled', false ) ) {
			\WP_CLI::line( 'Running AI code analysis...' );
			$ai_findings = $this->ai_analyzer->analyze( $download_path );
			$results['ai_findings'] = $ai_findings;

			if ( ! empty( $ai_findings ) ) {
				$results['safe'] = false;
				$this->print_ai_findings( $ai_findings );
			}
		} else {
			\WP_CLI::line( 'AI analysis disabled. Enable with: wp ai-security config set --key=ai_enabled --value=true' );
		}

		// Clean up downloaded files.
		$this->downloader->cleanup( $download_path );

		// Cache results.
		$this->cache->set( 'scan_' . $slug, $results );

		// Log audit trail.
		$this->audit_logger->log( $slug, $this->get_package_type(), $results );

		return $results;
	}

	/**
	 * Print vulnerability findings.
	 *
	 * @param array $vulnerabilities List of vulnerabilities.
	 */
	protected function print_vulnerabilities( $vulnerabilities ) {
		\WP_CLI::warning( 'Found ' . count( $vulnerabilities) . ' known vulnerability(ies):' );
		foreach ( $vulnerabilities as $vuln ) {
			$severity_color = $this->get_severity_color( $vuln['severity'] ?? 'medium' );
			\WP_CLI::line( sprintf(
				'  [%s] %s (CVE: %s)',
				strtoupper( $vuln['severity'] ?? 'N/A' ),
				$vuln['title'] ?? 'Unknown vulnerability',
				$vuln['cve'] ?? 'N/A'
			) );
		}
	}

	/**
	 * Print AI analysis findings.
	 *
	 * @param array $findings AI analysis findings.
	 */
	protected function print_ai_findings( $findings ) {
		\WP_CLI::warning( 'AI Analysis found ' . count( $findings ) . ' potential issue(s):' );
		foreach ( $findings as $finding ) {
			\WP_CLI::line( sprintf(
				'  [%s] %s (File: %s)',
				strtoupper( $finding['severity'] ?? 'low' ),
				$finding['title'] ?? 'Issue detected',
				$finding['file'] ?? 'Unknown'
			) );
		}
	}

	/**
	 * Get severity color for output.
	 *
	 * @param string $severity Severity level.
	 * @return string Color code.
	 */
	protected function get_severity_color( $severity ) {
		$colors = array(
			'critical' => 'red',
			'high'     => 'red',
			'medium'   => 'yellow',
			'low'      => 'cyan',
		);
		return $colors[ strtolower( $severity ) ] ?? 'white';
	}

	/**
	 * Get package type (plugin or theme).
	 *
	 * @return string
	 */
	abstract protected function get_package_type();
}