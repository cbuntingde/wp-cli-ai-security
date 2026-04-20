<?php
/**
 * Scan Exception for WPAISecurity.
 *
 * @package WPAISecurity\Exceptions
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

namespace WPAISecurity\Exceptions;

/**
 * Exception for security scan failures.
 */
class ScanException extends WPAISecurityException {

	/**
	 * Scan type that failed.
	 *
	 * @var string
	 */
	protected $scan_type;

	/**
	 * Constructor.
	 *
	 * @param string $message   Exception message.
	 * @param string $scan_type Type of scan that failed (e.g., 'vulnerability', 'ai').
	 * @param string $slug     Package slug associated with this exception.
	 */
	public function __construct(
		string $message = '',
		string $scan_type = '',
		string $slug = ''
	) {
		parent::__construct( $message, $slug );
		$this->scan_type = $scan_type;
	}

	/**
	 * Get the scan type that failed.
	 *
	 * @return string
	 */
	public function getScanType(): string {
		return $this->scan_type;
	}
}
