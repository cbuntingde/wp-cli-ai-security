<?php
/**
 * Download Exception for WPAISecurity.
 *
 * @package WPAISecurity\Exceptions
 */

namespace WPAISecurity\Exceptions;

/**
 * Exception for package download failures.
 */
class DownloadException extends WPAISecurityException {

	/**
	 * Download URL that failed.
	 *
	 * @var string
	 */
	protected $url;

	/**
	 * Constructor.
	 *
	 * @param string $message Exception message.
	 * @param string $url     Download URL that failed.
	 * @param string $slug    Package slug associated with this exception.
	 */
	public function __construct(
		string $message = '',
		string $url = '',
		string $slug = ''
	) {
		parent::__construct( $message, $slug );
		$this->url = $url;
	}

	/**
	 * Get the download URL that failed.
	 *
	 * @return string
	 */
	public function getUrl(): string {
		return $this->url;
	}
}
