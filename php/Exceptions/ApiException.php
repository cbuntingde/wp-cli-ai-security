<?php
/**
 * API Exception for WPAISecurity.
 *
 * @package WPAISecurity\Exceptions
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

namespace WPAISecurity\Exceptions;

/**
 * Exception for API-related failures.
 */
class ApiException extends WPAISecurityException {

	/**
	 * HTTP status code.
	 *
	 * @var int
	 */
	protected $http_code;

	/**
	 * API provider name.
	 *
	 * @var string
	 */
	protected $provider;

	/**
	 * Constructor.
	 *
	 * @param string $message  Exception message.
	 * @param string $provider API provider name.
	 * @param int    $http_code HTTP status code.
	 * @param string $slug     Package slug associated with this exception.
	 */
	public function __construct(
		string $message = '',
		string $provider = '',
		int $http_code = 0,
		string $slug = ''
	) {
		parent::__construct( $message, $slug );
		$this->provider  = $provider;
		$this->http_code = $http_code;
	}

	/**
	 * Get the HTTP status code.
	 *
	 * @return int
	 */
	public function getHttpCode(): int {
		return $this->http_code;
	}

	/**
	 * Get the API provider name.
	 *
	 * @return string
	 */
	public function getProvider(): string {
		return $this->provider;
	}
}
