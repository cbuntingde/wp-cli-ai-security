<?php
/**
 * Base exception for WPAISecurity.
 *
 * @package WPAISecurity\Exceptions
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

namespace WPAISecurity\Exceptions;

/**
 * Base exception class for all WPAISecurity exceptions.
 */
class WPAISecurityException extends \Exception {

	/**
	 * Package slug associated with this exception.
	 *
	 * @var string
	 */
	protected $slug;

	/**
	 * Constructor.
	 *
	 * @param string      $message Exception message.
	 * @param string      $slug    Package slug associated with this exception.
	 * @param int         $code    Error code.
	 * @param \Throwable  $previous Previous exception for chaining.
	 */
	public function __construct(
		string $message = '',
		string $slug = '',
		int $code = 0,
		?\Throwable $previous = null
	) {
		parent::__construct( $message, $code, $previous );
		$this->slug = $slug;
	}

	/**
	 * Get the package slug associated with this exception.
	 *
	 * @return string
	 */
	public function getSlug(): string {
		return $this->slug;
	}
}
