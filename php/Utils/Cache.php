<?php
/**
 * Cache utility for AI Security.
 *
 * @package WPAISecurity
 */

namespace WPAISecurity\Utils;

use WPAISecurity\Services\Config;

/**
 * Handles caching of scan results and API responses.
 */
class Cache {

	/**
	 * Configuration service.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Cache directory.
	 *
	 * @var string
	 */
	private $cache_dir;

	/**
	 * Constructor.
	 *
	 * @param Config $config Configuration service.
	 */
	public function __construct( Config $config ) {
		$this->config    = $config;
		$this->cache_dir = $config->get( 'cache_dir', sys_get_temp_dir() . '/wp-ai-security' );

		if ( ! is_dir( $this->cache_dir ) ) {
			mkdir( $this->cache_dir, 0700, true );
		}
	}

	/**
	 * Get cached data.
	 *
	 * @param string $key Cache key.
	 * @return mixed Cached data or false if not found/expired.
	 */
	public function get( $key ) {
		$file = $this->get_cache_file( $key );

		if ( ! file_exists( $file ) ) {
			return false;
		}

		$data = json_decode( file_get_contents( $file ), true );

		// Check expiration.
		if ( isset( $data['expires'] ) && $data['expires'] < time() ) {
			unlink( $file );
			return false;
		}

		return $data['value'] ?? false;
	}

	/**
	 * Set cached data.
	 *
	 * @param string $key   Cache key.
	 * @param mixed  $value Value to cache.
	 * @param int    $ttl   Time to live in seconds (default: 24 hours).
	 */
	public function set( $key, $value, $ttl = null ) {
		$ttl = $ttl ?? $this->config->get( 'cache_ttl', 86400 );

		$data = array(
			'value'   => $value,
			'expires' => time() + $ttl,
			'created' => time(),
		);

		$file = $this->get_cache_file( $key );
		file_put_contents( $file, json_encode( $data ) );
	}

	/**
	 * Delete cached data.
	 *
	 * @param string $key Cache key.
	 */
	public function delete( $key ) {
		$file = $this->get_cache_file( $key );
		if ( file_exists( $file ) ) {
			unlink( $file );
		}
	}

	/**
	 * Clear all cache.
	 */
	public function clear() {
		$files = glob( $this->cache_dir . '/*.json' );
		foreach ( $files as $file ) {
			unlink( $file );
		}
	}

	/**
	 * Clear all cache including audit history.
	 */
	public function clear_all() {
		$this->clear();

		// Clear audit log as well.
		$audit_file = $this->config->get( 'cache_dir', sys_get_temp_dir() ) . '/wp-ai-security/audit.json';
		if ( file_exists( $audit_file ) ) {
			unlink( $audit_file );
		}
	}

	/**
	 * Get cache file path.
	 *
	 * @param string $key Cache key.
	 * @return string
	 */
	private function get_cache_file( $key ) {
		$hash = md5( $key );
		return $this->cache_dir . '/' . $hash . '.json';
	}

	/**
	 * Get count of cached items.
	 *
	 * @return int
	 */
	public function get_count() {
		$files = glob( $this->cache_dir . '/*.json' );
		return count( $files );
	}

	/**
	 * Get cache directory path.
	 *
	 * @return string
	 */
	public function get_cache_dir() {
		return $this->cache_dir;
	}
}