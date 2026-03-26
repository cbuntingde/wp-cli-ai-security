<?php
/**
 * Downloader utility for AI Security.
 *
 * Downloads WordPress plugins and themes for security analysis.
 *
 * @package WPAISecurity
 */

namespace WPAISecurity\Utils;

use WPAISecurity\Services\Config;

/**
 * Handles downloading WordPress packages for security scanning.
 */
class Downloader {

	/**
	 * Configuration service.
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Temporary directory for downloads.
	 *
	 * @var string
	 */
	private $temp_dir;

	/**
	 * Constructor.
	 *
	 * @param Config $config Configuration service.
	 */
	public function __construct( Config $config ) {
		$this->config   = $config;
		$this->temp_dir = $config->get( 'cache_dir', sys_get_temp_dir() ) . '/wp-ai-security/downloads';

		if ( ! is_dir( $this->temp_dir ) ) {
			mkdir( $this->temp_dir, 0755, true );
		}
	}

	/**
	 * Download a WordPress package for analysis.
	 *
	 * @param string $slug Package slug (plugin or theme).
	 * @param string $type Package type ('plugin' or 'theme').
	 * @return string|false Path to downloaded package or false on failure.
	 */
	public function download_package( $slug, $type ) {
		// Validate slug to prevent path traversal and injection attacks
		if ( ! $this->validate_slug( $slug ) ) {
			\WP_CLI::error( 'Invalid package slug. Slug must contain only lowercase letters, numbers, and hyphens.' );
			return false;
		}

		$download_url = $this->get_download_url( $slug, $type );

		if ( ! $download_url ) {
			return false;
		}

		$zip_path = $this->temp_dir . '/' . $slug . '.zip';

		// Download the package with SSL verification.
		$context = stream_context_create( array(
			'http' => array(
				'method'  => 'GET',
				'timeout' => 120,
				'user_agent' => 'WP-AI-Security/1.0',
			),
			'ssl' => array(
				'verify_peer'      => true,
				'verify_peer_name' => true,
			),
		) );

		$response = @file_get_contents( $download_url, false, $context );

		if ( false === $response ) {
			\WP_CLI::error( "Failed to download {$slug}. Please check the slug and try again." );
			return false;
		}

		file_put_contents( $zip_path, $response );

		// Extract the zip.
		$extract_dir = $this->temp_dir . '/' . $slug;

		if ( is_dir( $extract_dir ) ) {
			$this->recursive_delete( $extract_dir );
		}

		mkdir( $extract_dir, 0755, true );

		$zip = new \ZipArchive();
		if ( true !== $zip->open( $zip_path ) ) {
			\WP_CLI::error( 'Failed to open zip archive.' );
			return false;
		}

		$zip->extractTo( $extract_dir );
		$zip->close();

		// Clean up zip file.
		unlink( $zip_path );

		return $extract_dir;
	}

	/**
	 * Get the download URL for a WordPress package.
	 *
	 * @param string $slug Package slug.
	 * @param string $type Package type.
	 * @return string|false Download URL or false on failure.
	 */
	private function get_download_url( $slug, $type ) {
		// Check if it's a URL.
		if ( preg_match( '/^https?:\/\//', $slug ) ) {
			return $slug;
		}

		// WordPress.org API endpoints.
		if ( 'plugin' === $type ) {
			// Get latest version download URL from WordPress.org API.
			$api_url = "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={$slug}";
		} else {
			// For themes, use the WordPress.org theme API.
			$api_url = "https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]={$slug}";
		}

		$response = @file_get_contents( $api_url );
		if ( false === $response ) {
			return false;
		}

		$data = json_decode( $response, true );

		if ( empty( $data['download_link'] ) ) {
			// Try alternative: construct download URL directly.
			if ( 'plugin' === $type ) {
				return "https://downloads.wordpress.org/plugin/{$slug}.latest-stable.zip";
			} else {
				return "https://downloads.wordpress.org/theme/{$slug}.latest-stable.zip";
			}
		}

		return $data['download_link'];
	}

	/**
	 * Recursively delete a directory.
	 *
	 * @param string $path Path to delete.
	 */
	private function recursive_delete( $path ) {
		if ( is_dir( $path ) ) {
			$files = array_diff( scandir( $path ), array( '.', '..' ) );
			foreach ( $files as $file ) {
				$this->recursive_delete( $path . '/' . $file );
			}
			rmdir( $path );
		} elseif ( is_file( $path ) ) {
			unlink( $path );
		}
	}

	/**
	 * Clean up downloaded package.
	 *
	 * @param string $path Path to clean up.
	 */
	public function cleanup( $path ) {
		if ( is_dir( $path ) ) {
			$this->recursive_delete( $path );
		}
	}

	/**
	 * Clean up all downloads.
	 */
	public function cleanup_all() {
		$this->recursive_delete( $this->temp_dir );
		mkdir( $this->temp_dir, 0755, true );
	}

	/**
	 * Get temp directory path.
	 *
	 * @return string
	 */
	public function get_temp_dir() {
		return $this->temp_dir;
	}

	/**
	 * Validate package slug to prevent injection attacks.
	 *
	 * @param string $slug Package slug to validate.
	 * @return bool True if valid, false otherwise.
	 */
	private function validate_slug( $slug ) {
		// Allow URLs directly (user provided external source)
		if ( preg_match( '/^https?:\/\//', $slug ) ) {
			return $this->validate_url( $slug );
		}

		// WordPress slugs: lowercase letters, numbers, hyphens only
		// 1-64 characters
		return (bool) preg_match( '/^[a-z0-9][a-z0-9-]*[a-z0-9]$/', $slug );
	}

	/**
	 * Validate URL to prevent SSRF attacks.
	 *
	 * @param string $url URL to validate.
	 * @return bool True if valid, false otherwise.
	 */
	private function validate_url( $url ) {
		$parsed = parse_url( $url );

		// Only allow http and https
		if ( ! isset( $parsed['scheme'] ) || ! in_array( $parsed['scheme'], array( 'http', 'https' ), true ) ) {
			return false;
		}

		// Block localhost and private IP ranges
		if ( isset( $parsed['host'] ) ) {
			$host = strtolower( $parsed['host'] );
			$blocked = array(
				'localhost',
				'127.0.0.1',
				'::1',
				'0.0.0.0',
				'169.254.169.254', // AWS metadata
			);

			if ( in_array( $host, $blocked, true ) ) {
				return false;
			}

			// Check for private IP ranges
			$ip = gethostbyname( $host );
			if ( $ip ) {
				$long_ip = ip2long( $ip );
				// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
				if ( $long_ip ) {
					$private_ranges = array(
						array( ip2long( '10.0.0.0' ), ip2long( '10.255.255.255' ) ),
						array( ip2long( '172.16.0.0' ), ip2long( '172.31.255.255' ) ),
						array( ip2long( '192.168.0.0' ), ip2long( '192.168.255.255' ) ),
					);
					foreach ( $private_ranges as $range ) {
						if ( $long_ip >= $range[0] && $long_ip <= $range[1] ) {
							return false;
						}
					}
				}
			}
		}

		return true;
	}
}