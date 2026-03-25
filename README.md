# WP-CLI AI Security

> AI-powered security scanning for WordPress plugins and themes.

[![Version](https://img.shields.io/packagist/v/wp-ai-security/wp-cli-ai-security.svg)](https://packagist.org/packages/wp-ai-security/wp-cli-ai-security)
[![PHP Version](https://img.shields.io/packagist/php-v/wp-ai-security/wp-cli-ai-security.svg)](https://packagist.org/packages/wp-ai-security/wp-cli-ai-security)
[![License](https://img.shields.io/packagist/l/wp-ai-security/wp-cli-ai-security.svg)](LICENSE)
[![WP-CLI Version](https://img.shields.io/packagist/dependency/wp-cli/wp-cli.svg)](https://make.wordpress.org/cli/)

WP-CLI AI Security is a WP-CLI package that adds AI-powered security scanning capabilities to your WordPress workflow. Scan plugins and themes before installing, audit existing installations, and detect vulnerabilities and malicious code patterns.

## Why WP-CLI AI Security?

WordPress powers over 40% of all websites, making it a prime target for attackers. The WordPress ecosystem relies heavily on third-party plugins and themes, which are a common vector for vulnerabilities. This tool helps you:

- **Scan before you install** — Detect known vulnerabilities and suspicious code patterns before adding packages to your site
- **Audit existing installations** — Continuously monitor your installed plugins and themes for security issues
- **Leverage AI for deeper analysis** — Detect obfuscated code, backdoors, and novel attack patterns that traditional scanners miss
- **Maintain compliance** — Keep audit trails of all security scans for compliance purposes

## Features

| Feature | Description |
|---------|-------------|
| **Pre-install Scanning** | Download and analyze packages before installation |
| **Post-install Auditing** | Scan all installed plugins and themes |
| **Vulnerability Detection** | Check against CVE databases (WPScan, Patchstack, NVD) |
| **AI Code Analysis** | Detect suspicious patterns, backdoors, malware |
| **Multiple AI Providers** | Semgrep (local), OpenAI API, or built-in pattern matching |
| **Caching** | Avoid repeated scans with intelligent caching |
| **Audit Logging** | Maintain compliance-ready audit trails |
| **Strict Mode** | Optionally block installations with security issues |

## Requirements

- **PHP** 7.4 or higher
- **WP-CLI** 2.8 or higher
- **WordPress** 5.0 or higher

## Installation

### Method 1: Via Composer (Recommended)

Add to your project's development dependencies:

```bash
composer require wp-ai-security/wp-cli-ai-security --dev
```

Or install globally:

```bash
composer global require wp-ai-security/wp-cli-ai-security
```

### Method 2: Manual Registration

If you have an existing WP-CLI package cache, you can register this package manually. Add to your project's `composer.json`:

```json
{
    "require-dev": {
        "wp-ai-security/wp-cli-ai-security": "^1.0"
    },
    "extra": {
        "wp-cli-packages": {
            "ai-security": "wp-ai-security/wp-cli-ai-security"
        }
    }
}
```

## Quick Start

```bash
# Check the status of AI Security
wp ai-security status

# Scan a plugin before installing
wp ai-plugin scan woocommerce

# Install a plugin with security scan
wp ai-plugin install elementor --scan --activate

# Audit all installed plugins
wp ai-audit plugins

# View audit history
wp ai-audit history
```

## Configuration

### Setting Up Vulnerability Scanning

For accurate vulnerability detection, configure an API key:

```bash
# Using WPScan (recommended - free tier available)
wp ai-security config set --key=api_key --value=YOUR_WPSCAN_API_KEY
wp ai-security config set --key=api_provider --value=wpscan

# Or using Patchstack
wp ai-security config set --key=api_key --value=YOUR_PATCHSTACK_API_KEY
wp ai-security config set --key=api_provider --value=patchstack

# Or using NVD (free, no API key required)
wp ai-security config set --key=api_provider --value=nvd
```

Get a free WPScan API key at: https://wpscan.com/api

### Setting Up AI Analysis

```bash
# Enable AI analysis
wp ai-security config set --key=ai_enabled --value=true

# Option 1: Use Semgrep (local, free)
# Install: pip install semgrep
wp ai-security config set --key=ai_provider --value=semgrep

# Option 2: Use OpenAI API (requires API key)
wp ai-security config set --key=ai_provider --value=openai
wp ai-security config set --key=ai_api_key --value=YOUR_OPENAI_API_KEY
```

### Advanced Configuration

```bash
# Enable strict mode - blocks installation on any security finding
wp ai-security config set --key=strict_mode --value=true

# Set minimum severity to report (info, low, medium, high, critical)
wp ai-security config set --key=min_severity --value=medium

# Set cache TTL in seconds (default: 86400 = 24 hours)
wp ai-security config set --key=cache_ttl --value=43200

# Disable audit logging
wp ai-security config set --key=log_audits --value=false
```

## Commands Reference

### ai-plugin — Plugin Security Commands

```bash
# Scan a plugin for security issues
wp ai-plugin scan <slug>

# Scan with force refresh (bypass cache)
wp ai-plugin scan <slug> --force

# Install plugin with security scan
wp ai-plugin install <slug> --scan

# Install with scan and activation
wp ai-plugin install <slug> --scan --activate

# Skip security scan (not recommended)
wp ai-plugin install <slug> --skip-scan

# List installed plugins with security status
wp ai-plugin list

# List in JSON format
wp ai-plugin list --format=json
```

### ai-theme — Theme Security Commands

```bash
# Scan a theme for security issues
wp ai-theme scan <slug>

# Install theme with security scan
wp ai-theme install <slug> --scan --activate

# List installed themes with security status
wp ai-theme list
```

### ai-audit — Audit Commands

```bash
# Audit all installed plugins
wp ai-audit plugins

# Audit all plugins with force refresh
wp ai-audit plugins --force

# Audit all installed themes
wp ai-audit themes

# View scan history
wp ai-audit history

# View last 50 entries
wp ai-audit history --limit=50

# View audit summary statistics
wp ai-audit summary

# Export audit log to file
wp ai-audit export /path/to/audit.json
```

### ai-security — Management Commands

```bash
# Show AI Security status and configuration
wp ai-security status

# Set configuration value
wp ai-security config set --key=api_key --value=YOUR_KEY

# Get configuration value
wp ai-security config get --key=api_key

# Clear scan cache
wp ai-security cache clear

# Clear all cache and audit history
wp ai-security cache clear --all
```

## Output Examples

### Scanning a Plugin

```
$ wp ai-plugin scan woocommerce
Scanning plugin: woocommerce
----------------------------------------
Downloading woocommerce for analysis...
Checking for known vulnerabilities...
Found 2 known vulnerability(ies):
  [HIGH] SQL Injection vulnerability (CVE-2024-1234)
  [MEDIUM] XSS vulnerability (CVE-2024-5678)
Running AI code analysis...

AI Analysis found 1 potential issue(s):
  [MEDIUM] Raw user input access (File: class-wc-ajax.php)

Security issues detected!
```

### Installation with Strict Mode

```
$ wp ai-plugin install vulnerable-plugin --scan
Installing plugin with security scan: vulnerable-plugin
----------------------------------------
Downloading vulnerable-plugin for analysis...
Checking for known vulnerabilities...
Found 1 known vulnerability(ones):
  [CRITICAL] Remote Code Execution (CVE-2024-9999)

Error: Installation blocked due to security issues. Use --skip-scan to bypass (not recommended).
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    wp ai-plugin install                      │
│                         (user command)                        │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  1. Download Package                                         │
│     - Fetch from WordPress.org or URL                        │
│     - Extract to temporary directory                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  2. Vulnerability Scan                                       │
│     - Query WPScan/Patchstack/NVD API                        │
│     - Check against CVE database                             │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  3. AI Code Analysis (if enabled)                            │
│     - Semgrep pattern matching                               │
│     - OpenAI GPT analysis (optional)                         │
│     - Built-in pattern detection                             │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  4. Decision                                                 │
│     - If strict_mode: block on any finding                   │
│     - Otherwise: warn and continue                           │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  5. Install (or abort)                                       │
│     - Call wp plugin install                                 │
│     - Log audit trail                                        │
└─────────────────────────────────────────────────────────────┘
```

## API Keys & Services

### Vulnerability Data Providers

| Provider | Free Tier | Rate Limits | Accuracy |
|----------|-----------|-------------|----------|
| [WPScan](https://wpscan.com/api) | Yes (limited) | 25/day (free) | Excellent |
| [Patchstack](https://patchstack.com) | No | Custom | Excellent |
| [NVD (NIST)](https://nvd.nist.gov) | Yes | 6/minute | Good |

### AI Analysis Providers

| Provider | Cost | Local | Description |
|----------|------|-------|-------------|
| [Semgrep](https://semgrep.dev) | Free | Yes | Static analysis engine, rule-based |
| OpenAI | Pay-per-use | No | GPT-4 for semantic code analysis |
| Pattern Matching | Free | Yes | Built-in rules, no external deps |

## Security Considerations

- **API keys are stored locally** in `~/.wp-ai-security/config.json` (user home directory)
- **Downloaded packages** are stored in temporary directories and cleaned up after scanning
- **Audit logs** are stored locally and can be exported for compliance
- **No data is sent to external services** except for API queries to vulnerability databases and AI providers

## Troubleshooting

### "Semgrep not installed" warning

Install Semgrep locally:

```bash
pip install semgrep
```

### "API request failed" error

- Check your API key is correct
- For WPScan: ensure you have API credits remaining
- For NVD: this is rate-limited; wait and retry

### "Failed to download" error

- Check the plugin/theme slug is correct
- Ensure you have network connectivity
- Try with a specific version: `wp ai-plugin scan woocommerce --version=8.0.0`

## Development

### Running Tests

```bash
# Install dependencies
composer install

# Run PHPUnit tests
./vendor/bin/phpunit

# Run with coverage
./vendor/bin/phpunit --coverage-html htmlcov
```

### Code Style

This project follows WordPress PHP Coding Standards and PSR-4 autoloading.

```bash
# Check code style
composer run cs

# Auto-fix code style
composer run cbf
```

## License

MIT License — see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting PRs.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a Pull Request

## Support

- **Issues**: https://github.com/wp-ai-security/wp-cli-ai-security/issues
- **Discussions**: https://github.com/wp-ai-security/wp-cli-ai-security/discussions
- **Security**: Please report vulnerabilities via GitHub security advisories

## Related Projects

- [WPackagist](https://wpackagist.org/) — Composer repository for WordPress plugins/themes
- [WP Packages](https://wp-packages.org/) — Alternative Composer repository by Roots
- [WPScan](https://wpscan.com/) — WordPress security scanner
- [Semgrep](https://semgrep.dev/) — Static analysis engine

---

Built with ❤️ for the WordPress community