# Contributing to WP-CLI AI Security

Thank you for your interest in contributing to WP-CLI AI Security!

## Code of Conduct

By participating in this project, you are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior to the maintainers.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When creating a bug report, include:

1. **Title**: Clear and concise description
2. **Environment**: PHP version, WP-CLI version, WordPress version, OS
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Expected Behavior**: What you expected to happen
5. **Actual Behavior**: What actually happened
6. **Logs**: Any relevant error messages or logs
7. **Screenshots**: If applicable

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) when creating issues.

### Suggesting Features

Feature requests are welcome! Please use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md) and include:

1. **Use Case**: What problem does this solve?
2. **Proposed Solution**: How would you implement this?
3. **Alternatives**: What other solutions have you considered?

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes following our coding standards
4. Add tests if applicable
5. Ensure all tests pass
6. Commit with clear messages (follow [conventional commits](https://www.conventionalcommits.org/))
7. Push to your fork
8. Submit a Pull Request

## Development Setup

```bash
# Clone the repository
git clone https://github.com/wp-ai-security/wp-cli-ai-security.git
cd wp-cli-ai-security

# Install dependencies
composer install

# Run tests
./vendor/bin/phpunit
```

## Coding Standards

This project follows:

- [WordPress Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/)
- [PSR-4 Autoloading](https://www.php-fig.org/psr/psr-4/)
- [PSR-12 Extended Coding Style](https://www.php-fig.org/psr/psr-12/)

### Code Quality Tools

```bash
# Run PHP CodeSniffer
composer run cs

# Auto-fix coding standards
composer run cbf

# Run PHPStan static analysis
composer run analyse
```

## Testing

Write tests for new features and bug fixes. This project uses PHPUnit.

```bash
# Run all tests
./vendor/bin/phpunit

# Run specific test file
./vendor/bin/phpunit tests/Service/VulnerabilityScannerTest.php

# Run with coverage
./vendor/bin/phpunit --coverage-html coverage
```

### Test Structure

```
tests/
├── Service/
│   ├── VulnerabilityScannerTest.php
│   ├── AIAnalyzerTest.php
│   └── ConfigTest.php
├── Utils/
│   ├── CacheTest.php
│   └── AuditLoggerTest.php
└── Commands/
    └── PluginScanTest.php
```

## Commit Messages

Follow conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

Example:
```
feat(vuln-scanner): add NVD API support

Add NVD as a fallback vulnerability data source when no API key is configured.
Includes rate limiting and proper error handling.

Closes #42
```

## Security Considerations

When contributing code that handles:

- **API keys**: Never log or expose API keys
- **User input**: Always sanitize and validate input
- **File operations**: Use secure paths, prevent directory traversal
- **External requests**: Use timeouts, handle errors gracefully

## Recognition

Contributors will be acknowledged in:
- README.md contributors section
- Release notes
- GitHub contributors page

## Getting Help

- **Documentation**: Check the [README](README.md) and [wiki](https://github.com/wp-ai-security/wp-cli-ai-security/wiki)
- **Discussions**: Use [GitHub Discussions](https://github.com/wp-ai-security/wp-cli-ai-security/discussions)
- **Issues**: For bug reports and feature requests

---

Thank you for contributing! 🚀