# Contributing

Contributions are welcome! Here's how you can help.

## Reporting Issues

- Check existing issues before creating a new one
- Include PHP version and relevant error messages
- For detection failures: include the domain (if not confidential)

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run static analysis
5. Commit with a clear message
6. Open a Pull Request

## Code Style

This project uses [Mago](https://github.com/carthage-software/mago) for static analysis and formatting:

```bash
# Format code
mago fmt

# Run linter
mago lint

# Run analyzer
mago analyze
```

## Adding Detection Strategies

When adding new mail server detection strategies:

1. Add the method in `src/AutoDetector.php`
2. Call it from `autoDetect()` in the appropriate order
3. Return results in the standard format with appropriate score
4. Update README.md with the new strategy

## Questions?

Open an issue for questions or suggestions.
