# Contributing to LLM Security Checker

Thank you for your interest in contributing to LLM Security Checker! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the code, not the person
- Help others learn and grow

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported
2. Provide a clear description of the bug
3. Include steps to reproduce
4. Provide expected vs actual behavior
5. Include your environment details (OS, Python version, etc.)

### Suggesting Enhancements

1. Check if the enhancement has been suggested
2. Provide a clear description of the enhancement
3. Explain the use case and benefits
4. Provide examples if possible

### Submitting Pull Requests

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Test your changes thoroughly
5. Commit with clear messages: `git commit -m "Add feature: description"`
6. Push to your fork: `git push origin feature/your-feature`
7. Submit a pull request with a clear description

## Development Setup

```bash
# Clone the repository
git clone https://github.com/bolbolsec/llm-security-checker.git
cd llm-security-checker

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 llm_security_checker.py --help
```

## Code Style

- Follow PEP 8 guidelines
- Use meaningful variable names
- Add docstrings to functions
- Add comments for complex logic
- Keep lines under 100 characters

## Testing

- Test your changes with various inputs
- Test with different Python versions
- Test with different operating systems
- Include test cases for new features

## Documentation

- Update README.md if adding new features
- Update relevant guide files
- Add examples for new functionality
- Keep documentation clear and concise

## Areas for Contribution

### New Attack Vectors

Add new LLM attack payloads to `llm_attacks.py`:
- Prompt injection variants
- Adversarial inputs
- Data extraction techniques
- Model manipulation attacks

### New Security Checks

Add new security check functions to `llm_security_checker.py`:
- API security checks
- Authentication mechanisms
- Data protection measures
- Compliance checks

### Documentation

- Improve existing documentation
- Add tutorials and guides
- Create video tutorials
- Translate documentation

### Bug Fixes

- Fix reported issues
- Improve error handling
- Optimize performance
- Fix security vulnerabilities

## Questions?

Feel free to open an issue or contact the maintainers.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing! 🎉
