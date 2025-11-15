# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-11-15

### Added

#### Core Features
- Comprehensive LLM security assessment tool
- 13 security test categories
- 371 attack payloads across 20 categories
- 100+ prompt injection variants

#### Command-Line Options
- `--url`: Specify target URL directly
- `--curl-file`: Parse curl commands from file
- `--headers`: Custom headers as JSON
- `--data`: Custom request body as JSON
- `--method`: HTTP method selection (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
- `--log-file`: Log all requests and responses
- `--threads`: Parallel scanning (1-20 threads)
- `--output`: Save results to file
- `--resume`: Resume interrupted scans
- `--checks`: Select specific security checks
- `-v, --verbose`: Verbosity levels (-v, -vv)
- `--proxy`: HTTP/HTTPS proxy support

#### Security Tests
1. SSL/TLS & Connectivity Security
2. Authentication & Authorization
3. Input Validation & Injection Attacks
4. Rate Limiting & DoS Protection
5. Data Exposure & Information Disclosure
6. Comprehensive Prompt Injection & Jailbreak Attacks (100+ variants)
7. Model Extraction & Membership Inference
8. Response Validation & Output Encoding
9. API Security Headers
10. Session Management
11. Sensitive Data Handling
12. Comprehensive LLM-Specific Attacks
13. Error Handling & Logging

#### Attack Categories
- Prompt Injection & Jailbreaks (157 payloads)
- Adversarial Inputs & Evasion (20 payloads)
- Data Extraction & Privacy Attacks (15 payloads)
- Denial of Service & Resource Exhaustion (10 payloads)
- Input Validation Bypass (15 payloads)
- Indirect Prompt Injection (9 payloads)
- Model Behavior Manipulation (15 payloads)
- Context Window Attacks (10 payloads)
- Compliance & Regulatory Bypass (10 payloads)
- Timing & Side Channel Attacks (5 payloads)
- Special Characters & Encoding (10 payloads)
- Mathematical & Logical Exploits (10 payloads)
- Knowledge Base Attacks (10 payloads)
- Multi-Turn Exploitation (10 payloads)
- System Prompt Discovery (10 payloads)
- Capability Probing (10 payloads)
- Consistency Attacks (10 payloads)
- Creative Exploitation (15 payloads)
- Emotional & Psychological Manipulation (10 payloads)
- Technical Exploitation (10 payloads)

#### Features
- Thread-safe logging and output
- Scan state persistence for resume functionality
- Selective check execution
- JSON-based configuration
- Comprehensive error handling
- Color-coded console output
- Security scoring and assessment
- Sensitive data redaction

#### Documentation
- README.md: Main documentation
- QUICK_START.md: Quick start guide
- USAGE_EXAMPLES.md: Comprehensive usage examples
- CURL_PARSING.md: Curl parsing guide
- ADVANCED_USAGE.md: Advanced usage scenarios
- LLM_ATTACKS_GUIDE.md: Attack vectors documentation
- LOGGING_AND_THREADING.md: Logging and threading guide
- RESUME_AND_OUTPUT.md: Resume and output guide
- SELECTIVE_CHECKS.md: Selective checks guide
- CONTRIBUTING.md: Contribution guidelines

### Technical Details

#### Architecture
- Modular design with separate modules for attacks, state management, and curl parsing
- Thread-safe operations with locks for concurrent access
- Efficient payload management with categorized attack vectors
- Flexible configuration system

#### Performance
- Parallel scanning with configurable threads
- Optimized request handling
- Efficient state persistence
- Minimal memory footprint

#### Security
- Sensitive data redaction in logs
- Secure session handling
- Protected state file management
- Input validation and sanitization

## Future Roadmap

### Planned Features
- Web UI dashboard
- Database integration for result storage
- Advanced reporting (PDF, HTML, JSON)
- Integration with CI/CD pipelines
- Machine learning-based vulnerability detection
- Real-time monitoring and alerting
- Multi-target scanning
- Custom payload creation interface

### Planned Improvements
- Additional attack vectors
- More security checks
- Performance optimizations
- Enhanced documentation
- Community contributions

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Author

**bolbolsec** - Security Researcher and Developer

## Acknowledgments

- OWASP for security guidelines
- LLM security research community
- Contributors and testers
