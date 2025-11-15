# LLM Security Checker

A comprehensive script for performing a complete security checklist for LLM endpoints.

## Features

This script performs 12 categories of security tests:

1. **SSL/TLS & Connectivity Security** - Check HTTPS, SSL certificate, and HSTS
2. **Authentication & Authorization** - Test session_id and authentication
3. **Input Validation & Injection Attacks** - SQL, Command, XSS, Path Traversal, LDAP, XXE
4. **Rate Limiting & DoS Protection** - Check request rate limiting
5. **Information Disclosure** - Check detailed errors and sensitive headers
6. **Prompt Injection & Jailbreak** - **60+ prompt injection attacks** including:
   - Direct Instruction Override
   - System Prompt Extraction
   - Developer/Admin Mode Claims
   - Role-Playing Jailbreaks
   - DAN (Do Anything Now) Variants
   - Hypothetical Scenarios
   - Token Smuggling
   - Context Confusion
   - Encoding Bypass
   - Recursive Injection
   - Authority Claims
   - Social Engineering
   - Format Injection
   - Persona-Based Jailbreaks
   - Multi-Language Attacks
   - And many more...
7. **Model Extraction & Membership Inference** - Check model information disclosure
8. **Response Validation & Output Encoding** - Validate JSON and encoding
9. **Security Headers** - Check security headers (CSP, X-Frame-Options, etc)
10. **Session Management** - Test session fixation and cookie flags
11. **Sensitive Data Handling** - Check session_id and PII disclosure
12. **Error Handling & Logging** - Test error handling and large payloads

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python3 llm_security_checker.py
```

### With Basic Logs (-v)

```bash
python3 llm_security_checker.py -v
```

Display basic logs with timestamp:
- Test start
- Request status
- Diagnostic messages

### With Detailed Logs (-vv)

```bash
python3 llm_security_checker.py -vv
```

Display all details including:
- HTTP requests (method, URL, payload, headers)
- HTTP responses (status code, headers, body)
- All basic logs

**Note:** Sensitive headers (Authorization, Cookie, Set-Cookie) are hidden for security.

### Using Proxy

```bash
python3 llm_security_checker.py --proxy http://localhost:8080
```

### Combining Options

```bash
# Detailed logs + Proxy
python3 llm_security_checker.py -vv --proxy http://localhost:8080

# Basic logs + Proxy
python3 llm_security_checker.py -v --proxy http://localhost:8080
```

## Output

The script displays results with different colors:

- ✓ **PASS** (Green): Test passed
- ✗ **FAIL** (Red): Vulnerability found
- ⚠ **WARN** (Yellow): Warning or potential issue
- ℹ **INFO** (Blue): Diagnostic information

## Final Result

The script calculates a security score (0-100%):

- **80%+**: GOOD
- **60-80%**: FAIR
- **<60%**: POOR

## Command Line Options

```
-v, --verbose         Increase verbosity level (-v for basic, -vv for detailed)
--proxy PROXY         Use HTTP/HTTPS proxy (e.g., http://localhost:8080)
--curl-file FILE      Parse curl command from file
--url URL             Target LLM URL (e.g., https://api.example.com/chat)
--headers JSON        Custom headers as JSON (e.g., '{"Authorization":"Bearer token"}')
--data JSON           Custom request body as JSON (e.g., '{"question":"test","user_id":"123"}')
--method METHOD       HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS) - default: POST
--log-file FILE       Log all requests and responses to file (e.g., scan.log)
--threads N           Number of parallel threads for scanning (1-20, default: 1)
--output FILE         Save scan results to file (e.g., results.txt)
--resume              Resume interrupted scan from where it stopped
--checks LIST         Specific checks to run (e.g., ssl,auth,injection)
-h, --help            Show help message
```

### Option Explanations:

- **`--curl-file`**: Parse curl file and extract all details (URL, headers, cookies)
- **`--url`**: Specify target URL directly (required if `--curl-file` not used)
- **`--headers`**: Specify additional or replacement headers as JSON object
  - Can be used with `--curl-file` (merged)
  - Can be used with `--url` (replaced)
- **`--data`**: Specify request body as JSON object
  - Can be used with `--curl-file` (overridden)
  - Can be used with `--url` (replaced)
  - Optional (not needed for GET requests)
- **`--method`**: Specify HTTP method
  - Default: POST
  - Can be used with `--curl-file` (overridden)
  - Can be used with `--url` (replaced)
- **`--log-file`**: Log all requests and responses to file
  - Includes timestamps, headers, payloads, and responses
  - Sensitive data (Authorization, Cookies) redacted as `***REDACTED***`
  - Thread-safe for parallel scanning
- **`--threads`**: Control number of parallel threads
  - 1-20 threads (default: 1)
  - More threads = faster scanning
  - Recommended: 5-10 for normal scanning
- **`--output`**: Save scan results to file
  - ANSI colors removed (plain text only)
  - Thread-safe for parallel scanning
  - Results saved to both console and file
- **`--resume`**: Resume interrupted scan
  - State saved in `.scan_state.json`
  - Only works for same URL
  - Can change threads and other options
- **`--checks`**: Select specific checks to run
  - 13 available: ssl, auth, input, rate, info, injection, extraction, response, headers, session, sensitive, llm, error
  - Separate with comma: `--checks ssl,auth,injection`
  - Useful for fast and focused scanning

## Usage Examples

### Basic Usage

```bash
# Simple run
python3 llm_security_checker.py

# With basic logs
python3 llm_security_checker.py -v

# With all request/response details
python3 llm_security_checker.py -vv

# Using Burp Suite proxy
python3 llm_security_checker.py --proxy http://localhost:8080

# Combine: detailed logs + Burp proxy
python3 llm_security_checker.py -vv --proxy http://localhost:8080

# Combine: detailed logs + Zaproxy
python3 llm_security_checker.py -vv --proxy http://localhost:8090
```

### Using Curl File

```bash
# Parse curl file and scan with its details
python3 llm_security_checker.py --curl-file request.curl

# Parse curl file + basic logs
python3 llm_security_checker.py --curl-file request.curl -v

# Parse curl file + detailed logs
python3 llm_security_checker.py --curl-file request.curl -vv

# Parse curl file + use proxy
python3 llm_security_checker.py --curl-file request.curl --proxy http://localhost:8080

# Parse curl file + detailed logs + proxy
python3 llm_security_checker.py --curl-file request.curl -vv --proxy http://localhost:8080

# Parse curl file + add custom headers
python3 llm_security_checker.py --curl-file request.curl --headers '{"Authorization":"Bearer token123"}'

# Parse curl file + replace headers
python3 llm_security_checker.py --curl-file request.curl --headers '{"X-API-Key":"key123","X-Custom":"value"}'
```

### Using URL and Custom Headers

```bash
# URL only (with default headers)
python3 llm_security_checker.py --url https://api.example.com/chat

# URL + one custom header
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token"}'

# URL + multiple custom headers
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token","X-API-Key":"key123"}'

# URL + headers + detailed logs
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token"}' -vv

# URL + headers + proxy
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token"}' --proxy http://localhost:8080

# URL + headers + detailed logs + proxy
python3 llm_security_checker.py --url https://api.example.com/chat --headers '{"Authorization":"Bearer token"}' -vv --proxy http://localhost:8080
```

### Using Custom Request Data

```bash
# URL + custom data
python3 llm_security_checker.py --url https://api.example.com/chat --data '{"question":"test"}'

# URL + custom data with multiple fields
python3 llm_security_checker.py --url https://api.example.com/chat --data '{"question":"test","user_id":"123","model":"gpt-4"}'

# URL + headers + custom data
python3 llm_security_checker.py --url https://api.example.com/chat \
  --headers '{"Authorization":"Bearer token"}' \
  --data '{"question":"test","user_id":"123"}'

# URL + custom data + detailed logs
python3 llm_security_checker.py --url https://api.example.com/chat \
  --data '{"prompt":"hello","model":"gpt-4"}' \
  -vv
```

### Using Custom HTTP Method

```bash
# URL + GET method
python3 llm_security_checker.py --url https://api.example.com/chat --method GET

# URL + PUT method
python3 llm_security_checker.py --url https://api.example.com/chat --method PUT --data '{"id":"123","content":"updated"}'

# URL + DELETE method
python3 llm_security_checker.py --url https://api.example.com/chat --method DELETE

# URL + PATCH method
python3 llm_security_checker.py --url https://api.example.com/chat --method PATCH --data '{"status":"active"}'

# URL + custom method + headers + data
python3 llm_security_checker.py --url https://api.example.com/chat \
  --method PUT \
  --headers '{"Authorization":"Bearer token"}' \
  --data '{"question":"test","updated":true}' \
  -vv
```

### Using Logging

```bash
# Simple - all requests and responses logged
python3 llm_security_checker.py --url https://api.example.com/chat --log-file scan.log

# With verbose logging
python3 llm_security_checker.py --url https://api.example.com/chat --log-file scan.log -vv

# Curl file + logging
python3 llm_security_checker.py --curl-file request.curl --log-file scan.log

# All details in log
python3 llm_security_checker.py --url https://api.example.com/chat \
  --headers '{"Authorization":"Bearer token"}' \
  --data '{"question":"test"}' \
  --log-file detailed_scan.log \
  -vv
```

### Using Threads (Parallel Scanning)

```bash
# 5 threads - normal speed
python3 llm_security_checker.py --url https://api.example.com/chat --threads 5

# 10 threads - high speed
python3 llm_security_checker.py --url https://api.example.com/chat --threads 10

# 10 threads + logging
python3 llm_security_checker.py --url https://api.example.com/chat --threads 10 --log-file scan.log

# Curl file + 8 threads + logging
python3 llm_security_checker.py --curl-file request.curl --threads 8 --log-file scan.log
```

### Using Output (Save Results)

```bash
# Simple - results saved to file
python3 llm_security_checker.py --url https://api.example.com/chat --output results.txt

# With logging
python3 llm_security_checker.py --url https://api.example.com/chat \
  --output results.txt \
  --log-file scan.log

# With threads and output
python3 llm_security_checker.py --url https://api.example.com/chat \
  --output results.txt \
  --threads 10 \
  -v
```

### Using Resume (Continue Interrupted Scan)

```bash
# Start scan
python3 llm_security_checker.py --url https://api.example.com/chat \
  --output results.txt \
  --threads 5

# If interrupted (Ctrl+C), continue:
python3 llm_security_checker.py --url https://api.example.com/chat \
  --resume \
  --output results.txt

# Resume with different threads
python3 llm_security_checker.py --url https://api.example.com/chat \
  --resume \
  --output results.txt \
  --threads 10
```

### Using Selective Checks (Specific Tests)

```bash
# Prompt Injection only (fast)
python3 llm_security_checker.py --url https://api.example.com/chat --checks injection

# Multiple checks
python3 llm_security_checker.py --url https://api.example.com/chat --checks ssl,auth,injection

# Basic checks
python3 llm_security_checker.py --url https://api.example.com/chat \
  --checks ssl,auth,headers,session

# LLM checks
python3 llm_security_checker.py --url https://api.example.com/chat \
  --checks injection,extraction,llm \
  --threads 10
```

### Combining All Options

```bash
# Curl file + custom headers + logging + threads + output + resume
python3 llm_security_checker.py --curl-file request.curl \
  --headers '{"X-API-Key":"key123"}' \
  --threads 8 \
  --log-file scan.log \
  --output results.txt \
  --resume \
  -vv

# URL + headers + data + method + proxy + logging + threads + output
python3 llm_security_checker.py --url https://api.example.com/chat \
  --headers '{"Authorization":"Bearer token","X-Custom":"value"}' \
  --data '{"question":"test","user_id":"123"}' \
  --method POST \
  --proxy http://localhost:8080 \
  --threads 10 \
  --log-file full_scan.log \
  --output results.txt \
  -vv
```

### Creating Curl File

To save curl command to file:

```bash
# Method 1: Copy directly from browser
# In Chrome/Firefox: DevTools > Network > Right-click request > Copy > Copy as cURL

# Method 2: Save to file
cat > request.curl << 'EOF'
curl 'https://example.com/api/chat' \
  -H 'accept: */*' \
  -H 'content-type: application/json' \
  -b 'session_id=abc123' \
  --data-raw '{"session_id":"abc123","question":"test"}'
EOF

# Then scan:
python3 llm_security_checker.py --curl-file request.curl
```

## Notes

- Some tests require manual review
- This script is for educational and diagnostic testing
- Additional tests required for production use
- When using proxy, ensure your proxy supports HTTPS requests

## Author

LLM Security Assessment Tool
