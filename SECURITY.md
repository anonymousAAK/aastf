# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

AASTF is a security testing tool. We take security of the tool itself seriously.

**Do NOT report security vulnerabilities through public GitHub issues.**

To report a vulnerability, please email: **security@aastf.dev** (or the repo owner's email if that's not set up yet — check the GitHub profile)

Alternatively, use [GitHub's private vulnerability reporting](https://github.com/anonymousAAK/aastf/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response timeline

- **Acknowledgement:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix for critical issues:** Within 14 days
- **Fix for other issues:** Within 30 days

### Scope

The following are in scope:
- AASTF CLI tool code
- Scenario evaluation logic
- Sandbox server
- Report generation
- Dependencies

The following are out of scope:
- Vulnerabilities in the agents being tested (that's what AASTF finds)
- Social engineering attacks
- Denial of service against the CLI

## Security Design

AASTF is designed with the following security principles:

1. **No phone-home:** AASTF never sends data to external servers. All execution is local.
2. **Sandboxed execution:** Agent testing runs against a local FastAPI mock server, not production systems.
3. **No dynamic code execution:** The `custom_evaluator` field in scenarios is a no-op (disabled for security).
4. **Input validation:** All scenario YAML files are validated against strict Pydantic schemas.
5. **Path traversal prevention:** CLI validates all paths resolve within the working directory.

## Acknowledgements

We gratefully acknowledge security researchers who help keep AASTF safe.

(No acknowledgements yet — be the first!)
