# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use one of the following methods:

1. **GitHub Security Advisory** (preferred): [Report a vulnerability](https://github.com/thijsvos/password-crack-orchestrate/security/advisories/new)
2. **Email**: Send details to the repository owner via their GitHub profile

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity, but critical issues are prioritized

## Scope

This policy covers:

- The coordinator (`crack-coord`), agent (`crack-agent`), and CLI (`crackctl`) binaries
- The Noise IK transport protocol implementation
- Key generation and storage
- The REST API
- SQLite data storage

## Supported Versions

Only the latest release is supported with security updates.
