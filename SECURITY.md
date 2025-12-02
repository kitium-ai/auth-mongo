# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 3.x.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability within @kitiumai/auth-mongo, please send an email to security@kitiumai.com. All security vulnerabilities will be promptly addressed.

Please include the following information:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Best Practices

When using @kitiumai/auth-mongo in production:

1. **Connection Security**: Always use TLS/SSL for MongoDB connections
2. **Network Access**: Restrict MongoDB network access to trusted sources only
3. **Authentication**: Enable MongoDB authentication and use strong credentials
4. **Encryption**: Consider MongoDB field-level encryption for sensitive data
5. **Monitoring**: Enable audit logging and monitor for suspicious activity
6. **Updates**: Keep the package and MongoDB server updated to the latest versions
7. **Backups**: Implement regular backup strategies for your authentication data

## Responsible Disclosure

We ask that you do not publicly disclose the vulnerability until we have had a chance to address it. We will acknowledge your email within 48 hours and will send a more detailed response within 7 days.
