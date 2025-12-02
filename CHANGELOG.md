# @kitiumai/auth-mongo

## 1.0.0

### Added

- Initial release of enterprise-grade MongoDB storage adapter
- Full support for users, sessions, API keys, organizations, RBAC, SSO, and 2FA
- Comprehensive indexing strategy for optimal query performance
- TTL indexes for automatic expiration of sessions and tokens
- Retry logic with exponential backoff for resilient operations and enforced per-operation timeouts
- Hardened API key helpers with scrypt hashing, constant-time verification, and rotation support
- Health check endpoint for monitoring and readiness probes
- Test coverage for timeout enforcement and API key verification, plus Vitest aliases for offline runs
- Production-ready error handling and logging
