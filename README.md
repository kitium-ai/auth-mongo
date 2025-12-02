# @kitiumai/auth-mongo

MongoDB storage adapter for `@kitiumai/auth`. It manages all persistence (users, sessions, API keys, orgs, RBAC, SSO, 2FA) and boots an enterprise-friendly schema with indexes, transactions, and operational safeguards.

## Installation

```bash
pnpm add @kitiumai/auth-mongo mongodb
```

Requires MongoDB 4.2+ (for transactions) and Node 16+.

## Quick start

```ts
import { MongoStorageAdapter } from '@kitiumai/auth-mongo';
import { AuthCore, createStorageConfig } from '@kitiumai/auth';

const storage = new MongoStorageAdapter(process.env.MONGODB_URI!, {
  maxPoolSize: 10,
  minPoolSize: 2,
  maxIdleTimeMS: 30_000,
  serverSelectionTimeoutMS: 5_000,
  maxRetries: 2,
});

await storage.connect(); // creates collections and indexes if missing

const auth = new AuthCore({
  appUrl: 'https://example.com',
  providers: [], // add your email/OAuth/SAML providers
  storage: createStorageConfig({ driver: 'mongo', url: process.env.MONGODB_URI }),
  apiKeys: { prefix: 'kit', hash: { algo: 'argon2id' } },
  sessions: { cookieName: 'kitium_session', ttlSeconds: 60 * 60 * 24 },
});
```

### Resilient connection options

```ts
const storage = new MongoStorageAdapter(process.env.MONGODB_URI!, {
  maxPoolSize: 20, // connection pool size
  maxRetries: 3, // retry failed operations with exponential backoff
  operationTimeoutMS: 10_000, // per-operation timeout
});
```

### API key security helpers

```ts
const storage = new MongoStorageAdapter(process.env.MONGODB_URI!, {
  apiKeyHashAlgorithm: 'scrypt', // hardened hashing for API key secrets
  apiKeySalt: Buffer.from(process.env.API_KEY_SALT!, 'hex'),
});

// Create and persist a key with prefix/last-four metadata for audits
const { record, key } = await storage.createApiKeyWithSecret('user_123', ['read', 'write'], 'kit');

// Validate a presented key using constant-time comparison
const matched = await storage.verifyApiKeySecret(key);

// Rotate a key and expire the previous one immediately
const rotation = await storage.rotateApiKey(record.id, { expiresOldKeysAt: new Date() });
console.log(rotation.key);
```

### Health checks

```ts
const health = await storage.healthCheck();
if (health.status !== 'ok') {
  throw new Error(`database unhealthy (latency ${health.latencyMs}ms)`);
}
```

## What it creates

- Collections: `auth_migrations` (schema versioning), `users`, `api_keys`, `sessions`, `organizations`, `email_verification_tokens`, `email_verification_token_attempts`, `auth_events`, `roles`, `user_roles`, `sso_providers`, `sso_links`, `sso_sessions`, `twofa_devices`, `twofa_backup_codes`, `twofa_sessions`
- Indexes on common lookup fields (ids, foreign keys, expirations, email, etc.) for optimal query performance.
- TTL indexes for automatic expiration of sessions and tokens.

## Core API

All methods come from the `StorageAdapter` interface in `@kitiumai/auth`.

- Connection: `connect()`, `disconnect()`
- API keys: `createApiKey`, `createApiKeyWithSecret`, `verifyApiKeySecret`, `rotateApiKey`, `getApiKey`, `getApiKeyByHash`, `getApiKeysByPrefixAndLastFour`, `updateApiKey`, `deleteApiKey`, `listApiKeys`
- Sessions: `createSession`, `getSession`, `updateSession`, `deleteSession`
- Users: `createUser`, `getUser`, `getUserByEmail`, `getUserByOAuth`, `updateUser`, `deleteUser`, `linkOAuthAccount`
- Organizations: `createOrganization`, `getOrganization`, `updateOrganization`, `deleteOrganization`
- Email verification: `createEmailVerificationToken`, `getEmailVerificationTokens`, `getEmailVerificationTokenById`, `markEmailVerificationTokenAsUsed`, `deleteExpiredEmailVerificationTokens`, `getEmailVerificationTokenAttempts`, `incrementEmailVerificationTokenAttempts`
- Events: `emitEvent`
- RBAC: `createRole`, `getRole`, `updateRole`, `deleteRole`, `listRoles`, `assignRoleToUser`, `revokeRoleFromUser`, `getUserRoles`
- SSO: `createSSOProvider`, `getSSOProvider`, `updateSSOProvider`, `deleteSSOProvider`, `listSSOProviders`, `createSSOLink`, `getSSOLink`, `getUserSSOLinks`, `deleteSSOLink`, `createSSOSession`, `getSSOSession`
- 2FA: `createTwoFactorDevice`, `getTwoFactorDevice`, `updateTwoFactorDevice`, `listTwoFactorDevices`, `deleteTwoFactorDevice`, `createBackupCodes`, `getBackupCodes`, `markBackupCodeUsed`, `createTwoFactorSession`, `getTwoFactorSession`, `completeTwoFactorSession`

## Usage snippets

Create a user and session:

```ts
const user = await storage.createUser({ email: 'hi@example.com', entitlements: [] });
const session = await storage.createSession({
  userId: user.id,
  entitlements: [],
  expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
});
```

Issue an API key:

```ts
const apiKey = await storage.createApiKey({
  principalId: user.id,
  hash: 'argon2-hash',
  prefix: 'kit',
  lastFour: 'abcd',
  scopes: ['read'],
  metadata: { name: 'cli' },
  expiresAt: null,
});
```

Record an auth event:

```ts
await storage.emitEvent({
  type: 'user.login',
  principalId: user.id,
  orgId: undefined,
  data: { ip: '127.0.0.1' },
  timestamp: new Date(),
});
```

## Production checklist

- **Resiliency:** configure `operationTimeoutMS`, `maxRetries`, and pool limits to protect MongoDB during traffic spikes.
- **Migrations:** run `connect()` as part of deploys to apply schema changes; the adapter records applied migrations in `auth_migrations` for safe rollbacks.
- **Backups and DR:** schedule regular backups of MongoDB and practice restores; auth data is critical to user access.
- **Security:** enable TLS on MongoDB, restrict network access, and consider MongoDB field-level encryption for sensitive data.
- **Observability:** forward the adapter's structured debug logs to your logging stack and export database metrics (connections, operations, latency) to your monitoring system.

## Notes

- `connect()` is idempotent and safe to call on startup; it will run pending migrations and create missing collections/indexes.
- All document fields are stored in their native types for optimal performance.
- Operations use MongoDB transactions where appropriate for data consistency.
- Errors are wrapped in `InternalError` with retry hints where applicable, and a `healthCheck()` helper is provided for readiness probes.
