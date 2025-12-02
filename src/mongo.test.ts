import { beforeAll, describe, expect, it, vi } from 'vitest';
import { randomBytes } from 'node:crypto';

// eslint-disable-next-line @typescript-eslint/naming-convention
let MongoStorageAdapter: typeof import('./mongo').MongoStorageAdapter;

vi.mock('@kitiumai/logger', () => ({
  getLogger: () => ({ info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() }),
}));

vi.mock('@kitiumai/error', () => ({
  // eslint-disable-next-line @typescript-eslint/naming-convention
  InternalError: class InternalError extends Error {
    code?: string;
    constructor(opts: { code?: string; message?: string }) {
      super(opts?.message);
      if (opts?.code !== undefined) {
        this.code = opts.code;
      }
    }
  },
}));

beforeAll(async () => {
  const module = await import('./mongo');
  MongoStorageAdapter = module.MongoStorageAdapter;
});

const randomId = (): string => randomBytes(8).toString('hex');

describe('MongoStorageAdapter hardening', () => {
  it('enforces per-operation timeout', async () => {
    const adapter = new MongoStorageAdapter('mongodb://localhost:27017', {
      operationTimeoutMS: 5,
      maxRetries: 0,
    });

    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (adapter as any).withRetry(
        () => new Promise((resolve) => setTimeout(resolve, 20)),
        'timeout-test'
      )
    ).rejects.toMatchObject({ code: 'auth-mongo/operation_timeout' });
  });

  it('supports scrypt-hashed API keys with prefix/last-four matching', async () => {
    const adapter = new MongoStorageAdapter('mongodb://localhost:27017', {
      apiKeyHashAlgorithm: 'scrypt',
      apiKeySalt: Buffer.from('enterprise-salt'),
    });

    const secret = `api_${randomId()}`;
    const lastFour = secret.slice(-4);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const hashed = (adapter as any).hashApiKeySecret(secret);

    const storedRecord = {
      id: 'key-1',
      principalId: 'principal-123',
      hash: hashed,
      prefix: 'api',
      lastFour,
      scopes: ['read'],
      metadata: {},
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Stub backing store
    adapter.getApiKeysByPrefixAndLastFour = async () => [storedRecord];

    const verified = await adapter.verifyApiKeySecret(secret);
    expect(verified?.id).toBe('key-1');

    const notFound = await adapter.verifyApiKeySecret(`${secret}-mismatch`);
    expect(notFound).toBeNull();
  });
});
