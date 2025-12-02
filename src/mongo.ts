import {
  MongoClient,
  Db,
  Collection,
  MongoClientOptions,
  Document,
  Filter,
  UpdateFilter,
} from 'mongodb';
import { getLogger } from '@kitiumai/logger';
import { InternalError } from '@kitiumai/error';
import { randomBytes, createHash, scryptSync, timingSafeEqual } from 'node:crypto';

// Utility functions
const generateId = (): string => {
  return randomBytes(16).toString('hex');
};

const generateApiKey = (prefix: string): string => {
  const secret = randomBytes(32).toString('hex');
  return `${prefix}_${secret}`;
};

type ApiKeyHashAlgorithm = 'sha256' | 'scrypt';

const hashApiKey = (
  key: string,
  algorithm: ApiKeyHashAlgorithm,
  salt?: Buffer,
  // eslint-disable-next-line @typescript-eslint/naming-convention
  scryptParams: { N: number; r: number; p: number } = { N: 16384, r: 8, p: 1 }
): string => {
  if (algorithm === 'scrypt') {
    const result = scryptSync(key, salt ?? Buffer.alloc(0), 32, scryptParams);
    return result.toString('hex');
  }

  return createHash('sha256').update(key).digest('hex');
};
import { setTimeout as delay } from 'node:timers/promises';
import type {
  StorageAdapter,
  ApiKeyRecord,
  SessionRecord,
  OrganizationRecord,
  AuthEvent,
  UserRecord,
  CreateUserInput,
  UpdateUserInput,
  OAuthLink,
  EmailVerificationToken,
  OrganizationMember,
  RoleRecord,
  TwoFactorDevice,
  BackupCode,
  TwoFactorSession,
  SSOLink,
  SSOSession,
  Permission,
  SSOProviderType,
  TwoFactorMethod,
} from '@kitiumai/auth';

interface MongoDocument extends Document {
  _id?: string;
  [key: string]: unknown;
}

type MongoAdapterOptions = MongoClientOptions & {
  operationTimeoutMS?: number;
  maxRetries?: number;
  databaseName?: string;
  apiKeyHashAlgorithm?: ApiKeyHashAlgorithm;
  apiKeySalt?: Buffer;
};

export class MongoStorageAdapter implements StorageAdapter {
  private client: MongoClient;
  private db: Db | null = null;
  private readonly logger = getLogger();
  private readonly defaultRetries: number;
  private readonly databaseName: string;
  private readonly operationTimeoutMS: number | null;
  private readonly apiKeyHashAlgorithm: ApiKeyHashAlgorithm;
  private readonly apiKeySalt?: Buffer;

  constructor(connectionString: string, options?: MongoAdapterOptions) {
    const {
      operationTimeoutMS,
      maxRetries,
      databaseName,
      apiKeyHashAlgorithm,
      apiKeySalt,
      ...clientOptions
    } = options ?? {};

    this.client = new MongoClient(connectionString, {
      maxPoolSize: 10,
      minPoolSize: 2,
      maxIdleTimeMS: 30_000,
      serverSelectionTimeoutMS: 5_000,
      ...clientOptions,
    });

    this.defaultRetries = maxRetries ?? 2;
    this.databaseName = databaseName ?? 'auth';
    this.operationTimeoutMS = operationTimeoutMS ?? null;
    this.apiKeyHashAlgorithm = apiKeyHashAlgorithm ?? 'sha256';
    if (apiKeySalt !== undefined) {
      this.apiKeySalt = apiKeySalt;
    }
  }

  async connect(): Promise<void> {
    try {
      await this.client.connect();
      this.db = this.client.db(this.databaseName);
      await this.runMigrations();
      this.logger.info('MongoDB adapter connected successfully');
    } catch (error) {
      this.logger.error('Failed to connect to MongoDB', { error });
      throw new InternalError({
        code: 'auth-mongo/connection_failed',
        message: 'Failed to connect to MongoDB',
        severity: 'error',
        retryable: true,
        cause: error,
      });
    }
  }

  async disconnect(): Promise<void> {
    try {
      await this.client.close();
      this.logger.info('MongoDB adapter disconnected');
    } catch (error) {
      this.logger.error('Error disconnecting from MongoDB', { error });
      throw new InternalError({
        code: 'auth-mongo/disconnect_failed',
        message: 'Failed to disconnect from MongoDB',
        severity: 'error',
        retryable: false,
        cause: error,
      });
    }
  }

  private getDatabase(): Db {
    if (!this.db) {
      throw new InternalError({
        code: 'auth-mongo/not_connected',
        message: 'MongoDB client not connected',
        severity: 'error',
        retryable: false,
      });
    }
    return this.db;
  }

  private getCollection<T extends MongoDocument>(name: string): Collection<T> {
    return this.getDatabase().collection<T>(name);
  }

  private async withRetry<T>(operation: () => Promise<T>, operationName: string): Promise<T> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.defaultRetries; attempt += 1) {
      try {
        const start = Date.now();
        let timeoutHandle: NodeJS.Timeout | undefined;
        const timeoutPromise =
          this.operationTimeoutMS !== null
            ? new Promise<never>((_, reject) => {
                timeoutHandle = setTimeout(() => {
                  reject(
                    new InternalError({
                      code: 'auth-mongo/operation_timeout',
                      message: `MongoDB operation exceeded ${this.operationTimeoutMS}ms: ${operationName}`,
                      severity: 'error',
                      retryable: false,
                    })
                  );
                }, this.operationTimeoutMS as number);
              })
            : null;

        const result = timeoutPromise
          ? await Promise.race([operation(), timeoutPromise])
          : await operation();

        if (timeoutHandle) {
          clearTimeout(timeoutHandle);
        }

        const durationMs = Date.now() - start;

        this.logger.debug('mongo.operation', {
          operation: operationName,
          durationMs,
        });

        return result;
      } catch (error) {
        lastError = error;
        const retryable = attempt < this.defaultRetries;

        this.logger.warn('MongoDB operation failed', {
          operation: operationName,
          attempt,
          retryable,
          error,
        });

        if (!retryable) {
          if (error instanceof InternalError && error.code === 'auth-mongo/operation_timeout') {
            throw error;
          }
          throw new InternalError({
            code: 'auth-mongo/operation_failed',
            message: `Failed to execute MongoDB operation: ${operationName}`,
            severity: 'error',
            retryable: false,
            cause: error,
          });
        }

        await delay(50 * 2 ** attempt);
      }
    }

    throw lastError;
  }

  async healthCheck(): Promise<{ status: 'ok' | 'error'; latencyMs: number }> {
    const start = Date.now();
    try {
      await this.getDatabase().admin().ping();
      return { status: 'ok', latencyMs: Date.now() - start };
    } catch (error) {
      this.logger.error('MongoDB health check failed', { error });
      return { status: 'error', latencyMs: Date.now() - start };
    }
  }

  private async runMigrations(): Promise<void> {
    const migrationsCollection = this.getCollection<{ id: string; appliedAt: Date }>(
      'auth_migrations'
    );

    const migrationId = '0001_initial_schema_v2';
    const existing = await migrationsCollection.findOne({ id: migrationId });

    if (existing) {
      return;
    }

    // Create all collections and indexes
    await this.createCollections();
    await this.createIndexes();

    // Record migration
    await migrationsCollection.insertOne({
      id: migrationId,
      appliedAt: new Date(),
    });
  }

  private async createCollections(): Promise<void> {
    const db = this.getDatabase();
    const collections = [
      'users',
      'api_keys',
      'sessions',
      'organizations',
      'email_verification_tokens',
      'email_verification_token_attempts',
      'auth_events',
      'roles',
      'user_roles',
      'sso_providers',
      'sso_links',
      'sso_sessions',
      'twofa_devices',
      'twofa_backup_codes',
      'twofa_sessions',
    ];

    const existingCollections = await db.listCollections().toArray();
    const existingNames = new Set(existingCollections.map((c) => c.name));

    for (const collectionName of collections) {
      if (!existingNames.has(collectionName)) {
        await db.createCollection(collectionName);
      }
    }
  }

  private async createIndexes(): Promise<void> {
    // Users indexes
    await this.getCollection('users').createIndexes([
      { key: { email: 1 }, unique: true, sparse: true },
      { key: { createdAt: 1 } },
    ]);

    // API Keys indexes
    await this.getCollection('api_keys').createIndexes([
      { key: { principalId: 1 } },
      { key: { hash: 1 }, unique: true },
      { key: { prefix: 1, lastFour: 1 } },
      { key: { expiresAt: 1 }, sparse: true },
    ]);

    // Sessions indexes
    await this.getCollection('sessions').createIndexes([
      { key: { userId: 1 } },
      { key: { expiresAt: 1 }, expireAfterSeconds: 0 }, // TTL index
    ]);

    // Organizations indexes
    await this.getCollection('organizations').createIndexes([
      { key: { plan: 1 } },
      { key: { createdAt: 1 } },
    ]);

    // Email verification tokens indexes
    await this.getCollection('email_verification_tokens').createIndexes([
      { key: { email: 1 } },
      { key: { type: 1 } },
      { key: { codeHash: 1 } },
      { key: { expiresAt: 1 }, expireAfterSeconds: 0 }, // TTL index
    ]);

    // Auth events indexes
    await this.getCollection('auth_events').createIndexes([
      { key: { principalId: 1 } },
      { key: { type: 1 } },
      { key: { timestamp: 1 } },
    ]);

    // Roles indexes
    await this.getCollection('roles').createIndexes([
      { key: { orgId: 1 } },
      { key: { createdAt: 1 } },
    ]);

    // User roles indexes
    await this.getCollection('user_roles').createIndexes([
      { key: { userId: 1 } },
      { key: { roleId: 1 } },
      { key: { orgId: 1 } },
    ]);

    // SSO providers indexes
    await this.getCollection('sso_providers').createIndexes([
      { key: { orgId: 1 } },
      { key: { type: 1 } },
    ]);

    // SSO links indexes
    await this.getCollection('sso_links').createIndexes([
      { key: { userId: 1 } },
      { key: { providerId: 1 } },
      { key: { providerType: 1, providerSubject: 1 } },
    ]);

    // SSO sessions indexes
    await this.getCollection('sso_sessions').createIndexes([
      { key: { userId: 1 } },
      { key: { providerId: 1 } },
      { key: { expiresAt: 1 }, expireAfterSeconds: 0 }, // TTL index
    ]);

    // 2FA devices indexes
    await this.getCollection('twofa_devices').createIndexes([
      { key: { userId: 1 } },
      { key: { createdAt: 1 } },
    ]);

    // 2FA backup codes indexes
    await this.getCollection('twofa_backup_codes').createIndexes([
      { key: { userId: 1 } },
      { key: { used: 1 } },
    ]);

    // 2FA sessions indexes
    await this.getCollection('twofa_sessions').createIndexes([
      { key: { userId: 1 } },
      { key: { sessionId: 1 } },
      { key: { expiresAt: 1 }, expireAfterSeconds: 0 }, // TTL index
    ]);
  }

  /**
   * Create an API key with plaintext secret (convenience method)
   */
  async createApiKeyWithSecret(
    principalId: string,
    scopes: string[],
    prefix: string = 'api'
  ): Promise<{ record: ApiKeyRecord; key: string }> {
    const key = generateApiKey(prefix);
    const hash = hashApiKey(key, this.apiKeyHashAlgorithm, this.apiKeySalt);
    const parts = key.split('_');
    const lastFour = parts[parts.length - 1]!.slice(-4);

    const record = await this.createApiKey({
      principalId,
      hash,
      prefix,
      lastFour,
      scopes,
    });

    return { record, key };
  }

  private hashApiKeySecret(secret: string): string {
    return hashApiKey(secret, this.apiKeyHashAlgorithm, this.apiKeySalt);
  }

  async verifyApiKeySecret(rawKey: string): Promise<ApiKeyRecord | null> {
    const parts = rawKey.split('_');
    if (parts.length < 2) {
      return null;
    }

    const prefix = parts[0]!;
    const lastFour = parts[parts.length - 1]!.slice(-4);
    const candidates = await this.getApiKeysByPrefixAndLastFour(prefix, lastFour);

    if (!candidates.length) {
      return null;
    }

    const hashed = this.hashApiKeySecret(rawKey);
    const hashedBuffer = Buffer.from(hashed, 'hex');

    for (const candidate of candidates) {
      const candidateHash = Buffer.from(candidate.hash, 'hex');
      if (
        candidateHash.length === hashedBuffer.length &&
        timingSafeEqual(candidateHash, hashedBuffer)
      ) {
        return candidate;
      }
    }

    return null;
  }

  async rotateApiKey(
    id: string,
    options?: { scopes?: string[]; expiresOldKeysAt?: Date }
  ): Promise<{ record: ApiKeyRecord; key: string }> {
    const existing = await this.getApiKey(id);

    if (!existing) {
      throw new InternalError({
        code: 'auth-mongo/api_key_not_found',
        message: 'API key not found for rotation',
        severity: 'error',
        retryable: false,
      });
    }

    const rotationExpiry = options?.expiresOldKeysAt ?? new Date();
    await this.updateApiKey(id, { expiresAt: rotationExpiry });

    return this.createApiKeyWithSecret(
      existing.principalId,
      options?.scopes ?? existing.scopes,
      existing.prefix
    );
  }

  // API Key methods
  async createApiKey(
    data: Omit<ApiKeyRecord, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<ApiKeyRecord> {
    return this.withRetry(async () => {
      const id = generateId();
      const now = new Date();

      const doc = {
        _id: id,
        principalId: data.principalId,
        hash: data.hash,
        prefix: data.prefix,
        lastFour: data.lastFour,
        scopes: data.scopes,
        metadata: data.metadata ?? {},
        expiresAt: data.expiresAt ?? null,
        createdAt: now,
        updatedAt: now,
      };

      await this.getCollection('api_keys').insertOne(doc);
      return this.mapApiKeyRecord(doc);
    }, 'createApiKey');
  }

  async getApiKey(id: string): Promise<ApiKeyRecord | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('api_keys').findOne({ _id: id });
      return doc ? this.mapApiKeyRecord(doc) : null;
    }, 'getApiKey');
  }

  async getApiKeyByHash(hash: string): Promise<ApiKeyRecord | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('api_keys').findOne({ hash });
      return doc ? this.mapApiKeyRecord(doc) : null;
    }, 'getApiKeyByHash');
  }

  async getApiKeysByPrefixAndLastFour(prefix: string, lastFour: string): Promise<ApiKeyRecord[]> {
    return this.withRetry(async () => {
      const docs = await this.getCollection('api_keys').find({ prefix, lastFour }).toArray();
      return docs.map((doc) => this.mapApiKeyRecord(doc));
    }, 'getApiKeysByPrefixAndLastFour');
  }

  async updateApiKey(id: string, data: Partial<ApiKeyRecord>): Promise<ApiKeyRecord> {
    return this.withRetry(async () => {
      const updateDoc: UpdateFilter<MongoDocument> = {
        $set: {
          updatedAt: new Date(),
        },
      };

      const setFields = updateDoc.$set as MongoDocument;

      for (const [key, value] of Object.entries(data)) {
        if (key === 'id' || key === 'createdAt') {
          continue;
        }
        setFields[key] = value;
      }

      const result = await this.getCollection('api_keys').findOneAndUpdate({ _id: id }, updateDoc, {
        returnDocument: 'after',
      });

      if (!result) {
        throw new InternalError({
          code: 'auth-mongo/update_failed',
          message: 'Failed to update API key',
          severity: 'error',
          retryable: false,
        });
      }

      return this.mapApiKeyRecord(result);
    }, 'updateApiKey');
  }

  async deleteApiKey(id: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('api_keys').deleteOne({ _id: id });
    }, 'deleteApiKey');
  }

  async listApiKeys(principalId: string): Promise<ApiKeyRecord[]> {
    return this.withRetry(async () => {
      const docs = await this.getCollection('api_keys')
        .find({ principalId })
        .sort({ createdAt: -1 })
        .toArray();
      return docs.map((doc) => this.mapApiKeyRecord(doc));
    }, 'listApiKeys');
  }

  // Session methods
  async createSession(data: Omit<SessionRecord, 'id' | 'createdAt'>): Promise<SessionRecord> {
    return this.withRetry(async () => {
      const id = generateId();
      const now = new Date();

      const doc = {
        _id: id,
        userId: data.userId,
        orgId: data.orgId || null,
        plan: data.plan || null,
        entitlements: data.entitlements || [],
        expiresAt: data.expiresAt,
        metadata: data.metadata || {},
        createdAt: now,
        updatedAt: now,
      };

      await this.getCollection('sessions').insertOne(doc);
      return this.mapSessionRecord(doc);
    }, 'createSession');
  }

  async getSession(id: string): Promise<SessionRecord | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('sessions').findOne({ _id: id });
      return doc ? this.mapSessionRecord(doc) : null;
    }, 'getSession');
  }

  async updateSession(id: string, data: Partial<SessionRecord>): Promise<SessionRecord> {
    return this.withRetry(async () => {
      const updateDoc: UpdateFilter<MongoDocument> = {
        $set: {
          updatedAt: new Date(),
        },
      };

      const setFields = updateDoc.$set as MongoDocument;

      for (const [key, value] of Object.entries(data)) {
        if (key === 'id' || key === 'createdAt') {
          continue;
        }
        setFields[key] = value;
      }

      const result = await this.getCollection('sessions').findOneAndUpdate({ _id: id }, updateDoc, {
        returnDocument: 'after',
      });

      if (!result) {
        throw new InternalError({
          code: 'auth-mongo/update_failed',
          message: 'Failed to update session',
          severity: 'error',
          retryable: false,
        });
      }

      return this.mapSessionRecord(result);
    }, 'updateSession');
  }

  async deleteSession(id: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('sessions').deleteOne({ _id: id });
    }, 'deleteSession');
  }

  // Organization methods
  async createOrganization(
    data: Omit<OrganizationRecord, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<OrganizationRecord> {
    return this.withRetry(async () => {
      const id = generateId();
      const now = new Date();

      const doc = {
        _id: id,
        name: data.name,
        plan: data.plan,
        seats: data.seats,
        members: data.members,
        metadata: data.metadata || {},
        createdAt: now,
        updatedAt: now,
      };

      await this.getCollection('organizations').insertOne(doc);
      return this.mapOrganizationRecord(doc);
    }, 'createOrganization');
  }

  async getOrganization(id: string): Promise<OrganizationRecord | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('organizations').findOne({ _id: id });
      return doc ? this.mapOrganizationRecord(doc) : null;
    }, 'getOrganization');
  }

  async updateOrganization(
    id: string,
    data: Partial<OrganizationRecord>
  ): Promise<OrganizationRecord> {
    return this.withRetry(async () => {
      const updateDoc: UpdateFilter<MongoDocument> = {
        $set: {
          updatedAt: new Date(),
        },
      };

      const setFields = updateDoc.$set as MongoDocument;

      for (const [key, value] of Object.entries(data)) {
        if (key === 'id' || key === 'createdAt') {
          continue;
        }
        setFields[key] = value;
      }

      const result = await this.getCollection('organizations').findOneAndUpdate(
        { _id: id },
        updateDoc,
        { returnDocument: 'after' }
      );

      if (!result) {
        throw new InternalError({
          code: 'auth-mongo/update_failed',
          message: 'Failed to update organization',
          severity: 'error',
          retryable: false,
        });
      }

      return this.mapOrganizationRecord(result);
    }, 'updateOrganization');
  }

  async deleteOrganization(id: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('organizations').deleteOne({ _id: id });
    }, 'deleteOrganization');
  }

  // User methods
  async createUser(data: CreateUserInput): Promise<UserRecord> {
    return this.withRetry(async () => {
      const id = generateId();
      const now = new Date();

      const doc = {
        _id: id,
        email: data.email || null,
        name: data.name || null,
        picture: data.picture || null,
        plan: data.plan || 'free',
        entitlements: data.entitlements || [],
        oauth: {},
        metadata: data.metadata || {},
        createdAt: now,
        updatedAt: now,
      };

      await this.getCollection('users').insertOne(doc);
      return this.mapUserRecord(doc);
    }, 'createUser');
  }

  async getUser(id: string): Promise<UserRecord | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('users').findOne({ _id: id });
      return doc ? this.mapUserRecord(doc) : null;
    }, 'getUser');
  }

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('users').findOne({ email });
      return doc ? this.mapUserRecord(doc) : null;
    }, 'getUserByEmail');
  }

  async getUserByOAuth(provider: string, sub: string): Promise<UserRecord | null> {
    return this.withRetry(async () => {
      const filter: Filter<MongoDocument> = {};
      filter[`oauth.${provider}.sub`] = sub;

      const doc = await this.getCollection('users').findOne(filter);
      return doc ? this.mapUserRecord(doc) : null;
    }, 'getUserByOAuth');
  }

  async updateUser(id: string, data: UpdateUserInput): Promise<UserRecord> {
    return this.withRetry(async () => {
      const updateDoc: UpdateFilter<MongoDocument> = {
        $set: {
          updatedAt: new Date(),
        },
      };

      const setFields = updateDoc.$set as MongoDocument;

      for (const [key, value] of Object.entries(data)) {
        setFields[key] = value;
      }

      const result = await this.getCollection('users').findOneAndUpdate({ _id: id }, updateDoc, {
        returnDocument: 'after',
      });

      if (!result) {
        throw new InternalError({
          code: 'auth-mongo/update_failed',
          message: 'Failed to update user',
          severity: 'error',
          retryable: false,
        });
      }

      return this.mapUserRecord(result);
    }, 'updateUser');
  }

  async deleteUser(id: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('users').deleteOne({ _id: id });
    }, 'deleteUser');
  }

  async linkOAuthAccount(
    userId: string,
    provider: string,
    oauthLink: OAuthLink
  ): Promise<UserRecord> {
    return this.withRetry(async () => {
      const updateDoc: UpdateFilter<MongoDocument> = {
        $set: {
          updatedAt: new Date(),
        },
      };

      const setFields = updateDoc.$set as MongoDocument;
      setFields[`oauth.${provider}`] = {
        provider: oauthLink.provider,
        sub: oauthLink.sub,
        email: oauthLink.email,
        name: oauthLink.name,
        linkedAt: oauthLink.linkedAt,
      };

      const result = await this.getCollection('users').findOneAndUpdate(
        { _id: userId },
        updateDoc,
        { returnDocument: 'after' }
      );

      if (!result) {
        throw new InternalError({
          code: 'auth-mongo/link_failed',
          message: 'Failed to link OAuth account',
          severity: 'error',
          retryable: false,
        });
      }

      return this.mapUserRecord(result);
    }, 'linkOAuthAccount');
  }

  // Email Verification Token methods
  async createEmailVerificationToken(
    data: Omit<EmailVerificationToken, 'id'>
  ): Promise<EmailVerificationToken> {
    return this.withRetry(async () => {
      const id = generateId();

      const doc = {
        _id: id,
        email: data.email,
        code: data.code,
        codeHash: data.codeHash,
        type: data.type,
        userId: data.userId || null,
        metadata: data.metadata || {},
        expiresAt: data.expiresAt,
        usedAt: null,
        createdAt: new Date(),
      };

      await this.getCollection('email_verification_tokens').insertOne(doc);
      return this.mapEmailVerificationToken(doc);
    }, 'createEmailVerificationToken');
  }

  async getEmailVerificationTokens(
    email: string,
    type?: string
  ): Promise<EmailVerificationToken[]> {
    return this.withRetry(async () => {
      const filter: Filter<MongoDocument> = { email };
      if (type) {
        filter['type'] = type;
      }

      const docs = await this.getCollection('email_verification_tokens')
        .find(filter)
        .sort({ createdAt: -1 })
        .toArray();

      return docs.map((doc) => this.mapEmailVerificationToken(doc));
    }, 'getEmailVerificationTokens');
  }

  async getEmailVerificationTokenById(id: string): Promise<EmailVerificationToken | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('email_verification_tokens').findOne({ _id: id });
      return doc ? this.mapEmailVerificationToken(doc) : null;
    }, 'getEmailVerificationTokenById');
  }

  async markEmailVerificationTokenAsUsed(id: string): Promise<EmailVerificationToken> {
    return this.withRetry(async () => {
      const result = await this.getCollection('email_verification_tokens').findOneAndUpdate(
        { _id: id },
        { $set: { usedAt: new Date() } },
        { returnDocument: 'after' }
      );

      if (!result) {
        throw new InternalError({
          code: 'auth-mongo/update_failed',
          message: 'Failed to mark email verification token as used',
          severity: 'error',
          retryable: false,
        });
      }

      return this.mapEmailVerificationToken(result);
    }, 'markEmailVerificationTokenAsUsed');
  }

  async deleteExpiredEmailVerificationTokens(): Promise<number> {
    return this.withRetry(async () => {
      const result = await this.getCollection('email_verification_tokens').deleteMany({
        expiresAt: { $lt: new Date() },
      });
      return result.deletedCount;
    }, 'deleteExpiredEmailVerificationTokens');
  }

  async getEmailVerificationTokenAttempts(tokenId: string): Promise<number> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('email_verification_token_attempts').findOne({
        _id: tokenId,
      });
      return (doc?.['attempts'] as number) || 0;
    }, 'getEmailVerificationTokenAttempts');
  }

  async incrementEmailVerificationTokenAttempts(tokenId: string): Promise<number> {
    return this.withRetry(async () => {
      const collection = this.getCollection('email_verification_token_attempts');
      const incrementValue: number = 1;
      await collection.updateOne(
        { _id: tokenId },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { $inc: { attempts: incrementValue } } as any,
        {
          upsert: true as boolean,
        }
      );

      const doc = await collection.findOne({ _id: tokenId });
      return (doc?.['attempts'] as number) || 1;
    }, 'incrementEmailVerificationTokenAttempts');
  }

  // Event methods
  async emitEvent(event: AuthEvent): Promise<void> {
    return this.withRetry(async () => {
      const doc = {
        type: event.type,
        principalId: event.principalId,
        orgId: event.orgId,
        data: event.data,
        timestamp: event.timestamp,
      };

      await this.getCollection('auth_events').insertOne(doc);
    }, 'emitEvent');
  }

  // RBAC methods
  async createRole(data: Omit<RoleRecord, 'id' | 'createdAt' | 'updatedAt'>): Promise<RoleRecord> {
    return this.withRetry(async () => {
      const id = generateId();
      const now = new Date();

      const doc = {
        _id: id,
        orgId: data.orgId,
        name: data.name,
        description: data.description || null,
        isSystem: data.isSystem || false,
        permissions: data.permissions || [],
        metadata: data.metadata || {},
        createdAt: now,
        updatedAt: now,
      };

      await this.getCollection('roles').insertOne(doc);
      return this.mapRoleRecord(doc);
    }, 'createRole');
  }

  async getRole(roleId: string): Promise<RoleRecord | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('roles').findOne({ _id: roleId });
      return doc ? this.mapRoleRecord(doc) : null;
    }, 'getRole');
  }

  async updateRole(roleId: string, data: Partial<RoleRecord>): Promise<RoleRecord> {
    return this.withRetry(async () => {
      const updateDoc: UpdateFilter<MongoDocument> = {
        $set: {
          updatedAt: new Date(),
        },
      };

      const setFields = updateDoc.$set as MongoDocument;

      for (const [key, value] of Object.entries(data)) {
        if (key === 'id' || key === 'createdAt') {
          continue;
        }
        setFields[key] = value;
      }

      const result = await this.getCollection('roles').findOneAndUpdate(
        { _id: roleId },
        updateDoc,
        { returnDocument: 'after' }
      );

      if (!result) {
        throw new InternalError({
          code: 'auth-mongo/update_failed',
          message: 'Failed to update role',
          severity: 'error',
          retryable: false,
        });
      }

      return this.mapRoleRecord(result);
    }, 'updateRole');
  }

  async deleteRole(roleId: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('roles').deleteOne({ _id: roleId });
    }, 'deleteRole');
  }

  async listRoles(orgId: string): Promise<RoleRecord[]> {
    return this.withRetry(async () => {
      const docs = await this.getCollection('roles')
        .find({ orgId })
        .sort({ createdAt: -1 })
        .toArray();
      return docs.map((doc) => this.mapRoleRecord(doc));
    }, 'listRoles');
  }

  async assignRoleToUser(userId: string, roleId: string, orgId: string): Promise<RoleRecord> {
    return this.withRetry(async () => {
      const id = generateId();

      const doc = {
        _id: id,
        userId,
        roleId,
        orgId,
        assignedAt: new Date(),
      };

      await this.getCollection('user_roles').insertOne(doc);

      const role = await this.getRole(roleId);
      if (!role) {
        throw new InternalError({
          code: 'auth-mongo/role_not_found',
          message: 'Role not found',
          severity: 'error',
          retryable: false,
          context: { roleId },
        });
      }
      return role;
    }, 'assignRoleToUser');
  }

  async revokeRoleFromUser(userId: string, roleId: string, orgId: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('user_roles').deleteOne({ userId, roleId, orgId });
    }, 'revokeRoleFromUser');
  }

  async getUserRoles(userId: string, orgId: string): Promise<RoleRecord[]> {
    return this.withRetry(async () => {
      const userRoles = await this.getCollection('user_roles').find({ userId, orgId }).toArray();

      const roleIds = userRoles.map((ur) => ur['roleId'] as string);
      const roles = await this.getCollection('roles')
        .find({ _id: { $in: roleIds as unknown as string[] } })
        .sort({ createdAt: -1 })
        .toArray();

      return roles.map((doc) => this.mapRoleRecord(doc));
    }, 'getUserRoles');
  }

  // SSO methods
  async createSSOProvider(data: MongoDocument): Promise<unknown> {
    return this.withRetry(async () => {
      const id = generateId();
      const now = new Date();

      const doc = {
        _id: id,
        type: data['type'],
        name: data['name'],
        orgId: data['orgId'] || null,
        metadataUrl: data['metadataUrl'] || data['metadata_url'] || null,
        clientId: data['clientId'] || data['client_id'] || null,
        clientSecret: data['clientSecret'] || data['client_secret'] || null,
        tokenEndpointAuthMethod:
          data['tokenEndpointAuthMethod'] || data['token_endpoint_auth_method'] || null,
        idpEntityId: data['idpEntityId'] || data['idp_entity_id'] || null,
        idpSsoUrl: data['idpSsoUrl'] || data['idp_sso_url'] || null,
        idpSloUrl: data['idpSloUrl'] || data['idp_slo_url'] || null,
        idpCertificate: data['idpCertificate'] || data['idp_certificate'] || null,
        spEntityId: data['spEntityId'] || data['sp_entity_id'] || null,
        spAcsUrl: data['spAcsUrl'] || data['sp_acs_url'] || null,
        spSloUrl: data['spSloUrl'] || data['sp_slo_url'] || null,
        signingCert: data['signingCert'] || data['signing_cert'] || null,
        signingKey: data['signingKey'] || data['signing_key'] || null,
        encryptionEnabled: data['encryptionEnabled'] || data['encryption_enabled'] || false,
        forceAuthn: data['forceAuthn'] || data['force_authn'] || false,
        scopes: data['scopes'] || [],
        redirectUris: data['redirectUris'] || data['redirect_uris'] || [],
        claimMapping: data['claimMapping'] || data['claim_mapping'] || {},
        attributeMapping: data['attributeMapping'] || data['attribute_mapping'] || {},
        metadata: data['metadata'] || {},
        createdAt: now,
        updatedAt: now,
      };

      await this.getCollection('sso_providers').insertOne(doc);
      return this.mapSSOProviderRecord(doc);
    }, 'createSSOProvider');
  }

  async getSSOProvider(providerId: string): Promise<unknown | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('sso_providers').findOne({ _id: providerId });
      return doc ? this.mapSSOProviderRecord(doc) : null;
    }, 'getSSOProvider');
  }

  async updateSSOProvider(providerId: string, data: Partial<unknown>): Promise<unknown> {
    return this.withRetry(async () => {
      const updateDoc: UpdateFilter<MongoDocument> = {
        $set: {
          updatedAt: new Date(),
        },
      };

      const setFields = updateDoc.$set as MongoDocument;

      for (const [key, value] of Object.entries(data)) {
        if (key === 'id' || key === 'createdAt') {
          continue;
        }
        setFields[key] = value;
      }

      const result = await this.getCollection('sso_providers').findOneAndUpdate(
        { _id: providerId },
        updateDoc,
        { returnDocument: 'after' }
      );

      if (!result) {
        throw new InternalError({
          code: 'auth-mongo/update_failed',
          message: 'Failed to update SSO provider',
          severity: 'error',
          retryable: false,
        });
      }

      return this.mapSSOProviderRecord(result);
    }, 'updateSSOProvider');
  }

  async deleteSSOProvider(providerId: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('sso_providers').deleteOne({ _id: providerId });
    }, 'deleteSSOProvider');
  }

  async listSSOProviders(orgId?: string): Promise<unknown[]> {
    return this.withRetry(async () => {
      const filter: Filter<MongoDocument> = {};
      if (orgId) {
        filter.$or = [{ orgId }, { orgId: null }];
      }

      const docs = await this.getCollection('sso_providers')
        .find(filter)
        .sort({ createdAt: -1 })
        .toArray();

      return docs.map((doc) => this.mapSSOProviderRecord(doc));
    }, 'listSSOProviders');
  }

  async createSSOLink(data: Omit<SSOLink, 'id' | 'linkedAt'>): Promise<SSOLink> {
    return this.withRetry(async () => {
      const id = generateId();

      const doc = {
        _id: id,
        userId: data.userId,
        providerId: data.providerId,
        providerType: data.providerType,
        providerSubject: data.providerSubject,
        providerEmail: data.providerEmail || null,
        autoProvisioned: data.autoProvisioned || false,
        metadata: data.metadata || {},
        linkedAt: new Date(),
        lastAuthAt: data.lastAuthAt || new Date(),
      };

      await this.getCollection('sso_links').insertOne(doc);
      return this.mapSSOLinkRecord(doc);
    }, 'createSSOLink');
  }

  async getSSOLink(linkId: string): Promise<SSOLink | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('sso_links').findOne({ _id: linkId });
      return doc ? this.mapSSOLinkRecord(doc) : null;
    }, 'getSSOLink');
  }

  async getUserSSOLinks(userId: string): Promise<SSOLink[]> {
    return this.withRetry(async () => {
      const docs = await this.getCollection('sso_links')
        .find({ userId })
        .sort({ linkedAt: -1 })
        .toArray();
      return docs.map((doc) => this.mapSSOLinkRecord(doc));
    }, 'getUserSSOLinks');
  }

  async deleteSSOLink(linkId: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('sso_links').deleteOne({ _id: linkId });
    }, 'deleteSSOLink');
  }

  async createSSOSession(data: Omit<SSOSession, 'id' | 'linkedAt'>): Promise<SSOSession> {
    return this.withRetry(async () => {
      const id = generateId();

      const doc = {
        _id: id,
        userId: data.userId,
        providerId: data.providerId,
        providerType: data.providerType,
        providerSubject: data.providerSubject,
        sessionToken: data.sessionToken || null,
        expiresAt: data.expiresAt,
        linkedAt: new Date(),
        lastAuthAt: data.lastAuthAt || new Date(),
      };

      await this.getCollection('sso_sessions').insertOne(doc);
      return this.mapSSOSessionRecord(doc);
    }, 'createSSOSession');
  }

  async getSSOSession(sessionId: string): Promise<SSOSession | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('sso_sessions').findOne({ _id: sessionId });
      return doc ? this.mapSSOSessionRecord(doc) : null;
    }, 'getSSOSession');
  }

  // 2FA methods
  async createTwoFactorDevice(
    data: Omit<TwoFactorDevice, 'id' | 'createdAt'>
  ): Promise<TwoFactorDevice> {
    return this.withRetry(async () => {
      const id = generateId();
      const now = new Date();

      const doc = {
        _id: id,
        userId: data.userId,
        method: data.method,
        name: data.name || null,
        verified: data.verified || false,
        phoneNumber: data.phoneNumber || null,
        secret: data.secret || null,
        lastUsedAt: null,
        metadata: data.metadata || {},
        createdAt: now,
        updatedAt: now,
      };

      await this.getCollection('twofa_devices').insertOne(doc);
      return this.mapTwoFactorDeviceRecord(doc);
    }, 'createTwoFactorDevice');
  }

  async getTwoFactorDevice(deviceId: string): Promise<TwoFactorDevice | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('twofa_devices').findOne({ _id: deviceId });
      return doc ? this.mapTwoFactorDeviceRecord(doc) : null;
    }, 'getTwoFactorDevice');
  }

  async listTwoFactorDevices(userId: string): Promise<TwoFactorDevice[]> {
    return this.withRetry(async () => {
      const docs = await this.getCollection('twofa_devices')
        .find({ userId })
        .sort({ createdAt: -1 })
        .toArray();
      return docs.map((doc) => this.mapTwoFactorDeviceRecord(doc));
    }, 'listTwoFactorDevices');
  }

  async updateTwoFactorDevice(
    deviceId: string,
    data: Partial<TwoFactorDevice>
  ): Promise<TwoFactorDevice> {
    return this.withRetry(async () => {
      const updateDoc: UpdateFilter<MongoDocument> = {
        $set: {
          updatedAt: new Date(),
        },
      };

      const setFields = updateDoc.$set as MongoDocument;

      for (const [key, value] of Object.entries(data)) {
        if (key === 'id' || key === 'createdAt') {
          continue;
        }
        setFields[key] = value;
      }

      const result = await this.getCollection('twofa_devices').findOneAndUpdate(
        { _id: deviceId },
        updateDoc,
        { returnDocument: 'after' }
      );

      if (!result) {
        throw new InternalError({
          code: 'auth-mongo/update_failed',
          message: 'Failed to update two-factor device',
          severity: 'error',
          retryable: false,
        });
      }

      return this.mapTwoFactorDeviceRecord(result);
    }, 'updateTwoFactorDevice');
  }

  async deleteTwoFactorDevice(deviceId: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('twofa_devices').deleteOne({ _id: deviceId });
    }, 'deleteTwoFactorDevice');
  }

  async createBackupCodes(userId: string, codes: BackupCode[]): Promise<BackupCode[]> {
    return this.withRetry(async () => {
      const createdCodes: BackupCode[] = [];

      for (const codeData of codes) {
        const id = generateId();
        const codeValue = typeof codeData === 'string' ? codeData : codeData['code'] || '';

        const doc = {
          _id: id,
          userId,
          code: codeValue,
          used: false,
          usedAt: null,
          createdAt: new Date(),
        };

        await this.getCollection('twofa_backup_codes').insertOne(doc);
        createdCodes.push(this.mapBackupCodeRecord(doc));
      }

      return createdCodes;
    }, 'createBackupCodes');
  }

  async getBackupCodes(userId: string): Promise<BackupCode[]> {
    return this.withRetry(async () => {
      const docs = await this.getCollection('twofa_backup_codes')
        .find({ userId })
        .sort({ createdAt: -1 })
        .toArray();
      return docs.map((doc) => this.mapBackupCodeRecord(doc));
    }, 'getBackupCodes');
  }

  async markBackupCodeUsed(codeId: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('twofa_backup_codes').updateOne(
        { _id: codeId },
        { $set: { used: true, usedAt: new Date() } }
      );
    }, 'markBackupCodeUsed');
  }

  async createTwoFactorSession(data: TwoFactorSession): Promise<TwoFactorSession> {
    return this.withRetry(async () => {
      const id = generateId();

      const doc = {
        _id: id,
        userId: data.userId,
        sessionId: data.sessionId,
        deviceId: data.deviceId,
        method: data.method,
        verificationCode: data.verificationCode || null,
        attemptCount: data.attemptCount || 0,
        maxAttempts: data.maxAttempts || 5,
        expiresAt: data.expiresAt,
        completedAt: null,
        createdAt: new Date(),
      };

      await this.getCollection('twofa_sessions').insertOne(doc);
      return this.mapTwoFactorSessionRecord(doc);
    }, 'createTwoFactorSession');
  }

  async getTwoFactorSession(sessionId: string): Promise<TwoFactorSession | null> {
    return this.withRetry(async () => {
      const doc = await this.getCollection('twofa_sessions').findOne({ _id: sessionId });
      return doc ? this.mapTwoFactorSessionRecord(doc) : null;
    }, 'getTwoFactorSession');
  }

  async completeTwoFactorSession(sessionId: string): Promise<void> {
    return this.withRetry(async () => {
      await this.getCollection('twofa_sessions').updateOne(
        { _id: sessionId },
        { $set: { completedAt: new Date() } }
      );
    }, 'completeTwoFactorSession');
  }

  // Helper mapping methods
  private mapApiKeyRecord(doc: MongoDocument): ApiKeyRecord {
    const result: ApiKeyRecord = {
      id: doc['_id'] as string,
      principalId: doc['principalId'] as string,
      hash: doc['hash'] as string,
      prefix: doc['prefix'] as string,
      lastFour: doc['lastFour'] as string,
      scopes: (doc['scopes'] as string[]) || [],
      metadata: (doc['metadata'] as Record<string, string>) || {},
      createdAt: new Date(doc['createdAt'] as Date),
      updatedAt: new Date(doc['updatedAt'] as Date),
    } as ApiKeyRecord;
    if (doc['expiresAt']) {
      result.expiresAt = new Date(doc['expiresAt'] as Date);
    }
    return result;
  }

  private mapSessionRecord(doc: MongoDocument): SessionRecord {
    const result: SessionRecord = {
      id: doc['_id'] as string,
      userId: doc['userId'] as string,
      entitlements: (doc['entitlements'] as string[]) || [],
      expiresAt: new Date(doc['expiresAt'] as Date),
      metadata: (doc['metadata'] as Record<string, unknown>) || {},
      createdAt: new Date(doc['createdAt'] as Date),
      updatedAt: new Date(doc['updatedAt'] as Date),
    } as SessionRecord;
    if (doc['orgId']) {
      result.orgId = doc['orgId'] as string;
    }
    if (doc['plan']) {
      result.plan = doc['plan'] as string;
    }
    return result;
  }

  private mapOrganizationRecord(doc: MongoDocument): OrganizationRecord {
    return {
      id: doc['_id'] as string,
      name: doc['name'] as string,
      plan: doc['plan'] as string,
      seats: doc['seats'] as number,
      members: (doc['members'] || []) as OrganizationMember[],
      metadata: (doc['metadata'] as Record<string, unknown>) || {},
      createdAt: new Date(doc['createdAt'] as Date),
      updatedAt: new Date(doc['updatedAt'] as Date),
    };
  }

  private mapUserRecord(doc: MongoDocument): UserRecord {
    const result: UserRecord = {
      id: doc['_id'] as string,
      entitlements: (doc['entitlements'] as string[]) || [],
      oauth: (doc['oauth'] || {}) as Record<string, OAuthLink>,
      metadata: (doc['metadata'] as Record<string, unknown>) || {},
      createdAt: new Date(doc['createdAt'] as Date),
      updatedAt: new Date(doc['updatedAt'] as Date),
    } as UserRecord;
    if (doc['email']) {
      result.email = doc['email'] as string;
    }
    if (doc['name']) {
      result.name = doc['name'] as string;
    }
    if (doc['picture']) {
      result.picture = doc['picture'] as string;
    }
    if (doc['plan']) {
      result.plan = doc['plan'] as string;
    }
    return result;
  }

  private mapEmailVerificationToken(doc: MongoDocument): EmailVerificationToken {
    const result: EmailVerificationToken = {
      id: doc['_id'] as string,
      email: doc['email'] as string,
      code: doc['code'] as string,
      codeHash: doc['codeHash'] as string,
      type: doc['type'] as EmailVerificationToken['type'],
      metadata: (doc['metadata'] as Record<string, unknown>) || {},
      expiresAt: new Date(doc['expiresAt'] as Date),
      createdAt: new Date(doc['createdAt'] as Date),
    } as EmailVerificationToken;
    if (doc['userId']) {
      result.userId = doc['userId'] as string;
    }
    if (doc['usedAt']) {
      result.usedAt = new Date(doc['usedAt'] as Date);
    }
    return result;
  }

  private mapRoleRecord(doc: MongoDocument): RoleRecord {
    return {
      id: doc['_id'] as string,
      orgId: doc['orgId'] as string,
      name: doc['name'] as string,
      description: doc['description'] as string,
      isSystem: doc['isSystem'] as boolean,
      permissions: ((doc['permissions'] || []) as unknown[]).map((p) => p as Permission),
      metadata: (doc['metadata'] as Record<string, unknown>) || {},
      createdAt: doc['createdAt'] as Date,
      updatedAt: doc['updatedAt'] as Date,
    };
  }

  private mapSSOProviderRecord(doc: MongoDocument): unknown {
    return {
      id: doc['_id'] as string,
      type: doc['type'] as SSOProviderType,
      name: doc['name'] as string,
      orgId: doc['orgId'] as string,
      metadataUrl: doc['metadataUrl'] as string,
      clientId: doc['clientId'] as string,
      clientSecret: doc['clientSecret'] as string,
      tokenEndpointAuthMethod: doc['tokenEndpointAuthMethod'] as string,
      idpEntityId: doc['idpEntityId'] as string,
      idpSsoUrl: doc['idpSsoUrl'] as string,
      idpSloUrl: doc['idpSloUrl'] as string,
      idpCertificate: doc['idpCertificate'] as string,
      spEntityId: doc['spEntityId'] as string,
      spAcsUrl: doc['spAcsUrl'] as string,
      spSloUrl: doc['spSloUrl'] as string,
      signingCert: doc['signingCert'] as string,
      signingKey: doc['signingKey'] as string,
      encryptionEnabled: doc['encryptionEnabled'] as boolean,
      forceAuthn: doc['forceAuthn'] as boolean,
      scopes: (doc['scopes'] as string[]) || [],
      redirectUris: (doc['redirectUris'] as string[]) || [],
      claimMapping: (doc['claimMapping'] as Record<string, unknown>) || {},
      attributeMapping: (doc['attributeMapping'] as Record<string, unknown>) || {},
      metadata: (doc['metadata'] as Record<string, unknown>) || {},
      createdAt: doc['createdAt'] as Date,
      updatedAt: doc['updatedAt'] as Date,
    };
  }

  private mapSSOLinkRecord(doc: MongoDocument): SSOLink {
    return {
      id: doc['_id'] as string,
      userId: doc['userId'] as string,
      providerId: doc['providerId'] as string,
      providerType: doc['providerType'] as SSOProviderType,
      providerSubject: doc['providerSubject'] as string,
      providerEmail: doc['providerEmail'] as string,
      autoProvisioned: doc['autoProvisioned'] as boolean,
      metadata: (doc['metadata'] as Record<string, unknown>) || {},
      linkedAt: doc['linkedAt'] as Date,
      lastAuthAt: doc['lastAuthAt'] as Date,
    };
  }

  private mapSSOSessionRecord(doc: MongoDocument): SSOSession {
    return {
      id: doc['_id'] as string,
      userId: doc['userId'] as string,
      providerId: doc['providerId'] as string,
      providerType: doc['providerType'] as SSOProviderType,
      providerSubject: doc['providerSubject'] as string,
      sessionToken: doc['sessionToken'] as string,
      expiresAt: doc['expiresAt'] as Date,
      linkedAt: doc['linkedAt'] as Date,
      lastAuthAt: doc['lastAuthAt'] as Date,
    };
  }

  private mapTwoFactorDeviceRecord(doc: MongoDocument): TwoFactorDevice {
    return {
      id: doc['_id'] as string,
      userId: doc['userId'] as string,
      method: doc['method'] as TwoFactorMethod,
      name: doc['name'] as string,
      verified: doc['verified'] as boolean,
      phoneNumber: doc['phoneNumber'] as string,
      secret: doc['secret'] as string,
      lastUsedAt: doc['lastUsedAt'] as Date,
      metadata: (doc['metadata'] as Record<string, unknown>) || {},
      createdAt: doc['createdAt'] as Date,
      updatedAt: doc['updatedAt'] as Date,
    };
  }

  private mapBackupCodeRecord(doc: MongoDocument): BackupCode {
    return {
      id: doc['_id'] as string,
      userId: doc['userId'] as string,
      code: doc['code'] as string,
      used: doc['used'] as boolean,
      usedAt: doc['usedAt'] as Date,
      createdAt: doc['createdAt'] as Date,
    };
  }

  private mapTwoFactorSessionRecord(doc: MongoDocument): TwoFactorSession {
    return {
      id: doc['_id'] as string,
      userId: doc['userId'] as string,
      sessionId: doc['sessionId'] as string,
      deviceId: doc['deviceId'] as string,
      method: doc['method'] as TwoFactorMethod,
      verificationCode: doc['verificationCode'] as string,
      attemptCount: doc['attemptCount'] as number,
      maxAttempts: doc['maxAttempts'] as number,
      expiresAt: doc['expiresAt'] as Date,
      completedAt: doc['completedAt'] as Date,
      createdAt: doc['createdAt'] as Date,
    };
  }
}
