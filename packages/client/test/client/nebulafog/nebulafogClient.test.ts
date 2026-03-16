import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReadResourceResult } from '@modelcontextprotocol/core';
import { CONFIDENTIAL_RESOURCE_META_KEY } from '@modelcontextprotocol/core';
import { KeyStore } from '../../../../server/src/nebulafog/keyStore.js';
import { encryptResource } from '../../../src/nebulafog/crypto.js';
import { NebulafogClient } from '../../../src/nebulafog/nebulafogClient.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async function generateAgentKeyPair(): Promise<CryptoKeyPair> {
  return globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  );
}

interface TestContext {
  agentKeyPair: CryptoKeyPair;
  keyStore: KeyStore;
  resourceId: string;
  plaintext: string;
  ciphertext: string;
  wrappedDek: string;
  capabilityToken: string;
  keyRetrievalUri: string;
}

async function buildTestContext(): Promise<TestContext> {
  const agentKeyPair = await generateAgentKeyPair();
  const keyStore = new KeyStore();
  const resourceId = '550e8400-e29b-41d4-a716-446655440000';
  const plaintext = 'secret data: classified!';

  // Encrypt plaintext with server keyStore
  const ciphertext = await keyStore.encryptResource(resourceId, plaintext);

  // Approve the agent and get a wrappedDek
  const publicKeyJwk = await globalThis.crypto.subtle.exportKey('jwk', agentKeyPair.publicKey);
  const { wrappedDek, capabilityToken } = await keyStore.approveAgent(
    resourceId,
    'test-agent',
    publicKeyJwk,
  );

  const keyRetrievalUri = `http://localhost:3000/nebulafog/keys/${capabilityToken}`;

  return {
    agentKeyPair,
    keyStore,
    resourceId,
    plaintext,
    ciphertext,
    wrappedDek,
    capabilityToken,
    keyRetrievalUri,
  };
}

/**
 * Build a ReadResourceResult simulating an authorized ConfidentialResource response.
 */
function makeAuthorizedResult(
  resourceId: string,
  ciphertext: string,
  keyRetrievalUri: string,
): ReadResourceResult {
  return {
    contents: [],
    _meta: {
      [CONFIDENTIAL_RESOURCE_META_KEY]: {
        encryptedContents: ciphertext,
        keyRetrievalUri,
        algorithm: 'AES-256-GCM',
        resourceId,
      },
    },
  };
}

/**
 * Build a ReadResourceResult simulating an UNAUTHORIZED ConfidentialResource response
 * (no keyRetrievalUri — agent is not approved).
 */
function makeUnauthorizedResult(resourceId: string, ciphertext: string): ReadResourceResult {
  return {
    contents: [],
    _meta: {
      [CONFIDENTIAL_RESOURCE_META_KEY]: {
        encryptedContents: ciphertext,
        algorithm: 'AES-256-GCM',
        resourceId,
        // keyRetrievalUri intentionally absent
      },
    },
  };
}

/** Build a plain (non-confidential) ReadResourceResult. */
function makePlainResult(uri: string, text: string): ReadResourceResult {
  return {
    contents: [{ uri, text, mimeType: 'text/plain' }],
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('NebulafogClient', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    globalThis.fetch = fetchMock;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('CLIENT-01: readResource decryption', () => {
    it('readResource decrypts confidential resource using DEK from server', async () => {
      const ctx = await buildTestContext();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'test-agent',
        agentName: 'Test Agent',
        keyPair: ctx.agentKeyPair,
      });

      // Spy on the internal client's readResource (no connect() call needed)
      const mockReadResource = vi
        .fn()
        .mockResolvedValue(
          makeAuthorizedResult(ctx.resourceId, ctx.ciphertext, ctx.keyRetrievalUri),
        );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.readResource = mockReadResource;

      // Mock: DEK fetch from key retrieval endpoint
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ wrappedDek: ctx.wrappedDek }),
      });

      const result = await client.readResource({ uri: 'nebulafog://resource/test' });

      expect(result.contents).toHaveLength(1);
      expect(result.contents[0]).toMatchObject({
        uri: 'nebulafog://resource/test',
        text: ctx.plaintext,
      });
    });

    it('readResource returns raw resource when no keyRetrievalUri in _meta', async () => {
      const ctx = await buildTestContext();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'test-agent',
        agentName: 'Test Agent',
        keyPair: ctx.agentKeyPair,
      });

      const rawResult = makeUnauthorizedResult(ctx.resourceId, ctx.ciphertext);
      const mockReadResource = vi.fn().mockResolvedValue(rawResult);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.readResource = mockReadResource;

      const result = await client.readResource({ uri: 'nebulafog://resource/test' });

      // Must return raw result unchanged — no fetch for DEK
      expect(result).toBe(rawResult);
      // DEK fetch must NOT have been called (fetch mock was never configured)
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('readResource returns raw result when no ConfidentialResource meta present', async () => {
      const agentKeyPair = await generateAgentKeyPair();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'test-agent',
        agentName: 'Test Agent',
        keyPair: agentKeyPair,
      });

      const plainResult = makePlainResult('file://test.txt', 'hello world');
      const mockReadResource = vi.fn().mockResolvedValue(plainResult);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.readResource = mockReadResource;

      const result = await client.readResource({ uri: 'file://test.txt' });

      expect(result).toBe(plainResult);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('readResource retries with fresh DEK on GCM failure (evict + re-fetch)', async () => {
      const ctx = await buildTestContext();

      // Build a second rotated wrappedDek for same resource (simulates DEK rotation)
      const publicKeyJwk = await globalThis.crypto.subtle.exportKey('jwk', ctx.agentKeyPair.publicKey);
      const keyStore2 = new KeyStore();
      await keyStore2.encryptResource(ctx.resourceId, ctx.plaintext);
      const { wrappedDek: rotatedWrappedDek } = await keyStore2.approveAgent(
        ctx.resourceId,
        'test-agent',
        publicKeyJwk,
      );
      // Also re-encrypt with the new DEK to get a valid ciphertext
      const newCiphertext = await keyStore2.encryptResource(ctx.resourceId, ctx.plaintext);

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'test-agent',
        agentName: 'Test Agent',
        keyPair: ctx.agentKeyPair,
      });

      // The server returns ciphertext encrypted with key2 but keyRetrievalUri points to original token
      const mockReadResource = vi
        .fn()
        .mockResolvedValue(
          makeAuthorizedResult(ctx.resourceId, newCiphertext, ctx.keyRetrievalUri),
        );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.readResource = mockReadResource;

      // First fetch returns the ORIGINAL wrappedDek (stale — wrong DEK for newCiphertext)
      // Second fetch returns the rotated one (after evict)
      fetchMock
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ wrappedDek: ctx.wrappedDek }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ wrappedDek: rotatedWrappedDek }),
        });

      // Should succeed after retry (second DEK matches newCiphertext)
      const result = await client.readResource({ uri: 'nebulafog://resource/test' });
      expect(result.contents).toHaveLength(1);
      expect(result.contents[0]).toMatchObject({ text: ctx.plaintext });
      // Fetch was called twice (initial + retry after evict)
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });

  describe('CLIENT-02: re-encryption on sampling', () => {
    it('sampling re-encrypts resource when output is tainted by confidential source', async () => {
      const ctx = await buildTestContext();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'test-agent',
        agentName: 'Test Agent',
        keyPair: ctx.agentKeyPair,
      });

      // Simulate a readResource call to taint the session
      const mockReadResource = vi
        .fn()
        .mockResolvedValue(
          makeAuthorizedResult(ctx.resourceId, ctx.ciphertext, ctx.keyRetrievalUri),
        );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.readResource = mockReadResource;

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ wrappedDek: ctx.wrappedDek }),
      });

      // Perform readResource to taint the session
      await client.readResource({ uri: 'nebulafog://resource/test' });

      // Register a sampling handler
      let capturedSamplingRequest: unknown = null;
      let samplingHandlerResult: unknown = null;
      const userSamplingHandler = vi.fn().mockImplementation(async () => ({
        role: 'assistant' as const,
        content: { type: 'text' as const, text: `Answer using: ${ctx.plaintext}` },
        model: 'test-model',
      }));

      client.setSamplingHandler(userSamplingHandler);

      // Retrieve the registered handler from the internal client
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const internalClient = (client as any)._client;
      const registeredHandlers = internalClient._requestHandlers;
      const samplingHandler = registeredHandlers?.get('sampling/createMessage');
      expect(samplingHandler).toBeDefined();

      // Simulate a sampling request arriving
      const fakeRequest = {
        method: 'sampling/createMessage',
        params: {
          messages: [],
          maxTokens: 100,
        },
      };

      samplingHandlerResult = await samplingHandler(fakeRequest, {});
      capturedSamplingRequest = fakeRequest;

      // The result must be re-encrypted
      expect(samplingHandlerResult).toBeDefined();
      expect(capturedSamplingRequest).toBeDefined();
      const result = samplingHandlerResult as {
        role: string;
        content: { type: string; text: string };
        model: string;
      };

      // Content should contain ConfidentialResource meta (as JSON text)
      const content = JSON.parse(result.content.text) as {
        _meta: Record<string, unknown>;
      };
      const meta = content._meta[CONFIDENTIAL_RESOURCE_META_KEY] as {
        encryptedContents: string;
        keyRetrievalUri: string;
        algorithm: string;
        resourceId: string;
      };

      expect(meta).toMatchObject({
        algorithm: 'AES-256-GCM',
        resourceId: ctx.resourceId,
        keyRetrievalUri: ctx.keyRetrievalUri,
      });
      expect(meta.encryptedContents).toBeDefined();
      expect(typeof meta.encryptedContents).toBe('string');
    });

    it('sampling does not re-encrypt when output is clean (no confidential source)', async () => {
      const agentKeyPair = await generateAgentKeyPair();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'test-agent',
        agentName: 'Test Agent',
        keyPair: agentKeyPair,
      });

      const userSamplingHandler = vi.fn().mockResolvedValue({
        role: 'assistant' as const,
        content: { type: 'text' as const, text: 'plain answer' },
        model: 'test-model',
      });

      client.setSamplingHandler(userSamplingHandler);

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const internalClient = (client as any)._client;
      const registeredHandlers = internalClient._requestHandlers;
      const samplingHandler = registeredHandlers?.get('sampling/createMessage');

      const result = await samplingHandler(
        { method: 'sampling/createMessage', params: { messages: [], maxTokens: 100 } },
        {},
      );

      // No taint — result must be passed through unchanged
      expect(result).toMatchObject({
        role: 'assistant',
        content: { type: 'text', text: 'plain answer' },
        model: 'test-model',
      });
    });

    it('re-encrypted sampling output uses ConfidentialResource _meta schema', async () => {
      const ctx = await buildTestContext();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'test-agent',
        agentName: 'Test Agent',
        keyPair: ctx.agentKeyPair,
      });

      const mockReadResource = vi
        .fn()
        .mockResolvedValue(
          makeAuthorizedResult(ctx.resourceId, ctx.ciphertext, ctx.keyRetrievalUri),
        );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.readResource = mockReadResource;

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ wrappedDek: ctx.wrappedDek }),
      });

      await client.readResource({ uri: 'nebulafog://resource/test' });

      client.setSamplingHandler(async () => ({
        role: 'assistant' as const,
        content: { type: 'text' as const, text: `Uses secret: ${ctx.plaintext}` },
        model: 'test-model',
      }));

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const samplingHandler = (client as any)._client._requestHandlers?.get('sampling/createMessage');
      const result = await samplingHandler(
        { method: 'sampling/createMessage', params: { messages: [], maxTokens: 100 } },
        {},
      );

      const parsed = JSON.parse(result.content.text) as {
        _meta: Record<string, unknown>;
      };
      const meta = parsed._meta[CONFIDENTIAL_RESOURCE_META_KEY] as Record<string, unknown>;

      // All four required fields must be present
      expect(meta).toHaveProperty('encryptedContents');
      expect(meta).toHaveProperty('keyRetrievalUri');
      expect(meta).toHaveProperty('algorithm', 'AES-256-GCM');
      expect(meta).toHaveProperty('resourceId', ctx.resourceId);
    });
  });

  describe('CLIENT-03: DEK caching', () => {
    it('cache hit skips key fetch — second readResource call does not call keys endpoint', async () => {
      const ctx = await buildTestContext();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'test-agent',
        agentName: 'Test Agent',
        keyPair: ctx.agentKeyPair,
      });

      const mockReadResource = vi
        .fn()
        .mockResolvedValue(
          makeAuthorizedResult(ctx.resourceId, ctx.ciphertext, ctx.keyRetrievalUri),
        );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.readResource = mockReadResource;

      // Only one DEK fetch should be made
      fetchMock.mockResolvedValue({
        ok: true,
        json: async () => ({ wrappedDek: ctx.wrappedDek }),
      });

      // Call readResource twice for the same resource
      await client.readResource({ uri: 'nebulafog://resource/test' });
      await client.readResource({ uri: 'nebulafog://resource/test' });

      // fetch for DEK must have been called exactly once
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('first fetch calls keys endpoint exactly once per resource', async () => {
      // Prepare TWO separate resources
      const ctx1 = await buildTestContext();
      const keyStore2 = new KeyStore();
      const resourceId2 = '550e8400-e29b-41d4-a716-446655440001';
      const plaintext2 = 'second secret resource';
      const ciphertext2 = await keyStore2.encryptResource(resourceId2, plaintext2);
      const publicKeyJwk = await globalThis.crypto.subtle.exportKey(
        'jwk',
        ctx1.agentKeyPair.publicKey,
      );
      const { wrappedDek: wrappedDek2, capabilityToken: token2 } = await keyStore2.approveAgent(
        resourceId2,
        'test-agent',
        publicKeyJwk,
      );
      const keyRetrievalUri2 = `http://localhost:3000/nebulafog/keys/${token2}`;

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'test-agent',
        agentName: 'Test Agent',
        keyPair: ctx1.agentKeyPair,
      });

      const mockReadResource = vi
        .fn()
        .mockResolvedValueOnce(
          makeAuthorizedResult(ctx1.resourceId, ctx1.ciphertext, ctx1.keyRetrievalUri),
        )
        .mockResolvedValueOnce(makeAuthorizedResult(resourceId2, ciphertext2, keyRetrievalUri2));
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.readResource = mockReadResource;

      fetchMock
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ wrappedDek: ctx1.wrappedDek }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ wrappedDek: wrappedDek2 }),
        });

      await client.readResource({ uri: 'nebulafog://resource/1' });
      await client.readResource({ uri: 'nebulafog://resource/2' });

      // Two separate DEK fetches — one per resource
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });
  });

  describe('connect() and getApprovalStatus()', () => {
    it('connect() calls POST /nebulafog/register with agentId, name, publicKey JWK', async () => {
      const agentKeyPair = await generateAgentKeyPair();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'my-agent-id',
        agentName: 'My Agent',
        keyPair: agentKeyPair,
      });

      // Mock register 201
      fetchMock.mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({}) });
      // Mock MCP connect (transport.start)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.connect = vi.fn().mockResolvedValue(undefined);

      await client.connect();

      // Check register was called
      expect(fetchMock).toHaveBeenCalledOnce();
      const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
      expect(url).toBe('http://localhost:3000/nebulafog/register');
      expect(init.method).toBe('POST');
      const body = JSON.parse(init.body as string) as {
        agentId: string;
        name: string;
        publicKey: JsonWebKey;
      };
      expect(body.agentId).toBe('my-agent-id');
      expect(body.name).toBe('My Agent');
      expect(body.publicKey).toMatchObject({ kty: 'EC', crv: 'P-256' });
    });

    it('connect() treats 409 from register as success (idempotent)', async () => {
      const agentKeyPair = await generateAgentKeyPair();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'existing-agent',
        agentName: 'Existing Agent',
        keyPair: agentKeyPair,
      });

      // Mock register returning 409 (already registered)
      fetchMock.mockResolvedValueOnce({ ok: false, status: 409, json: async () => ({}) });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (client as any)._client.connect = vi.fn().mockResolvedValue(undefined);

      // Must not throw
      await expect(client.connect()).resolves.not.toThrow();
    });

    it('getApprovalStatus() calls GET /nebulafog/agents/:agentId/status and returns status', async () => {
      const agentKeyPair = await generateAgentKeyPair();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'status-agent',
        agentName: 'Status Agent',
        keyPair: agentKeyPair,
      });

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: 'approved' }),
      });

      const status = await client.getApprovalStatus();

      expect(fetchMock).toHaveBeenCalledOnce();
      expect(fetchMock.mock.calls[0][0]).toBe(
        'http://localhost:3000/nebulafog/agents/status-agent/status',
      );
      expect(status).toBe('approved');
    });

    it('getApprovalStatus() throws on 404 (agent not registered)', async () => {
      const agentKeyPair = await generateAgentKeyPair();

      const client = new NebulafogClient({
        serverUrl: 'http://localhost:3000',
        agentId: 'unregistered-agent',
        agentName: 'Unregistered Agent',
        keyPair: agentKeyPair,
      });

      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({}),
      });

      await expect(client.getApprovalStatus()).rejects.toThrow();
    });
  });
});
