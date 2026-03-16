import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KeyStore } from '../../../../server/src/nebulafog/keyStore.js';
import { DekCache } from '../../../src/nebulafog/dekCache.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Generate a fresh P-256 key pair for agent identity. */
async function generateAgentKeyPair(): Promise<CryptoKeyPair> {
  return globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  );
}

/**
 * Build a realistic wrappedDek by going through KeyStore.approveAgent.
 * Returns { wrappedDek: string } matching the key retrieval endpoint response.
 */
async function buildWrappedDek(
  agentKeyPair: CryptoKeyPair,
): Promise<{ wrappedDek: string; publicKeyJwk: JsonWebKey }> {
  const keyStore = new KeyStore();
  const publicKeyJwk = await globalThis.crypto.subtle.exportKey('jwk', agentKeyPair.publicKey);
  const { wrappedDek } = await keyStore.approveAgent('res-001', 'agent-test', publicKeyJwk);
  return { wrappedDek, publicKeyJwk };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DekCache', () => {
  let agentKeyPair: CryptoKeyPair;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    agentKeyPair = await generateAgentKeyPair();
    fetchMock = vi.fn();
    globalThis.fetch = fetchMock;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('cache miss triggers fetch from keys endpoint', async () => {
    const { wrappedDek } = await buildWrappedDek(agentKeyPair);
    const keyRetrievalUri = 'http://localhost:3000/nebulafog/keys/test-token-001';

    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ wrappedDek }),
    });

    const cache = new DekCache(agentKeyPair.privateKey);
    const dek = await cache.getOrFetch('res-001', keyRetrievalUri);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(keyRetrievalUri);
    expect(dek).toBeDefined();
    // Verify it's a usable CryptoKey by checking type
    expect(dek.type).toBe('secret');
    expect(dek.algorithm).toMatchObject({ name: 'AES-GCM' });
  });

  it('cache hit returns DEK without calling keys endpoint again', async () => {
    const { wrappedDek } = await buildWrappedDek(agentKeyPair);
    const keyRetrievalUri = 'http://localhost:3000/nebulafog/keys/test-token-002';

    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ wrappedDek }),
    });

    const cache = new DekCache(agentKeyPair.privateKey);
    const dek1 = await cache.getOrFetch('res-002', keyRetrievalUri);
    const dek2 = await cache.getOrFetch('res-002', keyRetrievalUri);

    // fetch must have been called exactly once (second call hits cache)
    expect(fetchMock).toHaveBeenCalledTimes(1);
    // Both calls return the same CryptoKey reference
    expect(dek1).toBe(dek2);
  });

  it('evict clears entry so next access re-fetches', async () => {
    const { wrappedDek } = await buildWrappedDek(agentKeyPair);
    const keyRetrievalUri = 'http://localhost:3000/nebulafog/keys/test-token-003';

    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ wrappedDek }),
    });

    const cache = new DekCache(agentKeyPair.privateKey);
    await cache.getOrFetch('res-003', keyRetrievalUri);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // Evict — next getOrFetch must call fetch again
    cache.evict('res-003');
    await cache.getOrFetch('res-003', keyRetrievalUri);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('getKeyRetrievalUri returns URI used for last fetch for that resourceId', async () => {
    const { wrappedDek } = await buildWrappedDek(agentKeyPair);
    const keyRetrievalUri = 'http://localhost:3000/nebulafog/keys/test-token-004';

    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ wrappedDek }),
    });

    const cache = new DekCache(agentKeyPair.privateKey);
    expect(cache.getKeyRetrievalUri('res-004')).toBeUndefined();

    await cache.getOrFetch('res-004', keyRetrievalUri);

    expect(cache.getKeyRetrievalUri('res-004')).toBe(keyRetrievalUri);
  });

  it('getCached returns undefined for unknown resourceId', () => {
    const cache = new DekCache(agentKeyPair.privateKey);
    expect(cache.getCached('nonexistent')).toBeUndefined();
  });
});
