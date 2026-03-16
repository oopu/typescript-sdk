/**
 * DekCache — In-memory cache for unwrapped Data Encryption Keys (DEKs).
 *
 * Caches DEKs by resourceId to avoid repeated key retrieval calls (CLIENT-03).
 * Each DEK is fetched from the server's key retrieval endpoint and unwrapped
 * using the agent's private key.
 */

import { unwrapDek } from './crypto.js';

export class DekCache {
  private readonly _cache = new Map<string, CryptoKey>();
  private readonly _uriCache = new Map<string, string>();
  private readonly _privateKey: CryptoKey;

  constructor(privateKey: CryptoKey) {
    this._privateKey = privateKey;
  }

  /**
   * Return the cached DEK for resourceId, or fetch it from keyRetrievalUri if not cached.
   */
  async getOrFetch(resourceId: string, keyRetrievalUri: string): Promise<CryptoKey> {
    const cached = this._cache.get(resourceId);
    if (cached) return cached;
    return this._fetchAndCache(resourceId, keyRetrievalUri);
  }

  private async _fetchAndCache(resourceId: string, keyRetrievalUri: string): Promise<CryptoKey> {
    const res = await fetch(keyRetrievalUri);
    if (!res.ok) throw new Error(`DEK fetch failed: ${res.status}`);
    const body = (await res.json()) as { wrappedDek: string };
    const dek = await unwrapDek(body.wrappedDek, this._privateKey);
    this._cache.set(resourceId, dek);
    this._uriCache.set(resourceId, keyRetrievalUri);
    return dek;
  }

  /**
   * Evict the cached DEK for resourceId so the next getOrFetch call re-fetches it.
   */
  evict(resourceId: string): void {
    this._cache.delete(resourceId);
    this._uriCache.delete(resourceId);
  }

  /**
   * Return the cached DEK for resourceId without fetching, or undefined if not cached.
   */
  getCached(resourceId: string): CryptoKey | undefined {
    return this._cache.get(resourceId);
  }

  /**
   * Return the URI used for the last fetch for resourceId, or undefined if never fetched.
   */
  getKeyRetrievalUri(resourceId: string): string | undefined {
    return this._uriCache.get(resourceId);
  }
}
