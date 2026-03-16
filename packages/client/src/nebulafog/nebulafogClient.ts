/**
 * NebulafogClient — Client-side SDK for nebulafog confidential resource access.
 *
 * Drop-in replacement for the MCP Client that transparently:
 *   - CLIENT-01: Decrypts ConfidentialResources for authorized agents
 *   - CLIENT-02: Re-encrypts sampling handler output when the turn was tainted by a ConfidentialResource read
 *   - CLIENT-03: Caches DEKs per resourceId to avoid repeated key retrieval calls
 */

import type {
  Implementation,
  ListResourcesRequest,
  ReadResourceRequest,
  ReadResourceResult,
  RequestOptions,
} from '@modelcontextprotocol/core';
import { CONFIDENTIAL_RESOURCE_CAPABILITY_KEY, CONFIDENTIAL_RESOURCE_META_KEY } from '@modelcontextprotocol/core';

import { Client } from '../client/client.js';
import { StreamableHTTPClientTransport } from '../client/streamableHttp.js';
import { decryptResource, encryptResource } from './crypto.js';
import { DekCache } from './dekCache.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface NebulafogClientOptions {
  /** Base URL of the MCP server (e.g. 'http://localhost:3000') */
  serverUrl: string;
  /** Unique agent identifier */
  agentId: string;
  /** Human-readable agent name */
  agentName: string;
  /** Caller-provided EC P-256 key pair */
  keyPair: CryptoKeyPair;
  /** Optional MCP client info */
  clientInfo?: Implementation;
}

// ---------------------------------------------------------------------------
// NebulafogClient
// ---------------------------------------------------------------------------

export class NebulafogClient {
  private readonly _client: Client;
  private readonly _dekCache: DekCache;
  private readonly _options: NebulafogClientOptions;
  /** resourceIds that were read as ConfidentialResources in the current session turn */
  private readonly _taintedResourceIds = new Set<string>();

  constructor(options: NebulafogClientOptions) {
    this._options = options;
    this._dekCache = new DekCache(options.keyPair.privateKey);

    const clientInfo: Implementation = options.clientInfo ?? {
      name: options.agentName,
      version: '1.0.0',
    };

    this._client = new Client(clientInfo, {
      capabilities: {
        sampling: {},
        experimental: {
          [CONFIDENTIAL_RESOURCE_CAPABILITY_KEY]: { version: '1' },
        },
      },
    });
  }

  /**
   * Register the agent and connect to the MCP server.
   *
   * 1. POST /nebulafog/register — treats 409 as success (idempotent)
   * 2. Connect the underlying Client via StreamableHTTPClientTransport
   */
  async connect(): Promise<void> {
    const { serverUrl, agentId, agentName, keyPair } = this._options;

    // Export public key as JWK for registration
    const publicKey = await globalThis.crypto.subtle.exportKey('jwk', keyPair.publicKey);

    // Register agent (409 = already registered, treat as success)
    const regRes = await fetch(`${serverUrl}/nebulafog/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ agentId, name: agentName, publicKey }),
    });

    if (!regRes.ok && regRes.status !== 409) {
      throw new Error(`Agent registration failed: ${regRes.status}`);
    }

    // Connect transport with agent ID header
    const transport = new StreamableHTTPClientTransport(new URL(`${serverUrl}/mcp`), {
      requestInit: {
        headers: { 'X-Nebulafog-Agent-Id': agentId },
      },
    });

    await this._client.connect(transport);
  }

  /**
   * Read a resource, transparently decrypting ConfidentialResources.
   *
   * - If the response has no ConfidentialResource meta: returned unchanged
   * - If the response has ConfidentialResource meta but no keyRetrievalUri: returned unchanged (unauthorized)
   * - If authorized: DEK is fetched (or from cache), resource is decrypted, synthetic result returned
   */
  async readResource(
    params: ReadResourceRequest['params'],
    options?: RequestOptions,
  ): Promise<ReadResourceResult> {
    const raw = await this._client.readResource(params, options);
    return this._maybeDecrypt(params.uri, raw);
  }

  private async _maybeDecrypt(uri: string, result: ReadResourceResult): Promise<ReadResourceResult> {
    const metaValue = result._meta?.[CONFIDENTIAL_RESOURCE_META_KEY] as
      | Record<string, unknown>
      | undefined;

    // No ConfidentialResource namespace key — return unchanged
    if (!metaValue) {
      return result;
    }

    // Namespace key present but no keyRetrievalUri — unauthorized agent
    if (!('keyRetrievalUri' in metaValue) || !metaValue.keyRetrievalUri) {
      return result;
    }

    const encryptedContents = metaValue.encryptedContents as string;
    const keyRetrievalUri = metaValue.keyRetrievalUri as string;
    const resourceId = metaValue.resourceId as string;

    // Fetch or retrieve cached DEK, decrypt contents
    try {
      const dek = await this._dekCache.getOrFetch(resourceId, keyRetrievalUri);
      const plaintext = await decryptResource(encryptedContents, dek);
      this._taintedResourceIds.add(resourceId);
      return {
        ...result,
        contents: [{ uri, text: plaintext }],
      };
    } catch (err) {
      // On GCM failure (wrong DEK / stale cache): evict and retry once
      if (err instanceof Error && (err.name === 'OperationError' || err.message.includes('HMAC verification failed'))) {
        this._dekCache.evict(resourceId);
        const freshDek = await this._dekCache.getOrFetch(resourceId, keyRetrievalUri);
        const plaintext = await decryptResource(encryptedContents, freshDek);
        this._taintedResourceIds.add(resourceId);
        return {
          ...result,
          contents: [{ uri, text: plaintext }],
        };
      }
      throw err;
    }
  }

  /**
   * List resources via the underlying MCP Client.
   */
  async listResources(
    params?: ListResourcesRequest['params'],
    options?: RequestOptions,
  ) {
    return this._client.listResources(params, options);
  }

  /**
   * Register a sampling handler that automatically re-encrypts output when the
   * session turn is tainted by a ConfidentialResource read (CLIENT-02).
   */
  setSamplingHandler(
    handler: (request: unknown, ctx: unknown) => Promise<{
      role: 'assistant';
      content: { type: 'text'; text: string } | Array<{ type: string; text?: string }>;
      model: string;
    }>,
  ): void {
    const self = this;

    const wrappedHandler = async (request: unknown, ctx: unknown) => {
      const handlerResult = await handler(request, ctx);

      // If no tainted resource reads in this turn, pass through unchanged
      if (self._taintedResourceIds.size === 0) {
        return handlerResult;
      }

      // Pick the first tainted resourceId
      const resourceId = [...self._taintedResourceIds][0];
      const cachedDek = self._dekCache.getCached(resourceId);
      const keyRetrievalUri = self._dekCache.getKeyRetrievalUri(resourceId);

      if (!cachedDek || !keyRetrievalUri) {
        // No DEK available to re-encrypt — return unchanged
        return handlerResult;
      }

      // Extract text from content
      const content = handlerResult.content;
      let text: string;
      if (Array.isArray(content)) {
        const textItem = content.find((c) => c.type === 'text');
        text = textItem?.text ?? '';
      } else {
        text = (content as { type: string; text: string }).text ?? '';
      }

      // Re-encrypt the text using the DEK
      const encryptedContents = await encryptResource(text, cachedDek);

      // Return with ConfidentialResource _meta wrapping
      return {
        ...handlerResult,
        content: {
          type: 'text' as const,
          text: JSON.stringify({
            _meta: {
              [CONFIDENTIAL_RESOURCE_META_KEY]: {
                encryptedContents,
                keyRetrievalUri,
                algorithm: 'AES-256-GCM',
                resourceId,
              },
            },
          }),
        },
      };
    };

    this._client.setRequestHandler('sampling/createMessage', wrappedHandler as Parameters<Client['setRequestHandler']>[1]);
  }

  /**
   * Check the agent's approval status.
   *
   * Calls GET /nebulafog/agents/:agentId/status.
   * Throws on 404 (agent not registered).
   */
  async getApprovalStatus(): Promise<'pending' | 'approved' | 'denied'> {
    const { serverUrl, agentId } = this._options;
    const res = await fetch(`${serverUrl}/nebulafog/agents/${agentId}/status`);
    if (!res.ok) {
      throw new Error(`getApprovalStatus failed: ${res.status}`);
    }
    const body = (await res.json()) as { status: 'pending' | 'approved' | 'denied' };
    return body.status;
  }

  /**
   * Close the underlying MCP Client connection.
   */
  async close(): Promise<void> {
    await this._client.close();
  }
}
