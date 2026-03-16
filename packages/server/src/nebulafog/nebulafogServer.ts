/**
 * NebulafogServer — integration facade wiring McpServer + KeyStore + AgentRegistry + routes.
 *
 * Responsibilities:
 *   - Advertises 'io.nebulafog/confidential-resource/v1' in MCP server experimental capabilities
 *   - Pre-processes MCP initialize requests to extract agent-id before SDK handles them
 *   - Maps session IDs to agent IDs for use in resource readCallbacks
 *   - Registers confidential resources with readCallbacks that enforce authorization
 *
 * Security contract:
 *   - Unauthorized agents (unregistered, pending, denied) receive contents:[] with
 *     _meta containing encryptedContents and algorithm but NO keyRetrievalUri
 *   - Authorized agents receive contents:[] with _meta containing encryptedContents,
 *     keyRetrievalUri, algorithm, resourceId
 *   - No information is leaked about registration state via status codes or error messages
 */

import type { ReadResourceResult } from '@modelcontextprotocol/core';
import { CONFIDENTIAL_RESOURCE_META_KEY } from '@modelcontextprotocol/core';

import type { McpServer } from '../server/mcp.js';
import { KeyStore } from './keyStore.js';
import { AgentRegistry } from './agentRegistry.js';
import type { NebulafogConfig } from './config.js';

export class NebulafogServer {
  readonly mcpServer: McpServer;
  readonly keyStore: KeyStore;
  readonly registry: AgentRegistry;
  readonly config: NebulafogConfig;

  /**
   * sessionId → agentId, populated during initialize handshake.
   * Keyed by transport session ID (from ctx.sessionId in request handlers).
   */
  private readonly sessionAgentMap = new Map<string, string>();

  constructor(mcpServer: McpServer, config: NebulafogConfig) {
    this.mcpServer = mcpServer;
    this.config = config;
    this.keyStore = new KeyStore();
    this.registry = new AgentRegistry();

    // Advertise nebulafog confidential resource capability in server experimental capabilities.
    // Must be done before calling connect() — registerCapabilities throws if already connected.
    mcpServer.server.registerCapabilities({
      experimental: {
        [CONFIDENTIAL_RESOURCE_META_KEY]: { version: '1' },
      },
    });
  }

  /**
   * Register a confidential resource with the McpServer.
   *
   * Encrypts the plaintext immediately using KeyStore and registers an MCP resource
   * with a readCallback that enforces authorization. The readCallback:
   *   - Returns contents:[] with encryptedContents and algorithm but NO keyRetrievalUri
   *     for any agent that is not in the sessionAgentMap or not approved in registry.
   *   - Returns contents:[] with encryptedContents, algorithm, keyRetrievalUri, and resourceId
   *     for agents that are approved and have a wrappedDek in keyStore.
   */
  async registerConfidentialResource(
    resourceId: string,
    name: string,
    uri: string,
    plaintext: string,
  ): Promise<void> {
    // Pre-encrypt the plaintext so the ciphertext is ready for the readCallback.
    await this.keyStore.encryptResource(resourceId, plaintext);

    const self = this;

    this.mcpServer.registerResource(
      name,
      uri,
      { mimeType: 'application/octet-stream' },
      async (_uri, ctx): Promise<ReadResourceResult> => {
        return self._readCallbackForResource(resourceId, ctx.sessionId);
      },
    );
  }

  /**
   * Core readCallback logic for a confidential resource.
   *
   * Extracted for direct invocation in tests via testReadCallback().
   *
   * @param resourceId - The confidential resource identifier.
   * @param sessionId - The MCP session ID (from ctx.sessionId in the readCallback).
   */
  private async _readCallbackForResource(
    resourceId: string,
    sessionId: string | undefined,
  ): Promise<ReadResourceResult> {
    const agentId = sessionId ? this.sessionAgentMap.get(sessionId) : undefined;
    const isAuthorized = agentId ? this.registry.isApproved(agentId) : false;
    const entry = this.keyStore.getEntry(resourceId);

    // Unauthorized path: contents:[], _meta with ciphertext but no keyRetrievalUri.
    // Per spec: no 403, no error message, no information leakage about registration state.
    if (!isAuthorized || !entry) {
      const metaValue: Record<string, unknown> = {
        encryptedContents: entry ? entry.ciphertext : '',
        algorithm: 'AES-256-GCM' as const,
        resourceId,
      };
      return {
        contents: [],
        _meta: { [CONFIDENTIAL_RESOURCE_META_KEY]: metaValue },
      } as ReadResourceResult;
    }

    // Authorized path: capability token was created by POST /approve in routes.ts (Plan 04).
    // Simply look up the existing wrappedCopies entry — do NOT call keyStore.approveAgent() here.
    const agentEntry = entry.wrappedCopies.get(agentId!);
    const keyRetrievalUri = agentEntry
      ? `${this.config.serverBaseUrl}/nebulafog/keys/${agentEntry.capabilityToken}`
      : undefined;

    const metaValue: Record<string, unknown> = {
      encryptedContents: entry.ciphertext,
      ...(keyRetrievalUri !== undefined && { keyRetrievalUri }),
      algorithm: 'AES-256-GCM' as const,
      resourceId,
    };

    return {
      contents: [],
      _meta: { [CONFIDENTIAL_RESOURCE_META_KEY]: metaValue },
    } as ReadResourceResult;
  }

  /**
   * Map a session ID to an agent ID.
   *
   * Called from the Express POST /mcp handler when processing an initialize request
   * via the onsessioninitialized callback. This is the integration point between the
   * MCP protocol layer and the nebulafog authorization layer.
   *
   * @param sessionId - The MCP transport session ID.
   * @param agentId - The agent ID extracted from params.experimental['io.nebulafog/agent-id'].
   */
  mapSessionToAgent(sessionId: string, agentId: string): void {
    this.sessionAgentMap.set(sessionId, agentId);
  }

  /**
   * Test helper — exposes the readCallback logic for direct invocation in unit tests.
   *
   * In production, the readCallback is invoked by the McpServer when an MCP client sends
   * a resources/read request. This helper allows tests to call the callback directly
   * without going through the full HTTP/MCP stack.
   *
   * @param resourceId - The confidential resource identifier.
   * @param sessionId - The session ID to use (simulates ctx.sessionId from McpServer).
   */
  async testReadCallback(resourceId: string, sessionId: string): Promise<ReadResourceResult> {
    return this._readCallbackForResource(resourceId, sessionId);
  }
}
