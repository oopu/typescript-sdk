/**
 * Integration tests for NebulafogServer readCallback paths.
 *
 * Tests the two critical paths of the confidential resource read interceptor:
 *   1. Unauthorized agent (no agent-id or not approved) → contents:[], _meta with
 *      encryptedContents but NO keyRetrievalUri
 *   2. Authorized agent (registered + approved with resourceId) → contents:[], _meta
 *      with encryptedContents AND keyRetrievalUri present
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { McpServer } from '../../../src/server/mcp.js';
import { NebulafogServer } from '../../../src/nebulafog/index.js';
import { CONFIDENTIAL_RESOURCE_META_KEY } from '@modelcontextprotocol/core';

// Real P-256 public key JWK for ECDH-ES wrapping
const TEST_AGENT_PUBLIC_KEY: JsonWebKey = {
  key_ops: [],
  ext: true,
  kty: 'EC',
  x: 'asp0BAl2plF27trBSIqYKvB6wTPU3zIIHk33hjPAzUk',
  y: 'whiDuzk2vbalvRoz9UrNP0gtm6ZTVGsjFH4xGEkHQwU',
  crv: 'P-256',
};

describe('NebulafogServer', () => {
  let nebulafogServer: NebulafogServer;

  beforeEach(() => {
    const mcpServer = new McpServer(
      { name: 'test-server', version: '1.0.0' },
    );
    nebulafogServer = new NebulafogServer(mcpServer, {
      adminToken: 'test-admin-token',
      serverBaseUrl: 'http://localhost:3000',
    });
  });

  describe('readCallback: unauthorized agent → no keyRetrievalUri', () => {
    it('returns contents:[] when session has no associated agentId', async () => {
      await nebulafogServer.registerConfidentialResource('doc1', 'Test Doc', 'nebulafog://doc1', 'secret content');

      const result = await nebulafogServer.testReadCallback('doc1', 'session-without-agent');

      expect(result.contents).toEqual([]);
    });

    it('returns _meta with encryptedContents and NO keyRetrievalUri for unknown session', async () => {
      await nebulafogServer.registerConfidentialResource('doc1', 'Test Doc', 'nebulafog://doc1', 'secret content');

      const result = await nebulafogServer.testReadCallback('doc1', 'session-without-agent');

      const meta = (result._meta as Record<string, unknown>)?.[CONFIDENTIAL_RESOURCE_META_KEY] as Record<string, unknown>;
      expect(meta).toBeDefined();
      expect(meta.encryptedContents).toBeDefined();
      expect(typeof meta.encryptedContents).toBe('string');
      expect((meta.encryptedContents as string).length).toBeGreaterThan(0);
      expect(meta.keyRetrievalUri).toBeUndefined();
    });

    it('returns _meta.algorithm AES-256-GCM for unauthorized agent', async () => {
      await nebulafogServer.registerConfidentialResource('doc2', 'Test Doc 2', 'nebulafog://doc2', 'secret');

      const result = await nebulafogServer.testReadCallback('doc2', 'unregistered-session');

      const meta = (result._meta as Record<string, unknown>)?.[CONFIDENTIAL_RESOURCE_META_KEY] as Record<string, unknown>;
      expect(meta.algorithm).toBe('AES-256-GCM');
    });

    it('returns no keyRetrievalUri even for a registered-but-pending agent', async () => {
      await nebulafogServer.registerConfidentialResource('doc3', 'Test Doc 3', 'nebulafog://doc3', 'secret');
      const agentId = 'agent-pending-001';
      nebulafogServer.registry.register(agentId, 'Pending Agent', TEST_AGENT_PUBLIC_KEY);
      // NOT approving — agent stays pending
      // Populate session map with the pending agent
      (nebulafogServer['sessionAgentMap'] as Map<string, string>).set('session-pending', agentId);

      const result = await nebulafogServer.testReadCallback('doc3', 'session-pending');

      const meta = (result._meta as Record<string, unknown>)?.[CONFIDENTIAL_RESOURCE_META_KEY] as Record<string, unknown>;
      expect(meta.keyRetrievalUri).toBeUndefined();
    });
  });

  describe('readCallback: authorized agent → keyRetrievalUri present', () => {
    it('returns keyRetrievalUri matching serverBaseUrl/nebulafog/keys/{capabilityToken}', async () => {
      const resourceId = 'doc-authorized';
      await nebulafogServer.registerConfidentialResource(resourceId, 'Authorized Doc', `nebulafog://${resourceId}`, 'top secret');

      const agentId = 'agent-authorized-001';
      nebulafogServer.registry.register(agentId, 'Authorized Agent', TEST_AGENT_PUBLIC_KEY);
      await nebulafogServer.keyStore.approveAgent(resourceId, agentId, TEST_AGENT_PUBLIC_KEY);
      nebulafogServer.registry.approve(agentId);

      // Populate sessionAgentMap as the initialize pre-processing would
      (nebulafogServer['sessionAgentMap'] as Map<string, string>).set('session-authorized', agentId);

      const result = await nebulafogServer.testReadCallback(resourceId, 'session-authorized');

      expect(result.contents).toEqual([]);
      const meta = (result._meta as Record<string, unknown>)?.[CONFIDENTIAL_RESOURCE_META_KEY] as Record<string, unknown>;
      expect(meta).toBeDefined();
      expect(typeof meta.keyRetrievalUri).toBe('string');
      expect((meta.keyRetrievalUri as string)).toMatch(/^http:\/\/localhost:3000\/nebulafog\/keys\/.+/);
    });

    it('keyRetrievalUri contains the capabilityToken from keyStore', async () => {
      const resourceId = 'doc-token-check';
      await nebulafogServer.registerConfidentialResource(resourceId, 'Token Check Doc', `nebulafog://${resourceId}`, 'secret');

      const agentId = 'agent-token-check';
      nebulafogServer.registry.register(agentId, 'Token Check Agent', TEST_AGENT_PUBLIC_KEY);
      const { capabilityToken } = await nebulafogServer.keyStore.approveAgent(resourceId, agentId, TEST_AGENT_PUBLIC_KEY);
      nebulafogServer.registry.approve(agentId);

      (nebulafogServer['sessionAgentMap'] as Map<string, string>).set('session-token-check', agentId);

      const result = await nebulafogServer.testReadCallback(resourceId, 'session-token-check');

      const meta = (result._meta as Record<string, unknown>)?.[CONFIDENTIAL_RESOURCE_META_KEY] as Record<string, unknown>;
      expect(meta.keyRetrievalUri).toBe(`http://localhost:3000/nebulafog/keys/${capabilityToken}`);
    });

    it('returns encryptedContents in _meta for authorized agent', async () => {
      const resourceId = 'doc-enc-check';
      await nebulafogServer.registerConfidentialResource(resourceId, 'Enc Check', `nebulafog://${resourceId}`, 'confidential');

      const agentId = 'agent-enc-check';
      nebulafogServer.registry.register(agentId, 'Enc Check Agent', TEST_AGENT_PUBLIC_KEY);
      await nebulafogServer.keyStore.approveAgent(resourceId, agentId, TEST_AGENT_PUBLIC_KEY);
      nebulafogServer.registry.approve(agentId);
      (nebulafogServer['sessionAgentMap'] as Map<string, string>).set('session-enc-check', agentId);

      const result = await nebulafogServer.testReadCallback(resourceId, 'session-enc-check');

      const meta = (result._meta as Record<string, unknown>)?.[CONFIDENTIAL_RESOURCE_META_KEY] as Record<string, unknown>;
      expect(typeof meta.encryptedContents).toBe('string');
      expect((meta.encryptedContents as string).length).toBeGreaterThan(0);
    });
  });

  describe('NebulafogServer construction', () => {
    it('exposes keyStore and registry as public properties', () => {
      expect(nebulafogServer.keyStore).toBeDefined();
      expect(nebulafogServer.registry).toBeDefined();
    });

    it('exposes config as public property', () => {
      expect(nebulafogServer.config.adminToken).toBe('test-admin-token');
      expect(nebulafogServer.config.serverBaseUrl).toBe('http://localhost:3000');
    });

    it('exposes mcpServer as public property', () => {
      expect(nebulafogServer.mcpServer).toBeDefined();
    });
  });
});
