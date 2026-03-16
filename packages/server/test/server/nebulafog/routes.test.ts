import express from 'express';
import request from 'supertest';
import { describe, it, expect, beforeEach } from 'vitest';

import { AgentRegistry } from '../../../src/nebulafog/agentRegistry.js';
import { KeyStore } from '../../../src/nebulafog/keyStore.js';
import { createNebulafogRouter } from '../../../src/nebulafog/routes.js';
import type { NebulafogConfig } from '../../../src/nebulafog/config.js';

const TEST_ADMIN_TOKEN = 'test-admin-token-abc123';

// A real EC P-256 JWK for testing (generated via crypto.subtle)
const AGENT_PUBLIC_KEY_JWK: JsonWebKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  key_ops: [],
  ext: true,
};

const AGENT_PUBLIC_KEY_JWK_2: JsonWebKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA',
  y: 'rquLYAe6t4oj7P5yjFkY0VK2mJqBGHqKgD3DKakuWGw',
  key_ops: [],
  ext: true,
};

function buildApp(
  keyStore: KeyStore,
  registry: AgentRegistry,
  config: NebulafogConfig,
) {
  const app = express();
  app.use(express.json());
  app.use('/nebulafog', createNebulafogRouter(keyStore, registry, config));
  return app;
}

describe('Nebulafog Routes', () => {
  let keyStore: KeyStore;
  let registry: AgentRegistry;
  let config: NebulafogConfig;
  let app: ReturnType<typeof express>;

  beforeEach(() => {
    keyStore = new KeyStore();
    registry = new AgentRegistry();
    config = {
      adminToken: TEST_ADMIN_TOKEN,
      serverBaseUrl: 'http://localhost:3000',
    };
    app = buildApp(keyStore, registry, config);
  });

  describe('POST /nebulafog/register (SERV-01)', () => {
    it('returns 201 and pending record for valid registration body', async () => {
      const res = await request(app)
        .post('/nebulafog/register')
        .send({ agentId: 'agent-1', name: 'Test Agent', publicKey: AGENT_PUBLIC_KEY_JWK });
      expect(res.status).toBe(201);
      expect(res.body.agentId).toBe('agent-1');
      expect(res.body.name).toBe('Test Agent');
      expect(res.body.status).toBe('pending');
      expect(res.body.registeredAt).toBeDefined();
    });

    it('returns 400 for missing agentId', async () => {
      const res = await request(app)
        .post('/nebulafog/register')
        .send({ name: 'Test Agent', publicKey: AGENT_PUBLIC_KEY_JWK });
      expect(res.status).toBe(400);
    });

    it('returns 400 for missing publicKey', async () => {
      const res = await request(app)
        .post('/nebulafog/register')
        .send({ agentId: 'agent-1', name: 'Test Agent' });
      expect(res.status).toBe(400);
    });

    it('returns 409 for duplicate agentId', async () => {
      await request(app)
        .post('/nebulafog/register')
        .send({ agentId: 'agent-dup', name: 'Test Agent', publicKey: AGENT_PUBLIC_KEY_JWK });
      const res = await request(app)
        .post('/nebulafog/register')
        .send({ agentId: 'agent-dup', name: 'Test Agent 2', publicKey: AGENT_PUBLIC_KEY_JWK });
      expect(res.status).toBe(409);
    });

    it('fires webhook if webhookUrl configured (fire-and-forget)', async () => {
      // Configure an unreachable webhook URL
      const appWithWebhook = buildApp(keyStore, registry, {
        ...config,
        webhookUrl: 'http://localhost:1/webhook',
      });
      const res = await request(appWithWebhook)
        .post('/nebulafog/register')
        .send({ agentId: 'agent-webhook', name: 'Webhook Agent', publicKey: AGENT_PUBLIC_KEY_JWK });
      // Must still return 201 even if webhook fails (fire-and-forget)
      expect(res.status).toBe(201);
    });
  });

  describe('GET /nebulafog/admin/agents (SERV-02)', () => {
    it('returns 401 without Authorization header', async () => {
      const res = await request(app).get('/nebulafog/admin/agents');
      expect(res.status).toBe(401);
    });

    it('returns 401 with wrong token', async () => {
      const res = await request(app)
        .get('/nebulafog/admin/agents')
        .set('Authorization', 'Bearer wrong-token');
      expect(res.status).toBe(401);
    });

    it('returns 200 with list of all agents for valid admin token', async () => {
      // Register an agent first
      await request(app)
        .post('/nebulafog/register')
        .send({ agentId: 'agent-list', name: 'List Agent', publicKey: AGENT_PUBLIC_KEY_JWK });

      const res = await request(app)
        .get('/nebulafog/admin/agents')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body.length).toBeGreaterThanOrEqual(1);
      expect(res.body[0].agentId).toBe('agent-list');
    });
  });

  describe('POST /nebulafog/admin/agents/:agentId/approve (SERV-02)', () => {
    it('returns 401 without admin token', async () => {
      const res = await request(app)
        .post('/nebulafog/admin/agents/agent-1/approve');
      expect(res.status).toBe(401);
    });

    it('returns 200 and approved status for valid approve request', async () => {
      registry.register('agent-approve', 'Approve Agent', AGENT_PUBLIC_KEY_JWK);
      const res = await request(app)
        .post('/nebulafog/admin/agents/agent-approve/approve')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`)
        .send({});
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('approved');
    });

    it('returns 404 for unknown agentId', async () => {
      const res = await request(app)
        .post('/nebulafog/admin/agents/nonexistent/approve')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`)
        .send({});
      expect(res.status).toBe(404);
    });

    it('approve with resourceId creates capability token in keyStore', async () => {
      // 1. Register an agent
      registry.register('agent-dek', 'DEK Agent', AGENT_PUBLIC_KEY_JWK);

      // 2. POST approve with resourceId
      const res = await request(app)
        .post('/nebulafog/admin/agents/agent-dek/approve')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`)
        .send({ resourceId: 'resource-123' });

      // 3. Assert response 200 + capabilityToken present
      expect(res.status).toBe(200);
      expect(res.body.capabilityToken).toBeDefined();
      expect(typeof res.body.capabilityToken).toBe('string');

      // 4. Assert keyStore.getEntry(resourceId).wrappedCopies.get(agentId) is defined
      const entry = keyStore.getEntry('resource-123');
      expect(entry).toBeDefined();
      expect(entry!.wrappedCopies.get('agent-dek')).toBeDefined();

      // 5. Assert lookupByCapabilityToken returns { wrappedDek: string }
      const lookup = keyStore.lookupByCapabilityToken(res.body.capabilityToken);
      expect(lookup).toBeDefined();
      expect(typeof lookup!.wrappedDek).toBe('string');
    });
  });

  describe('POST /nebulafog/admin/agents/:agentId/deny (SERV-02)', () => {
    it('returns 401 without admin token', async () => {
      const res = await request(app)
        .post('/nebulafog/admin/agents/agent-1/deny');
      expect(res.status).toBe(401);
    });

    it('returns 200 and denied status for valid deny request', async () => {
      registry.register('agent-deny', 'Deny Agent', AGENT_PUBLIC_KEY_JWK);
      const res = await request(app)
        .post('/nebulafog/admin/agents/agent-deny/deny')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('denied');
    });
  });

  describe('POST /nebulafog/admin/resources/:resourceId/rotate-dek', () => {
    it('returns 401 without admin token', async () => {
      const res = await request(app)
        .post('/nebulafog/admin/resources/resource-1/rotate-dek');
      expect(res.status).toBe(401);
    });

    it('rotates DEK and re-issues capability tokens for all approved agents', async () => {
      // Set up: register and approve an agent with a resourceId via the route
      registry.register('agent-rotate', 'Rotate Agent', AGENT_PUBLIC_KEY_JWK);
      await request(app)
        .post('/nebulafog/admin/agents/agent-rotate/approve')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`)
        .send({ resourceId: 'resource-rotate' });

      const res = await request(app)
        .post('/nebulafog/admin/resources/resource-rotate/rotate-dek')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`);
      expect(res.status).toBe(200);
      expect(res.body.resourceId).toBe('resource-rotate');
      expect(typeof res.body.rotatedAgentCount).toBe('number');
      expect(res.body.rotatedAgentCount).toBeGreaterThanOrEqual(1);
    });
  });

  describe('GET /nebulafog/agents/:agentId/status', () => {
    it('returns 200 with status pending for a registered pending agent', async () => {
      registry.register('agent-status-pending', 'Pending Agent', AGENT_PUBLIC_KEY_JWK);
      const res = await request(app).get('/nebulafog/agents/agent-status-pending/status');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('pending');
    });

    it('returns 200 with status approved for an approved agent', async () => {
      registry.register('agent-status-approved', 'Approved Agent', AGENT_PUBLIC_KEY_JWK);
      registry.approve('agent-status-approved');
      const res = await request(app).get('/nebulafog/agents/agent-status-approved/status');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('approved');
    });

    it('returns 404 for unknown agentId', async () => {
      const res = await request(app).get('/nebulafog/agents/nonexistent-agent/status');
      expect(res.status).toBe(404);
    });
  });

  describe('GET /nebulafog/keys/:token (SERV-04)', () => {
    it('returns 200 with wrappedDek for valid capability token', async () => {
      // Create a capability token via approveAgent
      registry.register('agent-key', 'Key Agent', AGENT_PUBLIC_KEY_JWK);
      const approveRes = await request(app)
        .post('/nebulafog/admin/agents/agent-key/approve')
        .set('Authorization', `Bearer ${TEST_ADMIN_TOKEN}`)
        .send({ resourceId: 'resource-key' });
      expect(approveRes.status).toBe(200);
      const { capabilityToken } = approveRes.body;

      const res = await request(app).get(`/nebulafog/keys/${capabilityToken}`);
      expect(res.status).toBe(200);
      expect(typeof res.body.wrappedDek).toBe('string');
    });

    it('returns 404 for unknown token', async () => {
      const res = await request(app).get('/nebulafog/keys/unknown-token-xyz');
      expect(res.status).toBe(404);
    });
  });
});
