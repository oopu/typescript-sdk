/**
 * createNebulafogRouter — Express Router factory for all /nebulafog/* endpoints.
 *
 * Endpoints:
 *   POST   /register                                  → SERV-01: agent self-registration
 *   GET    /admin/agents                              → SERV-02: list agents (admin-only)
 *   POST   /admin/agents/:agentId/approve             → SERV-02: approve agent (admin-only)
 *   POST   /admin/agents/:agentId/deny                → SERV-02: deny agent (admin-only)
 *   POST   /admin/resources/:resourceId/rotate-dek    → DEK rotation (admin-only)
 *   GET    /keys/:token                               → SERV-04: retrieve wrapped DEK by capability token
 *
 * Security:
 *   Admin endpoints use timing-safe Bearer token comparison (timingSafeEqual).
 *   Webhook is fire-and-forget — registration 201 is not gated on webhook delivery.
 */

import { timingSafeEqual } from 'node:crypto';
import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';

import type { KeyStore } from './keyStore.js';
import type { AgentRegistry } from './agentRegistry.js';
import type { NebulafogConfig } from './config.js';

// ---------------------------------------------------------------------------
// Admin auth middleware
// ---------------------------------------------------------------------------

function makeAdminAuth(expectedToken: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const token = authHeader.slice('Bearer '.length);
    // Guard: timingSafeEqual requires equal-length buffers — length mismatch is a fast 401
    const expected = Buffer.from(expectedToken, 'utf8');
    const provided = Buffer.from(token, 'utf8');
    if (
      provided.length !== expected.length ||
      !timingSafeEqual(provided, expected)
    ) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Router factory
// ---------------------------------------------------------------------------

export function createNebulafogRouter(
  keyStore: KeyStore,
  registry: AgentRegistry,
  config: NebulafogConfig,
): Router {
  const router = Router();
  const adminAuth = makeAdminAuth(config.adminToken);

  // -------------------------------------------------------------------------
  // POST /register
  // -------------------------------------------------------------------------
  router.post('/register', (req: Request, res: Response): void => {
    const { agentId, name, publicKey } = req.body ?? {};

    // Validate required fields
    if (
      typeof agentId !== 'string' || !agentId ||
      typeof name !== 'string' || !name ||
      typeof publicKey !== 'object' || publicKey === null
    ) {
      res.status(400).json({ error: 'Missing required fields: agentId, name, publicKey' });
      return;
    }

    let record;
    try {
      record = registry.register(agentId, name, publicKey as JsonWebKey);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('already registered')) {
        res.status(409).json({ error: message });
        return;
      }
      res.status(500).json({ error: 'Internal server error' });
      return;
    }

    // Fire-and-forget webhook
    if (config.webhookUrl) {
      void (async () => {
        try {
          await fetch(config.webhookUrl!, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              agentId: record.agentId,
              name: record.name,
              registeredAt: record.registeredAt,
              approveUrl: `${config.serverBaseUrl}/nebulafog/admin/agents/${record.agentId}/approve`,
            }),
          });
        } catch (e) {
          console.error('Webhook failed:', e);
        }
      })();
    }

    res.status(201).json(record);
  });

  // -------------------------------------------------------------------------
  // GET /agents/:agentId/status — unauthenticated, agents check their own status
  // -------------------------------------------------------------------------
  router.get('/agents/:agentId/status', (req: Request, res: Response): void => {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const agentId = req.params['agentId']!;
    const agent = registry.getAgent(agentId);
    if (!agent) {
      res.status(404).json({ error: `Agent '${agentId}' not found` });
      return;
    }
    res.status(200).json({ status: agent.status });
  });

  // -------------------------------------------------------------------------
  // GET /admin/agents
  // -------------------------------------------------------------------------
  router.get('/admin/agents', adminAuth, (_req: Request, res: Response): void => {
    res.status(200).json(registry.listAgents());
  });

  // -------------------------------------------------------------------------
  // POST /admin/agents/:agentId/approve
  // -------------------------------------------------------------------------
  router.post(
    '/admin/agents/:agentId/approve',
    adminAuth,
    async (req: Request, res: Response): Promise<void> => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const agentId = req.params['agentId']!;
      const { resourceId } = req.body ?? {};

      try {
        registry.approve(agentId);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes('not found')) {
          res.status(404).json({ error: message });
          return;
        }
        res.status(500).json({ error: 'Internal server error' });
        return;
      }

      const updatedRecord = registry.getAgent(agentId)!;

      // If resourceId is provided, issue capability token via keyStore
      if (typeof resourceId === 'string' && resourceId) {
        const publicKey = registry.getPublicKey(agentId);
        if (publicKey) {
          try {
            const result = await keyStore.approveAgent(resourceId, agentId, publicKey);
            res.status(200).json({ ...updatedRecord, capabilityToken: result.capabilityToken });
            return;
          } catch (err) {
            console.error('keyStore.approveAgent failed:', err);
            res.status(500).json({ error: 'Key issuance failed' });
            return;
          }
        }
      }

      res.status(200).json(updatedRecord);
    },
  );

  // -------------------------------------------------------------------------
  // POST /admin/agents/:agentId/deny
  // -------------------------------------------------------------------------
  router.post(
    '/admin/agents/:agentId/deny',
    adminAuth,
    (req: Request, res: Response): void => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const agentId = req.params['agentId']!;

      try {
        registry.deny(agentId);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes('not found')) {
          res.status(404).json({ error: message });
          return;
        }
        res.status(500).json({ error: 'Internal server error' });
        return;
      }

      const updatedRecord = registry.getAgent(agentId)!;
      res.status(200).json(updatedRecord);
    },
  );

  // -------------------------------------------------------------------------
  // POST /admin/resources/:resourceId/rotate-dek
  // -------------------------------------------------------------------------
  router.post(
    '/admin/resources/:resourceId/rotate-dek',
    adminAuth,
    async (req: Request, res: Response): Promise<void> => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const resourceId = req.params['resourceId']!;

      try {
        const result = await keyStore.rotateDek(resourceId);
        res.status(200).json({ resourceId, rotatedAgentCount: result.size });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes('unknown resourceId')) {
          res.status(404).json({ error: message });
          return;
        }
        res.status(500).json({ error: 'Internal server error' });
        return;
      }
    },
  );

  // -------------------------------------------------------------------------
  // GET /keys/:token
  // -------------------------------------------------------------------------
  router.get('/keys/:token', (req: Request, res: Response): void => {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const token = req.params['token']!;
    const result = keyStore.lookupByCapabilityToken(token);
    if (!result) {
      res.status(404).json({ error: 'Unknown capability token' });
      return;
    }
    res.status(200).json({ wrappedDek: result.wrappedDek });
  });

  return router;
}
