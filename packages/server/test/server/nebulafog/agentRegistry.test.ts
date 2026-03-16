import { describe, it, expect, beforeEach } from 'vitest';
import { AgentRegistry, AgentRecord, AgentStatus } from '../../../src/nebulafog/agentRegistry.js';

const SAMPLE_JWK: JsonWebKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'abc123',
  y: 'def456',
};

describe('AgentRegistry', () => {
  let registry: AgentRegistry;

  beforeEach(() => {
    registry = new AgentRegistry();
  });

  describe('SERV-01: Agent registration creates pending record', () => {
    it('register() creates a pending agent record with provided agentId, name, publicKey', () => {
      const record = registry.register('agent-1', 'Test Agent', SAMPLE_JWK);
      expect(record.agentId).toBe('agent-1');
      expect(record.name).toBe('Test Agent');
      expect(record.publicKey).toEqual(SAMPLE_JWK);
      expect(record.status).toBe('pending');
    });

    it('register() returns the created agent record with a valid ISO 8601 registeredAt timestamp', () => {
      const before = new Date().toISOString();
      const record = registry.register('agent-2', 'Another Agent', SAMPLE_JWK);
      const after = new Date().toISOString();
      expect(record.registeredAt).toBeDefined();
      expect(new Date(record.registeredAt).toISOString()).toBe(record.registeredAt);
      expect(record.registeredAt >= before).toBe(true);
      expect(record.registeredAt <= after).toBe(true);
    });

    it('register() throws if agentId already registered', () => {
      registry.register('agent-dup', 'First', SAMPLE_JWK);
      expect(() => registry.register('agent-dup', 'Second', SAMPLE_JWK)).toThrow(
        'Agent agent-dup already registered',
      );
    });
  });

  describe('SERV-02: Approval queue management', () => {
    it('listAgents() returns all agents with their current status', () => {
      registry.register('agent-a', 'Alpha', SAMPLE_JWK);
      registry.register('agent-b', 'Beta', SAMPLE_JWK);
      const agents = registry.listAgents();
      expect(agents).toHaveLength(2);
      const ids = agents.map((a) => a.agentId);
      expect(ids).toContain('agent-a');
      expect(ids).toContain('agent-b');
    });

    it('approve() changes agent status from pending to approved', () => {
      registry.register('agent-x', 'X', SAMPLE_JWK);
      registry.approve('agent-x');
      const record = registry.getAgent('agent-x');
      expect(record?.status).toBe('approved');
    });

    it('deny() changes agent status from pending to denied', () => {
      registry.register('agent-y', 'Y', SAMPLE_JWK);
      registry.deny('agent-y');
      const record = registry.getAgent('agent-y');
      expect(record?.status).toBe('denied');
    });

    it('approve() throws if agent does not exist', () => {
      expect(() => registry.approve('nonexistent')).toThrow('Agent nonexistent not found');
    });

    it('isApproved() returns true for approved agents, false for all others', () => {
      registry.register('agent-pending', 'Pending', SAMPLE_JWK);
      registry.register('agent-approved', 'Approved', SAMPLE_JWK);
      registry.register('agent-denied', 'Denied', SAMPLE_JWK);
      registry.approve('agent-approved');
      registry.deny('agent-denied');

      expect(registry.isApproved('agent-approved')).toBe(true);
      expect(registry.isApproved('agent-pending')).toBe(false);
      expect(registry.isApproved('agent-denied')).toBe(false);
      expect(registry.isApproved('unknown-id')).toBe(false);
    });

    it('getPublicKey() returns agent public key JWK for registered agents', () => {
      registry.register('agent-key', 'KeyAgent', SAMPLE_JWK);
      expect(registry.getPublicKey('agent-key')).toEqual(SAMPLE_JWK);
    });

    it('getPublicKey() returns undefined for unknown agentId', () => {
      expect(registry.getPublicKey('nobody')).toBeUndefined();
    });

    it('deny() throws if agent does not exist', () => {
      expect(() => registry.deny('nobody')).toThrow('Agent nobody not found');
    });

    it('approve() is idempotent — calling twice on same agent does not throw', () => {
      registry.register('agent-idem', 'Idempotent', SAMPLE_JWK);
      registry.approve('agent-idem');
      expect(() => registry.approve('agent-idem')).not.toThrow();
      expect(registry.isApproved('agent-idem')).toBe(true);
    });

    it('deny() is idempotent — calling twice on same agent does not throw', () => {
      registry.register('agent-idem-deny', 'IdempotentDeny', SAMPLE_JWK);
      registry.deny('agent-idem-deny');
      expect(() => registry.deny('agent-idem-deny')).not.toThrow();
      expect(registry.getAgent('agent-idem-deny')?.status).toBe('denied');
    });

    it('listApprovedAgentIds() returns only approved agentIds', () => {
      registry.register('ag-pending', 'Pending', SAMPLE_JWK);
      registry.register('ag-approved-1', 'Approved1', SAMPLE_JWK);
      registry.register('ag-approved-2', 'Approved2', SAMPLE_JWK);
      registry.register('ag-denied', 'Denied', SAMPLE_JWK);
      registry.approve('ag-approved-1');
      registry.approve('ag-approved-2');
      registry.deny('ag-denied');

      const approvedIds = registry.listApprovedAgentIds();
      expect(approvedIds).toHaveLength(2);
      expect(approvedIds).toContain('ag-approved-1');
      expect(approvedIds).toContain('ag-approved-2');
      expect(approvedIds).not.toContain('ag-pending');
      expect(approvedIds).not.toContain('ag-denied');
    });
  });

  describe('Type exports', () => {
    it('exports AgentStatus type — compile-time check via usage', () => {
      const status: AgentStatus = 'pending';
      expect(['pending', 'approved', 'denied']).toContain(status);
    });

    it('exports AgentRecord interface — compile-time check via usage', () => {
      const record: AgentRecord = registry.register('agent-type-check', 'TypeCheck', SAMPLE_JWK);
      expect(record).toBeDefined();
    });
  });
});
