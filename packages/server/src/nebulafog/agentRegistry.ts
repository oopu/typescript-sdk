/**
 * AgentRegistry — registration and approval state machine for NebulaFog agents.
 *
 * Implements SERV-01 (agent registration creates a pending record) and
 * SERV-02 (operator approval/deny queue). Pure business logic; no crypto dependencies.
 *
 * Storage is in-process Map — persistence and clustering are deferred to v2.
 */

export type AgentStatus = 'pending' | 'approved' | 'denied';

export interface AgentRecord {
  agentId: string;
  name: string;
  /** EC P-256 JWK submitted at registration. JWS signature verification is deferred to v2. */
  publicKey: JsonWebKey;
  status: AgentStatus;
  /** ISO 8601 timestamp of initial registration. */
  registeredAt: string;
}

export class AgentRegistry {
  private readonly _agents = new Map<string, AgentRecord>();

  /**
   * Creates a pending AgentRecord for the given agentId.
   *
   * @throws Error if agentId already exists.
   */
  register(agentId: string, name: string, publicKey: JsonWebKey): AgentRecord {
    if (this._agents.has(agentId)) {
      throw new Error(`Agent ${agentId} already registered`);
    }
    const record: AgentRecord = {
      agentId,
      name,
      publicKey,
      status: 'pending',
      registeredAt: new Date().toISOString(),
    };
    this._agents.set(agentId, record);
    return record;
  }

  /**
   * Sets the agent's status to 'approved'. Idempotent if already approved.
   *
   * @throws Error if agentId is not found.
   */
  approve(agentId: string): void {
    const record = this._requireAgent(agentId);
    record.status = 'approved';
  }

  /**
   * Sets the agent's status to 'denied'. Idempotent if already denied.
   *
   * @throws Error if agentId is not found.
   */
  deny(agentId: string): void {
    const record = this._requireAgent(agentId);
    record.status = 'denied';
  }

  /**
   * Returns true iff the agent exists and its status is 'approved'.
   */
  isApproved(agentId: string): boolean {
    return this._agents.get(agentId)?.status === 'approved';
  }

  /**
   * Returns all AgentRecords regardless of status.
   */
  listAgents(): AgentRecord[] {
    return Array.from(this._agents.values());
  }

  /**
   * Returns the AgentRecord for agentId, or undefined if not found.
   */
  getAgent(agentId: string): AgentRecord | undefined {
    return this._agents.get(agentId);
  }

  /**
   * Returns the EC P-256 JWK submitted at registration, or undefined if agentId not found.
   */
  getPublicKey(agentId: string): JsonWebKey | undefined {
    return this._agents.get(agentId)?.publicKey;
  }

  /**
   * Returns all agentIds whose status is 'approved'.
   * Used by KeyStore.rotateDek to iterate agents for DEK re-wrapping.
   */
  listApprovedAgentIds(): string[] {
    return Array.from(this._agents.values())
      .filter((r) => r.status === 'approved')
      .map((r) => r.agentId);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private _requireAgent(agentId: string): AgentRecord {
    const record = this._agents.get(agentId);
    if (!record) {
      throw new Error(`Agent ${agentId} not found`);
    }
    return record;
  }
}
