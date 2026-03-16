/**
 * Configuration for the NebulafogServer extension.
 *
 * Production note: in-memory key storage is used in v1.
 * For production, replace KeyStore's internal Map with Redis or equivalent persistent store.
 * Key material should be stored encrypted at rest using envelope encryption.
 */
export interface NebulafogConfig {
  /** Static admin token for bearer auth on /nebulafog/admin/* endpoints. Set at server startup. */
  adminToken: string;
  /** Base URL of this server (e.g. 'http://localhost:3000') — used to build keyRetrievalUri values. */
  serverBaseUrl: string;
  /**
   * Optional webhook URL. When set, server POSTs a notification on each new agent registration.
   * Payload: { agentId, name, registeredAt, approveUrl }
   * Fire-and-forget in v1 — no retries. Omit to disable.
   */
  webhookUrl?: string;
}
