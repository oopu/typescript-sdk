/**
 * nebulafog — Public re-exports for the client SDK nebulafog module.
 *
 * NebulafogClient and DekCache are implemented in Plan 02.
 * crypto primitives are implemented in Plan 01 (this plan).
 */

export { NebulafogClient } from './nebulafogClient.js';
export type { NebulafogClientOptions } from './nebulafogClient.js';
export { DekCache } from './dekCache.js';
export {
  unwrapDek,
  decryptResource,
  encryptResource,
  deriveCommitmentKey,
} from './crypto.js';
