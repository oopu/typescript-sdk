import * as z from 'zod/v4';

/**
 * Namespace key used to carry ConfidentialResource metadata in MCP _meta fields.
 */
export const CONFIDENTIAL_RESOURCE_META_KEY = 'io.nebulafog/confidential-resource/v1' as const;

/**
 * Namespace key used to advertise ConfidentialResource capability in experimental fields.
 */
export const CONFIDENTIAL_RESOURCE_CAPABILITY_KEY = 'io.nebulafog/confidential-resource/v1' as const;

/**
 * Schema for the ConfidentialResource metadata object carried under
 * `_meta[CONFIDENTIAL_RESOURCE_META_KEY]` in MCP resource responses.
 *
 * The encryptedContents field holds the AES-256-GCM ciphertext; the byte layout
 * (IV prefix, tag suffix, etc.) is enforced at the protocol level, not here.
 */
export const ConfidentialResourceMetaSchema = z.object({
  /** AES-256-GCM ciphertext (base64-encoded by convention; format enforced by protocol). */
  encryptedContents: z.string(),
  /** URI from which the wrapping key can be retrieved with proper authorization. */
  keyRetrievalUri: z.string().url(),
  /** Encryption algorithm — locked to AES-256-GCM, no algorithm agility. */
  algorithm: z.literal('AES-256-GCM'),
  /** Stable UUID v4 identifier for this confidential resource. */
  resourceId: z.string().uuid(),
});

/** TypeScript type auto-derived from ConfidentialResourceMetaSchema. */
export type ConfidentialResourceMeta = z.infer<typeof ConfidentialResourceMetaSchema>;

/**
 * Schema for the ConfidentialResource capability advertised in the MCP
 * `experimental` field during capability negotiation.
 */
export const ConfidentialResourceCapabilitySchema = z.object({
  /** Capability version — currently locked to '1'. */
  version: z.literal('1'),
});

/** TypeScript type auto-derived from ConfidentialResourceCapabilitySchema. */
export type ConfidentialResourceCapability = z.infer<typeof ConfidentialResourceCapabilitySchema>;

/**
 * Returns true if the given resource contents object carries ConfidentialResource
 * metadata under the namespace key, false otherwise.
 */
export function isConfidentialResource(contents: { _meta?: Record<string, unknown> }): boolean {
  return (
    contents._meta !== undefined &&
    Object.prototype.hasOwnProperty.call(contents._meta, CONFIDENTIAL_RESOURCE_META_KEY)
  );
}

/**
 * Parses ConfidentialResource metadata from a MCP resource `_meta` object.
 *
 * Returns the parsed `ConfidentialResourceMeta` if the namespace key is present
 * and the value conforms to the schema; returns null otherwise.
 */
export function parseConfidentialResourceMeta(
  meta: Record<string, unknown> | undefined,
): ConfidentialResourceMeta | null {
  if (meta === undefined) {
    return null;
  }

  const raw = meta[CONFIDENTIAL_RESOURCE_META_KEY];
  if (raw === undefined) {
    return null;
  }

  const result = ConfidentialResourceMetaSchema.safeParse(raw);
  return result.success ? result.data : null;
}
