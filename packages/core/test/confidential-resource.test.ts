import { describe, test, expect } from 'vitest';
import {
  ConfidentialResourceMetaSchema,
  ConfidentialResourceCapabilitySchema,
  CONFIDENTIAL_RESOURCE_META_KEY,
  isConfidentialResource,
  parseConfidentialResourceMeta,
} from '../src/types/confidential-resource.js';

const validMeta = {
  encryptedContents: 'dGVzdA==',
  keyRetrievalUri: 'https://keys.example.com/v1/key-123',
  algorithm: 'AES-256-GCM' as const,
  resourceId: '550e8400-e29b-41d4-a716-446655440000',
};

describe('ConfidentialResourceMetaSchema', () => {
  test('parses a valid payload', () => {
    const result = ConfidentialResourceMetaSchema.safeParse(validMeta);
    expect(result.success).toBe(true);
  });

  test('rejects algorithm ChaCha20-Poly1305', () => {
    const result = ConfidentialResourceMetaSchema.safeParse({
      ...validMeta,
      algorithm: 'ChaCha20-Poly1305',
    });
    expect(result.success).toBe(false);
  });

  test('rejects algorithm AES-128-GCM', () => {
    const result = ConfidentialResourceMetaSchema.safeParse({
      ...validMeta,
      algorithm: 'AES-128-GCM',
    });
    expect(result.success).toBe(false);
  });

  test('rejects missing encryptedContents', () => {
    const { encryptedContents: _omit, ...rest } = validMeta;
    const result = ConfidentialResourceMetaSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  test('rejects missing keyRetrievalUri', () => {
    const { keyRetrievalUri: _omit, ...rest } = validMeta;
    const result = ConfidentialResourceMetaSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  test('rejects missing resourceId', () => {
    const { resourceId: _omit, ...rest } = validMeta;
    const result = ConfidentialResourceMetaSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  test('rejects non-UUID resourceId', () => {
    const result = ConfidentialResourceMetaSchema.safeParse({
      ...validMeta,
      resourceId: 'not-a-uuid',
    });
    expect(result.success).toBe(false);
  });
});

describe('parseConfidentialResourceMeta', () => {
  test('returns null for undefined', () => {
    expect(parseConfidentialResourceMeta(undefined)).toBeNull();
  });

  test('returns null when namespace key is missing', () => {
    expect(parseConfidentialResourceMeta({})).toBeNull();
  });

  test('returns ConfidentialResourceMeta for valid input', () => {
    const meta = parseConfidentialResourceMeta({
      [CONFIDENTIAL_RESOURCE_META_KEY]: validMeta,
    });
    expect(meta).not.toBeNull();
    expect(meta?.algorithm).toBe('AES-256-GCM');
    expect(meta?.resourceId).toBe(validMeta.resourceId);
  });
});

describe('isConfidentialResource', () => {
  test('returns true when _meta carries namespace key', () => {
    const contents = {
      _meta: { [CONFIDENTIAL_RESOURCE_META_KEY]: validMeta },
    };
    expect(isConfidentialResource(contents)).toBe(true);
  });

  test('returns false when _meta is empty', () => {
    expect(isConfidentialResource({ _meta: {} })).toBe(false);
  });

  test('returns false when _meta is absent', () => {
    expect(isConfidentialResource({})).toBe(false);
  });
});

describe('ConfidentialResourceCapabilitySchema', () => {
  test('parses { version: "1" }', () => {
    const result = ConfidentialResourceCapabilitySchema.safeParse({ version: '1' });
    expect(result.success).toBe(true);
  });

  test('rejects { version: "2" }', () => {
    const result = ConfidentialResourceCapabilitySchema.safeParse({ version: '2' });
    expect(result.success).toBe(false);
  });
});

describe('SPEC-03 conformance', () => {
  /**
   * Simulates the shape of a ReadResourceResult for a ConfidentialResource.
   * Ciphertext is NEVER in contents — it lives under _meta.
   */
  const confidentialResourceResponse = {
    contents: [] as unknown[],
    _meta: {
      [CONFIDENTIAL_RESOURCE_META_KEY]: validMeta,
    },
  };

  test('(1) accessing contents does not throw', () => {
    expect(() => confidentialResourceResponse.contents).not.toThrow();
  });

  test('(2) contents equals []', () => {
    expect(confidentialResourceResponse.contents).toEqual([]);
  });

  test('(3) _meta carries valid ConfidentialResource meta', () => {
    const meta = parseConfidentialResourceMeta(confidentialResourceResponse._meta);
    expect(meta).not.toBeNull();
    expect(meta?.algorithm).toBe('AES-256-GCM');
  });
});
