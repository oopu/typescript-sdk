/**
 * crypto.test.ts — Round-trip interop tests for the nebulafog client crypto module.
 *
 * Tests verify that client crypto functions are exact inverses of server KeyStore methods.
 * The critical test is the full interop test (Test 7) which crosses the server/client boundary.
 */

import { describe, it, expect, beforeAll } from 'vitest';

import {
  unwrapDek,
  decryptResource,
  encryptResource,
  deriveCommitmentKey,
} from '../../../src/nebulafog/crypto.js';
import { KeyStore } from '../../../../server/src/nebulafog/keyStore.js';

// ---------------------------------------------------------------------------
// Shared test fixtures (generated once for the test suite)
// ---------------------------------------------------------------------------

let agentKeyPair: CryptoKeyPair;
let agentPublicKeyJwk: JsonWebKey;
let keyStore: KeyStore;

beforeAll(async () => {
  // Generate a real EC P-256 key pair for the agent
  agentKeyPair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey'],
  );
  agentPublicKeyJwk = await globalThis.crypto.subtle.exportKey('jwk', agentKeyPair.publicKey);
  keyStore = new KeyStore();
});

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Generate a fresh AES-256-GCM DEK for local tests. */
async function generateLocalDek(): Promise<CryptoKey> {
  return globalThis.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('nebulafog crypto', () => {
  it('unwrapDek round-trip: wrap a DEK with server pattern, unwrap with client, verify DEK can decrypt known ciphertext', async () => {
    const RESOURCE_ID = 'test-resource-unwrap';
    const PLAINTEXT = 'Hello, secure world!';

    // Server side: encrypt resource and approve agent (wraps DEK for agent)
    const ciphertext = await keyStore.encryptResource(RESOURCE_ID, PLAINTEXT);
    const { wrappedDek, capabilityToken: _token } = await keyStore.approveAgent(
      RESOURCE_ID,
      'test-agent-unwrap',
      agentPublicKeyJwk,
    );

    // Client side: unwrap the DEK using agent private key
    const unwrappedDek = await unwrapDek(wrappedDek, agentKeyPair.privateKey);

    // Verify: use the unwrapped DEK to decrypt the ciphertext
    const plaintext = await decryptResource(ciphertext, unwrappedDek);
    expect(plaintext).toBe(PLAINTEXT);
  });

  it('decryptResource: server KeyStore._encryptWithDek output is correctly decrypted by client', async () => {
    const RESOURCE_ID = 'test-resource-decrypt';
    const PLAINTEXT = 'Sensitive payload from server';

    const ciphertext = await keyStore.encryptResource(RESOURCE_ID, PLAINTEXT);
    const { wrappedDek } = await keyStore.approveAgent(
      RESOURCE_ID,
      'test-agent-decrypt',
      agentPublicKeyJwk,
    );

    const dek = await unwrapDek(wrappedDek, agentKeyPair.privateKey);
    const result = await decryptResource(ciphertext, dek);
    expect(result).toBe(PLAINTEXT);
  });

  it('decryptResource rejects tampered HMAC: flipping a byte in HMAC region throws HMAC verification failed', async () => {
    const dek = await generateLocalDek();
    const ciphertext = await encryptResource('test data', dek);

    // Decode and flip the last byte (in the HMAC region)
    const bytes = Buffer.from(ciphertext, 'base64');
    bytes[bytes.length - 1] ^= 0xff;
    const tampered = bytes.toString('base64');

    await expect(decryptResource(tampered, dek)).rejects.toThrow(
      'HMAC verification failed',
    );
  });

  it('decryptResource rejects tampered ciphertext: HMAC check fails before GCM decryption', async () => {
    const dek = await generateLocalDek();
    const ciphertext = await encryptResource('another test', dek);

    // Decode and flip a byte in the ciphertext region (after nonce, before HMAC)
    const bytes = Buffer.from(ciphertext, 'base64');
    // nonce = bytes[0..12), ciphertext region starts at 12, HMAC at end-32
    // Flip the first ciphertext byte (offset 12)
    bytes[12] ^= 0x01;
    const tampered = bytes.toString('base64');

    await expect(decryptResource(tampered, dek)).rejects.toThrow(
      'HMAC verification failed',
    );
  });

  it('encryptResource produces valid wire format: first 12 bytes nonce, last 32 bytes HMAC, middle is ciphertext+tag', async () => {
    const dek = await generateLocalDek();
    const plaintext = 'Wire format test';
    const result = await encryptResource(plaintext, dek);

    // Must be valid base64
    const bytes = Buffer.from(result, 'base64');

    // Minimum length: 12 nonce + 16 GCM tag (for empty plaintext, though we have actual bytes) + 32 HMAC
    // AES-GCM ciphertext length = plaintext length + 16-byte tag
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const expectedMinLength = 12 + plaintextBytes.length + 16 + 32;
    expect(bytes.length).toBe(expectedMinLength);

    // Verify the HMAC covers nonce || ciphertext+tag by decrypting successfully
    const decrypted = await decryptResource(result, dek);
    expect(decrypted).toBe(plaintext);
  });

  it('encryptResource round-trip: client encrypt then client decrypt returns original plaintext', async () => {
    const dek = await generateLocalDek();
    const plaintext = 'Round-trip test with unicode: 🔐';

    const ciphertext = await encryptResource(plaintext, dek);
    const decrypted = await decryptResource(ciphertext, dek);
    expect(decrypted).toBe(plaintext);
  });

  it('Full interop: server KeyStore encrypts + wraps, client unwrapDek + decryptResource recovers plaintext', async () => {
    const RESOURCE_ID = 'test-resource-full-interop';
    const PLAINTEXT = 'Top-secret resource contents accessible only by approved agents';

    // Server side: encrypt resource for storage
    const encryptedContents = await keyStore.encryptResource(RESOURCE_ID, PLAINTEXT);

    // Server side: approve agent and issue capability (wraps DEK for this agent's public key)
    const { wrappedDek } = await keyStore.approveAgent(
      RESOURCE_ID,
      'test-agent-interop',
      agentPublicKeyJwk,
    );

    // Client side: unwrap the DEK using the agent's private key
    const dek = await unwrapDek(wrappedDek, agentKeyPair.privateKey);

    // Client side: decrypt the resource using the recovered DEK
    const plaintext = await decryptResource(encryptedContents, dek);

    expect(plaintext).toBe(PLAINTEXT);
  });

  it('Two encryptions of same plaintext produce different base64 outputs (fresh nonce)', async () => {
    const dek = await generateLocalDek();
    const plaintext = 'same plaintext, different nonces';

    const cipher1 = await encryptResource(plaintext, dek);
    const cipher2 = await encryptResource(plaintext, dek);

    expect(cipher1).not.toBe(cipher2);

    // Both must still decrypt correctly
    const dec1 = await decryptResource(cipher1, dek);
    const dec2 = await decryptResource(cipher2, dek);
    expect(dec1).toBe(plaintext);
    expect(dec2).toBe(plaintext);
  });

  it('deriveCommitmentKey produces consistent keys from same DEK', async () => {
    const dek = await generateLocalDek();
    // Verify deriveCommitmentKey works by using it in a sign/verify cycle
    const hmacKey = await deriveCommitmentKey(dek);
    const data = new TextEncoder().encode('test data');
    const sig = await globalThis.crypto.subtle.sign('HMAC', hmacKey, data);
    const hmacKey2 = await deriveCommitmentKey(dek);
    const valid = await globalThis.crypto.subtle.verify('HMAC', hmacKey2, sig, data);
    expect(valid).toBe(true);
  });
});
