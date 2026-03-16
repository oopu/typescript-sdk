/**
 * crypto — Client-side cryptographic primitives for nebulafog.
 *
 * These are the exact inverses of the server's KeyStore private methods.
 *
 * Wire format: nonce[12] || ciphertext+GCM-tag || HMAC-SHA256[32]
 * DEK wrapping: ECDH-ES (ephemeral P-256) + AES-256-KW
 * HMAC commitment: HKDF(DEK, salt=empty, info='nebulafog-commitment-v1') -> HMAC-SHA256
 *
 * All operations use Web Crypto API exclusively (globalThis.crypto.subtle).
 * No external dependencies.
 */

// ---------------------------------------------------------------------------
// Wire-format constants
// ---------------------------------------------------------------------------

const NONCE_BYTES = 12;
const HMAC_BYTES = 32;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Derive an HMAC-SHA256 commitment key from a DEK via HKDF.
 *
 * Must produce the same key as the server's KeyStore._deriveCommitmentKey.
 * Info label is EXACTLY 'nebulafog-commitment-v1' — matches server exactly.
 */
export async function deriveCommitmentKey(dek: CryptoKey): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  // Export raw DEK bytes and import as HKDF key material
  const rawDek = await globalThis.crypto.subtle.exportKey('raw', dek);
  const hkdfKeyMaterial = await globalThis.crypto.subtle.importKey(
    'raw',
    rawDek,
    'HKDF',
    false,
    ['deriveKey'],
  );
  return globalThis.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encoder.encode('nebulafog-commitment-v1'),
    },
    hkdfKeyMaterial,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify'],
  );
}

/**
 * Unwrap a DEK from the server's wrapped DEK JSON string.
 *
 * Input JSON: { wrappedDek: base64, ephemeralPublicKey: JWK }
 * Key agreement: ECDH(agentPrivateKey, ephemeralPublicKey) -> AES-KW -> unwrap DEK
 *
 * The unwrapped DEK has extractable: true and usages ['encrypt', 'decrypt'] so that:
 *   - deriveCommitmentKey can export raw bytes (requires extractable: true)
 *   - encryptResource can use the DEK for re-encryption (requires 'encrypt')
 */
export async function unwrapDek(
  wrappedDekJson: string,
  agentPrivateKey: CryptoKey,
): Promise<CryptoKey> {
  const { wrappedDek: wrappedDekBase64, ephemeralPublicKey: ephemeralPublicKeyJwk } =
    JSON.parse(wrappedDekJson) as { wrappedDek: string; ephemeralPublicKey: JsonWebKey };

  // Import ephemeral public key for ECDH
  const ephemeralPublicKey = await globalThis.crypto.subtle.importKey(
    'jwk',
    ephemeralPublicKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );

  // ECDH key agreement: derive wrapping key from agent private + ephemeral public
  const wrappingKey = await globalThis.crypto.subtle.deriveKey(
    { name: 'ECDH', public: ephemeralPublicKey },
    agentPrivateKey,
    { name: 'AES-KW', length: 256 },
    false,
    ['unwrapKey'],
  );

  // Decode the wrapped DEK bytes and unwrap using AES-KW
  const wrappedDekBytes = Buffer.from(wrappedDekBase64, 'base64');

  return globalThis.crypto.subtle.unwrapKey(
    'raw',
    wrappedDekBytes,
    wrappingKey,
    'AES-KW',
    { name: 'AES-GCM', length: 256 },
    true, // extractable: true — required for deriveCommitmentKey (exports raw bytes)
    ['encrypt', 'decrypt'], // encrypt needed for CLIENT-02 re-encryption
  );
}

/**
 * Decrypt a resource ciphertext using the provided DEK.
 *
 * Wire format: nonce[12] || ciphertext+GCM-tag || HMAC-SHA256[32]
 *
 * Verifies HMAC commitment BEFORE attempting AES-GCM decryption (fail fast on tamper).
 * Throws if HMAC is invalid: Error('HMAC verification failed — DEK mismatch or ciphertext tampered')
 */
export async function decryptResource(
  ciphertextBase64: string,
  dek: CryptoKey,
): Promise<string> {
  const bytes = new Uint8Array(Buffer.from(ciphertextBase64, 'base64'));

  // Split wire format: nonce[12] || ciphertext+tag[...] || HMAC[32]
  const nonce = bytes.slice(0, NONCE_BYTES);
  const ciphertextAndTag = bytes.slice(NONCE_BYTES, bytes.length - HMAC_BYTES);
  const hmacTag = bytes.slice(bytes.length - HMAC_BYTES);

  // Verify HMAC FIRST (covers nonce || ciphertext+tag)
  const hmacKey = await deriveCommitmentKey(dek);
  const toVerify = new Uint8Array(nonce.length + ciphertextAndTag.length);
  toVerify.set(nonce, 0);
  toVerify.set(ciphertextAndTag, nonce.length);

  const hmacValid = await globalThis.crypto.subtle.verify('HMAC', hmacKey, hmacTag, toVerify);
  if (!hmacValid) {
    throw new Error('HMAC verification failed — DEK mismatch or ciphertext tampered');
  }

  // Decrypt with AES-256-GCM
  const plaintextBytes = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    dek,
    ciphertextAndTag,
  );

  return new TextDecoder().decode(plaintextBytes);
}

/**
 * Encrypt plaintext using the provided DEK.
 *
 * Produces wire-format ciphertext identical to server's KeyStore._encryptWithDek output.
 * Each call uses a fresh random 96-bit nonce (crypto.getRandomValues).
 *
 * Wire format (base64-encoded): nonce[12] || ciphertext+GCM-tag || HMAC-SHA256[32]
 */
export async function encryptResource(
  plaintext: string,
  dek: CryptoKey,
): Promise<string> {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const plaintextBytes = new TextEncoder().encode(plaintext);

  const ciphertextAndTag = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      dek,
      plaintextBytes,
    ),
  );

  // Derive HMAC commitment key and compute HMAC over (nonce || ciphertext+tag)
  const hmacKey = await deriveCommitmentKey(dek);
  const toMac = new Uint8Array(nonce.length + ciphertextAndTag.length);
  toMac.set(nonce, 0);
  toMac.set(ciphertextAndTag, nonce.length);

  const hmacTag = new Uint8Array(
    await globalThis.crypto.subtle.sign('HMAC', hmacKey, toMac),
  );

  // Assemble wire format: nonce || ciphertext+tag || HMAC
  const output = new Uint8Array(nonce.length + ciphertextAndTag.length + hmacTag.length);
  output.set(nonce, 0);
  output.set(ciphertextAndTag, nonce.length);
  output.set(hmacTag, nonce.length + ciphertextAndTag.length);

  return Buffer.from(output).toString('base64');
}
