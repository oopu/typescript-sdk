/**
 * KeyStore — AES-256-GCM encryption + ECDH-ES+AES-256-KW DEK wrapping.
 *
 * Security properties:
 * - Each encryption uses a fresh 96-bit random nonce (crypto.getRandomValues)
 * - Wire format: nonce[12] || ciphertext+GCM-tag || HMAC-SHA256[32]
 * - HMAC key derived via HKDF from DEK with info label 'nebulafog-commitment-v1'
 * - DEK is generated once per resource (lazy), reused for subsequent approvals
 * - Each approveAgent call uses a fresh ephemeral EC P-256 key pair (per-recipient forward secrecy)
 * - DEK never leaves the KeyStore in raw form — only AES-KW wrapped copies are returned
 */

interface StoreEntry {
  dek: CryptoKey;
  /** Original plaintext — retained for rotation re-encryption */
  plaintext: string;
  ciphertext: string;
  wrappedCopies: Map<
    string,
    {
      wrappedDek: string;
      capabilityToken: string;
      /** Agent's ECDH public key, retained for rotation re-wrapping */
      publicKey: JsonWebKey;
    }
  >;
}

export class KeyStore {
  private readonly _store = new Map<string, StoreEntry>();

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Encrypt plaintext for a resource using AES-256-GCM with a fresh nonce.
   *
   * Wire format (base64-encoded):
   *   bytes  0–11: nonce (96-bit, random)
   *   bytes 12..N-33: AES-GCM ciphertext + 16-byte GCM auth tag
   *   bytes  N-32..N-1: HMAC-SHA256 commitment (HKDF-derived key, info 'nebulafog-commitment-v1')
   */
  async encryptResource(resourceId: string, plaintext: string): Promise<string> {
    // Lazily fetch or create a DEK for this resource. If no entry exists yet we
    // create a temporary one; approveAgent will replace it with the canonical entry.
    const entry = this._store.get(resourceId);
    if (entry) {
      const ciphertext = await this._encryptWithDek(entry.dek, plaintext);
      entry.plaintext = plaintext;
      entry.ciphertext = ciphertext;
      return ciphertext;
    }
    // No entry yet — generate a standalone DEK for this call only (will be
    // overwritten when approveAgent is called for the first time).
    const dek = await this._generateDek();
    const ciphertext = await this._encryptWithDek(dek, plaintext);
    this._store.set(resourceId, {
      dek,
      plaintext,
      ciphertext,
      wrappedCopies: new Map(),
    });
    return ciphertext;
  }

  /**
   * Approve an agent for access to a resource.
   *
   * Lazy DEK: generates a new DEK on the first call for a resource, reuses it
   * for subsequent approvals. Always uses a fresh ephemeral ECDH key pair.
   *
   * Returns { wrappedDek: JSON string, capabilityToken: UUID }.
   */
  async approveAgent(
    resourceId: string,
    agentId: string,
    agentPublicKeyJwk: JsonWebKey
  ): Promise<{ wrappedDek: string; capabilityToken: string }> {
    let entry = this._store.get(resourceId);

    if (!entry) {
      // First approval — generate DEK and encrypt an empty placeholder.
      // Callers should call encryptResource separately for the actual content.
      const dek = await this._generateDek();
      const ciphertext = await this._encryptWithDek(dek, '');
      entry = { dek, plaintext: '', ciphertext, wrappedCopies: new Map() };
      this._store.set(resourceId, entry);
    }

    const wrappedDek = await this._wrapDek(entry.dek, agentPublicKeyJwk);
    const capabilityToken = globalThis.crypto.randomUUID();

    entry.wrappedCopies.set(agentId, {
      wrappedDek,
      capabilityToken,
      publicKey: agentPublicKeyJwk,
    });

    return { wrappedDek, capabilityToken };
  }

  /**
   * Rotate the DEK for a resource.
   *
   * Generates a new DEK, re-encrypts the stored plaintext, then re-wraps the
   * new DEK for every previously-approved agent (new ephemeral key per agent,
   * new capabilityToken per agent). Returns a Map<agentId, { wrappedDek, capabilityToken }>.
   */
  async rotateDek(
    resourceId: string
  ): Promise<Map<string, { wrappedDek: string; capabilityToken: string }>> {
    const entry = this._store.get(resourceId);
    if (!entry) {
      throw new Error(`KeyStore: unknown resourceId '${resourceId}'`);
    }

    const newDek = await this._generateDek();
    const newCiphertext = await this._encryptWithDek(newDek, entry.plaintext);

    const newWrappedCopies = new Map<
      string,
      { wrappedDek: string; capabilityToken: string; publicKey: JsonWebKey }
    >();
    const result = new Map<string, { wrappedDek: string; capabilityToken: string }>();

    for (const [agentId, agentData] of entry.wrappedCopies) {
      const wrappedDek = await this._wrapDek(newDek, agentData.publicKey);
      const capabilityToken = globalThis.crypto.randomUUID();
      newWrappedCopies.set(agentId, { wrappedDek, capabilityToken, publicKey: agentData.publicKey });
      result.set(agentId, { wrappedDek, capabilityToken });
    }

    // Fully replace the store entry with the new DEK and re-encrypted data.
    this._store.set(resourceId, {
      dek: newDek,
      plaintext: entry.plaintext,
      ciphertext: newCiphertext,
      wrappedCopies: newWrappedCopies,
    });

    return result;
  }

  /**
   * Returns the public store entry (ciphertext + wrappedCopies) for a resource,
   * or undefined if the resource is not in the store.
   */
  getEntry(
    resourceId: string
  ):
    | {
        ciphertext: string;
        wrappedCopies: Map<string, { wrappedDek: string; capabilityToken: string }>;
      }
    | undefined {
    const entry = this._store.get(resourceId);
    if (!entry) return undefined;
    // Return a view that strips the internal dek and plaintext fields.
    return { ciphertext: entry.ciphertext, wrappedCopies: entry.wrappedCopies };
  }

  /**
   * Looks up a capability token across all resources.
   *
   * Returns { wrappedDek } if found, or undefined.
   */
  lookupByCapabilityToken(token: string): { wrappedDek: string } | undefined {
    for (const entry of this._store.values()) {
      for (const copy of entry.wrappedCopies.values()) {
        if (copy.capabilityToken === token) {
          return { wrappedDek: copy.wrappedDek };
        }
      }
    }
    return undefined;
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /** Generate a new AES-256-GCM DEK. */
  private async _generateDek(): Promise<CryptoKey> {
    return globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable so it can be wrapped
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  }

  /**
   * Encrypt plaintext with a given DEK using AES-256-GCM.
   *
   * Wire format: nonce[12] || ciphertext+GCM-tag || HMAC-SHA256[32]
   */
  private async _encryptWithDek(dek: CryptoKey, plaintext: string): Promise<string> {
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext);

    const ciphertextAndTag = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        dek,
        plaintextBytes
      )
    );

    // Derive HMAC commitment key via HKDF
    const hmacKey = await this._deriveCommitmentKey(dek);

    // HMAC covers nonce || ciphertext+tag
    const toMac = new Uint8Array(nonce.length + ciphertextAndTag.length);
    toMac.set(nonce, 0);
    toMac.set(ciphertextAndTag, nonce.length);

    const hmacTag = new Uint8Array(
      await globalThis.crypto.subtle.sign('HMAC', hmacKey, toMac)
    );

    // Assemble wire format
    const output = new Uint8Array(nonce.length + ciphertextAndTag.length + hmacTag.length);
    output.set(nonce, 0);
    output.set(ciphertextAndTag, nonce.length);
    output.set(hmacTag, nonce.length + ciphertextAndTag.length);

    return Buffer.from(output).toString('base64');
  }

  /**
   * Derive a HMAC-SHA256 commitment key from the DEK via HKDF.
   * Info label is EXACTLY 'nebulafog-commitment-v1' per spec.
   */
  private async _deriveCommitmentKey(dek: CryptoKey): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    // Import raw DEK bytes as HKDF key material
    const rawDek = await globalThis.crypto.subtle.exportKey('raw', dek);
    const hkdfKeyMaterial = await globalThis.crypto.subtle.importKey(
      'raw',
      rawDek,
      'HKDF',
      false,
      ['deriveKey']
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
      ['sign', 'verify']
    );
  }

  /**
   * Wrap the DEK for a recipient using ECDH-ES+AES-256-KW.
   *
   * Generates a FRESH ephemeral EC P-256 key pair per call.
   * Returns JSON: { wrappedDek: base64, ephemeralPublicKey: JWK }
   */
  private async _wrapDek(dek: CryptoKey, recipientPublicKeyJwk: JsonWebKey): Promise<string> {
    // Import recipient's public key for ECDH
    const recipientPublicKey = await globalThis.crypto.subtle.importKey(
      'jwk',
      recipientPublicKeyJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // Generate fresh ephemeral key pair per call (mandatory for per-recipient forward secrecy)
    const ephemeralKeyPair = await globalThis.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    );

    // ECDH key agreement: derive wrapping key from ephemeral private + recipient public
    const wrappingKey = await globalThis.crypto.subtle.deriveKey(
      { name: 'ECDH', public: recipientPublicKey },
      ephemeralKeyPair.privateKey,
      { name: 'AES-KW', length: 256 },
      false,
      ['wrapKey', 'unwrapKey']
    );

    // Wrap the DEK using AES-KW
    const wrappedDekBytes = new Uint8Array(
      await globalThis.crypto.subtle.wrapKey('raw', dek, wrappingKey, 'AES-KW')
    );

    // Export ephemeral public key as JWK for inclusion in the wrapped DEK JSON
    const ephemeralPublicKeyJwk = await globalThis.crypto.subtle.exportKey(
      'jwk',
      ephemeralKeyPair.publicKey
    );

    return JSON.stringify({
      wrappedDek: Buffer.from(wrappedDekBytes).toString('base64'),
      ephemeralPublicKey: ephemeralPublicKeyJwk,
    });
  }
}
