# ConfidentialResource Specification

**Version:** v1
**Status:** Authoritative
**Last updated:** 2026-03-14
**Source schema:** `packages/core/src/types/confidential-resource.ts`

---

## 1. Overview

This document is the authoritative specification for the `ConfidentialResource` type in the Nebula Fog MCP protocol extension. It defines the type schema, wire format, cryptographic contract, key management protocol, privileged output semantics, and graceful degradation behavior that all conforming implementations MUST follow.

**Scope:** This spec covers everything a Phase 2 (MCP server) or Phase 3 (MCP client SDK) implementer needs to produce a conforming implementation. No other document is required.

**Core security property:** Unauthorized agents receive ciphertext they cannot decrypt, regardless of where they run or what they observe.

---

## 2. Schema Reference

### Namespace Key

```
CONFIDENTIAL_RESOURCE_META_KEY = 'io.nebulafog/confidential-resource/v1'
```

This constant is exported from the schema source file and MUST be used verbatim wherever the namespace key appears.

### Location in MCP Wire Types

The `ConfidentialResource` metadata lives inside the `_meta` field of an MCP `ResourceContents` object — it does NOT appear in the `contents` array. This is the Zod schema extension pattern used throughout the MCP SDK:

```
ResourceContents._meta[CONFIDENTIAL_RESOURCE_META_KEY] = ConfidentialResourceMeta
```

The `contents` array is always `[]` on the wire (see Section 9).

### ConfidentialResourceMeta Fields

| Field | Type | Description |
|-------|------|-------------|
| `encryptedContents` | `string` (base64) | The encrypted payload. Byte layout defined in Section 3. |
| `keyRetrievalUri` | `string` (URL) | URI where an authorized agent retrieves the wrapped DEK. |
| `algorithm` | `'AES-256-GCM'` (literal) | Encryption algorithm. Fixed value — no algorithm agility. |
| `resourceId` | `string` (UUID v4) | Stable identifier for this resource across key issuance events. |

**Zod definition (source of truth):**

```typescript
const ConfidentialResourceMetaSchema = z.object({
  encryptedContents: z.string(),    // base64-encoded wire payload
  keyRetrievalUri:   z.string().url(),
  algorithm:         z.literal('AES-256-GCM'),
  resourceId:        z.string().uuid(),
});
```

**Source file:** `packages/core/src/types/confidential-resource.ts`

---

## 3. Wire Format — Byte Layout

The `encryptedContents` field contains a base64-encoded binary payload. The decoded payload has the following exact byte layout:

| Offset | Length | Field | Notes |
|--------|--------|-------|-------|
| 0 | 12 bytes | Nonce | Random 96-bit value; see Section 4 |
| 12 | N bytes | Ciphertext | AES-256-GCM output; N is the plaintext length + 16-byte GCM auth tag |
| 12 + N | 32 bytes | HMAC-SHA256 tag | Commitment mitigation; see Section 6 |

**Total decoded length:** 12 + N + 32 bytes, where N is the length of the AES-256-GCM ciphertext output (plaintext length + 16-byte GCM authentication tag).

**Encoding:** The entire binary payload (nonce || ciphertext || hmac_tag) is base64-encoded as a single string and stored in `encryptedContents`. There is no separate schema field for the nonce or HMAC tag — both are embedded in `encryptedContents` at the byte positions above.

**Critical:** The HMAC tag occupies the LAST 32 bytes of the base64-decoded payload. Implementations extracting the HMAC tag MUST slice `decoded.slice(-32)` and use `decoded.slice(0, -32)` as the authenticated ciphertext input.

**Decoding algorithm (pseudocode):**

```
decoded  = base64Decode(encryptedContents)      // total length: 12 + N + 32
nonce    = decoded.slice(0, 12)                  // bytes 0..11
hmacTag  = decoded.slice(-32)                    // last 32 bytes
cipher   = decoded.slice(12, decoded.length - 32) // bytes 12..12+N-1
```

---

## 4. Nonce Generation Policy

- **Source:** `crypto.getRandomValues(new Uint8Array(12))` — Web Crypto API, available in all conforming runtimes
- **Size:** 96 bits (12 bytes) — matches AES-GCM's recommended nonce size
- **Placement:** Prepended to the ciphertext in the wire payload (bytes 0–11); not a separate schema field
- **Frequency:** Implementations MUST generate a fresh nonce for every encryption call — one nonce per `encryptedContents` value

**Security requirement:** Nonce reuse with the same AES-GCM key completely breaks confidentiality and authenticity. This is not a recommendation — it is a hard requirement. Any implementation that reuses a nonce with the same DEK produces an insecure ciphertext and MUST be rejected as non-conforming.

---

## 5. Algorithm

**Fixed algorithm:** AES-256-GCM only.

The `algorithm` field is a Zod `z.literal('AES-256-GCM')`. This value is fixed — there is no algorithm agility in v1.

**Rejection rule:** Implementations MUST reject any `ConfidentialResource` payload where `algorithm !== 'AES-256-GCM'`. A payload with any other algorithm value MUST be treated as invalid and MUST NOT be decrypted.

**Rationale:** Algorithm agility creates unverified code paths that are difficult to test and have historically been exploited. Native Web Crypto API support for AES-GCM avoids external library dependencies while providing hardware acceleration on modern runtimes. The HMAC commitment mitigation (Section 6) is designed specifically for AES-GCM.

---

## 6. Key Commitment Mitigation

### Problem

AES-GCM does not provide key commitment: an adversary can craft a ciphertext that decrypts validly (passes GCM authentication) under two different keys. This means that in multi-recipient scenarios, a server could issue a ciphertext that appears valid to Agent A under key K_A and also appears valid to Agent B under key K_B, even though A and B were given different keys. This breaks the trust model.

### Mitigation

An HMAC-SHA256 tag is appended to every ciphertext. This tag cryptographically binds the ciphertext to exactly one DEK.

**HMAC key derivation:**

```
hmacKey = HKDF(
  ikm:  DEK,                          // the Data Encryption Key (32 bytes for AES-256)
  info: "nebulafog-commitment-v1",    // exact string, UTF-8 encoded — do not modify
  salt: (none / zero-length),
  hash: SHA-256,
  length: 32 bytes
)
```

The info label MUST be exactly `"nebulafog-commitment-v1"` (UTF-8, 24 bytes). Any other value produces a different HMAC key and will cause verification failures across implementations.

**HMAC computation:**

```
hmacTag = HMAC-SHA256(hmacKey, nonce || ciphertext)
```

The HMAC covers both the nonce and the ciphertext. The tag is appended as the last 32 bytes of the wire payload.

**Verification rule:** Implementations MUST verify the HMAC tag before decrypting. If the tag does not match, the payload MUST be rejected — do not proceed to AES-GCM decryption. Verification before decryption is a security requirement (prevents oracle attacks against the AES-GCM decryption path).

---

## 7. Key Wrapping (DEK Issuance)

### Algorithm

**ECDH-ES+AES-256-KW** as defined in RFC 7518 (JWE). This is a standard JWE key wrapping algorithm with broad library support.

### Agent Key Registration

- **Format:** EC P-256 public key in JWK format
- **Location:** Submitted in the agent registration payload to the MCP server — NOT embedded in the AgentCard
- **Rationale for separation:** AgentCards are A2A identity documents; cryptographic key material belongs in the registration exchange. Mixing them would couple the A2A identity spec to Nebula Fog's key management protocol.

### DEK Issuance Properties

**Forward secrecy (mandatory):** Each DEK issuance MUST use a fresh ephemeral EC key pair on the server side. Reusing the ephemeral key across issuances eliminates forward secrecy and is not permitted. This is a hard spec requirement, not a recommendation.

**Per-recipient wrapping (v1 requirement):** Each authorized agent receives a separately wrapped copy of the DEK, encrypted to their own registered public key. Multiple agents authorized for the same resource each receive an independent wrapping of the same DEK.

**Traitor tracing:** Because each wrapped copy is unique to one agent's key pair, a leaked unwrapped DEK (plaintext DEK) can be attributed to the agent whose wrapped copy was compromised. The MCP server MUST record which agent received which wrapped copy to enable this attribution. This is a v1 requirement, not a future enhancement.

---

## 8. Privileged Output (SPEC-02)

This section defines privileged output semantics. All four properties are normative and MUST be implemented as stated.

### (a) Definition

A turn is **privileged** if and only if the MCP client SDK decrypted one or more `ConfidentialResource` objects during that turn.

A "turn" is a single request/response cycle in the MCP session — from the agent invoking a tool or resource fetch through the SDK returning the result to the agent model.

### (b) Scope

Privilege applies to the **entire turn response** — not to individual fields, not to individual resources, and not to the specific portions of the agent's output that reference the decrypted content.

Once a turn is privileged (i.e., any `ConfidentialResource` decryption occurred during that turn), all output produced by the agent model in that turn is treated as privileged. There is no mechanism to "un-taint" a turn or to mark portions of the output as non-privileged.

### (c) Enforcement

The MCP client SDK middleware MUST re-encrypt the entire turn response before any output leaves the authorized context. This is enforced at the SDK layer — the agent model has no mechanism to bypass it.

Agent code cannot opt out of privileged output enforcement. The agent model is not consulted about whether its output is privileged — the SDK makes that determination based on whether any `ConfidentialResource` decryption occurred in the turn.

### (d) Source-Level Determination (Not Taint-Tracked)

Privilege is determined by **source** — whether a `ConfidentialResource` was decrypted in this turn — not by data flow through the agent's reasoning.

A turn is privileged if any `ConfidentialResource` decryption occurred, regardless of whether the agent's output explicitly references the decrypted content, quotes it, paraphrases it, or makes inferences from it. Taint-tracking at the content/segment level is explicitly out of scope for v1 — it is too model-dependent to be reliably enforced.

**Implication:** An agent that decrypts a `ConfidentialResource` but produces output entirely unrelated to it still produces a privileged turn. This is a conservative policy that prioritizes security over precision.

---

## 9. Graceful Degradation (SPEC-03)

### Wire Shape

The `ConfidentialResource` wire shape is fixed — it is not a fallback activated by a capability flag. All MCP clients receive the same response:

```json
{
  "contents": [],
  "_meta": {
    "io.nebulafog/confidential-resource/v1": {
      "encryptedContents": "<base64>",
      "keyRetrievalUri": "https://...",
      "algorithm": "AES-256-GCM",
      "resourceId": "<uuid-v4>"
    }
  }
}
```

**Key invariants:**
- `contents` is ALWAYS `[]` — ciphertext is NEVER placed in `contents`
- A stock MCP client that reads `contents` sees an empty array and receives no error
- The `_meta` key `io.nebulafog/confidential-resource/v1` is always present

### Capability Advertisement

The MCP server SHOULD advertise `"io.nebulafog/confidential-resource/v1"` in the `experimental` capability field during the `initialize` handshake:

```json
{
  "capabilities": {
    "experimental": {
      "io.nebulafog/confidential-resource/v1": {}
    }
  }
}
```

This advertisement is **informational only**. It does not change the wire response. All clients — whether or not they advertise support — receive the same `contents: []` response.

### Conformance Test Assertions

A conforming graceful degradation test MUST assert all three of the following:

1. **No exception thrown:** Passing the response to a stock MCP client parser produces no error or exception.
2. **Empty contents:** `response.contents` equals `[]` (empty array, not null, not undefined).
3. **Meta present and valid:** `response._meta['io.nebulafog/confidential-resource/v1']` is present and successfully parses as a valid `ConfidentialResourceMeta` object (all required fields present, `algorithm === 'AES-256-GCM'`, `resourceId` is a valid UUID v4).

A test that omits any of these three assertions does not satisfy SPEC-03.

---

## 10. Implementation Constraints Summary

| Constraint | Value |
|------------|-------|
| Algorithm | `AES-256-GCM` only (`z.literal`) |
| Nonce size | 96 bits (12 bytes) |
| Nonce source | `crypto.getRandomValues()` |
| Nonce placement | Bytes 0–11 of decoded `encryptedContents` |
| HMAC algorithm | HMAC-SHA256 |
| HMAC label | `"nebulafog-commitment-v1"` (exact string) |
| HMAC position | Last 32 bytes of decoded `encryptedContents` |
| HMAC coverage | `nonce \|\| ciphertext` |
| Verify before decrypt | Yes — mandatory, not optional |
| Key wrap algorithm | ECDH-ES+AES-256-KW (RFC 7518) |
| Agent key type | EC P-256 (JWK format) |
| Key location | Registration payload (not AgentCard) |
| Ephemeral key per issuance | Mandatory (not recommended) |
| DEK wrapping model | Per-recipient (mandatory for traitor tracing) |
| `contents` on wire | Always `[]` |
| Namespace key | `io.nebulafog/confidential-resource/v1` |
| `resourceId` format | UUID v4 |
| Algorithm agility | Prohibited — reject all values other than `AES-256-GCM` |

---

## Appendix: Cross-References

| Symbol | Defined in | Used in |
|--------|-----------|---------|
| `CONFIDENTIAL_RESOURCE_META_KEY` | `packages/core/src/types/confidential-resource.ts` | All schema lookups, conformance tests |
| `ConfidentialResourceMetaSchema` | `packages/core/src/types/confidential-resource.ts` | Server issuance, client SDK parsing |
| `experimental` capability field | MCP SDK `ServerCapabilitiesSchema` (`types.ts:525`) | Capability advertisement during initialize |
| `_meta` field | MCP SDK `ResourceContentsSchema` | Namespace key placement |
| `AgentExtension` interface | `a2a-js/src/types/pb/a2a_types.ts:508` | AgentCard extension declarations |

---

*This document supersedes any conflicting description in CONTEXT.md, RESEARCH.md, or inline code comments. Treat this spec as the ground truth for all cryptographic decisions in Nebula Fog v1.*
