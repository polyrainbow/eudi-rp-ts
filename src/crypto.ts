import { type KeyObject, createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';

/**
 * The only signature algorithm we accept.
 *
 * The EUDI reference issuer advertises `credential_signing_alg_values_supported:
 * ["ES256"]` for every SD-JWT VC configuration, so an allowlist of one is not a
 * simplification here. Keeping it an allowlist, rather than trusting the `alg`
 * in the token, is what prevents algorithm-substitution attacks.
 */
export const ALLOWED_JWS_ALG = 'ES256' as const;

/** IANA hash algorithm names (SD-JWT's `_sd_alg` claim) -> node digest names. */
const HASH_NAMES: Record<string, string> = {
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512',
};

/** Hasher in the shape `@sd-jwt/core` expects. */
export function hasher(data: string | ArrayBuffer, alg: string): Uint8Array {
  const nodeAlg = HASH_NAMES[alg.toLowerCase()];
  if (!nodeAlg) throw new Error(`Unsupported hash algorithm: ${alg}`);
  const input = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return new Uint8Array(createHash(nodeAlg).update(input).digest());
}

export function base64urlEncode(input: Uint8Array | Buffer): string {
  return Buffer.from(input).toString('base64url');
}

/**
 * Verify a JWS signature over `data` (the `header.payload` signing input).
 *
 * JWS carries ECDSA signatures as raw R||S (RFC 7515 §3.4), which node calls
 * `ieee-p1363`. The default `der` encoding would reject every valid JWS.
 */
export function verifyEs256(publicKey: KeyObject, data: string, signatureB64u: string): boolean {
  try {
    return nodeVerify(
      'sha256',
      Buffer.from(data, 'utf8'),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signatureB64u, 'base64url'),
    );
  } catch {
    return false;
  }
}

/** Import an EC P-256 public key from a JWK (used for the holder's `cnf.jwk`). */
export function importEcP256Jwk(jwk: unknown): KeyObject | undefined {
  if (typeof jwk !== 'object' || jwk === null) return undefined;
  const { kty, crv } = jwk as Record<string, unknown>;
  if (kty !== 'EC' || crv !== 'P-256') return undefined;
  try {
    return createPublicKey({ key: jwk as import('node:crypto').JsonWebKey, format: 'jwk' });
  } catch {
    return undefined;
  }
}

/** Decode a JWS/JWT header without verifying anything. */
export function decodeProtectedHeader(compactJwt: string): Record<string, unknown> {
  const segment = compactJwt.split('.')[0];
  if (!segment) throw new Error('Malformed JWT: missing header');
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** Decode a JWS/JWT payload without verifying anything. */
export function decodeUnverifiedPayload(compactJwt: string): Record<string, unknown> {
  const segment = compactJwt.split('.')[1];
  if (!segment) throw new Error('Malformed JWT: missing payload');
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}
