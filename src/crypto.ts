import { type KeyObject, createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';

/**
 * ECDSA algorithms this can verify.
 *
 * The EUDI reference issuer advertises only `ES256`, which is why that is the
 * default allowlist — but an allowlist of one is a policy, not a limit, and a
 * different ecosystem may sign with a larger curve.
 *
 * The critical property is that the caller states which algorithms are
 * acceptable and the token's own `alg` is checked against that list. Trusting
 * the `alg` header to select the verification algorithm is how algorithm
 * substitution attacks work.
 */
export const SUPPORTED_JWS_ALGS = {
  ES256: { hash: 'sha256', namedCurve: 'prime256v1' },
  ES384: { hash: 'sha384', namedCurve: 'secp384r1' },
  ES512: { hash: 'sha512', namedCurve: 'secp521r1' },
} as const;

export type JwsAlg = keyof typeof SUPPORTED_JWS_ALGS;

/** Default policy: what the EUDI reference infrastructure actually uses. */
export const DEFAULT_ALLOWED_ALGS: readonly JwsAlg[] = ['ES256'];

/** @deprecated use DEFAULT_ALLOWED_ALGS; retained so existing callers compile. */
export const ALLOWED_JWS_ALG = 'ES256' as const;

export function isSupportedAlg(alg: unknown): alg is JwsAlg {
  return typeof alg === 'string' && alg in SUPPORTED_JWS_ALGS;
}

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
export function verifyJws(
  publicKey: KeyObject,
  data: string,
  signatureB64u: string,
  alg: JwsAlg = 'ES256',
): boolean {
  const spec = SUPPORTED_JWS_ALGS[alg];
  if (!spec) return false;

  // The key's curve has to match the algorithm. Verifying an ES256 signature
  // with a P-384 key would otherwise fail confusingly rather than clearly.
  const curve = publicKey.asymmetricKeyDetails?.namedCurve;
  if (curve && curve !== spec.namedCurve) return false;

  try {
    return nodeVerify(
      spec.hash,
      Buffer.from(data, 'utf8'),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signatureB64u, 'base64url'),
    );
  } catch {
    return false;
  }
}

/** @deprecated use verifyJws. */
export const verifyEs256 = (publicKey: KeyObject, data: string, signatureB64u: string): boolean =>
  verifyJws(publicKey, data, signatureB64u, 'ES256');

/** JWK curve names, as they appear in a `cnf.jwk`. */
const JWK_CURVES: Record<string, JwsAlg> = { 'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512' };

/** Import an EC public key from a JWK (used for the holder's `cnf.jwk`). */
export function importEcJwk(jwk: unknown, allowed: readonly JwsAlg[] = DEFAULT_ALLOWED_ALGS): KeyObject | undefined {
  if (typeof jwk !== 'object' || jwk === null) return undefined;
  const { kty, crv } = jwk as Record<string, unknown>;
  if (kty !== 'EC' || typeof crv !== 'string') return undefined;
  const alg = JWK_CURVES[crv];
  if (!alg || !allowed.includes(alg)) return undefined;
  try {
    return createPublicKey({ key: jwk as import('node:crypto').JsonWebKey, format: 'jwk' });
  } catch {
    return undefined;
  }
}

/** @deprecated use importEcJwk. */
export const importEcP256Jwk = (jwk: unknown): KeyObject | undefined => importEcJwk(jwk, ['ES256']);

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
