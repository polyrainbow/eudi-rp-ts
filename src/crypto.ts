import { type KeyObject, constants, createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';

/**
 * Algorithms this can verify.
 *
 * ECDSA is what the EUDI reference deployment uses, end to end: the PID
 * document signer, the status list token and the wallet's key binding are all
 * `ES256`. RSA is here because the ecosystem a chain *terminates* in is not that
 * deployment — 2013 of the 2305 certificates on the live eIDAS trusted lists
 * carry RSA keys against 274 EC ones (REPRODUCE.md), so a qualified issuer
 * signing with `RS256` or `PS256` is the ordinary case outside the pilot, and
 * refusing it made three quarters of eIDAS unverifiable on principle.
 *
 * Two properties matter more than the list itself:
 *
 *  - The **caller** states which algorithms are acceptable and the token's own
 *    `alg` is checked against that list. Selecting the verification algorithm
 *    from the `alg` header is how algorithm substitution attacks work, so the
 *    default allowlist stays narrow and widening it is a deliberate act.
 *  - The **key** must match the algorithm. An RSA key cannot verify an `ES256`
 *    signature and a P-256 key cannot verify `ES384`; `keyUnusableFor` makes
 *    that a stated refusal rather than a confusing failure.
 */
export const SUPPORTED_JWS_ALGS = {
  ES256: { family: 'ec', hash: 'sha256', namedCurve: 'prime256v1' },
  ES384: { family: 'ec', hash: 'sha384', namedCurve: 'secp384r1' },
  ES512: { family: 'ec', hash: 'sha512', namedCurve: 'secp521r1' },
  // RSASSA-PKCS1-v1_5 (RFC 7518 §3.3).
  RS256: { family: 'rsa', hash: 'sha256', padding: 'pkcs1' },
  RS384: { family: 'rsa', hash: 'sha384', padding: 'pkcs1' },
  RS512: { family: 'rsa', hash: 'sha512', padding: 'pkcs1' },
  // RSASSA-PSS (RFC 7518 §3.5): MGF1 with the same hash, salt length equal to
  // the digest length — `RSA_PSS_SALTLEN_DIGEST`, rather than a literal.
  PS256: { family: 'rsa', hash: 'sha256', padding: 'pss' },
  PS384: { family: 'rsa', hash: 'sha384', padding: 'pss' },
  PS512: { family: 'rsa', hash: 'sha512', padding: 'pss' },
} as const;

export type JwsAlg = keyof typeof SUPPORTED_JWS_ALGS;
type AlgSpec = (typeof SUPPORTED_JWS_ALGS)[JwsAlg];

/**
 * RFC 7518 §3.3: "A key of size 2048 bits or larger MUST be used" with RS* and
 * PS*. Four of the 2305 certificates on the live trusted lists are 1024-bit, so
 * this refuses something real, which is the point of having a floor.
 */
export const MIN_RSA_MODULUS_BITS = 2048;

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
 * Why this key cannot be used with this algorithm, or undefined if it can.
 *
 * Returned as a sentence rather than a boolean because the caller that most
 * needs it — path validation — has to report a reason code, and
 * `SIGNATURE_INVALID` would be the wrong one: a 1024-bit RSA key or a P-256 key
 * offered for `ES384` is an unusable key, not a bad signature. Deriving that
 * distinction from a failed verification is exactly the mistake this codebase
 * has made once already.
 */
export function keyUnusableFor(publicKey: KeyObject, alg: JwsAlg): string | undefined {
  const spec: AlgSpec = SUPPORTED_JWS_ALGS[alg];
  const type = publicKey.asymmetricKeyType;

  if (spec.family === 'ec') {
    if (type !== 'ec') return `${alg} needs an EC key, got ${String(type)}`;
    const curve = publicKey.asymmetricKeyDetails?.namedCurve;
    // Verifying an ES256 signature with a P-384 key would otherwise fail
    // confusingly rather than clearly.
    if (curve && curve !== spec.namedCurve) {
      return `${alg} needs curve ${spec.namedCurve}, got ${curve}`;
    }
    return undefined;
  }

  // An `rsa-pss` key carries its parameters in the key itself (RFC 4055) and is
  // restricted to PSS, so it may not stand in for an RS* signature.
  const acceptable = spec.padding === 'pss' ? ['rsa', 'rsa-pss'] : ['rsa'];
  if (!type || !acceptable.includes(type)) {
    return `${alg} needs ${acceptable.join(' or ')}, got ${String(type)}`;
  }
  const bits = publicKey.asymmetricKeyDetails?.modulusLength;
  if (bits !== undefined && bits < MIN_RSA_MODULUS_BITS) {
    return `${alg} needs an RSA key of at least ${MIN_RSA_MODULUS_BITS} bits, got ${bits}`;
  }
  return undefined;
}

/**
 * Why no supported algorithm could use this key, or undefined if some could.
 *
 * The alg-specific pairing is `keyUnusableFor`; this is the question path
 * validation can ask, since a certificate names a key long before any token
 * names an algorithm. It refuses two things that are really on the live trusted
 * lists: 24 certificates carrying brainpool curves, which JOSE has no algorithm
 * for, and 4 carrying 1024-bit RSA keys (REPRODUCE.md).
 */
export function unsupportedKeyReason(publicKey: KeyObject): string | undefined {
  const type = publicKey.asymmetricKeyType;

  if (type === 'ec') {
    const curve = publicKey.asymmetricKeyDetails?.namedCurve;
    const known = Object.values(SUPPORTED_JWS_ALGS).some(
      (spec) => spec.family === 'ec' && spec.namedCurve === curve,
    );
    return curve === undefined || known
      ? undefined
      : `EC curve ${curve} has no JWS algorithm here (P-256, P-384 and P-521 only)`;
  }

  if (type === 'rsa' || type === 'rsa-pss') {
    const bits = publicKey.asymmetricKeyDetails?.modulusLength;
    return bits !== undefined && bits < MIN_RSA_MODULUS_BITS
      ? `RSA key is ${bits} bits, and RFC 7518 §3.3 requires at least ${MIN_RSA_MODULUS_BITS}`
      : undefined;
  }

  return `key type ${String(type)} is not supported (EC and RSA are)`;
}

/**
 * Verify a JWS signature over `data` (the `header.payload` signing input).
 *
 * JWS carries ECDSA signatures as raw R||S (RFC 7515 §3.4), which node calls
 * `ieee-p1363`. The default `der` encoding would reject every valid JWS. RSA has
 * no such trap — its signature is a plain integer — but it does carry two
 * paddings, and reading `alg` as PKCS#1 when the signer meant PSS produces a
 * clean "invalid signature" for a perfectly good signature.
 */
export function verifyJws(
  publicKey: KeyObject,
  /** JWS signing input as a string, or raw signed bytes as for COSE. */
  data: string | Uint8Array,
  signatureB64u: string,
  alg: JwsAlg = 'ES256',
): boolean {
  const spec: AlgSpec | undefined = SUPPORTED_JWS_ALGS[alg];
  if (!spec) return false;
  // Defence in depth: callers that can report a reason check this first and say
  // something useful. Here it only has to fail closed.
  if (keyUnusableFor(publicKey, alg)) return false;

  const input = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  const signature = Buffer.from(signatureB64u, 'base64url');

  try {
    if (spec.family === 'ec') {
      return nodeVerify(spec.hash, input, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
    }
    return nodeVerify(
      spec.hash,
      input,
      spec.padding === 'pss'
        ? {
            key: publicKey,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
          }
        : { key: publicKey, padding: constants.RSA_PKCS1_PADDING },
      signature,
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

/**
 * Import a public key from a JWK (used for the holder's `cnf.jwk`).
 *
 * The key is imported only if some allowed algorithm could use it, which for EC
 * is decided by the curve and for RSA cannot be decided here at all — an RSA
 * JWK names no algorithm, so any RSA algorithm in the allowed set admits it and
 * the pairing with the KB-JWT's own `alg` is enforced by `verifyJws`. Returning
 * a key an allowed algorithm could never use would only move the failure later.
 */
export function importPublicJwk(
  jwk: unknown,
  allowed: readonly JwsAlg[] = DEFAULT_ALLOWED_ALGS,
): KeyObject | undefined {
  if (typeof jwk !== 'object' || jwk === null) return undefined;
  const { kty, crv } = jwk as Record<string, unknown>;

  if (kty === 'EC') {
    if (typeof crv !== 'string') return undefined;
    const alg = JWK_CURVES[crv];
    if (!alg || !allowed.includes(alg)) return undefined;
  } else if (kty === 'RSA') {
    if (!allowed.some((alg) => SUPPORTED_JWS_ALGS[alg].family === 'rsa')) return undefined;
  } else {
    return undefined;
  }

  try {
    return createPublicKey({ key: jwk as import('node:crypto').JsonWebKey, format: 'jwk' });
  } catch {
    return undefined;
  }
}

/** @deprecated use importPublicJwk, which also accepts RSA. */
export const importEcJwk = importPublicJwk;

/** @deprecated use importPublicJwk. */
export const importEcP256Jwk = (jwk: unknown): KeyObject | undefined => importPublicJwk(jwk, ['ES256']);

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
