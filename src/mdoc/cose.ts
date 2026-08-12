import { type KeyObject, createPublicKey } from 'node:crypto';
import { type JwsAlg, verifyJws } from '../crypto.ts';
import { decode, encode, entriesOf, get, toBytes } from './cbor.ts';

/**
 * COSE_Sign1 verification, enough for mdoc.
 *
 * mdoc signs with COSE rather than JOSE, but the underlying operation is the
 * same ECDSA verification. The part that must be exact is *what* is signed: not
 * the payload, but a `Sig_structure` array that also commits to the protected
 * header and any external data (RFC 9052 §4.4). Verifying the payload alone
 * would let an attacker move a signature to a different algorithm or context.
 */
export type CoseSign1 = {
  /** Protected header, still encoded — the signature commits to these bytes. */
  protectedBytes: Uint8Array;
  protectedHeader: Map<number, unknown> | Record<string, unknown>;
  unprotectedHeader: unknown;
  /**
   * The signed payload, or null when detached.
   *
   * mdoc's device signature is detached: the structure carries null and the
   * verifier reconstructs DeviceAuthenticationBytes. Issuer auth is not.
   */
  payload: Uint8Array | null;
  signature: Uint8Array;
};

/** COSE header labels used here (RFC 9052 §3.1, RFC 9360 §2). */
const HEADER_ALG = 1;
const HEADER_X5CHAIN = 33;

/**
 * COSE algorithm identifiers (IANA COSE Algorithms registry).
 *
 * ECDSA only, deliberately, and unlike the JOSE side — which gained RSA because
 * the eIDAS trusted lists are built on it. ISO/IEC 18013-5 §9.1.3.4 permits only
 * ECDSA and EdDSA for issuer and device authentication, so an RSA-signed
 * `issuerAuth` is not an interoperability case this is refusing; it is a
 * document outside the standard. The registry entries exist (`PS256` is -37,
 * `RS256` is -257) and are left unmapped, which makes the refusal a stated
 * position rather than a gap: `coseAlg` returns undefined and the caller reports
 * `UNSUPPORTED_ALGORITHM`.
 *
 * EdDSA is the half of the standard not implemented here. Nothing in the EUDI
 * deployment uses it — the reference issuer advertises `-7` alone (REPRODUCE.md).
 */
const COSE_ALGS: Record<string, JwsAlg> = { '-7': 'ES256', '-35': 'ES384', '-36': 'ES512' };

/**
 * The COSE identifiers for those of `algs` that COSE can express.
 *
 * A verifier advertising `mso_mdoc` support has to name algorithms as numbers,
 * and only the ECDSA ones have a mapping here — see `COSE_ALGS`. An allowlist
 * of RSA algorithms therefore advertises nothing for mdoc, which is the honest
 * answer rather than a silent translation into something ISO 18013-5 forbids.
 */
export function coseAlgIdentifiers(algs: readonly JwsAlg[]): number[] {
  return Object.entries(COSE_ALGS)
    .filter(([, alg]) => algs.includes(alg))
    .map(([identifier]) => Number(identifier));
}

export function parseCoseSign1(value: unknown): CoseSign1 {
  const array = Array.isArray(value) ? value : undefined;
  if (!array || array.length !== 4) {
    throw new Error('COSE_Sign1 must be a four element array');
  }
  const protectedBytes = toBytes(array[0]);
  return {
    protectedBytes,
    // An empty protected header encodes as a zero-length string, not as a map.
    protectedHeader: protectedBytes.length === 0 ? new Map() : (decode(protectedBytes) as Map<number, unknown>),
    unprotectedHeader: array[1],
    payload: array[2] === null || array[2] === undefined ? null : toBytes(array[2]),
    signature: toBytes(array[3]),
  };
}

/** The signature algorithm, from the protected header only. */
export function coseAlg(sign1: CoseSign1): JwsAlg | undefined {
  const alg = get(sign1.protectedHeader, HEADER_ALG);
  return typeof alg === 'number' ? COSE_ALGS[String(alg)] : undefined;
}

/**
 * The certificate chain from the `x5chain` header (label 33).
 *
 * A single certificate may appear either bare or wrapped in an array; both are
 * seen in practice, and the EU reference issuer uses the bare form.
 */
export function coseX5Chain(sign1: CoseSign1): Uint8Array[] {
  const fromUnprotected = get(sign1.unprotectedHeader, HEADER_X5CHAIN);
  const value = fromUnprotected ?? get(sign1.protectedHeader, HEADER_X5CHAIN);
  if (value === undefined) return [];
  const list = Array.isArray(value) ? value : [value];
  return list.map((entry) => toBytes(entry));
}

/**
 * Verify a COSE_Sign1 against a public key.
 *
 * `externalAad` is empty for mdoc issuer auth and for device auth; the context
 * there is carried inside the payload rather than alongside it.
 */
export function verifyCoseSign1(
  sign1: CoseSign1,
  publicKey: KeyObject,
  alg: JwsAlg,
  externalAad: Uint8Array = new Uint8Array(0),
): boolean {
  // A detached payload has to be supplied by the caller before verifying;
  // there is nothing to check a signature against otherwise.
  if (sign1.payload === null) return false;

  const sigStructure = encode(['Signature1', sign1.protectedBytes, externalAad, sign1.payload]);

  // COSE carries ECDSA signatures as raw R||S, the same as JWS, so the existing
  // verifier applies once the signing input is built.
  return verifyJws(
    publicKey,
    sigStructure,
    Buffer.from(sign1.signature).toString('base64url'),
    alg,
  );
}

/** Build a Node key from a COSE_Key (RFC 9052 §7), for the device key. */
export function coseKeyToPublicKey(coseKey: unknown): KeyObject | undefined {
  const kty = get(coseKey, 1);
  const crv = get(coseKey, -1);
  const x = get(coseKey, -2);
  const y = get(coseKey, -3);
  // kty 2 is EC2; curves 1, 2, 3 are P-256, P-384, P-521.
  const curves: Record<string, string> = { '1': 'P-256', '2': 'P-384', '3': 'P-521' };
  if (kty !== 2 || typeof crv !== 'number' || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
    return undefined;
  }
  const namedCurve = curves[String(crv)];
  if (!namedCurve) return undefined;

  try {
    return createPublicKey({
      key: {
        kty: 'EC',
        crv: namedCurve,
        x: Buffer.from(x).toString('base64url'),
        y: Buffer.from(y).toString('base64url'),
      },
      format: 'jwk',
    });
  } catch {
    return undefined;
  }
}

export { entriesOf };
