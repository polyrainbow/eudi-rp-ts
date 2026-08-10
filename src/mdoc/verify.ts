import { X509Certificate, createHash } from 'node:crypto';
import { DEFAULT_ALLOWED_ALGS, type JwsAlg } from '../crypto.ts';
import { type Outcome, accept, reject } from '../result.ts';
import type { TrustAnchors } from '../trust/anchors.ts';
import { type PathValidationOptions, resolveIssuerCertificateChain } from '../trust/issuer-key.ts';
import { decode, decodeEmbedded, encodeTag24, entriesOf, get, toBytes, untag } from './cbor.ts';
import { coseAlg, coseX5Chain, parseCoseSign1, verifyCoseSign1 } from './cose.ts';

/**
 * ISO/IEC 18013-5 mdoc verification.
 *
 * Same shape as the SD-JWT VC path and the same trust layer: the format is
 * decoded here, but issuer identity still runs through `TrustAnchors` and the
 * certificate path validation used everywhere else. mdoc carries its chain in
 * the COSE `x5chain` header rather than a JOSE `x5c`, which is the only
 * difference that reaches the trust code.
 *
 * What is verified:
 *   - the issuer's COSE_Sign1 over the Mobile Security Object
 *   - that chain, against the caller's trust anchors
 *   - every disclosed element against its digest in the MSO
 *   - the MSO's own validity window and doc type
 *
 * Device authentication is separate — see `verifyDeviceResponse`.
 */
export type MdocVerifyOptions = {
  /** `IssuerSigned`, as issued: base64url CBOR. */
  issuerSigned: string | Uint8Array;
  anchors: TrustAnchors;
  /** Expected doc type, e.g. `eu.europa.ec.eudi.pid.1`. */
  expectedDocType?: string;
  allowedAlgs?: readonly JwsAlg[];
  pathValidation?: PathValidationOptions;
  now?: Date;
  /**
   * Accept a `validUntil` that is not valid RFC 3339.
   *
   * The EU reference issuer currently emits `...+00:00Z`, carrying both an
   * offset and a `Z` — reported upstream as issue #177. Strict by default,
   * because a validity window that cannot be read is not a validity window.
   */
  tolerateMalformedValidityDates?: boolean;
};

export type VerifiedMdoc = {
  docType: string;
  /** Disclosed elements, by namespace then element identifier. */
  claims: Record<string, Record<string, unknown>>;
  issuerCertificateSubject: string;
  /** The holder's device key, for device authentication. */
  deviceKey: unknown;
  validity: { signed: Date; validFrom: Date; validUntil: Date | undefined };
};

export async function verifyMdoc(options: MdocVerifyOptions): Promise<Outcome<VerifiedMdoc>> {
  const now = options.now ?? new Date();
  const allowedAlgs = options.allowedAlgs ?? DEFAULT_ALLOWED_ALGS;

  let issuerSigned: unknown;
  try {
    const bytes =
      typeof options.issuerSigned === 'string'
        ? new Uint8Array(Buffer.from(options.issuerSigned, 'base64url'))
        : options.issuerSigned;
    issuerSigned = decode(bytes);
  } catch (error) {
    return reject('CREDENTIAL_MALFORMED', `Cannot decode IssuerSigned CBOR: ${String(error)}`);
  }

  let sign1;
  try {
    sign1 = parseCoseSign1(get(issuerSigned, 'issuerAuth'));
  } catch (error) {
    return reject('CREDENTIAL_MALFORMED', `issuerAuth is not a COSE_Sign1: ${String(error)}`);
  }

  const alg = coseAlg(sign1);
  if (!alg || !allowedAlgs.includes(alg)) {
    return reject('UNSUPPORTED_ALGORITHM', `COSE alg is not in the allowed set (${allowedAlgs.join(', ')})`);
  }

  // The chain lives in the COSE header rather than a JOSE one, but from here
  // trust is established exactly as it is for SD-JWT VC.
  const chainDer = coseX5Chain(sign1);
  if (chainDer.length === 0) {
    return reject('ISSUER_KEY_UNRESOLVABLE', 'issuerAuth carries no x5chain header');
  }
  let chain: X509Certificate[];
  try {
    chain = chainDer.map((der) => new X509Certificate(Buffer.from(der)));
  } catch (error) {
    return reject('ISSUER_KEY_UNRESOLVABLE', `Cannot parse x5chain certificate: ${String(error)}`);
  }

  const trusted = resolveIssuerCertificateChain(chain, options.anchors, now, options.pathValidation ?? {});
  if (!trusted.verified) return trusted;

  if (!verifyCoseSign1(sign1, trusted.value.leaf.publicKey, alg)) {
    return reject('ISSUER_SIGNATURE_INVALID', 'issuerAuth signature does not verify');
  }

  // MobileSecurityObjectBytes is `#6.24(bstr .cbor MobileSecurityObject)`.
  if (sign1.payload === null) {
    return reject('CREDENTIAL_MALFORMED', 'issuerAuth has a detached payload');
  }
  let mso: unknown;
  try {
    mso = decodeEmbedded(untag(decode(sign1.payload)));
  } catch (error) {
    return reject('CREDENTIAL_MALFORMED', `Cannot decode MobileSecurityObject: ${String(error)}`);
  }

  const docType = get(mso, 'docType');
  if (typeof docType !== 'string') {
    return reject('CREDENTIAL_MALFORMED', 'MobileSecurityObject has no docType');
  }
  if (options.expectedDocType && docType !== options.expectedDocType) {
    return reject('UNEXPECTED_VCT', `Expected docType ${options.expectedDocType}, got ${docType}`);
  }

  const validity = readValidity(get(mso, 'validityInfo'));
  if (!validity.ok) {
    if (!options.tolerateMalformedValidityDates) {
      return reject('CREDENTIAL_MALFORMED', validity.detail);
    }
  }
  if (validity.validFrom && now < validity.validFrom) {
    return reject('CREDENTIAL_NOT_YET_VALID', `Valid from ${validity.validFrom.toISOString()}`);
  }
  if (validity.validUntil && now > validity.validUntil) {
    return reject('CREDENTIAL_EXPIRED', `Expired at ${validity.validUntil.toISOString()}`);
  }

  const digestAlgorithm = get(mso, 'digestAlgorithm');
  const nodeDigest = { 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' }[
    String(digestAlgorithm)
  ];
  if (!nodeDigest) {
    return reject('UNSUPPORTED_ALGORITHM', `Unsupported digestAlgorithm ${String(digestAlgorithm)}`);
  }

  const claims = checkDigests(issuerSigned, get(mso, 'valueDigests'), nodeDigest);
  if (!claims.verified) return claims;

  return accept({
    docType,
    claims: claims.value,
    issuerCertificateSubject: trusted.value.leaf.subject,
    deviceKey: get(get(mso, 'deviceKeyInfo'), 'deviceKey'),
    validity: {
      signed: validity.signed ?? new Date(0),
      validFrom: validity.validFrom ?? new Date(0),
      validUntil: validity.validUntil,
    },
  });
}

/**
 * Check every disclosed element against the digest the issuer committed to.
 *
 * This is what makes selective disclosure safe in mdoc: the signature covers
 * only the digests, so an element that is present but whose digest is absent or
 * different has been added or altered after issuance.
 */
function checkDigests(
  issuerSigned: unknown,
  valueDigests: unknown,
  nodeDigest: string,
): Outcome<Record<string, Record<string, unknown>>> {
  const claims: Record<string, Record<string, unknown>> = {};

  for (const [namespace, items] of entriesOf(get(issuerSigned, 'nameSpaces'))) {
    if (!Array.isArray(items)) {
      return reject('CREDENTIAL_MALFORMED', `Namespace ${String(namespace)} is not an array`);
    }
    const expected = get(valueDigests, namespace);
    if (expected === undefined) {
      return reject('CREDENTIAL_MALFORMED', `No digests for disclosed namespace ${String(namespace)}`);
    }

    const bucket: Record<string, unknown> = {};
    for (const tagged of items) {
      // The digest is over the tagged IssuerSignedItemBytes exactly as encoded,
      // not over the item's contents — re-encoding would not reproduce it.
      let itemBytes: Uint8Array;
      let item: unknown;
      try {
        itemBytes = toBytes(untag(tagged));
        item = decode(itemBytes);
      } catch (error) {
        return reject('CREDENTIAL_MALFORMED', `Unreadable IssuerSignedItem: ${String(error)}`);
      }

      const digestId = get(item, 'digestID');
      const identifier = get(item, 'elementIdentifier');
      if (typeof digestId !== 'number' || typeof identifier !== 'string') {
        return reject('CREDENTIAL_MALFORMED', 'IssuerSignedItem is missing digestID or elementIdentifier');
      }

      const committed = get(expected, digestId);
      if (committed === undefined) {
        return reject('CREDENTIAL_MALFORMED', `Element ${identifier} has no digest in the MSO`);
      }

      // Re-encode the tag so the hash covers the same bytes the issuer hashed.
      const actual = createHash(nodeDigest).update(encodeTag24(itemBytes)).digest();
      if (!actual.equals(Buffer.from(toBytes(committed)))) {
        return reject('CREDENTIAL_MALFORMED', `Digest mismatch for element ${identifier}`);
      }

      bucket[identifier] = normalise(get(item, 'elementValue'));
    }
    claims[String(namespace)] = bucket;
  }

  return accept(claims);
}

type Validity = { ok: boolean; detail: string; signed?: Date; validFrom?: Date; validUntil?: Date };

function readValidity(validityInfo: unknown): Validity {
  const asDate = (value: unknown): Date | undefined => {
    const raw = untag(value);
    if (raw instanceof Date) return Number.isNaN(raw.getTime()) ? undefined : raw;
    if (typeof raw === 'string') {
      const parsed = new Date(raw);
      return Number.isNaN(parsed.getTime()) ? undefined : parsed;
    }
    return undefined;
  };

  const signed = asDate(get(validityInfo, 'signed'));
  const validFrom = asDate(get(validityInfo, 'validFrom'));
  const validUntil = asDate(get(validityInfo, 'validUntil'));
  const rawUntil = get(validityInfo, 'validUntil');

  if (rawUntil !== undefined && validUntil === undefined) {
    return {
      ok: false,
      detail: 'validUntil is not a readable date (the EU reference issuer emits "+00:00Z", upstream issue #177)',
      ...(signed ? { signed } : {}),
      ...(validFrom ? { validFrom } : {}),
    };
  }
  return {
    ok: true,
    detail: '',
    ...(signed ? { signed } : {}),
    ...(validFrom ? { validFrom } : {}),
    ...(validUntil ? { validUntil } : {}),
  };
}

/** CBOR gives Maps and Dates; hand back something a caller can treat as JSON. */
function normalise(value: unknown): unknown {
  const raw = untag(value);
  if (raw instanceof Date) return raw.toISOString();
  if (raw instanceof Uint8Array) return Buffer.from(raw).toString('base64');
  if (Array.isArray(raw)) return raw.map(normalise);
  if (raw instanceof Map) {
    return Object.fromEntries([...raw.entries()].map(([k, v]) => [String(k), normalise(v)]));
  }
  if (raw && typeof raw === 'object') {
    return Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, normalise(v)]));
  }
  return raw;
}
