import { X509Certificate, createHash } from 'node:crypto';
import { DEFAULT_ALLOWED_ALGS, type JwsAlg, keyUnusableFor } from '../crypto.ts';
import type { TtlCache } from '../fetching.ts';
import { type Outcome, accept, reject } from '../result.ts';
import type { TrustAnchors } from '../trust/anchors.ts';
import { type PathValidationOptions, resolveIssuerCertificateChain } from '../trust/issuer-key.ts';
import { checkChainRevocation, revocationRejection, revocationVia } from '../trust/revocation.ts';
import { type EventSink, noopSink } from '../events.ts';
import { type StatusListReference, checkStatusList } from '../trust/status.ts';
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
 *   - the MSO's status reference, against the issuer's Token Status List
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
  /**
   * Check the MSO's status list. On by default, matching `verifyCredential`:
   * an mdoc carrying a status reference we do not check is one we might be
   * accepting after revocation. The EU reference issuer populates it — see
   * `test/fixtures/real/`. Requires network access to the issuer's status
   * endpoint, so tests that must stay offline turn it off explicitly.
   */
  checkStatus?: boolean;
  /** Injectable fetch for status list retrieval, for tests. */
  statusFetch?: typeof fetch;
  /**
   * Shared status list cache. Strongly recommended in a service: without one,
   * every verification refetches a document that covers many credentials.
   */
  statusCache?: TtlCache<string>;
  /** Abort a status list request after this long. */
  statusTimeoutMs?: number;
  /**
   * Check the issuer's *certificate chain* for revocation, via CRL or OCSP.
   * On by default and fails closed, exactly as for SD-JWT VC.
   */
  checkCertificateRevocation?: boolean;
  /** Injectable fetch for CRL and OCSP retrieval, for tests. */
  revocationFetch?: typeof fetch;
  /** Shared CRL/OCSP cache. */
  revocationCache?: TtlCache<Uint8Array>;
  /** Abort a CRL or OCSP request after this long. */
  revocationTimeoutMs?: number;
  /** Tolerance for clock differences with the issuer, in seconds. */
  clockSkewSeconds?: number;
  /**
   * Receives structured events for auditing and metrics. Carries no personal
   * data by construction — see `src/events.ts`. The same stream the SD-JWT VC
   * path emits: the format a wallet answers in must not decide whether a
   * verification is auditable.
   */
  onEvent?: EventSink;
  /**
   * Cancellation, and the only bound on the whole verification — the same
   * option `verifyCredential` takes, for the same reason: `timeoutMs` bounds
   * one request and this call can make several. Reported as
   * `VERIFICATION_ABORTED`.
   */
  signal?: AbortSignal;
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
  const emit = options.onEvent ?? noopSink;
  const startedAt = Date.now();

  /** Every rejecting exit from this function goes through this. */
  const rejectWith = <T>(outcome: Outcome<T>): Outcome<T> => {
    if (!outcome.verified) {
      emit({
        type: 'verification.rejected',
        format: 'mso_mdoc',
        reason: outcome.reason,
        durationMs: Date.now() - startedAt,
      });
    }
    return outcome;
  };

  // Before any of it, for the reason `verifyCredential` gives: the caller has
  // already said it does not want the answer.
  if (options.signal?.aborted) {
    return rejectWith(reject('VERIFICATION_ABORTED', 'Cancelled before verification began'));
  }

  let issuerSigned: unknown;
  try {
    const bytes =
      typeof options.issuerSigned === 'string'
        ? new Uint8Array(Buffer.from(options.issuerSigned, 'base64url'))
        : options.issuerSigned;
    issuerSigned = decode(bytes);
  } catch (error) {
    return rejectWith(reject('CREDENTIAL_MALFORMED', `Cannot decode IssuerSigned CBOR: ${String(error)}`));
  }

  let sign1;
  try {
    sign1 = parseCoseSign1(get(issuerSigned, 'issuerAuth'));
  } catch (error) {
    return rejectWith(reject('CREDENTIAL_MALFORMED', `issuerAuth is not a COSE_Sign1: ${String(error)}`));
  }

  const alg = coseAlg(sign1);
  if (!alg || !allowedAlgs.includes(alg)) {
    return rejectWith(
      reject('UNSUPPORTED_ALGORITHM', `COSE alg is not in the allowed set (${allowedAlgs.join(', ')})`),
    );
  }

  // The doc type is inside the signed MSO, which is unreadable until the
  // signature below has verified — so unlike the SD-JWT VC path, this cannot
  // name the credential type yet. It is on `verification.accepted` instead.
  emit({ type: 'verification.started', format: 'mso_mdoc', vct: undefined });

  // The chain lives in the COSE header rather than a JOSE one, but from here
  // trust is established exactly as it is for SD-JWT VC.
  const chainDer = coseX5Chain(sign1);
  if (chainDer.length === 0) {
    return rejectWith(reject('ISSUER_KEY_UNRESOLVABLE', 'issuerAuth carries no x5chain header'));
  }
  let chain: X509Certificate[];
  try {
    chain = chainDer.map((der) => new X509Certificate(Buffer.from(der)));
  } catch (error) {
    return rejectWith(reject('ISSUER_KEY_UNRESOLVABLE', `Cannot parse x5chain certificate: ${String(error)}`));
  }

  const trusted = resolveIssuerCertificateChain(chain, options.anchors, now, options.pathValidation ?? {});
  if (!trusted.verified) return rejectWith(trusted);

  const mismatch = keyUnusableFor(trusted.value.leaf.publicKey, alg);
  if (mismatch) {
    return rejectWith(
      reject('UNSUPPORTED_ALGORITHM', `Document signer key does not match issuerAuth: ${mismatch}`),
    );
  }
  emit({
    type: 'issuer.resolved',
    format: 'mso_mdoc',
    subject: trusted.value.leaf.subject,
    chainLength: trusted.value.chain.length,
  });

  if (!verifyCoseSign1(sign1, trusted.value.leaf.publicKey, alg)) {
    return rejectWith(reject('ISSUER_SIGNATURE_INVALID', 'issuerAuth signature does not verify'));
  }

  // MobileSecurityObjectBytes is `#6.24(bstr .cbor MobileSecurityObject)`.
  if (sign1.payload === null) {
    return rejectWith(reject('CREDENTIAL_MALFORMED', 'issuerAuth has a detached payload'));
  }
  let mso: unknown;
  try {
    mso = decodeEmbedded(untag(decode(sign1.payload)));
  } catch (error) {
    return rejectWith(reject('CREDENTIAL_MALFORMED', `Cannot decode MobileSecurityObject: ${String(error)}`));
  }

  const docType = get(mso, 'docType');
  if (typeof docType !== 'string') {
    return rejectWith(reject('CREDENTIAL_MALFORMED', 'MobileSecurityObject has no docType'));
  }
  if (options.expectedDocType && docType !== options.expectedDocType) {
    return rejectWith(reject('UNEXPECTED_VCT', `Expected docType ${options.expectedDocType}, got ${docType}`));
  }

  const validity = readValidity(get(mso, 'validityInfo'));
  if (!validity.ok) {
    if (!options.tolerateMalformedValidityDates) {
      return rejectWith(reject('CREDENTIAL_MALFORMED', validity.detail));
    }
  }
  if (validity.validFrom && now < validity.validFrom) {
    return rejectWith(reject('CREDENTIAL_NOT_YET_VALID', `Valid from ${validity.validFrom.toISOString()}`));
  }
  if (validity.validUntil && now > validity.validUntil) {
    return rejectWith(reject('CREDENTIAL_EXPIRED', `Expired at ${validity.validUntil.toISOString()}`));
  }

  const digestAlgorithm = get(mso, 'digestAlgorithm');
  const nodeDigest = { 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' }[
    String(digestAlgorithm)
  ];
  if (!nodeDigest) {
    return rejectWith(
      reject('UNSUPPORTED_ALGORITHM', `Unsupported digestAlgorithm ${String(digestAlgorithm)}`),
    );
  }

  const claims = checkDigests(issuerSigned, get(mso, 'valueDigests'), nodeDigest);
  if (!claims.verified) return rejectWith(claims);

  // Last, and only once everything local has passed: it is the one step that
  // reaches the network, and a credential that fails any check above does not
  // need a status lookup to be rejected.
  if (options.checkStatus ?? true) {
    const reference = readStatusReference(get(mso, 'status'));
    if (!reference.verified) return rejectWith(reference);

    if (reference.value) {
      const outcome = await checkStatusList(reference.value, {
        anchors: options.anchors,
        now,
        ...(options.statusFetch ? { fetchImpl: options.statusFetch } : {}),
        ...(options.statusCache ? { cache: options.statusCache } : {}),
        ...(options.statusTimeoutMs ? { timeoutMs: options.statusTimeoutMs } : {}),
        ...(options.clockSkewSeconds ? { clockSkewSeconds: options.clockSkewSeconds } : {}),
        // The status list is JOSE even when the credential is COSE, so the
        // policy that reaches it is the caller's list, not the COSE subset.
        allowedAlgs,
        ...(options.signal ? { signal: options.signal } : {}),
      });
      // Not reported as a status check when the caller cancelled: nothing was
      // checked, and the terminal rejection already says why.
      if (outcome.kind === 'aborted') {
        return rejectWith(reject('VERIFICATION_ABORTED', 'Cancelled while fetching the status list'));
      }
      // Emitted before the rejections below, so a revoked credential is
      // recorded as having been checked and not only as having been refused.
      emit({
        type: 'status.checked',
        outcome: outcome.kind === 'valid' ? 'valid' : outcome.kind === 'revoked' ? 'revoked' : 'unavailable',
        cached: options.statusCache !== undefined,
      });
      if (outcome.kind === 'revoked') {
        return rejectWith(
          reject('CREDENTIAL_REVOKED', `The issuer has revoked this credential (status ${outcome.status})`),
        );
      }
      // Fails closed, as on the SD-JWT VC path: a status list we could not
      // check is not a status list that said valid.
      if (outcome.kind === 'unavailable') {
        return rejectWith(reject('STATUS_UNAVAILABLE', outcome.detail));
      }
    }
  }

  // The issuer's own certificates, which is a different question from the
  // credential's status list above.
  if (options.checkCertificateRevocation ?? true) {
    const revocation = await checkChainRevocation(trusted.value.chain, {
      now,
      ...(options.revocationFetch ? { fetchImpl: options.revocationFetch } : {}),
      ...(options.revocationCache ? { cache: options.revocationCache } : {}),
      ...(options.revocationTimeoutMs ? { timeoutMs: options.revocationTimeoutMs } : {}),
      ...(options.clockSkewSeconds ? { clockSkewSeconds: options.clockSkewSeconds } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
    });
    if (revocation.kind !== 'aborted') {
      emit({ type: 'issuer.revocation.checked', outcome: revocation.kind, via: revocationVia(revocation) });
    }
    const rejected = revocationRejection(revocation);
    if (rejected) return rejectWith(rejected);
  }

  emit({ type: 'verification.accepted', format: 'mso_mdoc', vct: docType, durationMs: Date.now() - startedAt });

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
 * The MSO's status reference, if it carries one.
 *
 * `undefined` means the issuer published no revocation mechanism for this
 * credential, which is nothing to check. It is not the same as a `status`
 * element we cannot read: an issuer that said how to revoke, in terms we do not
 * implement, has not told us this credential is still valid. That fails closed,
 * on the same reasoning as an unevaluable Name Constraint failing the chain.
 *
 * `identifier_list` — which the EU reference issuer publishes alongside
 * `status_list` — is such a mechanism. When both are present the status list
 * settles it and the identifier list is not consulted.
 */
function readStatusReference(status: unknown): Outcome<StatusListReference | undefined> {
  if (status === undefined || status === null) return accept(undefined);

  const statusList = get(status, 'status_list');
  if (statusList === undefined) {
    const mechanisms = entriesOf(status).map(([key]) => String(key));
    return reject(
      'STATUS_UNAVAILABLE',
      `MSO carries a status element with no status_list (${mechanisms.join(', ') || 'empty'}), and no other mechanism is implemented`,
    );
  }

  const uri = get(statusList, 'uri');
  const index = get(statusList, 'idx');
  if (typeof uri !== 'string' || typeof index !== 'number') {
    return reject('CREDENTIAL_MALFORMED', 'MSO status_list is missing a string uri or a numeric idx');
  }

  return accept({ uri, index });
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
