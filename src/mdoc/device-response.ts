import { type Outcome, accept, reject } from '../result.ts';
import { type EventSink, noopSink, withoutVerdict } from '../events.ts';
import { type AgeResult, evaluateAgeOver18Mdoc } from '../predicate/age.ts';
import { DEFAULT_ALLOWED_ALGS, type JwsAlg } from '../crypto.ts';
import type { TtlCache } from '../fetching.ts';
import type { TrustAnchors } from '../trust/anchors.ts';
import type { PathValidationOptions } from '../trust/issuer-key.ts';
import { decode, encode, encodeTag24, get, toBytes, untag } from './cbor.ts';
import { coseAlg, coseKeyToPublicKey, parseCoseSign1, verifyCoseSign1 } from './cose.ts';
import { type VerifiedMdoc, verifyMdoc } from './verify.ts';

/**
 * Verify a `DeviceResponse`: the thing a wallet actually sends.
 *
 * Two independent signatures, proving different things:
 *
 *  - **issuerAuth** proves the issuer attested these claims. Verified by
 *    `verifyMdoc`, against the trust anchors.
 *  - **deviceSignature** proves *this* wallet holds the key the issuer bound
 *    the credential to, and that it produced this response for *this* request.
 *
 * The second is why a stolen credential is not enough to impersonate someone.
 * It signs a `DeviceAuthentication` structure containing the SessionTranscript,
 * which for OID4VP commits to our client identifier, nonce and response URI —
 * so a response captured from one verifier cannot be replayed at another.
 */
export type DeviceResponseOptions = {
  /** `DeviceResponse` CBOR: base64url, as it appears in a VP Token. */
  deviceResponse: string | Uint8Array;
  anchors: TrustAnchors;
  /** From `buildSessionTranscript`. The device signature commits to it. */
  sessionTranscript: Uint8Array;
  expectedDocType?: string;
  allowedAlgs?: readonly JwsAlg[];
  pathValidation?: PathValidationOptions;
  now?: Date;
  tolerateMalformedValidityDates?: boolean;
  /** Revocation, both kinds handled by `verifyMdoc`; on by default, fails closed. */
  checkStatus?: boolean;
  statusFetch?: typeof fetch;
  statusCache?: TtlCache<string>;
  statusTimeoutMs?: number;
  checkCertificateRevocation?: boolean;
  revocationFetch?: typeof fetch;
  revocationCache?: TtlCache<Uint8Array>;
  revocationTimeoutMs?: number;
  clockSkewSeconds?: number;
  /**
   * Receives structured events for auditing and metrics. Carries no personal
   * data by construction — see `src/events.ts`.
   *
   * The verdict is this function's, not `verifyMdoc`'s: device authentication
   * runs after the issuer's credential has verified and can still reject it, so
   * an inner `verification.accepted` would record an acceptance the caller was
   * never given.
   */
  onEvent?: EventSink;
  /** Cancellation or overall deadline; see `MdocVerifyOptions.signal`. */
  signal?: AbortSignal;
};

export type VerifiedDeviceResponse = VerifiedMdoc & {
  /** Claims the device itself asserted, outside the issuer's signature. */
  deviceSignedClaims: Record<string, Record<string, unknown>>;
};

export async function verifyDeviceResponse(
  options: DeviceResponseOptions,
): Promise<Outcome<VerifiedDeviceResponse>> {
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

  let response: unknown;
  try {
    const bytes =
      typeof options.deviceResponse === 'string'
        ? new Uint8Array(Buffer.from(options.deviceResponse, 'base64url'))
        : options.deviceResponse;
    response = decode(bytes);
  } catch (error) {
    return rejectWith(reject('CREDENTIAL_MALFORMED', `Cannot decode DeviceResponse: ${String(error)}`));
  }

  // A non-zero status is the wallet reporting a failure of its own.
  const status = get(response, 'status');
  if (typeof status === 'number' && status !== 0) {
    return rejectWith(reject('RESPONSE_INVALID', `Wallet returned DeviceResponse status ${status}`));
  }

  const documents = get(response, 'documents');
  if (!Array.isArray(documents) || documents.length === 0) {
    return rejectWith(reject('RESPONSE_INVALID', 'DeviceResponse contains no documents'));
  }
  if (documents.length > 1) {
    // Our query asks for one credential; more than one is a protocol error.
    return rejectWith(reject('RESPONSE_INVALID', `Expected one document, got ${documents.length}`));
  }

  const document = documents[0];
  const docType = get(document, 'docType');
  if (typeof docType !== 'string') {
    return rejectWith(reject('CREDENTIAL_MALFORMED', 'Document has no docType'));
  }

  const issuerSigned = get(document, 'issuerSigned');
  if (issuerSigned === undefined) {
    return rejectWith(reject('CREDENTIAL_MALFORMED', 'Document has no issuerSigned'));
  }

  const verified = await verifyMdoc({
    // Everything `verifyMdoc` observes is worth recording; only its verdict is
    // premature, because device authentication has not run yet.
    onEvent: withoutVerdict(emit),
    issuerSigned: encode(issuerSigned),
    anchors: options.anchors,
    ...(options.expectedDocType ? { expectedDocType: options.expectedDocType } : {}),
    ...(options.allowedAlgs ? { allowedAlgs: options.allowedAlgs } : {}),
    ...(options.pathValidation ? { pathValidation: options.pathValidation } : {}),
    ...(options.now ? { now: options.now } : {}),
    ...(options.tolerateMalformedValidityDates
      ? { tolerateMalformedValidityDates: options.tolerateMalformedValidityDates }
      : {}),
    ...(options.checkStatus !== undefined ? { checkStatus: options.checkStatus } : {}),
    ...(options.statusFetch ? { statusFetch: options.statusFetch } : {}),
    ...(options.statusCache ? { statusCache: options.statusCache } : {}),
    ...(options.statusTimeoutMs ? { statusTimeoutMs: options.statusTimeoutMs } : {}),
    ...(options.checkCertificateRevocation !== undefined
      ? { checkCertificateRevocation: options.checkCertificateRevocation }
      : {}),
    ...(options.revocationFetch ? { revocationFetch: options.revocationFetch } : {}),
    ...(options.revocationCache ? { revocationCache: options.revocationCache } : {}),
    ...(options.revocationTimeoutMs ? { revocationTimeoutMs: options.revocationTimeoutMs } : {}),
    ...(options.clockSkewSeconds ? { clockSkewSeconds: options.clockSkewSeconds } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
  });
  if (!verified.verified) return rejectWith(verified);

  // The document's own docType must match the one the issuer signed, or a
  // wallet could present a PID as though it were something else.
  if (docType !== verified.value.docType) {
    return rejectWith(
      reject('CREDENTIAL_MALFORMED', `docType ${docType} does not match the signed ${verified.value.docType}`),
    );
  }

  const deviceAuth = await verifyDeviceAuth(document, verified.value, options);
  if (!deviceAuth.verified) return rejectWith(deviceAuth);

  emit({
    type: 'verification.accepted',
    format: 'mso_mdoc',
    credentialTypes: [verified.value.docType],
    durationMs: Date.now() - startedAt,
  });

  return accept({ ...verified.value, deviceSignedClaims: deviceAuth.value });
}

export type AgeOver18MdocOptions = DeviceResponseOptions & {
  /**
   * Namespace holding the age elements. Defaults to the doc type.
   *
   * The default is right for the EUDI PID, where both are
   * `eu.europa.ec.eudi.pid.1`, and **wrong in general**: an ISO mDL has doc
   * type `org.iso.18013.5.1.mDL` and namespace `org.iso.18013.5.1`. mdoc does
   * not require the two to agree, so anything but a PID should say which.
   */
  namespace?: string;
};

/**
 * Verify a DeviceResponse and evaluate the age-over-18 predicate in one step —
 * the mdoc counterpart to `verifyAgeOver18SdJwtVc`.
 *
 * It existed as a shape before it existed as a function: `oid4vp/response.ts`
 * composed `verifyDeviceResponse` with `evaluateAgeOver18Mdoc` by hand, which
 * meant the mdoc branch carried its own copy of the verdict-ownership rule
 * below while the SD-JWT branch got it from `verifyAgeOver18SdJwtVc`. Two
 * copies of a rule is one more than can be relied on.
 *
 * The verdict is this function's, for the reason `src/events.ts` gives: the
 * predicate can reject a device response that verified perfectly, and an inner
 * `verification.accepted` would record an acceptance the caller never got.
 */
export async function verifyAgeOver18Mdoc(
  options: AgeOver18MdocOptions,
): Promise<Outcome<VerifiedDeviceResponse & AgeResult>> {
  const emit = options.onEvent ?? noopSink;
  const startedAt = Date.now();
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

  const verified = await verifyDeviceResponse({ ...options, onEvent: withoutVerdict(emit) });
  if (!verified.verified) return rejectWith(verified);

  const namespace = options.namespace ?? verified.value.docType;
  const age = evaluateAgeOver18Mdoc(verified.value.claims[namespace] ?? {}, options.now ?? new Date());
  if (!age.verified) return rejectWith(age);

  emit({
    type: 'verification.accepted',
    format: 'mso_mdoc',
    credentialTypes: [verified.value.docType],
    evidence: age.value.evidence,
    durationMs: Date.now() - startedAt,
  });

  return accept({ ...verified.value, ...age.value });
}

async function verifyDeviceAuth(
  document: unknown,
  verified: VerifiedMdoc,
  options: DeviceResponseOptions,
): Promise<Outcome<Record<string, Record<string, unknown>>>> {
  const deviceSigned = get(document, 'deviceSigned');
  if (deviceSigned === undefined) {
    return reject('KEY_BINDING_MISSING', 'Document carries no deviceSigned');
  }

  const deviceAuth = get(deviceSigned, 'deviceAuth');
  const deviceSignature = get(deviceAuth, 'deviceSignature');
  if (deviceSignature === undefined) {
    // deviceMac is the other permitted form. It requires an ECDH session key
    // that OID4VP over redirects does not establish, so its absence here is a
    // rejection rather than a gap to paper over.
    return reject(
      'KEY_BINDING_MISSING',
      get(deviceAuth, 'deviceMac') !== undefined
        ? 'deviceMac authentication is not supported; a deviceSignature is required'
        : 'deviceAuth carries neither a deviceSignature nor a deviceMac',
    );
  }

  let sign1;
  try {
    sign1 = parseCoseSign1(deviceSignature);
  } catch (error) {
    return reject('KEY_BINDING_INVALID', `deviceSignature is not a COSE_Sign1: ${String(error)}`);
  }

  const alg = coseAlg(sign1);
  const allowed = options.allowedAlgs ?? DEFAULT_ALLOWED_ALGS;
  if (!alg || !allowed.includes(alg)) {
    return reject('UNSUPPORTED_ALGORITHM', `Device signature alg is not in the allowed set`);
  }

  const deviceKey = coseKeyToPublicKey(verified.deviceKey);
  if (!deviceKey) {
    return reject('KEY_BINDING_INVALID', 'The issuer did not bind a usable device key');
  }

  // DeviceNameSpacesBytes must be used exactly as received: the signature
  // covers those bytes, so re-encoding the decoded value would not reproduce
  // them if the wallet's encoder differs from ours in any detail.
  let deviceNameSpacesBytes: Uint8Array;
  try {
    deviceNameSpacesBytes = encodeTag24(toBytes(untag(get(deviceSigned, 'nameSpaces'))));
  } catch (error) {
    return reject('CREDENTIAL_MALFORMED', `Unreadable DeviceNameSpaces: ${String(error)}`);
  }

  // The payload is detached: the COSE_Sign1 carries null and the verifier
  // reconstructs what was signed. Getting this wrong presents as a bad
  // signature, so it is the first thing to check when device auth fails.
  //
  //   DeviceAuthentication = ["DeviceAuthentication", SessionTranscript,
  //                           DocType, DeviceNameSpacesBytes]
  //
  // Assembled from already-encoded parts rather than re-serialised, so the
  // transcript and the wallet's namespace bytes survive byte for byte.
  const deviceAuthentication = Uint8Array.from([
    0x84, // array of four
    ...encode('DeviceAuthentication'),
    ...options.sessionTranscript,
    ...encode(verified.docType),
    ...deviceNameSpacesBytes,
  ]);

  if (!verifyCoseSign1({ ...sign1, payload: encodeTag24(deviceAuthentication) }, deviceKey, alg)) {
    return reject(
      'KEY_BINDING_INVALID',
      'Device signature does not verify over this session transcript — the response may have been produced for a different verifier',
    );
  }

  return accept(readDeviceNameSpaces(deviceNameSpacesBytes));
}

function readDeviceNameSpaces(tagged: Uint8Array): Record<string, Record<string, unknown>> {
  try {
    const inner = decode(tagged);
    const namespaces = decode(toBytes(untag(inner)));
    const result: Record<string, Record<string, unknown>> = {};
    for (const [ns, elements] of Object.entries(namespaces as Record<string, unknown>)) {
      result[ns] = elements as Record<string, unknown>;
    }
    return result;
  } catch {
    return {};
  }
}
