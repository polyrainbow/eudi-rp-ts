import { Openid4vpVerifier } from '@openid4vc/openid4vp';
import type { JWK } from 'jose';
import type { TtlCache } from '../fetching.ts';
import type { VerifierIdentity } from './identity.ts';
import { type Outcome, type Rejected, accept, reject } from '../result.ts';
import { type CredentialFormat, type EventSink, noopSink, withoutVerdict } from '../events.ts';
import type { TrustAnchors } from '../trust/anchors.ts';
import { type VerifiedCredential, verifySdJwtVc } from '../verify.ts';
import { createDecryptJwe, createVerifyJwt, generateRandom, hashCallback } from './callbacks.ts';
import { unsatisfiedClaims } from './claims.ts';
import {
  type CredentialQuery,
  type DcqlQuery,
  type MdocCredentialQuery,
  type SdJwtVcCredentialQuery,
  credentialQueryById,
  redundantCredential,
  unsatisfiedRequirement,
} from './query.ts';
import { verifyDeviceResponse } from '../mdoc/device-response.ts';
import { buildSessionTranscript, jwkThumbprint } from '../mdoc/session-transcript.ts';

/** Which credential format actually answered. */
export type PresentedFormat = CredentialFormat;

/**
 * One verified credential, and the Credential Query it answers.
 *
 * `claims` is the format's own structure, not a normalised one: an SD-JWT VC's
 * disclosed claims are a plain object, while an mdoc's are
 * `{ namespace: { element: value } }`. That is deliberate — OID4VP 1.0 §7.2
 * defines a claims path over exactly those two shapes, so a `ClaimsPath` taken
 * from the query reads either without the caller knowing which arrived. It also
 * used to be flattened to a single hardcoded PID namespace, which silently
 * discarded every other namespace an mdoc carried.
 */
export type PresentedCredential = VerifiedCredential & {
  /** The `id` of the Credential Query this answers, and its `vp_token` key. */
  queryId: string;
  format: PresentedFormat;
};

/** What the wallet returned, before any predicate is applied to it. */
export type PresentedCredentials = {
  /** In the order the `vp_token` listed them. */
  credentials: readonly PresentedCredential[];
  /**
   * The same credentials keyed by Credential Query id — the useful index when a
   * query asks for more than one thing, or offers alternatives and the caller
   * needs to know which was taken. Arrays because a query may set `multiple`.
   */
  byQueryId: Record<string, readonly PresentedCredential[]>;
};

/**
 * A rule over the whole answer, evaluated after every credential in it has been
 * verified and before the verdict is decided.
 *
 * The set rather than one credential is the right unit: a query offering two
 * formats is answered by either, and a query asking for two credentials is only
 * answered by both. `presets/age-over-18.ts` is one of these.
 *
 * `evidence` is a short non-identifying label for *how* the rule was satisfied,
 * put on `verification.accepted`. For the age predicate that is the privacy
 * distinction — the issuer's boolean discloses nothing else, a date of birth
 * discloses a date of birth — and an audit trail that cannot tell them apart
 * cannot say what the verifier learned.
 */
export type PredicateResult<T> = { value: T; evidence?: string };

export type PresentationPredicate<T> = (
  presented: PresentedCredentials,
  now: Date,
) => Outcome<PredicateResult<T>>;

/**
 * A verified presentation: the credentials, and whatever the predicate made of
 * them. `predicate` is `undefined` when no predicate was supplied.
 */
export type VerifiedPresentation<T = undefined> = PresentedCredentials & { predicate: T };

export type PresentationContext<T = undefined> = {
  config: VerifierIdentity;
  /** Shared status list cache, if the application keeps one. */
  statusCache?: TtlCache<string>;
  /** Shared CRL/OCSP cache, if the application keeps one. */
  revocationCache?: TtlCache<Uint8Array>;
  anchors: TrustAnchors;
  nonce: string;
  requestPayload: Record<string, unknown>;
  decryptionJwk: JWK | undefined;
  /**
   * Accept an mdoc whose `validUntil` is not valid RFC 3339.
   *
   * The EU reference issuer emits `...+00:00Z` (upstream issue #177). Strict by
   * default; an interop workaround, not a policy, so it is named as one.
   */
  tolerateMalformedMdocValidity?: boolean;
  /**
   * Receives structured events for auditing and metrics. Carries no personal
   * data by construction — see `src/events.ts`.
   *
   * Passed to every credential verifier that runs, so the stream is the same
   * whatever format answered. The envelope rejections this function makes
   * itself — a wallet that declined, a response that would not parse — are
   * emitted here with no format, because at that point no credential has been
   * seen.
   *
   * The verdict is this function's: it can verify several credentials, and one
   * `verification.accepted` per credential would report an acceptance nobody
   * was given. The inner verifiers therefore see a `withoutVerdict` sink.
   */
  onEvent?: EventSink;
  /**
   * Cancellation, and the only bound on the whole presentation check.
   *
   * A server handling this has one obvious source: `AbortSignal.timeout(ms)`
   * for a deadline it is willing to spend on a wallet's response. Aborting when
   * the *wallet* disconnects is usually wrong here — under `direct_post` the
   * browser is polling for the same outcome, so throwing the work away leaves
   * the session unanswered.
   */
  signal?: AbortSignal;
  /**
   * The DCQL query this response answers.
   *
   * Optional because the default is to read it back out of `requestPayload`,
   * where `buildAuthorizationRequest` put it — the request actually sent is the
   * authority on what the answer has to satisfy, and a copy passed separately
   * is a second thing to keep in step.
   */
  query?: DcqlQuery;
  /**
   * A rule over the verified credentials, evaluated before the verdict.
   *
   * Without one, "every credential the query asked for verified" is the whole
   * test — which is the right default for a query that asks for attributes, and
   * not enough for one that asks a question. `presets/age-over-18.ts` is the
   * predicate this library used to apply unconditionally.
   */
  predicate?: PresentationPredicate<T>;
  now?: Date;
};

/**
 * Validate an OID4VP authorization response and verify the credentials in it.
 *
 * Two distinct layers, and it is worth keeping them distinct:
 *
 *  1. `@openid4vc/openid4vp` handles the protocol envelope — JARM decryption,
 *     response shape, and matching the returned Presentations against the DCQL
 *     query we sent.
 *  2. Our credential verifiers handle each credential — issuer trust,
 *     signature, disclosures, key binding.
 *
 * Layer 1 says "the wallet answered the question we asked". Only layer 2 says
 * "and the answer is backed by credentials we trust". An optional `predicate`
 * is the third thing, and the caller's: "and the answer means what we needed".
 *
 * **Everything specific to the question comes from the query.** Which formats
 * may answer, which `vct` or doc type each must carry, which combinations are
 * enough — all of it is read back off the request that was sent, so asking
 * something else requires no change here. It used to be two module constants
 * naming the age query's two ids, which meant a second query could be built and
 * sent but never verified.
 */
export async function verifyPresentationResponse<T = undefined>(
  context: PresentationContext<T>,
  authorizationResponse: Record<string, unknown>,
): Promise<Outcome<VerifiedPresentation<T>>> {
  const emit = context.onEvent ?? noopSink;
  const startedAt = Date.now();

  /**
   * Every verdict is this function's, so every rejection goes through here —
   * including the ones a credential verifier produced, which run against a
   * `withoutVerdict` sink precisely so their rejection is reported once, here,
   * with the format it belongs to.
   */
  const rejectWith = (outcome: Rejected, format?: PresentedFormat): Rejected => {
    emit({
      type: 'verification.rejected',
      format,
      reason: outcome.reason,
      durationMs: Date.now() - startedAt,
    });
    return outcome;
  };

  // Before the envelope is even decrypted: JARM decryption is real work, and an
  // abort here is the caller saying nobody is waiting for the outcome.
  if (context.signal?.aborted) {
    return rejectWith(reject('VERIFICATION_ABORTED', 'Cancelled before the response was read'));
  }

  const verifier = new Openid4vpVerifier({
    callbacks: {
      hash: hashCallback,
      generateRandom,
      decryptJwe: createDecryptJwe(context.decryptionJwk),
      verifyJwt: createVerifyJwt(),
    } as never,
  });

  const declined = await walletErrorResponse(context, authorizationResponse);
  if (declined) return rejectWith(declined);

  let vpToken: unknown;
  try {
    const parsed = await verifier.parseOpenid4vpAuthorizationResponse({
      authorizationResponse,
      authorizationRequestPayload: context.requestPayload as never,
      callbacks: {
        decryptJwe: createDecryptJwe(context.decryptionJwk),
        verifyJwt: createVerifyJwt(),
      } as never,
    });

    verifier.validateOpenid4vpAuthorizationResponsePayload({
      authorizationRequestPayload: context.requestPayload as never,
      authorizationResponsePayload: parsed.authorizationResponsePayload as never,
    });

    vpToken = (parsed.authorizationResponsePayload as Record<string, unknown>)['vp_token'];
  } catch (error) {
    return rejectWith(reject('RESPONSE_INVALID', `OID4VP response rejected: ${errorMessage(error)}`));
  }

  if (typeof vpToken !== 'object' || vpToken === null) {
    return rejectWith(reject('RESPONSE_INVALID', 'vp_token is not a JSON object'));
  }
  const token = vpToken as Record<string, unknown>;

  const query = context.query ?? readDcqlQuery(context.requestPayload);
  if (!query) {
    return rejectWith(reject('RESPONSE_INVALID', 'Stored request payload carries no dcql_query'));
  }

  // Each key is a Credential Query id and each value an array of Presentations
  // (OID4VP 1.0 §8.1). A key we did not ask about is a protocol error rather
  // than something to ignore: nothing states what it should be checked against.
  const answered = new Set(Object.keys(token));
  const unknown = [...answered].find((queryId) => !credentialQueryById(query, queryId));
  if (unknown) {
    return rejectWith(reject('RESPONSE_INVALID', `vp_token has an entry for "${unknown}", which was not requested`));
  }

  // Whether the response answers the query is settled before anything in it is
  // verified — it is a property of which keys arrived, and verifying
  // credentials we are about to reject the response for is work nobody wants
  // done. It also keeps the reason honest: a surplus credential that happens to
  // be malformed is still a surplus credential.
  const unmet = unsatisfiedRequirement(query, answered);
  if (unmet) return rejectWith(reject('RESPONSE_INVALID', `Response does not answer the query: ${unmet}`));

  // And no more than answers it. A wallet answering both alternatives of a
  // query that offered a choice has disclosed a credential we had no basis to
  // ask for, and verifying it would be the act of collecting it.
  const surplus = redundantCredential(query, answered);
  if (surplus) {
    return rejectWith(reject('RESPONSE_INVALID', `Response answers "${surplus}", which the query did not need`));
  }

  const credentials: PresentedCredential[] = [];
  const byQueryId: Record<string, PresentedCredential[]> = {};
  const innerEvents = withoutVerdict(emit);

  for (const [queryId, entry] of Object.entries(token)) {
    // Non-null: every key was matched above, before anything was verified.
    const credentialQuery = credentialQueryById(query, queryId)!;

    const presentations = readPresentations(entry, credentialQuery);
    if (!presentations.verified) return rejectWith(presentations, credentialQuery.format);

    for (const presentation of presentations.value) {
      const verified =
        credentialQuery.format === 'dc+sd-jwt'
          ? await verifySdJwtVcPresentation(context, credentialQuery, presentation, innerEvents)
          : await verifyMdocPresentation(context, credentialQuery, presentation, innerEvents);
      if (!verified.verified) return rejectWith(verified, credentialQuery.format);

      // Only now can this be asked: the claims have to have been verified
      // before "was this disclosed" is a question about anything. A credential
      // that verifies without carrying what the query asked for is a wallet
      // answering something else, and saying so here is what keeps a caller
      // with no predicate from reading `undefined` off an accepted result.
      const missing = unsatisfiedClaims(credentialQuery, verified.value.claims);
      if (missing) {
        return rejectWith(
          reject('REQUESTED_CLAIMS_MISSING', `"${queryId}": ${missing}`),
          credentialQuery.format,
        );
      }

      credentials.push(verified.value);
      (byQueryId[queryId] ??= []).push(verified.value);
    }
  }

  const presented: PresentedCredentials = { credentials, byQueryId };
  const format = soleFormat(credentials);

  // `undefined as T` is sound only where it is reached: T defaults to undefined
  // and is inferred from `predicate`, so this branch is the one where the
  // caller asked for no predicate value.
  let value = undefined as T;
  let evidence: string | undefined;
  if (context.predicate) {
    const outcome = context.predicate(presented, context.now ?? new Date());
    if (!outcome.verified) return rejectWith(outcome, format);
    value = outcome.value.value;
    evidence = outcome.value.evidence;
  }

  emit({
    type: 'verification.accepted',
    format,
    credentialTypes: credentials.map((credential) => credential.credentialType),
    ...(evidence === undefined ? {} : { evidence }),
    durationMs: Date.now() - startedAt,
  });

  return accept({ ...presented, predicate: value });
}

/**
 * The format of the presented credentials, when they agree on one.
 *
 * Undefined for a set spanning both, where naming one would name the wrong one
 * — the same rule the envelope rejections follow. A query offering formats as
 * alternatives is answered by one credential, so in practice this is a format.
 */
function soleFormat(credentials: readonly PresentedCredential[]): PresentedFormat | undefined {
  const formats = new Set(credentials.map((credential) => credential.format));
  return formats.size === 1 ? [...formats][0] : undefined;
}

/**
 * The Presentations under one `vp_token` key (OID4VP 1.0 §8.1).
 *
 * Always an array in 1.0. More than one is a protocol error unless the
 * Credential Query set `multiple`, which defaults to false (§6.1) — the wallet
 * returning several where one was asked for means the caller is about to be
 * handed a credential it never requested a second of.
 */
function readPresentations(entry: unknown, query: CredentialQuery): Outcome<readonly string[]> {
  const presentations = Array.isArray(entry) ? entry : [entry];
  if (presentations.length === 0) {
    return reject('RESPONSE_INVALID', `"${query.id}" carries no Presentation`);
  }
  if (presentations.length > 1 && query.multiple !== true) {
    return reject(
      'RESPONSE_INVALID',
      `"${query.id}" carries ${presentations.length} Presentations; one was requested`,
    );
  }
  if (!presentations.every((presentation) => typeof presentation === 'string')) {
    return reject('RESPONSE_INVALID', `"${query.id}" carries a Presentation that is not a string`);
  }
  return accept(presentations as readonly string[]);
}

/**
 * The query as it was sent.
 *
 * `buildAuthorizationRequest` puts it on the payload and the application stores
 * that payload with the session, so by the time a response arrives the question
 * is already written down. Reading it back beats being told it again.
 */
function readDcqlQuery(requestPayload: Record<string, unknown>): DcqlQuery | undefined {
  const query = requestPayload['dcql_query'];
  if (typeof query !== 'object' || query === null) return undefined;
  const credentials = (query as { credentials?: unknown }).credentials;
  return Array.isArray(credentials) ? (query as DcqlQuery) : undefined;
}

/**
 * A wallet that declines answers with an OAuth 2.0 error response, not a
 * presentation (OID4VP 1.0 §8.2).
 *
 * Under `direct_post.jwt` that error is encrypted exactly like a successful
 * response, so it is invisible until after decryption. Left to the protocol
 * parser, which is looking for a `vp_token`, a perfectly well-formed refusal is
 * reported as a malformed response — hiding the reason the wallet gave. The
 * reference wallet does exactly this.
 *
 * Returns `undefined` when the response is not an error, including when it
 * cannot be decrypted: that is the parser's business to report, not ours.
 */
async function walletErrorResponse(
  context: PresentationContext<unknown>,
  authorizationResponse: Record<string, unknown>,
): Promise<Rejected | undefined> {
  let payload: Record<string, unknown>;

  const encrypted = authorizationResponse['response'];
  if (typeof encrypted === 'string') {
    const result = await createDecryptJwe(context.decryptionJwk)(encrypted);
    if (!result.decrypted) return undefined;
    try {
      payload = JSON.parse(result.payload) as Record<string, unknown>;
    } catch {
      return undefined;
    }
  } else {
    payload = authorizationResponse;
  }

  const code = payload['error'];
  if (typeof code !== 'string') return undefined;

  const description = payload['error_description'];
  return reject(
    'WALLET_ERROR',
    typeof description === 'string' ? `${code}: ${description}` : code,
  );
}

async function verifySdJwtVcPresentation(
  context: PresentationContext<unknown>,
  query: SdJwtVcCredentialQuery,
  credential: string,
  onEvent: EventSink,
): Promise<Outcome<PresentedCredential>> {
  // OID4VP 1.0 Appendix B.3.6: in the Key Binding JWT the `nonce` MUST be the
  // Authorization Request nonce and `aud` MUST be the full Client Identifier,
  // prefix included (§14.8). Read off the request we sent rather than
  // recomputed: under the `redirect_uri` prefix it is per-session.
  const audience = context.requestPayload['client_id'];
  if (typeof audience !== 'string') {
    return reject('RESPONSE_INVALID', 'Stored request payload has no client_id');
  }

  const result = await verifySdJwtVc({
    credential,
    anchors: context.anchors,
    // The types this query asked for, so a wallet cannot answer with a
    // credential of some other type that happens to verify.
    ...(query.meta.vct_values ? { expectedVct: query.meta.vct_values } : {}),
    checkStatus: context.config.checkStatus,
    ...(context.statusCache ? { statusCache: context.statusCache } : {}),
    checkCertificateRevocation: context.config.checkCertificateRevocation,
    ...(context.revocationCache ? { revocationCache: context.revocationCache } : {}),
    // The policy the request advertised in client_metadata. Enforcing a
    // narrower set than was advertised would reject a wallet for answering
    // exactly what it was asked for.
    ...(context.config.allowedAlgs ? { allowedAlgs: context.config.allowedAlgs } : {}),
    onEvent,
    ...(context.signal ? { signal: context.signal } : {}),
    ...(context.now ? { now: context.now } : {}),
    keyBinding: { nonce: context.nonce, audience },
  });

  return result.verified
    ? accept({ ...result.value, queryId: query.id, format: 'dc+sd-jwt' as const })
    : result;
}

/**
 * Verify an mdoc DeviceResponse.
 *
 * The holder binding works differently here: instead of a Key Binding JWT over
 * a nonce, the wallet signs a SessionTranscript that commits to our client
 * identifier, nonce and response URI. We rebuild that transcript from the
 * request we sent, so a response produced for anyone else will not verify.
 */
async function verifyMdocPresentation(
  context: PresentationContext<unknown>,
  query: MdocCredentialQuery,
  deviceResponse: string,
  onEvent: EventSink,
): Promise<Outcome<PresentedCredential>> {
  const transcript = sessionTranscriptFor(context);
  if (!transcript.verified) return transcript;

  const result = await verifyDeviceResponse({
    deviceResponse,
    anchors: context.anchors,
    sessionTranscript: transcript.value,
    // The doc type this query asked for. Nothing here assumes the EUDI PID's,
    // and nothing derives a namespace from it either: an mDL's doc type and
    // namespace differ, and the namespaces are the query's to state.
    ...(query.meta.doctype_value ? { expectedDocType: query.meta.doctype_value } : {}),
    ...(context.tolerateMalformedMdocValidity ? { tolerateMalformedValidityDates: true } : {}),
    // Same revocation policy and the same cache as the SD-JWT VC branch: the
    // format a wallet happens to answer in must not decide whether the
    // credential's status is checked.
    checkStatus: context.config.checkStatus,
    ...(context.statusCache ? { statusCache: context.statusCache } : {}),
    checkCertificateRevocation: context.config.checkCertificateRevocation,
    ...(context.revocationCache ? { revocationCache: context.revocationCache } : {}),
    ...(context.config.allowedAlgs ? { allowedAlgs: context.config.allowedAlgs } : {}),
    onEvent,
    ...(context.signal ? { signal: context.signal } : {}),
    ...(context.now ? { now: context.now } : {}),
  });
  if (!result.verified) return result;

  return accept({
    queryId: query.id,
    format: 'mso_mdoc' as const,
    // Namespace-keyed, which is the structure an mdoc claims path addresses
    // (OID4VP 1.0 §7.2). Flattening to one namespace here is what used to
    // discard every other namespace the wallet returned.
    claims: result.value.claims,
    credentialType: result.value.docType,
    issuerCertificateSubject: result.value.issuerCertificateSubject,
    // mdoc binds the holder through the device signature over the session
    // transcript rather than a Key Binding JWT; verifyDeviceResponse has
    // already established the equivalent guarantee.
    keyBinding: { audience: String(context.requestPayload['client_id']), nonce: context.nonce },
  });
}

/**
 * The SessionTranscript the wallet's device signature must have committed to.
 *
 * Rebuilt from the request we sent (OID4VP 1.0 §B.2.6.1), which is what binds
 * this response to this request.
 */
function sessionTranscriptFor(context: PresentationContext<unknown>): Outcome<Uint8Array> {
  const clientId = context.requestPayload['client_id'];
  const responseUri = context.requestPayload['response_uri'] ?? context.requestPayload['redirect_uri'];
  if (typeof clientId !== 'string' || typeof responseUri !== 'string') {
    return reject('RESPONSE_INVALID', 'Stored request payload lacks client_id or response_uri');
  }

  // The thumbprint is present only when the response is encrypted; the spec
  // requires null otherwise, and either mistake changes the transcript and so
  // invalidates every signature over it.
  const encrypted = context.requestPayload['response_mode'] === 'direct_post.jwt';
  const key = encrypted ? encryptionJwkFrom(context.requestPayload) : undefined;
  if (encrypted && !key) {
    return reject('RESPONSE_INVALID', 'Encrypted response mode with no published encryption key');
  }

  return accept(
    buildSessionTranscript({
      clientId,
      nonce: context.nonce,
      responseUri,
      ...(key ? { encryptionKeyThumbprint: jwkThumbprint(key) } : {}),
    }),
  );
}

function encryptionJwkFrom(
  requestPayload: Record<string, unknown>,
): { kty: string; crv: string; x: string; y: string } | undefined {
  const metadata = requestPayload['client_metadata'] as Record<string, unknown> | undefined;
  const jwks = metadata?.['jwks'] as { keys?: Record<string, unknown>[] } | undefined;
  const key = jwks?.keys?.find((candidate) => candidate['use'] === 'enc') ?? jwks?.keys?.[0];
  if (!key || typeof key['x'] !== 'string' || typeof key['y'] !== 'string') return undefined;
  return { kty: String(key['kty']), crv: String(key['crv']), x: key['x'], y: key['y'] };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
