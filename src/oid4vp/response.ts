import { Openid4vpVerifier } from '@openid4vc/openid4vp';
import type { JWK } from 'jose';
import type { TtlCache } from '../fetching.ts';
import type { VerifierIdentity } from './identity.ts';
import { type Outcome, type Rejected, accept, reject } from '../result.ts';
import type { TrustAnchors } from '../trust/anchors.ts';
import { type AgeResult, type VerifiedCredential, verifyAgeOver18 } from '../verify.ts';
import { createDecryptJwe, createVerifyJwt, generateRandom, hashCallback } from './callbacks.ts';
import { CREDENTIAL_QUERY_ID, MDOC_CREDENTIAL_QUERY_ID, PID_MDOC_NAMESPACE } from './query.ts';
import { evaluateAgeOver18Mdoc } from '../predicate/age.ts';
import { verifyDeviceResponse } from '../mdoc/device-response.ts';
import { buildSessionTranscript, jwkThumbprint } from '../mdoc/session-transcript.ts';

/** Which credential format actually answered. */
export type PresentedFormat = 'dc+sd-jwt' | 'mso_mdoc';

export type VerifiedPresentation = VerifiedCredential & AgeResult & { format: PresentedFormat };

export type PresentationContext = {
  config: VerifierIdentity;
  /** Shared status list cache, if the application keeps one. */
  statusCache?: TtlCache<string>;
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
};

/**
 * Validate an OID4VP authorization response and verify the credential inside it.
 *
 * Two distinct layers, and it is worth keeping them distinct:
 *
 *  1. `@openid4vc/openid4vp` handles the protocol envelope — JARM decryption,
 *     response shape, and matching the returned Presentations against the DCQL
 *     query we sent.
 *  2. Our Phase 1 verifier handles the credential — issuer trust, signature,
 *     disclosures, key binding, predicate.
 *
 * Layer 1 says "the wallet answered the question we asked". Only layer 2 says
 * "and the answer is backed by a credential we trust".
 */
export async function verifyPresentationResponse(
  context: PresentationContext,
  authorizationResponse: Record<string, unknown>,
): Promise<Outcome<VerifiedPresentation>> {
  const verifier = new Openid4vpVerifier({
    callbacks: {
      hash: hashCallback,
      generateRandom,
      decryptJwe: createDecryptJwe(context.decryptionJwk),
      verifyJwt: createVerifyJwt(),
    } as never,
  });

  const declined = await walletErrorResponse(context, authorizationResponse);
  if (declined) return declined;

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
    return reject('RESPONSE_INVALID', `OID4VP response rejected: ${errorMessage(error)}`);
  }

  if (typeof vpToken !== 'object' || vpToken === null) {
    return reject('RESPONSE_INVALID', 'vp_token is not a JSON object');
  }
  const token = vpToken as Record<string, unknown>;

  // The query offers both formats as alternatives, so the wallet answers with
  // whichever it holds. Exactly one entry is expected.
  const sdJwt = onePresentation(token[CREDENTIAL_QUERY_ID]);
  const mdoc = onePresentation(token[MDOC_CREDENTIAL_QUERY_ID]);

  if (sdJwt.present && mdoc.present) {
    return reject('RESPONSE_INVALID', 'vp_token answers both credential queries; expected one');
  }
  if (sdJwt.present) {
    return sdJwt.value ? await verifySdJwt(context, sdJwt.value) : reject('RESPONSE_INVALID', sdJwt.problem);
  }
  if (mdoc.present) {
    return mdoc.value ? await verifyMdocPresentation(context, mdoc.value) : reject('RESPONSE_INVALID', mdoc.problem);
  }

  return reject(
    'RESPONSE_INVALID',
    `vp_token has no entry for "${CREDENTIAL_QUERY_ID}" or "${MDOC_CREDENTIAL_QUERY_ID}"`,
  );
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
  context: PresentationContext,
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

async function verifySdJwt(
  context: PresentationContext,
  credential: string,
): Promise<Outcome<VerifiedPresentation>> {
  // OID4VP 1.0 Appendix B.3.6: in the Key Binding JWT the `nonce` MUST be the
  // Authorization Request nonce and `aud` MUST be the full Client Identifier,
  // prefix included (§14.8). Read off the request we sent rather than
  // recomputed: under the `redirect_uri` prefix it is per-session.
  const audience = context.requestPayload['client_id'];
  if (typeof audience !== 'string') {
    return reject('RESPONSE_INVALID', 'Stored request payload has no client_id');
  }

  const result = await verifyAgeOver18({
    credential,
    anchors: context.anchors,
    expectedVct: context.config.requestedVct,
    checkStatus: context.config.checkStatus,
    ...(context.statusCache ? { statusCache: context.statusCache } : {}),
    keyBinding: { nonce: context.nonce, audience },
  });

  return result.verified ? accept({ ...result.value, format: 'dc+sd-jwt' as const }) : result;
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
  context: PresentationContext,
  deviceResponse: string,
): Promise<Outcome<VerifiedPresentation>> {
  const transcript = sessionTranscriptFor(context);
  if (!transcript.verified) return transcript;

  const result = await verifyDeviceResponse({
    deviceResponse,
    anchors: context.anchors,
    sessionTranscript: transcript.value,
    expectedDocType: PID_MDOC_NAMESPACE,
    ...(context.tolerateMalformedMdocValidity ? { tolerateMalformedValidityDates: true } : {}),
  });
  if (!result.verified) return result;

  const elements = result.value.claims[PID_MDOC_NAMESPACE] ?? {};
  const age = evaluateAgeOver18Mdoc(elements, new Date());
  if (!age.verified) return age;

  return accept({
    ...age.value,
    format: 'mso_mdoc' as const,
    claims: elements,
    vct: result.value.docType,
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
function sessionTranscriptFor(context: PresentationContext): Outcome<Uint8Array> {
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

/**
 * One presentation from a `vp_token` entry.
 *
 * OID4VP 1.0 §8.1: each value is an array of Presentations. `multiple` was not
 * set in our query, so more than one is a protocol error.
 */
function onePresentation(entry: unknown): { present: boolean; value?: string; problem: string } {
  if (entry === undefined) return { present: false, problem: '' };
  const presentations = Array.isArray(entry) ? entry : [entry];
  if (presentations.length !== 1) {
    return { present: true, problem: `Expected one Presentation, got ${presentations.length}` };
  }
  const first = presentations[0];
  if (typeof first !== 'string') {
    return { present: true, problem: 'Presentation is not a string' };
  }
  return { present: true, value: first, problem: '' };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
