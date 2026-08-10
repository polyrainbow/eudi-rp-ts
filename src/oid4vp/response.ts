import { Openid4vpVerifier } from '@openid4vc/openid4vp';
import type { JWK } from 'jose';
import type { Config } from '../config.ts';
import { type Outcome, accept, reject } from '../result.ts';
import type { TrustAnchors } from '../trust/anchors.ts';
import { type AgeResult, type VerifiedCredential, verifyAgeOver18 } from '../verify.ts';
import { createDecryptJwe, createVerifyJwt, generateRandom, hashCallback } from './callbacks.ts';
import { CREDENTIAL_QUERY_ID } from './query.ts';

export type PresentationContext = {
  config: Config;
  anchors: TrustAnchors;
  nonce: string;
  requestPayload: Record<string, unknown>;
  decryptionJwk: JWK | undefined;
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
): Promise<Outcome<VerifiedCredential & AgeResult>> {
  const verifier = new Openid4vpVerifier({
    callbacks: {
      hash: hashCallback,
      generateRandom,
      decryptJwe: createDecryptJwe(context.decryptionJwk),
      verifyJwt: createVerifyJwt(),
    } as never,
  });

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

  const credential = extractCredential(vpToken);
  if (!credential.verified) return credential;

  // OID4VP 1.0 Appendix B.3.6: in the Key Binding JWT the `nonce` MUST be the
  // Authorization Request nonce and `aud` MUST be the full Client Identifier,
  // prefix included (§14.8, "Always Use the Full Client Identifier").
  //
  // Read straight off the request we sent rather than recomputing it from
  // config: under the `redirect_uri` prefix the Client Identifier is the
  // per-session response URI, so recomputing it could drift from what the
  // wallet was actually told.
  const audience = context.requestPayload['client_id'];
  if (typeof audience !== 'string') {
    return reject('RESPONSE_INVALID', 'Stored request payload has no client_id');
  }

  return verifyAgeOver18({
    credential: credential.value,
    anchors: context.anchors,
    expectedVct: context.config.requestedVct,
    checkStatus: context.config.trust.checkStatus,
    keyBinding: { nonce: context.nonce, audience },
  });
}

/**
 * Pull the single SD-JWT+KB out of the VP Token.
 *
 * OID4VP 1.0 §8.1: `vp_token` is an object keyed by the DCQL Credential Query
 * id, whose values are arrays of Presentations. For `dc+sd-jwt` each
 * Presentation is a string.
 */
function extractCredential(vpToken: unknown): Outcome<string> {
  if (typeof vpToken !== 'object' || vpToken === null) {
    return reject('RESPONSE_INVALID', 'vp_token is not a JSON object');
  }
  const entry = (vpToken as Record<string, unknown>)[CREDENTIAL_QUERY_ID];
  if (entry === undefined) {
    return reject('RESPONSE_INVALID', `vp_token has no entry for credential query "${CREDENTIAL_QUERY_ID}"`);
  }
  const presentations = Array.isArray(entry) ? entry : [entry];
  const [first, ...rest] = presentations;
  if (typeof first !== 'string') {
    return reject('RESPONSE_INVALID', 'Presentation is not a compact SD-JWT string');
  }
  if (rest.length > 0) {
    // `multiple` was not set in our query, so more than one is a protocol error.
    return reject('RESPONSE_INVALID', `Expected one Presentation, got ${presentations.length}`);
  }
  return accept(first);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
