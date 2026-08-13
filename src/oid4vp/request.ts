import { Openid4vpVerifier } from '@openid4vc/openid4vp';
import { exportJWK, generateKeyPair } from 'jose';
import type { JWK } from 'jose';
import { type VerifierIdentity, clientId, responseUri, verifierBaseUrl } from './identity.ts';
import { DEFAULT_ALLOWED_ALGS } from '../crypto.ts';
import { coseAlgIdentifiers } from '../mdoc/cose.ts';
import { createEncryptJwe, createSignJwt, generateRandom, hashCallback, requestSigningAlg } from './callbacks.ts';
import { type DcqlQuery, queryFormats } from './query.ts';

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

export type BuiltRequest = {
  nonce: string;
  state: string;
  requestPayload: Record<string, unknown>;
  /** Ephemeral private key, kept for decrypting a `direct_post.jwt` response. */
  decryptionJwk: JWK | undefined;
  /** The URI handed to the wallet, as a QR code and as a deep link. */
  walletUri: string;
  /**
   * Signed request object, served at `/oid4vp/request/:id` for the wallet to
   * fetch. Only set when the request is signed.
   */
  requestObject: { id: string; jwt: string } | undefined;
  /** Identifies this session in the `response_uri` the wallet posts to. */
  responseId: string;
};

/**
 * Build an OID4VP 1.0 authorization request for a DCQL query.
 *
 * The query is an argument rather than something this function builds, and that
 * is the whole of what makes this library general: it used to call
 * `ageOver18Query` itself, so one question was wired into the request builder
 * and, through the credential query ids, into the response verifier as well.
 * `verifyPresentationResponse` reads the query back off the payload returned
 * here, so whatever is asked is what the answer gets checked against.
 *
 * Two shapes, selected by config:
 *
 * `redirect_uri` (default) — the Client Identifier IS the response URI and the
 * request MUST NOT be signed, because the wallet has no way to obtain a
 * trusted key for it (OID4VP 1.0 §5.10). Needs no PKI, so the demo starts with
 * one command.
 *
 * `x509_san_dns` — the request MUST be signed, with the access certificate
 * chain in the JAR's `x5c` header and the DNS name matching a dNSName SAN in
 * the leaf.
 *
 * `x509_hash` — the same signed request, but the identifier is the SHA-256 of
 * the leaf rather than a name inside it. This is how the EU reference verifier
 * identifies itself, and it is the option to reach for when the certificate you
 * are issued carries a URI SAN, or none, instead of a dNSName.
 */
export async function buildAuthorizationRequest(
  config: VerifierIdentity,
  query: DcqlQuery,
): Promise<BuiltRequest> {
  const nonce = b64url(generateRandom(32));
  const state = b64url(generateRandom(32));
  // The response URI identifies the session. With `direct_post.jwt` the `state`
  // is sealed inside the encrypted response, so the path is the only thing that
  // says which session — and therefore which decryption key — a response
  // belongs to before we can decrypt it.
  const responseId = b64url(generateRandom(16));
  const responseUrl = responseUri(config, responseId);
  const allowedAlgs = config.allowedAlgs ?? DEFAULT_ALLOWED_ALGS;
  const signed = config.clientIdPrefix === 'x509_san_dns' || config.clientIdPrefix === 'x509_hash';

  // With direct_post.jwt the wallet encrypts the response to a key we publish
  // in client_metadata. It is ephemeral and per-session on purpose.
  const encryptResponse = signed;
  let decryptionJwk: JWK | undefined;
  let publicEncryptionJwk: JWK | undefined;
  if (encryptResponse) {
    const { privateKey, publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    decryptionJwk = { ...(await exportJWK(privateKey)), alg: 'ECDH-ES' };
    // OID4VP 1.0 §8.3: the JWK MUST carry `alg` (the wallet's JWE `alg` must
    // equal it) and a `kid` that identifies it within this request.
    publicEncryptionJwk = {
      ...(await exportJWK(publicKey)),
      use: 'enc',
      alg: 'ECDH-ES',
      kid: 'response-encryption',
    };
  }

  const requestPayload: Record<string, unknown> = {
    response_type: 'vp_token',
    client_id: clientId(config, responseUrl),
    response_uri: responseUrl,
    response_mode: encryptResponse ? 'direct_post.jwt' : 'direct_post',
    nonce,
    state,
    dcql_query: query,
    client_metadata: {
      client_name: config.clientName ?? 'eudi-rp-ts verifier',
      // Every format the DCQL query asks for MUST appear here, and only those:
      // a wallet checks the two against each other and refuses the whole
      // request otherwise — the EU reference wallet answers `invalid_request`
      // with "Verifier does not support all Formats requested in the DCQL
      // query". Declaring only `dc+sd-jwt` while the query also offered
      // `mso_mdoc` was exactly that bug, which is why this is derived from the
      // query rather than written out beside it.
      //
      // The algorithms are the policy that will actually be enforced, so a
      // wallet is not told ES256 by a verifier configured to accept more, nor
      // offered an algorithm the verification would then refuse.
      vp_formats_supported: Object.fromEntries(
        queryFormats(query).map((format) => [
          format,
          format === 'dc+sd-jwt'
            ? { 'sd-jwt_alg_values': [...allowedAlgs], 'kb-jwt_alg_values': [...allowedAlgs] }
            : // COSE algorithm identifiers here, not JOSE names: -7 is ES256
              // (RFC 9053 §2.1). Only the ECDSA subset appears, because that is
              // all ISO 18013-5 permits for issuer and device authentication.
              {
                issuerauth_alg_values: [...coseAlgIdentifiers(allowedAlgs)],
                deviceauth_alg_values: [...coseAlgIdentifiers(allowedAlgs)],
              },
        ]),
      ),
      // Encryption is described by the JWK alone. `authorization_encrypted_
      // response_alg`/`_enc` are pre-1.0 JARM names and appear nowhere in
      // OID4VP 1.0; the content encryption algorithm comes from
      // `encrypted_response_enc_values_supported`, which SHOULD be absent while
      // we use its default of A128GCM.
      ...(publicEncryptionJwk ? { jwks: { keys: [publicEncryptionJwk] } } : {}),
    },
  };

  const verifier = new Openid4vpVerifier({
    callbacks: {
      hash: hashCallback,
      generateRandom,
      signJwt: createSignJwt(
        config.accessCertificatePrivateKeyPem && config.accessCertificateChainPem
          ? {
              privateKeyPem: config.accessCertificatePrivateKeyPem,
              x5c: pemChainToBase64Der(config.accessCertificateChainPem),
            }
          : undefined,
      ),
      encryptJwe: createEncryptJwe(),
    } as never,
  });

  // A signed request object carries the whole x5c chain, which is far past what
  // a QR code can hold — passing it by value produces an unscannable code. So
  // the request is served from `request_uri` and the QR holds only a short URL
  // plus the client_id (OID4VP 1.0 §5.10).
  const requestObjectId = signed ? b64url(generateRandom(16)) : undefined;

  const created = await verifier.createOpenId4vpAuthorizationRequest({
    scheme: config.walletScheme,
    authorizationRequestPayload: requestPayload as never,
    ...(signed
      ? {
          jar: {
            jwtSigner: {
              method: 'x5c',
              // Must be the algorithm `createSignJwt` will actually use: this
              // value goes into the JAR header the wallet checks the signature
              // against, so a mismatch is an unverifiable request object.
              alg: requestSigningAlg(config.accessCertificatePrivateKeyPem!),
              x5c: pemChainToBase64Der(config.accessCertificateChainPem!),
            },
            expiresInSeconds: config.requestTtlSeconds,
            requestUri: `${verifierBaseUrl(config)}/oid4vp/request/${requestObjectId}`,
          } as never,
        }
      : {}),
  });

  const requestObjectJwt = (created.jar as { authorizationRequestJwt?: string } | undefined)
    ?.authorizationRequestJwt;

  return {
    nonce,
    state,
    responseId,
    requestPayload: created.authorizationRequestPayload as Record<string, unknown>,
    decryptionJwk,
    walletUri: created.authorizationRequest,
    requestObject:
      requestObjectId && requestObjectJwt ? { id: requestObjectId, jwt: requestObjectJwt } : undefined,
  };
}

/** PEM chain -> the base64 DER strings a JOSE `x5c` header expects. */
export function pemChainToBase64Der(pem: string): string[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) throw new Error('No certificates found in the access certificate chain');
  return blocks.map((block) => block.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''));
}
