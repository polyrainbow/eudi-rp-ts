import { Openid4vpVerifier } from '@openid4vc/openid4vp';
import { exportJWK, generateKeyPair } from 'jose';
import type { JWK } from 'jose';
import { type Config, clientId } from '../config.ts';
import { createEncryptJwe, createSignJwt, generateRandom, hashCallback } from './callbacks.ts';
import { ageOver18Query } from './query.ts';

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

export type BuiltRequest = {
  nonce: string;
  state: string;
  requestPayload: Record<string, unknown>;
  /** Ephemeral private key, kept for decrypting a `direct_post.jwt` response. */
  decryptionJwk: JWK | undefined;
  /** The URI handed to the wallet, as a QR code and as a deep link. */
  walletUri: string;
};

/**
 * Build an OID4VP 1.0 authorization request for the age-over-18 predicate.
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
 * the leaf. This is what the EUDI reference verifier uses, and what a real
 * wallet will accept.
 */
export async function buildAuthorizationRequest(config: Config): Promise<BuiltRequest> {
  const nonce = b64url(generateRandom(32));
  const state = b64url(generateRandom(32));
  const responseUri = `${config.baseUrl}/oid4vp/response`;
  const signed = config.clientIdPrefix === 'x509_san_dns';

  // With direct_post.jwt the wallet encrypts the response to a key we publish
  // in client_metadata. It is ephemeral and per-session on purpose.
  const encryptResponse = signed;
  let decryptionJwk: JWK | undefined;
  let publicEncryptionJwk: JWK | undefined;
  if (encryptResponse) {
    const { privateKey, publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    decryptionJwk = await exportJWK(privateKey);
    publicEncryptionJwk = { ...(await exportJWK(publicKey)), use: 'enc', alg: 'ECDH-ES', kid: 'response-encryption' };
  }

  const requestPayload: Record<string, unknown> = {
    response_type: 'vp_token',
    client_id: clientId(config),
    response_uri: responseUri,
    response_mode: encryptResponse ? 'direct_post.jwt' : 'direct_post',
    nonce,
    state,
    dcql_query: ageOver18Query(config.requestedVct),
    client_metadata: {
      client_name: 'eudi-rp-ts age check',
      vp_formats_supported: {
        'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
      },
      ...(publicEncryptionJwk
        ? {
            jwks: { keys: [publicEncryptionJwk] },
            authorization_encrypted_response_alg: 'ECDH-ES',
            authorization_encrypted_response_enc: 'A128GCM',
          }
        : {}),
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

  const created = await verifier.createOpenId4vpAuthorizationRequest({
    scheme: config.walletScheme,
    authorizationRequestPayload: requestPayload as never,
    ...(signed
      ? {
          jar: {
            jwtSigner: { method: 'x5c', alg: 'ES256', x5c: pemChainToBase64Der(config.accessCertificateChainPem!) },
            expiresInSeconds: config.requestTtlSeconds,
          } as never,
        }
      : {}),
  });

  return {
    nonce,
    state,
    requestPayload: created.authorizationRequestPayload as Record<string, unknown>,
    decryptionJwk,
    walletUri: created.authorizationRequest,
  };
}

/** PEM chain -> the base64 DER strings a JOSE `x5c` header expects. */
export function pemChainToBase64Der(pem: string): string[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) throw new Error('No certificates found in the access certificate chain');
  return blocks.map((block) => block.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''));
}
