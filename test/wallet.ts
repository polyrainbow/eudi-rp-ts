import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { CompactEncrypt, type JWK, importJWK } from 'jose';
import { webcrypto } from 'node:crypto';
import { base64urlEncode, hasher } from '../src/crypto.ts';

/**
 * A minimal stand-in for a wallet, for the round-trip test.
 *
 * It does exactly the two things the verifier depends on: disclose only the
 * requested claim, and mint a Key Binding JWT over the verifier's nonce and
 * Client Identifier. It is not a wallet implementation and makes no attempt to
 * be one — see README non-goals.
 */
const SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

export async function presentAgeOver18(options: {
  issuedCredential: string;
  holderPrivateJwk: webcrypto.JsonWebKey;
  /** OID4VP `nonce` from the authorization request. */
  nonce: string;
  /** The full Client Identifier, prefix included (OID4VP 1.0 §14.8). */
  audience: string;
  /** Override to test a wallet that discloses the wrong thing. */
  presentationFrame?: object;
}): Promise<string> {
  const holderKey = await webcrypto.subtle.importKey(
    'jwk',
    options.holderPrivateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );

  const sdjwt = new SDJwtVcInstance({
    hasher,
    kbSignAlg: 'ES256',
    kbSigner: async (data: string) =>
      base64urlEncode(
        new Uint8Array(await webcrypto.subtle.sign(SIGN, holderKey, new TextEncoder().encode(data))),
      ),
  });

  return await sdjwt.present(
    options.issuedCredential,
    (options.presentationFrame ?? { age_equal_or_over: { '18': true } }) as never,
    {
      kb: {
        payload: {
          iat: Math.floor(Date.now() / 1000),
          aud: options.audience,
          nonce: options.nonce,
        },
      },
    },
  );
}

/**
 * Seal an authorization response for `response_mode=direct_post.jwt`.
 *
 * The wallet encrypts `vp_token` and `state` to the ephemeral key the verifier
 * published in `client_metadata.jwks`, and posts the result as a single
 * `response` parameter. Nothing in the body is readable in transit — which is
 * why the verifier has to know which session a response belongs to from the
 * URL it was posted to.
 */
export async function encryptResponse(options: {
  vpToken: unknown;
  state: string;
  /** The verifier's public encryption JWK from client_metadata. */
  encryptionJwk: JWK;
  /** From `encrypted_response_enc_values_supported`; defaults to A128GCM. */
  enc?: string;
}): Promise<string> {
  // OID4VP 1.0 §8.3, as a real wallet does it: the JWE `alg` MUST equal the
  // chosen JWK's `alg`, the `enc` defaults to A128GCM, and the JWK's `kid` is
  // echoed so the verifier knows which key was used.
  const alg = options.encryptionJwk.alg;
  if (!alg) throw new Error('Verifier JWK has no alg; cannot choose a JWE algorithm');
  const enc = options.enc ?? 'A128GCM';
  const key = await importJWK(options.encryptionJwk, alg);

  return await new CompactEncrypt(
    new TextEncoder().encode(JSON.stringify({ vp_token: options.vpToken, state: options.state })),
  )
    .setProtectedHeader({ alg, enc, ...(options.encryptionJwk.kid ? { kid: options.encryptionJwk.kid } : {}) })
    .encrypt(key);
}
