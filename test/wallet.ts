import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
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
