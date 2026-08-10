import { createHash } from 'node:crypto';
import { encode } from './cbor.ts';

/**
 * The OID4VP SessionTranscript for mdoc, per OID4VP 1.0 §B.2.6.1.
 *
 * This is the binding that stops an mdoc presentation being replayed at a
 * different verifier. The wallet's device signature covers this structure, so
 * it commits to our client identifier, our nonce, our response URI, and — when
 * the response is encrypted — the key we published for it.
 *
 * ```
 * SessionTranscript      = [null, null, OpenID4VPHandover]
 * OpenID4VPHandover      = ["OpenID4VPHandover", sha256(OpenID4VPHandoverInfoBytes)]
 * OpenID4VPHandoverInfo  = [clientId, nonce, jwkThumbprint, responseUri]
 * ```
 *
 * DeviceEngagementBytes and EReaderKeyBytes are null because there is no
 * proximity engagement: the whole point of the handover is to substitute the
 * OID4VP request parameters for the NFC/QR exchange ISO 18013-5 assumes.
 */
export type HandoverParameters = {
  /** The full Client Identifier, prefix included. */
  clientId: string;
  /** The `nonce` from the authorization request. */
  nonce: string;
  /** `response_uri`, or `redirect_uri` when that response mode is used. */
  responseUri: string;
  /**
   * RFC 7638 SHA-256 thumbprint of the verifier's response encryption key,
   * or undefined when the response is not encrypted — the spec requires null
   * in that case, not omission.
   */
  encryptionKeyThumbprint?: Uint8Array;
};

export function buildSessionTranscript(parameters: HandoverParameters): Uint8Array {
  const handoverInfo = encode([
    parameters.clientId,
    parameters.nonce,
    parameters.encryptionKeyThumbprint ?? null,
    parameters.responseUri,
  ]);

  const handover = ['OpenID4VPHandover', new Uint8Array(createHash('sha256').update(handoverInfo).digest())];

  return encode([null, null, handover]);
}

/**
 * RFC 7638 JWK thumbprint of an EC public key.
 *
 * The members are hashed in lexicographic order with no whitespace, which is
 * the whole of the specification and the whole of the difficulty.
 */
export function jwkThumbprint(jwk: { kty: string; crv: string; x: string; y: string }): Uint8Array {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return new Uint8Array(createHash('sha256').update(canonical, 'utf8').digest());
}
