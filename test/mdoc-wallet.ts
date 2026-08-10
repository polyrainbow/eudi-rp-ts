import { createPrivateKey, sign as nodeSign } from 'node:crypto';
import { decode, encode, encodeTag24, get } from '../src/mdoc/cbor.ts';

/**
 * A minimal mdoc wallet, for testing device authentication.
 *
 * It does the one thing the verifier depends on: sign a `DeviceAuthentication`
 * structure with the device key, over the verifier's session transcript. Like
 * `test/wallet.ts` for SD-JWT, it is not an implementation of a wallet and does
 * not try to be.
 */
export function buildDeviceResponse(options: {
  /** `IssuerSigned` as issued, base64url CBOR. */
  issuerSigned: string;
  /** The device private key, as a JWK. */
  devicePrivateJwk: Record<string, unknown>;
  /** From `buildSessionTranscript`. */
  sessionTranscript: Uint8Array;
  docType: string;
  /** Claims the device asserts itself; usually none. */
  deviceNameSpaces?: Record<string, Record<string, unknown>>;
  /** Sign over a different transcript, to test replay rejection. */
  signOverTranscript?: Uint8Array;
}): Uint8Array {
  const issuerSigned = decode(new Uint8Array(Buffer.from(options.issuerSigned, 'base64url')));

  const deviceNameSpacesBytes = encodeTag24(encode(options.deviceNameSpaces ?? {}));

  // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript,
  //                         DocType, DeviceNameSpacesBytes]
  const deviceAuthentication = Uint8Array.from([
    0x84,
    ...encode('DeviceAuthentication'),
    ...(options.signOverTranscript ?? options.sessionTranscript),
    ...encode(options.docType),
    ...deviceNameSpacesBytes,
  ]);

  // COSE_Sign1 with a detached payload: the signature covers
  // DeviceAuthenticationBytes, but the structure carries null.
  const protectedHeader = encode(new Map([[1, -7]])); // alg: ES256
  const sigStructure = encode([
    'Signature1',
    protectedHeader,
    new Uint8Array(0),
    encodeTag24(deviceAuthentication),
  ]);

  const key = createPrivateKey({ key: options.devicePrivateJwk as never, format: 'jwk' });
  const signature = nodeSign('sha256', Buffer.from(sigStructure), {
    key,
    dsaEncoding: 'ieee-p1363',
  });

  const deviceSignature = [protectedHeader, new Map(), null, new Uint8Array(signature)];

  return encode({
    version: '1.0',
    documents: [
      {
        docType: options.docType,
        issuerSigned: get(issuerSigned, 'issuerAuth') !== undefined ? issuerSigned : issuerSigned,
        deviceSigned: {
          nameSpaces: { tag: 24, contents: encode(options.deviceNameSpaces ?? {}) },
          deviceAuth: { deviceSignature },
        },
      },
    ],
    status: 0,
  });
}
