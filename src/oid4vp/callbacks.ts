import { createHash, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import {
  CompactEncrypt,
  type JWK,
  SignJWT,
  compactDecrypt,
  exportJWK,
  importJWK,
  importPKCS8,
  jwtVerify,
} from 'jose';
import type { JwsAlg } from '../crypto.ts';

/**
 * `@openid4vc/openid4vp` is transport and state machine only — every
 * cryptographic operation is a callback the relying party supplies. These are
 * those callbacks, backed by `jose`.
 */

export type SigningMaterial = {
  /** PKCS#8 PEM of the access certificate's private key. */
  privateKeyPem: string;
  /** The access certificate chain, base64 DER, leaf first — the JAR `x5c`. */
  x5c: string[];
};

export function hashCallback(data: Uint8Array, alg: string) {
  const nodeAlg = alg.toLowerCase().replace('-', '');
  return new Uint8Array(createHash(nodeAlg).update(data).digest());
}

export function generateRandom(byteLength: number): Uint8Array {
  return new Uint8Array(randomBytes(byteLength));
}

/**
 * The JWS algorithm for signing with this access certificate's key.
 *
 * Derived from the key rather than fixed, because the key is issued by whoever
 * registered this relying party and is not ours to choose. An EC key on any of
 * the three JOSE curves signs with the matching ES*; an RSA key signs with
 * PS256, which is the one choice valid for both `rsa` and `rsa-pss` keys — an
 * `rsa-pss` key may not produce a PKCS#1 signature at all (RFC 4055).
 *
 * Worth knowing before obtaining an RSA access certificate: the OpenID4VC High
 * Assurance Interoperability Profile requires request objects to be signed with
 * ES256, so a wallet following it may refuse a PS256 request however correct it
 * is. Nothing here can fix that; signing with the wrong key would only turn a
 * refusal into a broken signature.
 */
export function requestSigningAlg(privateKeyPem: string): JwsAlg {
  const key = createPrivateKey(privateKeyPem);
  const type = key.asymmetricKeyType;

  if (type === 'rsa' || type === 'rsa-pss') return 'PS256';
  if (type !== 'ec') {
    throw new Error(`Access certificate key is ${String(type)}; EC and RSA keys are supported`);
  }
  const curve = key.asymmetricKeyDetails?.namedCurve;
  const alg = EC_CURVE_ALGS[String(curve)];
  if (!alg) throw new Error(`Access certificate key uses curve ${String(curve)}, which has no JWS algorithm`);
  return alg;
}

const EC_CURVE_ALGS: Record<string, JwsAlg> = {
  prime256v1: 'ES256',
  secp384r1: 'ES384',
  secp521r1: 'ES512',
};

export function createSignJwt(material: SigningMaterial | undefined) {
  return async (_signer: unknown, jwt: { header: Record<string, unknown>; payload: Record<string, unknown> }) => {
    if (!material) {
      throw new Error('Request signing was attempted without access certificate key material');
    }
    const alg = requestSigningAlg(material.privateKeyPem);
    const privateKey = await importPKCS8(material.privateKeyPem, alg);
    const signed = await new SignJWT(jwt.payload)
      .setProtectedHeader({ ...jwt.header, alg, x5c: material.x5c } as never)
      .sign(privateKey);
    const signerJwk = (await exportJWK(createPublicKey(material.privateKeyPem))) as JWK;
    return { jwt: signed, signerJwk: signerJwk as never };
  };
}

/**
 * Verify a JWT whose key travels with it.
 *
 * Used when parsing a JARM response. Trust in the key itself comes from the
 * response being tied to a session we created, plus the credential-level checks
 * that follow; this callback only proves the JWT is internally consistent.
 */
export function createVerifyJwt() {
  return async (
    signer: { method?: string; publicJwk?: JWK },
    jwt: { compact: string },
  ): Promise<{ verified: true; signerJwk: never } | { verified: false }> => {
    if (!signer.publicJwk) return { verified: false };
    try {
      const key = await importJWK(signer.publicJwk);
      await jwtVerify(jwt.compact, key);
      return { verified: true, signerJwk: signer.publicJwk as never };
    } catch {
      return { verified: false };
    }
  };
}

/** Decrypt a JARM response (`response_mode=direct_post.jwt`). */
export function createDecryptJwe(privateJwk: JWK | undefined) {
  return async (jwe: string) => {
    if (!privateJwk) return { decrypted: false as const };
    try {
      // jose cannot infer a key-agreement algorithm from a bare EC JWK, so the
      // algorithm has to be named. Take it from our own key rather than from
      // the incoming JWE header, which the sender controls.
      const key = await importJWK(privateJwk, privateJwk.alg ?? 'ECDH-ES');
      const { plaintext } = await compactDecrypt(jwe, key);
      return {
        decrypted: true as const,
        decryptionJwk: privateJwk as never,
        payload: new TextDecoder().decode(plaintext),
      };
    } catch {
      return { decrypted: false as const };
    }
  };
}

export function createEncryptJwe() {
  return async (encryptor: { publicJwk: JWK; alg: string; enc: string }, data: string) => {
    const key = await importJWK(encryptor.publicJwk, encryptor.alg);
    const jwe = await new CompactEncrypt(new TextEncoder().encode(data))
      .setProtectedHeader({ alg: encryptor.alg, enc: encryptor.enc } as never)
      .encrypt(key);
    return { encryptionJwk: encryptor.publicJwk as never, jwe };
  };
}
