import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { KeyObject } from 'node:crypto';
import {
  ALLOWED_JWS_ALG,
  decodeProtectedHeader,
  decodeUnverifiedPayload,
  hasher,
  importEcP256Jwk,
  verifyEs256,
} from './crypto.ts';
import { type Outcome, accept, reject } from './result.ts';
import { type AgeResult, evaluateAgeOver18 } from './predicate/age.ts';
import type { TrustAnchors } from './trust/anchors.ts';
import { resolveIssuerKeyFromX5c } from './trust/issuer-key.ts';

/**
 * SD-JWT VC media types accepted in the `typ` header.
 *
 * draft-ietf-oauth-sd-jwt-vc-18 defines `dc+sd-jwt` and says the older
 * `vc+sd-jwt` "should be accepted [...] for a reasonable transitional period".
 * The live EUDI reference issuer advertises `dc+sd-jwt`.
 */
const ACCEPTED_TYP = new Set(['dc+sd-jwt', 'vc+sd-jwt']);

export type KeyBindingExpectation = {
  /** Nonce this verifier issued in its presentation request. */
  nonce: string;
  /** This verifier's identifier, matched against the KB-JWT `aud`. */
  audience: string;
};

export type VerifyCredentialOptions = {
  /** Compact SD-JWT VC, optionally with a trailing Key Binding JWT. */
  credential: string;
  anchors: TrustAnchors;
  /** Expected `vct`. Omit to accept any type. */
  expectedVct?: string;
  /**
   * Required unless `requireKeyBinding` is false. `@sd-jwt/core` skips key
   * binding entirely when no nonce is supplied, even if a KB-JWT is present,
   * so this must not be optional by accident.
   */
  keyBinding?: KeyBindingExpectation;
  /** Only set false for issuer-side checks; a presentation must be bound. */
  requireKeyBinding?: boolean;
  now?: Date;
};

export type VerifiedCredential = {
  claims: Record<string, unknown>;
  vct: string;
  issuerCertificateSubject: string;
  keyBinding: { audience: string; nonce: string } | undefined;
};

export async function verifyCredential(
  options: VerifyCredentialOptions,
): Promise<Outcome<VerifiedCredential>> {
  const now = options.now ?? new Date();
  const requireKeyBinding = options.requireKeyBinding ?? true;

  if (requireKeyBinding && !options.keyBinding) {
    throw new Error('keyBinding is required unless requireKeyBinding is explicitly false');
  }

  const issuerJwt = options.credential.split('~')[0];
  if (!issuerJwt || issuerJwt.split('.').length !== 3) {
    return reject('CREDENTIAL_MALFORMED', 'Credential is not a compact SD-JWT');
  }

  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(issuerJwt);
  } catch (error) {
    return reject('CREDENTIAL_MALFORMED', `Cannot decode JWT header: ${String(error)}`);
  }

  if (header['alg'] !== ALLOWED_JWS_ALG) {
    return reject('UNSUPPORTED_ALGORITHM', `Expected alg ${ALLOWED_JWS_ALG}, got ${String(header['alg'])}`);
  }
  if (typeof header['typ'] !== 'string' || !ACCEPTED_TYP.has(header['typ'])) {
    return reject('CREDENTIAL_MALFORMED', `Unexpected typ header: ${String(header['typ'])}`);
  }

  const issuer = resolveIssuerKeyFromX5c(issuerJwt, options.anchors, now);
  if (!issuer.verified) return issuer;

  // Track which signature check failed, rather than parsing library messages.
  let issuerSignatureOk = false;
  let keyBindingSignatureOk = false;

  const sdjwt = new SDJwtVcInstance({
    hasher,
    verifier: (data, sig) => {
      issuerSignatureOk = verifyEs256(issuer.value.publicKey, data, sig);
      return issuerSignatureOk;
    },
    kbVerifier: (data, sig) => {
      const holderKey = holderKeyFrom(options.credential);
      if (!holderKey) return false;
      keyBindingSignatureOk = verifyEs256(holderKey, data, sig);
      return keyBindingSignatureOk;
    },
  });

  let result: Awaited<ReturnType<SDJwtVcInstance['verify']>>;
  try {
    result = await sdjwt.verify(options.credential, {
      currentDate: Math.floor(now.getTime() / 1000),
      // Supplying the nonce is what makes @sd-jwt verify the KB-JWT at all.
      ...(options.keyBinding ? { keyBindingNonce: options.keyBinding.nonce } : {}),
      // Phase 1 is offline. Status list checking arrives with Phase 2.
      disableStatusVerification: true,
    });
  } catch (error) {
    return mapLibraryError(error, { issuerSignatureOk, keyBindingSignatureOk, requireKeyBinding });
  }

  const claims = result.payload as unknown as Record<string, unknown>;
  const vct = typeof claims['vct'] === 'string' ? claims['vct'] : undefined;
  if (!vct) return reject('CREDENTIAL_MALFORMED', 'Credential has no `vct` claim');
  if (options.expectedVct && vct !== options.expectedVct) {
    return reject('UNEXPECTED_VCT', `Expected vct ${options.expectedVct}, got ${vct}`);
  }

  let keyBinding: VerifiedCredential['keyBinding'];
  if (options.keyBinding) {
    if (!result.kb) return reject('KEY_BINDING_MISSING', 'No Key Binding JWT in the presentation');
    // @sd-jwt checks that `aud` is present and that `nonce` matches, but never
    // checks `aud` against the verifier's own identifier. Without this check a
    // presentation made for another verifier would be accepted here.
    if (result.kb.payload.aud !== options.keyBinding.audience) {
      return reject(
        'KEY_BINDING_AUDIENCE_MISMATCH',
        `Key Binding JWT aud is ${String(result.kb.payload.aud)}, expected ${options.keyBinding.audience}`,
      );
    }
    keyBinding = { audience: result.kb.payload.aud, nonce: result.kb.payload.nonce };
  } else if (requireKeyBinding) {
    return reject('KEY_BINDING_MISSING', 'Key binding required but no expectation supplied');
  }

  return accept({
    claims,
    vct,
    issuerCertificateSubject: issuer.value.leaf.subject,
    keyBinding,
  });
}

/** Verify the credential and evaluate the age-over-18 predicate in one step. */
export async function verifyAgeOver18(
  options: VerifyCredentialOptions,
): Promise<Outcome<VerifiedCredential & AgeResult>> {
  const credential = await verifyCredential(options);
  if (!credential.verified) return credential;

  const age = evaluateAgeOver18(credential.value.claims, options.now ?? new Date());
  if (!age.verified) return age;

  return accept({ ...credential.value, ...age.value });
}

/**
 * The holder's public key, from the credential's `cnf.jwk`.
 *
 * Decoding the payload without verifying it is safe here: `@sd-jwt/core` only
 * invokes `kbVerifier` after the issuer signature over that same payload has
 * already been verified, so the `cnf` we read is issuer-attested.
 */
function holderKeyFrom(credential: string): KeyObject | undefined {
  const issuerJwt = credential.split('~')[0];
  if (!issuerJwt) return undefined;
  try {
    const cnf = decodeUnverifiedPayload(issuerJwt)['cnf'];
    if (typeof cnf !== 'object' || cnf === null) return undefined;
    return importEcP256Jwk((cnf as Record<string, unknown>)['jwk']);
  } catch {
    return undefined;
  }
}

function mapLibraryError(
  error: unknown,
  state: { issuerSignatureOk: boolean; keyBindingSignatureOk: boolean; requireKeyBinding: boolean },
): Outcome<never> {
  const message = error instanceof Error ? error.message : String(error);

  if (!state.issuerSignatureOk && /signature/i.test(message)) {
    return reject('ISSUER_SIGNATURE_INVALID', message);
  }
  if (/not yet valid/i.test(message)) return reject('CREDENTIAL_NOT_YET_VALID', message);
  if (/expired/i.test(message)) return reject('CREDENTIAL_EXPIRED', message);
  if (/Key Binding JWT not exist/i.test(message)) return reject('KEY_BINDING_MISSING', message);
  if (/Invalid Nonce/i.test(message)) return reject('KEY_BINDING_NONCE_MISMATCH', message);
  if (/sd_hash|Key Binding|Signature is not valid/i.test(message)) {
    return reject('KEY_BINDING_INVALID', message);
  }
  return reject('CREDENTIAL_MALFORMED', message);
}
