import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { KeyObject } from 'node:crypto';
import {
  DEFAULT_ALLOWED_ALGS,
  type JwsAlg,
  decodeProtectedHeader,
  decodeUnverifiedPayload,
  hasher,
  importPublicJwk,
  isSupportedAlg,
  keyUnusableFor,
  verifyJws,
} from './crypto.ts';
import { type Outcome, accept, reject } from './result.ts';
import { type AgeResult, evaluateAgeOver18 } from './predicate/age.ts';

export type { AgeResult };
import type { TrustAnchors } from './trust/anchors.ts';
import { type PathValidationOptions, resolveIssuerKeyFromX5c } from './trust/issuer-key.ts';
import { createStatusChecker } from './trust/status.ts';
import { checkChainRevocation, revocationRejection, revocationVia } from './trust/revocation.ts';
import type { TtlCache } from './fetching.ts';
import { type EventSink, noopSink, withoutVerdict } from './events.ts';

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
  /**
   * Check the credential's status list. On by default: a credential carrying a
   * `status` claim that we do not check is a credential we might be accepting
   * after revocation. Requires network access to the issuer's status endpoint,
   * so tests that must stay offline turn it off explicitly.
   */
  checkStatus?: boolean;
  /** Injectable fetch for status list retrieval, for tests. */
  statusFetch?: typeof fetch;
  /**
   * Shared status list cache. Strongly recommended in a service: without one,
   * every verification refetches a document that covers many credentials.
   */
  statusCache?: TtlCache<string>;
  /** Abort a status list request after this long. */
  statusTimeoutMs?: number;
  /**
   * Check the issuer's *certificate chain* for revocation, via CRL or OCSP.
   *
   * On by default and fails closed, like `checkStatus` — and answering a
   * different question from it. A certificate that publishes neither mechanism
   * is not a failure; one that publishes a CRL we cannot reach is. Requires
   * network access to the CA, so tests that must stay offline turn it off.
   */
  checkCertificateRevocation?: boolean;
  /** Injectable fetch for CRL and OCSP retrieval, for tests. */
  revocationFetch?: typeof fetch;
  /** Shared CRL/OCSP cache. A CRL covers every certificate its CA ever issued. */
  revocationCache?: TtlCache<Uint8Array>;
  /** Abort a CRL or OCSP request after this long. */
  revocationTimeoutMs?: number;
  /** Tolerance for clock differences with the issuer, in seconds. */
  clockSkewSeconds?: number;
  /** Extra constraints on the issuer's certificate chain. */
  pathValidation?: PathValidationOptions;
  /**
   * Signature algorithms accepted, for both the issuer signature and the Key
   * Binding JWT. Defaults to ES256, which is all the EUDI reference
   * infrastructure uses.
   */
  allowedAlgs?: readonly JwsAlg[];
  /**
   * Receives structured events for auditing and metrics. Carries no personal
   * data by construction — see `src/events.ts`.
   */
  onEvent?: EventSink;
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
  const emit = options.onEvent ?? noopSink;
  const startedAt = Date.now();

  /** Every exit from this function goes through one of these two. */
  const rejectWith = (outcome: Outcome<never>) => {
    if (!outcome.verified) {
      emit({
        type: 'verification.rejected',
        format: 'dc+sd-jwt',
        reason: outcome.reason,
        durationMs: Date.now() - startedAt,
      });
    }
    return outcome;
  };

  if (requireKeyBinding && !options.keyBinding) {
    throw new Error('keyBinding is required unless requireKeyBinding is explicitly false');
  }

  const issuerJwt = options.credential.split('~')[0];
  if (!issuerJwt || issuerJwt.split('.').length !== 3) {
    return rejectWith(reject('CREDENTIAL_MALFORMED', 'Credential is not a compact SD-JWT'));
  }

  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(issuerJwt);
  } catch (error) {
    return rejectWith(reject('CREDENTIAL_MALFORMED', `Cannot decode JWT header: ${String(error)}`));
  }

  const allowedAlgs = options.allowedAlgs ?? DEFAULT_ALLOWED_ALGS;
  const alg = header['alg'];
  // Checked against the caller's policy, never used to select the algorithm.
  if (!isSupportedAlg(alg) || !allowedAlgs.includes(alg)) {
    return rejectWith(
      reject('UNSUPPORTED_ALGORITHM', `alg ${String(alg)} is not in the allowed set (${allowedAlgs.join(', ')})`),
    );
  }
  if (typeof header['typ'] !== 'string' || !ACCEPTED_TYP.has(header['typ'])) {
    return rejectWith(reject('CREDENTIAL_MALFORMED', `Unexpected typ header: ${String(header['typ'])}`));
  }

  // Validity window, checked here rather than inferred from a thrown message.
  const payload = (() => {
    try {
      return decodeUnverifiedPayload(issuerJwt);
    } catch {
      return undefined;
    }
  })();
  if (!payload) return rejectWith(reject('CREDENTIAL_MALFORMED', 'Cannot decode JWT payload'));

  const skewSeconds = options.clockSkewSeconds ?? 0;
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const exp = payload['exp'];
  const nbf = payload['nbf'];
  if (typeof exp === 'number' && nowSeconds > exp + skewSeconds) {
    return rejectWith(reject('CREDENTIAL_EXPIRED', `Credential expired at ${new Date(exp * 1000).toISOString()}`));
  }
  if (typeof nbf === 'number' && nowSeconds < nbf - skewSeconds) {
    return rejectWith(reject('CREDENTIAL_NOT_YET_VALID', `Credential valid from ${new Date(nbf * 1000).toISOString()}`));
  }

  // Key binding presence and nonce, likewise. Reading the KB-JWT before its
  // signature is checked is safe because these comparisons only ever reject;
  // acceptance still requires the library's full verification below.
  if (options.keyBinding) {
    const kb = keyBindingJwt(options.credential);
    if (!kb) return rejectWith(reject('KEY_BINDING_MISSING', 'No Key Binding JWT in the presentation'));
    let kbPayload: Record<string, unknown>;
    try {
      kbPayload = decodeUnverifiedPayload(kb);
    } catch {
      return rejectWith(reject('KEY_BINDING_INVALID', 'Key Binding JWT payload is not decodable'));
    }
    if (kbPayload['nonce'] !== options.keyBinding.nonce) {
      return rejectWith(reject('KEY_BINDING_NONCE_MISMATCH', 'Key Binding JWT nonce is not the one we issued'));
    }
    if (kbPayload['aud'] !== options.keyBinding.audience) {
      return rejectWith(reject(
        'KEY_BINDING_AUDIENCE_MISMATCH',
        `Key Binding JWT aud is ${String(kbPayload['aud'])}, expected ${options.keyBinding.audience}`,
      ));
    }
  }

  emit({
    type: 'verification.started',
    format: 'dc+sd-jwt',
    vct: typeof payload['vct'] === 'string' ? payload['vct'] : undefined,
  });

  const issuer = resolveIssuerKeyFromX5c(issuerJwt, options.anchors, now, options.pathValidation ?? {});
  if (!issuer.verified) return rejectWith(issuer);
  // The certificate's key and the token's `alg` have been checked separately;
  // this is the pair. Doing it here rather than inside the verifier callback is
  // what keeps an RSA key offered for ES256 reported as UNSUPPORTED_ALGORITHM
  // instead of as a bad signature.
  const mismatch = keyUnusableFor(issuer.value.publicKey, alg);
  if (mismatch) {
    return rejectWith(reject('UNSUPPORTED_ALGORITHM', `Issuer key does not match the token: ${mismatch}`));
  }
  emit({
    type: 'issuer.resolved',
    format: 'dc+sd-jwt',
    subject: issuer.value.leaf.subject,
    chainLength: issuer.value.chain.length,
  });

  // Three states, not two: a token malformed enough that the library gives up
  // before checking a signature leaves it *untested*, which is not the same as
  // tested and wrong. Collapsing them reports a bad signature for what is
  // really a structural defect.
  type SignatureState = 'untested' | 'ok' | 'bad';
  let issuerSignature: SignatureState = 'untested';
  let keyBindingSignature: SignatureState = 'untested';

  const checkStatus = options.checkStatus ?? true;
  const status = createStatusChecker({
    anchors: options.anchors,
    now,
    ...(options.statusFetch ? { fetchImpl: options.statusFetch } : {}),
    ...(options.statusCache ? { cache: options.statusCache } : {}),
    ...(options.statusTimeoutMs ? { timeoutMs: options.statusTimeoutMs } : {}),
    // The same tolerance the credential's own `exp` gets, so the status list
    // and the credential are judged against one clock.
    ...(options.clockSkewSeconds ? { clockSkewSeconds: options.clockSkewSeconds } : {}),
    // And the same algorithm policy, for the same reason: the status list is a
    // second signed statement from the same issuer about the same credential.
    allowedAlgs,
  });

  const sdjwt = new SDJwtVcInstance({
    hasher,
    statusListFetcher: status.statusListFetcher,
    statusVerifier: status.statusVerifier,
    statusValidator: status.statusValidator,
    verifier: (data, sig) => {
      const ok = verifyJws(issuer.value.publicKey, data, sig, alg);
      issuerSignature = ok ? 'ok' : 'bad';
      return ok;
    },
    kbVerifier: (data, sig) => {
      const kbAlg = keyBindingAlg(options.credential, allowedAlgs);
      const holderKey = kbAlg && holderKeyFrom(options.credential, allowedAlgs);
      if (!kbAlg || !holderKey) {
        keyBindingSignature = 'bad';
        return false;
      }
      const ok = verifyJws(holderKey, data, sig, kbAlg);
      keyBindingSignature = ok ? 'ok' : 'bad';
      return ok;
    },
  });

  let result: Awaited<ReturnType<SDJwtVcInstance['verify']>>;
  try {
    result = await sdjwt.verify(options.credential, {
      currentDate: Math.floor(now.getTime() / 1000),
      ...(options.clockSkewSeconds ? { skewSeconds: options.clockSkewSeconds } : {}),
      // Supplying the nonce is what makes @sd-jwt verify the KB-JWT at all.
      ...(options.keyBinding ? { keyBindingNonce: options.keyBinding.nonce } : {}),
      // A credential with a `status` claim that we skip is one we could be
      // accepting after revocation.
      disableStatusVerification: !checkStatus,
    });
  } catch (error) {
    // The status checker records what it concluded, so revocation and an
    // unreachable endpoint are distinguished by state rather than by wording.
    if (status.outcome.kind === 'revoked') {
      return rejectWith(reject('CREDENTIAL_REVOKED', `The issuer has revoked this credential (status ${status.outcome.status})`));
    }
    if (status.outcome.kind === 'unavailable') {
      return rejectWith(reject('STATUS_UNAVAILABLE', status.outcome.detail));
    }
    return rejectWith(mapLibraryError(error, { issuerSignature, keyBindingSignature }));
  }

  const claims = result.payload as unknown as Record<string, unknown>;
  const vct = typeof claims['vct'] === 'string' ? claims['vct'] : undefined;
  if (!vct) return rejectWith(reject('CREDENTIAL_MALFORMED', 'Credential has no `vct` claim'));
  if (options.expectedVct && vct !== options.expectedVct) {
    return rejectWith(reject('UNEXPECTED_VCT', `Expected vct ${options.expectedVct}, got ${vct}`));
  }

  let keyBinding: VerifiedCredential['keyBinding'];
  if (options.keyBinding) {
    if (!result.kb) return rejectWith(reject('KEY_BINDING_MISSING', 'No Key Binding JWT in the presentation'));
    // @sd-jwt checks that `aud` is present and that `nonce` matches, but never
    // checks `aud` against the verifier's own identifier. Without this check a
    // presentation made for another verifier would be accepted here.
    if (result.kb.payload.aud !== options.keyBinding.audience) {
      return rejectWith(reject(
        'KEY_BINDING_AUDIENCE_MISMATCH',
        `Key Binding JWT aud is ${String(result.kb.payload.aud)}, expected ${options.keyBinding.audience}`,
      ));
    }
    keyBinding = { audience: result.kb.payload.aud, nonce: result.kb.payload.nonce };
  } else if (requireKeyBinding) {
    return rejectWith(reject('KEY_BINDING_MISSING', 'Key binding required but no expectation supplied'));
  }

  if (status.outcome.kind !== 'not-checked') {
    emit({
      type: 'status.checked',
      outcome: status.outcome.kind === 'revoked' ? 'revoked' : status.outcome.kind,
      cached: options.statusCache !== undefined,
    });
  }

  // Last, because it reaches the network and everything above can reject
  // without it. The chain is the one `resolveIssuerKeyFromX5c` returned, so
  // this checks what was actually trusted rather than re-deriving it.
  if (options.checkCertificateRevocation ?? true) {
    const revocation = await checkChainRevocation(issuer.value.chain, {
      now,
      ...(options.revocationFetch ? { fetchImpl: options.revocationFetch } : {}),
      ...(options.revocationCache ? { cache: options.revocationCache } : {}),
      ...(options.revocationTimeoutMs ? { timeoutMs: options.revocationTimeoutMs } : {}),
      ...(options.clockSkewSeconds ? { clockSkewSeconds: options.clockSkewSeconds } : {}),
    });
    emit({ type: 'issuer.revocation.checked', outcome: revocation.kind, via: revocationVia(revocation) });
    const rejected = revocationRejection(revocation);
    if (rejected) return rejectWith(rejected);
  }

  emit({ type: 'verification.accepted', format: 'dc+sd-jwt', vct, durationMs: Date.now() - startedAt });

  return accept({
    claims,
    vct,
    issuerCertificateSubject: issuer.value.leaf.subject,
    keyBinding,
  });
}

/**
 * Verify the credential and evaluate the age-over-18 predicate in one step.
 *
 * The verdict is this function's rather than `verifyCredential`'s: a credential
 * can verify perfectly and still fail the predicate, and an audit trail
 * recording `verification.accepted` for a presentation the caller was told to
 * reject would be wrong about the only thing it exists to record.
 *
 * It is also where `evidence` gets onto the event — which of the two ways the
 * predicate was satisfied. That distinction is the privacy one: the boolean
 * discloses nothing else, the birthdate discloses a date of birth, and a
 * relying party auditing what it actually learned needs to see which.
 */
export async function verifyAgeOver18(
  options: VerifyCredentialOptions,
): Promise<Outcome<VerifiedCredential & AgeResult>> {
  const emit = options.onEvent ?? noopSink;
  const startedAt = Date.now();
  const rejectWith = <T>(outcome: Outcome<T>): Outcome<T> => {
    if (!outcome.verified) {
      emit({
        type: 'verification.rejected',
        format: 'dc+sd-jwt',
        reason: outcome.reason,
        durationMs: Date.now() - startedAt,
      });
    }
    return outcome;
  };

  const credential = await verifyCredential({ ...options, onEvent: withoutVerdict(emit) });
  if (!credential.verified) return rejectWith(credential);

  const age = evaluateAgeOver18(credential.value.claims, options.now ?? new Date());
  if (!age.verified) return rejectWith(age);

  emit({
    type: 'verification.accepted',
    format: 'dc+sd-jwt',
    vct: credential.value.vct,
    evidence: age.value.evidence,
    durationMs: Date.now() - startedAt,
  });

  return accept({ ...credential.value, ...age.value });
}

/**
 * The holder's public key, from the credential's `cnf.jwk`.
 *
 * Decoding the payload without verifying it is safe here: `@sd-jwt/core` only
 * invokes `kbVerifier` after the issuer signature over that same payload has
 * already been verified, so the `cnf` we read is issuer-attested.
 */
/** The Key Binding JWT's own algorithm, subject to the same policy. */
function keyBindingAlg(credential: string, allowed: readonly JwsAlg[]): JwsAlg | undefined {
  const kb = keyBindingJwt(credential);
  if (!kb) return undefined;
  try {
    const alg = decodeProtectedHeader(kb)['alg'];
    return isSupportedAlg(alg) && allowed.includes(alg) ? alg : undefined;
  } catch {
    return undefined;
  }
}

function holderKeyFrom(credential: string, allowed: readonly JwsAlg[]): KeyObject | undefined {
  const issuerJwt = credential.split('~')[0];
  if (!issuerJwt) return undefined;
  try {
    const cnf = decodeUnverifiedPayload(issuerJwt)['cnf'];
    if (typeof cnf !== 'object' || cnf === null) return undefined;
    return importPublicJwk((cnf as Record<string, unknown>)['jwk'], allowed);
  } catch {
    return undefined;
  }
}

/**
 * Turn a library failure into a reason code, from recorded state only.
 *
 * Nothing here inspects the message. Reason codes derived by matching wording
 * change silently when a dependency rephrases an error — which happened once in
 * this codebase already — so every distinction that matters is either checked
 * explicitly before the library runs, or recorded by one of our callbacks.
 */
function mapLibraryError(
  error: unknown,
  state: { issuerSignature: 'untested' | 'ok' | 'bad'; keyBindingSignature: 'untested' | 'ok' | 'bad' },
): Outcome<never> {
  const message = error instanceof Error ? error.message : String(error);

  if (state.issuerSignature === 'bad') return reject('ISSUER_SIGNATURE_INVALID', message);
  if (state.keyBindingSignature === 'bad') return reject('KEY_BINDING_INVALID', message);
  // Either a signature was never reached, or both verified and what remains is
  // structural: an unreferenced disclosure, a bad digest, a wrong sd_hash.
  return reject('CREDENTIAL_MALFORMED', message);
}

/** The Key Binding JWT, which is the trailing `~`-separated segment if present. */
function keyBindingJwt(credential: string): string | undefined {
  const last = credential.split('~').at(-1);
  return last && last.split('.').length === 3 ? last : undefined;
}
