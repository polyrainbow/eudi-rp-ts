/**
 * Machine-readable outcomes. Every rejection path in this codebase ends at
 * exactly one of these codes, so a caller never has to parse an error string.
 */
export type ReasonCode =
  // Shape of the token itself
  | 'CREDENTIAL_MALFORMED'
  | 'UNSUPPORTED_ALGORITHM'
  | 'UNEXPECTED_CREDENTIAL_TYPE'
  // Issuer identity and trust
  | 'ISSUER_KEY_UNRESOLVABLE'
  | 'ISSUER_UNTRUSTED'
  | 'ISSUER_SIGNATURE_INVALID'
  /**
   * A CA in the chain carries Name Constraints (RFC 5280 §4.2.1.10) that the
   * certificate below it falls outside of. Distinct from `ISSUER_UNTRUSTED`:
   * the chain links and reaches an anchor, but a CA on it was not entitled to
   * certify this name.
   */
  | 'ISSUER_NAME_NOT_PERMITTED'
  /**
   * No certificate policy (RFC 5280 §4.2.1.4) is valid for the whole path —
   * either a CA on it required an explicit policy that a certificate below did
   * not assert, or nothing survived the intersection with the policies the
   * caller accepts. Distinct from `ISSUER_UNTRUSTED` for the same reason as
   * `ISSUER_NAME_NOT_PERMITTED`: the chain links and reaches an anchor, but not
   * under any policy that was agreed the whole way down.
   */
  | 'ISSUER_POLICY_NOT_PERMITTED'
  /**
   * A certificate on the path carries a critical extension this library does
   * not process, which RFC 5280 §6.1.4 (o) requires be rejected. Distinct from
   * `ISSUER_UNTRUSTED`, and the distinction is the useful part: nothing is
   * known to be wrong with the issuer, the chain or the credential — this
   * verifier is the thing that fell short, and the operator's next step is to
   * read the extension rather than to go looking at the issuer. `detail`
   * carries the OIDs.
   */
  | 'ISSUER_EXTENSION_UNRECOGNISED'
  // Validity window
  | 'CREDENTIAL_EXPIRED'
  | 'CREDENTIAL_NOT_YET_VALID'
  // Holder binding
  | 'KEY_BINDING_MISSING'
  | 'KEY_BINDING_INVALID'
  | 'KEY_BINDING_NONCE_MISMATCH'
  | 'KEY_BINDING_AUDIENCE_MISMATCH'
  /**
   * The credential verified, but does not carry the claims its Credential Query
   * asked for — or carries one with a value the query said it would not accept
   * (OID4VP 1.0 §6.3, §6.4.1).
   *
   * Distinct from `PREDICATE_*`, and the distinction is who fell short: this is
   * the wallet answering something other than what was asked, before any rule
   * of the caller's has been applied. A predicate rejection means the answer
   * arrived intact and did not satisfy the verifier's rule. Reporting one as
   * the other sends an operator to argue with a holder about a wallet bug.
   */
  | 'REQUESTED_CLAIMS_MISSING'
  // The predicate we were asked to prove
  | 'PREDICATE_CLAIM_MISSING'
  | 'PREDICATE_NOT_SATISFIED'
  // OID4VP protocol envelope (Phase 2)
  | 'RESPONSE_INVALID'
  | 'SESSION_UNKNOWN'
  | 'SESSION_EXPIRED'
  /**
   * The wallet declined and said why (OID4VP 1.0 §8.2). Distinct from
   * `RESPONSE_INVALID`: the response was well-formed, it just carried an error
   * instead of a presentation. `detail` holds the wallet's own error code.
   */
  | 'WALLET_ERROR'
  // Trust list retrieval (Phase 2)
  | 'TRUST_LIST_UNAVAILABLE'
  // Revocation of the credential, via Token Status List
  | 'CREDENTIAL_REVOKED'
  | 'STATUS_UNAVAILABLE'
  /**
   * A certificate in the issuer's chain has been revoked by its CA, via CRL or
   * OCSP. Distinct from `CREDENTIAL_REVOKED`: that is one credential withdrawn
   * by an issuer in good standing, this is the issuer's own key no longer being
   * trusted to have issued any of them.
   */
  | 'ISSUER_CERTIFICATE_REVOKED'
  /**
   * The issuer's chain publishes a CRL or an OCSP responder that could not be
   * fetched, verified, or read. Distinct from `STATUS_UNAVAILABLE`, which is
   * the credential's own status list.
   */
  | 'ISSUER_REVOCATION_UNAVAILABLE'
  /**
   * The caller's `AbortSignal` fired — a cancellation, or a deadline over the
   * whole verification rather than the per-request one each fetch already has.
   *
   * Distinct from `STATUS_UNAVAILABLE` and `ISSUER_REVOCATION_UNAVAILABLE`,
   * which is the point of having it: those say an endpoint we depend on did not
   * answer, and reporting our own cancellation as one of them blames an issuer
   * for a deadline we set. Derived from the signal's state rather than from the
   * shape of the error, on the same rule as every other code here.
   *
   * A rejection rather than a thrown `AbortError`, so that cancelling cannot
   * accidentally be caught somewhere that treats a throw as "keep going", and
   * so it fails closed like every other outcome.
   */
  | 'VERIFICATION_ABORTED';

export type Rejected = {
  verified: false;
  reason: ReasonCode;
  /** Human-readable context. Never parse this; switch on `reason` instead. */
  detail: string;
};

export type Verified<T> = {
  verified: true;
  value: T;
};

export type Outcome<T> = Verified<T> | Rejected;

export function reject(reason: ReasonCode, detail: string): Rejected {
  return { verified: false, reason, detail };
}

export function accept<T>(value: T): Verified<T> {
  return { verified: true, value };
}
