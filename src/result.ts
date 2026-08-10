/**
 * Machine-readable outcomes. Every rejection path in this codebase ends at
 * exactly one of these codes, so a caller never has to parse an error string.
 */
export type ReasonCode =
  // Shape of the token itself
  | 'CREDENTIAL_MALFORMED'
  | 'UNSUPPORTED_ALGORITHM'
  | 'UNEXPECTED_VCT'
  // Issuer identity and trust
  | 'ISSUER_KEY_UNRESOLVABLE'
  | 'ISSUER_UNTRUSTED'
  | 'ISSUER_SIGNATURE_INVALID'
  // Validity window
  | 'CREDENTIAL_EXPIRED'
  | 'CREDENTIAL_NOT_YET_VALID'
  // Holder binding
  | 'KEY_BINDING_MISSING'
  | 'KEY_BINDING_INVALID'
  | 'KEY_BINDING_NONCE_MISMATCH'
  | 'KEY_BINDING_AUDIENCE_MISMATCH'
  // The predicate we were asked to prove
  | 'PREDICATE_CLAIM_MISSING'
  | 'PREDICATE_NOT_SATISFIED';

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
