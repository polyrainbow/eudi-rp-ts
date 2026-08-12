/**
 * Structured verification events.
 *
 * The library never logs. For a relying party an audit trail is often a
 * compliance requirement rather than a convenience — what was asked for, of
 * whom, when, and what was decided — and that record has to survive a change of
 * logging library. So the library emits typed events and the application
 * decides what becomes a log line, a metric, or a row in a table.
 *
 * Events carry no personal data: no claim values, no subject identifiers, no
 * credential bytes. An audit trail that quietly accumulates dates of birth is
 * worse than none.
 */
export type VerificationEvent =
  | { type: 'verification.started'; vct: string | undefined }
  | { type: 'issuer.resolved'; subject: string; chainLength: number }
  | { type: 'status.checked'; outcome: 'valid' | 'revoked' | 'unavailable'; cached: boolean }
  /**
   * Revocation of the issuer's certificate chain, which is a different question
   * from `status.checked`. `via` is undefined when no mechanism answered.
   */
  | {
      type: 'issuer.revocation.checked';
      outcome: 'good' | 'revoked' | 'unavailable' | 'no-mechanism' | 'not-checked';
      via: 'crl' | 'ocsp' | undefined;
    }
  | { type: 'verification.accepted'; vct: string; evidence?: string; durationMs: number }
  | { type: 'verification.rejected'; reason: string; durationMs: number };

export type EventSink = (event: VerificationEvent) => void;

/** Ignores everything. The default, so callers opt in rather than out. */
export const noopSink: EventSink = () => {};
