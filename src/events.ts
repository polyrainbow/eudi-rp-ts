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
 *
 * **Both credential formats emit the same stream.** Which format a wallet
 * happens to answer in decides nothing about whether a verification is
 * auditable, for the same reason it decides nothing about whether the
 * credential's status is checked — see `src/oid4vp/response.ts`. `format` is on
 * the events precisely so a mixed stream stays readable, since the two formats
 * prove holder binding by different means.
 */

/** The credential format a verification ran over. */
export type CredentialFormat = 'dc+sd-jwt' | 'mso_mdoc';

export type VerificationEvent =
  /**
   * `vct` is the credential type when it is already known. For mdoc it is not:
   * the doc type lives inside the signed Mobile Security Object, so it is
   * unreadable until the issuer signature has been verified, which is after
   * this point. That is a property of the format, not a gap — the doc type
   * appears on `verification.accepted`.
   */
  | { type: 'verification.started'; format: CredentialFormat; vct: string | undefined }
  | { type: 'issuer.resolved'; format: CredentialFormat; subject: string; chainLength: number }
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
  | {
      type: 'verification.accepted';
      format: CredentialFormat;
      vct: string;
      evidence?: string;
      durationMs: number;
    }
  /**
   * `format` is undefined when the OID4VP envelope was rejected before any
   * credential was reached — a wallet that declined, a response that would not
   * decrypt — because at that point no credential has been seen and claiming a
   * format would be inventing one.
   */
  | {
      type: 'verification.rejected';
      format: CredentialFormat | undefined;
      reason: string;
      durationMs: number;
    };

export type EventSink = (event: VerificationEvent) => void;

/** Ignores everything. The default, so callers opt in rather than out. */
export const noopSink: EventSink = () => {};

/**
 * Exactly one `verification.accepted` or `verification.rejected` per
 * verification, and **the outermost verifier owns it**.
 *
 * The inner verifiers here are genuine entry points — `verifyMdoc` and
 * `verifyCredential` are exported and callers use them directly — but they are
 * also steps inside larger ones: `verifyDeviceResponse` still has to
 * authenticate the device afterwards, and `verifyAgeOver18` still has to
 * evaluate the predicate. Both can reject something the inner verifier just
 * accepted.
 *
 * Left alone that produces an audit trail which records `verification.accepted`
 * for a presentation the caller was told to reject — the one claim such a
 * record exists to make, made wrongly. So an outer verifier wraps the caller's
 * sink in this, letting every intermediate event through and withholding the
 * verdict until it is actually the verdict.
 */
export function withoutVerdict(sink: EventSink): EventSink {
  return (event) => {
    if (event.type === 'verification.accepted' || event.type === 'verification.rejected') return;
    sink(event);
  };
}
