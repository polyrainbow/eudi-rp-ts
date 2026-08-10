/**
 * The DCQL query for the age-over-18 predicate.
 *
 * DCQL (Digital Credentials Query Language) is OID4VP 1.0's replacement for
 * Presentation Exchange. Shape per OID4VP 1.0 §6 and Appendix B.3.5:
 *
 *   { credentials: [ { id, format, meta: { vct_values }, claims: [ { path } ] } ] }
 *
 * `path` is an array walking into the claim structure, so the EUDI PID Rulebook's
 * `age_equal_or_over.18` is `["age_equal_or_over", "18"]`. Asking for that path
 * specifically — rather than for the whole `age_equal_or_over` object or for
 * `birthdate` — is what keeps the wallet from over-disclosing.
 */
export const CREDENTIAL_QUERY_ID = 'age_over_18';

export function ageOver18Query(vct: string) {
  return {
    credentials: [
      {
        id: CREDENTIAL_QUERY_ID,
        format: 'dc+sd-jwt',
        meta: { vct_values: [vct] },
        // Requires the wallet to return an SD-JWT+KB, so the presentation is
        // bound to the holder's key and to our nonce (OID4VP 1.0 Appendix B.3).
        require_cryptographic_holder_binding: true,
        claims: [{ path: ['age_equal_or_over', '18'] }],
      },
    ],
  } as const;
}
