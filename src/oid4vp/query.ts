/**
 * The DCQL query for the age-over-18 predicate.
 *
 * DCQL (Digital Credentials Query Language) is OID4VP 1.0's replacement for
 * Presentation Exchange. Shape per OID4VP 1.0 §6 and Appendix B.3.5:
 *
 *   { credentials: [ { id, format, meta: { vct_values }, claims, claim_sets } ] }
 *
 * `path` walks into the claim structure, so the EUDI PID Rulebook's
 * `age_equal_or_over.18` is `["age_equal_or_over", "18"]`.
 */
export const CREDENTIAL_QUERY_ID = 'age_over_18';
/** The mdoc alternative. */
export const MDOC_CREDENTIAL_QUERY_ID = 'age_over_18_mdoc';
/** mdoc groups elements into namespaces; the PID's is its doc type. */
export const PID_MDOC_NAMESPACE = 'eu.europa.ec.eudi.pid.1';

/** Claim ids, referenced from `claim_sets`. */
const AGE_FLAG = 'age_equal_or_over_18';
const BIRTHDATE = 'birthdate';

/**
 * Two ways to satisfy the request, in order of preference.
 *
 * Asking only for `age_equal_or_over.18` matches nothing from the EU reference
 * issuer, which emits no age attribute at all — PID Rulebook v1.1 removed them
 * per CIR 2024/2977. OID4VP 1.0 §6.4.1: with `claims` present and `claim_sets`
 * absent the Verifier requests *all* listed claims, so a single-path query is
 * unsatisfiable against a real PID and the wallet returns nothing.
 *
 * `claim_sets` expresses preference instead — "the Wallet SHOULD return the
 * first option that it can satisfy". So we ask for the privacy-preserving
 * boolean first and accept a full date of birth only from a wallet that cannot
 * provide it. That ordering is the whole point: `birthdate` discloses far more
 * than the question we asked, and should never be the first choice.
 */
export function ageOver18Query(vct: string, mdocDocType: string = PID_MDOC_NAMESPACE) {
  return {
    credentials: [
      {
        id: CREDENTIAL_QUERY_ID,
        format: 'dc+sd-jwt',
        meta: { vct_values: [vct] },
        // Requires the wallet to return an SD-JWT+KB, so the presentation is
        // bound to the holder's key and to our nonce (OID4VP 1.0 Appendix B.3).
        require_cryptographic_holder_binding: true,
        claims: [
          { id: AGE_FLAG, path: ['age_equal_or_over', '18'] },
          { id: BIRTHDATE, path: ['birthdate'] },
        ],
        claim_sets: [[AGE_FLAG], [BIRTHDATE]],
      },
      {
        // mdoc spells the same information differently: a flat boolean, and
        // `birth_date` rather than `birthdate`, inside a namespace.
        id: MDOC_CREDENTIAL_QUERY_ID,
        format: 'mso_mdoc',
        meta: { doctype_value: mdocDocType },
        claims: [
          { id: AGE_FLAG, path: [mdocDocType, 'age_over_18'] },
          { id: BIRTHDATE, path: [mdocDocType, 'birth_date'] },
        ],
        claim_sets: [[AGE_FLAG], [BIRTHDATE]],
      },
    ],
    // Either credential answers the question. Without this the wallet would be
    // asked for *both* (OID4VP 1.0 §6.4.2), which no holder has, and it would
    // return nothing at all.
    credential_sets: [{ options: [[CREDENTIAL_QUERY_ID], [MDOC_CREDENTIAL_QUERY_ID]] }],
  } as const;
}
