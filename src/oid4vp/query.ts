/**
 * DCQL: the query a verifier sends, and the age-over-18 query built with it.
 *
 * DCQL (Digital Credentials Query Language) is OID4VP 1.0's replacement for
 * Presentation Exchange. Shape per OID4VP 1.0 §6:
 *
 *   { credentials: [ { id, format, meta, claims, claim_sets } ], credential_sets }
 *
 * The types here are structural, not a schema: nothing validates a query, and
 * `@openid4vc/openid4vp` is what puts it on the wire. They exist because a query
 * is also read *back*. What the wallet was asked for is what its answer has to
 * be checked against — the `vct` a presentation must carry, the doc type, which
 * `vp_formats_supported` the request has to advertise — and every one of those
 * facts is already stated in the query. A verifier that keeps its own second
 * copy has two things to keep in step instead of one.
 *
 * `path` walks into the claim structure, so the EUDI PID Rulebook's
 * `age_equal_or_over.18` is `["age_equal_or_over", "18"]`.
 */

/**
 * A claims path pointer (OID4VP 1.0 §7).
 *
 * A string selects an object member, a number an array index, and `null` every
 * element of an array. §7.2 maps the same pointer onto mdoc, where it is always
 * two steps: `[namespace, element identifier]`.
 */
export type ClaimsPath = readonly (string | number | null)[];

/** A Claims Query (OID4VP 1.0 §6.3). */
export type ClaimsQuery = {
  /** REQUIRED when the credential query has `claim_sets`, optional otherwise. */
  id?: string;
  path: ClaimsPath;
  /** Restricts the claim to these values; the wallet matches, we still check. */
  values?: readonly (string | number | boolean)[];
};

/**
 * The parameters a Credential Query carries whatever the format (§6.1).
 *
 * `trusted_authorities` is deliberately not modelled: this library decides
 * issuer trust from the `TrustAnchors` it is given, so a query naming
 * authorities the verification does not consult would describe a policy nothing
 * enforces. Adding it means resolving that first.
 */
type CommonCredentialQuery = {
  /** Identifies this credential in the response — the `vp_token` key. */
  id: string;
  /** Whether more than one credential may answer this query. Default false. */
  multiple?: boolean;
  /** Default true. Setting it false accepts a presentation nothing binds. */
  require_cryptographic_holder_binding?: boolean;
  /** Non-empty when present. Omitted asks for the whole credential. */
  claims?: readonly ClaimsQuery[];
  /**
   * Alternative sets of claim ids, in order of preference (§6.4.1): the wallet
   * SHOULD return the first it can satisfy. With `claims` alone and no
   * `claim_sets`, *all* the listed claims are required.
   */
  claim_sets?: readonly (readonly string[])[];
};

/** SD-JWT VC. `vct_values` is the format's `meta` per OID4VP 1.0 Appendix B.3.5. */
export type SdJwtVcCredentialQuery = CommonCredentialQuery & {
  format: 'dc+sd-jwt';
  meta: { vct_values?: readonly string[] };
};

/** ISO mdoc. `doctype_value` is the format's `meta` per OID4VP 1.0 Appendix B.2. */
export type MdocCredentialQuery = CommonCredentialQuery & {
  format: 'mso_mdoc';
  meta: { doctype_value?: string };
};

/**
 * One Credential Query (OID4VP 1.0 §6.1).
 *
 * Closed to the two formats this library can verify, on purpose: a query is a
 * promise to check the answer, and a request for a format nothing here verifies
 * is one whose response would have to be rejected on arrival.
 */
export type CredentialQuery = SdJwtVcCredentialQuery | MdocCredentialQuery;

/** A Credential Set Query (OID4VP 1.0 §6.2). */
export type CredentialSetQuery = {
  /** Non-empty; each option is a set of credential query ids that would do. */
  options: readonly (readonly string[])[];
  /** Default true. False asks for the set without insisting on it. */
  required?: boolean;
};

/**
 * A DCQL query (OID4VP 1.0 §6).
 *
 * Both arrays are non-empty where present, which the type does not enforce —
 * an empty `credentials` is a query the wallet answers with nothing, and it is
 * `@openid4vc/openid4vp` that rejects it rather than the compiler.
 */
export type DcqlQuery = {
  credentials: readonly CredentialQuery[];
  credential_sets?: readonly CredentialSetQuery[];
};

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
export function ageOver18Query(vct: string, mdocDocType: string = PID_MDOC_NAMESPACE): DcqlQuery {
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
  };
}
