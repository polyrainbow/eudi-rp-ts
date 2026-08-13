/**
 * DCQL: the query a verifier sends, and the code that reads it back.
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
 * That is why this module holds no query of its own. It used to export
 * `ageOver18Query` alongside the constants naming its two credential query ids,
 * and `oid4vp/response.ts` dispatched on those constants — which made one
 * question, asked one way, a property of the library rather than of the caller.
 * A query is now an argument to `buildAuthorizationRequest` and the answer is
 * checked against the query that was actually sent. `presets/age-over-18.ts` is
 * one builder of one query; the readers below are what any of them share.
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

/** The Credential Query a `vp_token` key refers to, or undefined if we asked no such thing. */
export function credentialQueryById(query: DcqlQuery, id: string): CredentialQuery | undefined {
  return query.credentials.find((candidate) => candidate.id === id);
}

/**
 * Every format the query asks for.
 *
 * `client_metadata.vp_formats_supported` MUST list all of them: a wallet checks
 * the two against each other and refuses the whole request otherwise. Derived
 * from the query rather than stated beside it, because "stated beside it" is
 * how the two came apart once already — see `request.ts`.
 */
export function queryFormats(query: DcqlQuery): readonly CredentialQuery['format'][] {
  return [...new Set(query.credentials.map((credential) => credential.format))];
}

/**
 * The mdoc namespaces a query reads elements from, in the order first asked for.
 *
 * OID4VP 1.0 §7.2: an mdoc claims path is always two steps, `[namespace,
 * element identifier]`. So the query already says which namespaces its answer
 * will arrive in, and nothing needs to assume the EUDI PID's — whose namespace
 * happens to equal its doc type, which an mDL's does not.
 *
 * Empty when the query names no claims, which asks for the whole credential.
 */
export function mdocNamespaces(query: MdocCredentialQuery): readonly string[] {
  const namespaces = (query.claims ?? [])
    .map((claim) => claim.path[0])
    .filter((first): first is string => typeof first === 'string');
  return [...new Set(namespaces)];
}

/**
 * Whether the credentials a wallet actually returned answer the question.
 *
 * OID4VP 1.0 §6.4.2, and it is two rules rather than one:
 *
 *   - with no `credential_sets`, every Credential Query is requested, so every
 *     one of them has to be answered;
 *   - with `credential_sets`, each required set is satisfied by *any one* of its
 *     options, and every id in that option must be present.
 *
 * Returns a description of the first unmet requirement, or undefined if the
 * response covers what was asked. `@openid4vc/openid4vp` performs its own DCQL
 * matching over the response, but it decides what the wallet may return; this
 * decides whether what arrived is enough for the caller to be told yes. A
 * verifier that skips it hands back a presentation missing the credential its
 * whole decision rests on, marked verified.
 */
export function unsatisfiedRequirement(query: DcqlQuery, answered: ReadonlySet<string>): string | undefined {
  if (!query.credential_sets) {
    const missing = query.credentials.find((credential) => !answered.has(credential.id));
    return missing && `no presentation for credential query "${missing.id}"`;
  }

  for (const set of query.credential_sets) {
    if (set.required === false) continue;
    const satisfied = set.options.some((option) => option.every((id) => answered.has(id)));
    if (!satisfied) {
      const options = set.options.map((option) => `[${option.join(', ')}]`).join(' or ');
      return `no credential set option was satisfied; needed ${options}`;
    }
  }
  return undefined;
}

/**
 * A credential the response would still have answered the query without.
 *
 * The general form of a check this library used to make in one special case:
 * a query offering an SD-JWT VC *or* an mdoc, answered with both, used to be
 * rejected as "answers both credential queries; expected one". The reason is
 * not arithmetic — it is that the holder disclosed a credential the verifier
 * did not need, and a relying party that accepts it has collected data its own
 * query says it had no basis for.
 *
 * "Not needed" is decided by removing it: if what remains still satisfies the
 * query, it was surplus. A query asking for two credentials outright keeps
 * both, since dropping either leaves it unanswered.
 *
 * Returns the id of the first surplus credential, or undefined.
 */
export function redundantCredential(query: DcqlQuery, answered: ReadonlySet<string>): string | undefined {
  if (unsatisfiedRequirement(query, answered)) return undefined; // Unanswered, not over-answered.

  for (const id of answered) {
    const without = new Set(answered);
    without.delete(id);
    if (!unsatisfiedRequirement(query, without)) return id;
  }
  return undefined;
}
