/**
 * Age over 18, as a DCQL query and as a predicate over the answer.
 *
 * This is a preset, and the distinction matters: the library verifies whatever
 * query it is given, and this file is one question asked one way. It lives
 * outside `oid4vp/` for that reason — nothing in the verification path imports
 * it, and a caller asking something else writes their own pair without touching
 * the library.
 *
 * The two halves belong together. A query that asks for `age_equal_or_over.18`
 * or a birth date and a predicate that reads exactly those two claims are one
 * decision written twice, and splitting them across modules is how they drift.
 */

import { type Rejected, accept, reject } from '../result.ts';
import type { DcqlQuery } from '../oid4vp/query.ts';
import type { PresentationPredicate } from '../oid4vp/response.ts';
import { type AgeResult, evaluateAgeOver18Mdoc, evaluateAgeOver18SdJwt } from '../predicate/age.ts';
import { PID_MDOC_DOCTYPE, PID_VCT } from './eudi-pid.ts';

/** Credential query ids. Exported so a caller can find the answer in `byQueryId`. */
export const AGE_OVER_18_SD_JWT_QUERY_ID = 'age_over_18';
export const AGE_OVER_18_MDOC_QUERY_ID = 'age_over_18_mdoc';

/** Claim ids, referenced from `claim_sets`. */
const AGE_FLAG = 'age_equal_or_over_18';
const BIRTHDATE = 'birthdate';

export type AgeOver18QueryOptions = {
  /** SD-JWT VC type to accept. Defaults to the EUDI PID. */
  vct?: string;
  /** mdoc doc type to accept. Defaults to the EUDI PID's. */
  mdocDocType?: string;
  /**
   * mdoc namespace the age elements live in. Defaults to the doc type, which is
   * right for the PID and wrong for an mDL — see `presets/eudi-pid.ts`.
   */
  mdocNamespace?: string;
};

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
export function ageOver18Query(options: AgeOver18QueryOptions = {}): DcqlQuery {
  const vct = options.vct ?? PID_VCT;
  const docType = options.mdocDocType ?? PID_MDOC_DOCTYPE;
  const namespace = options.mdocNamespace ?? docType;

  return {
    credentials: [
      {
        id: AGE_OVER_18_SD_JWT_QUERY_ID,
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
        id: AGE_OVER_18_MDOC_QUERY_ID,
        format: 'mso_mdoc',
        meta: { doctype_value: docType },
        claims: [
          { id: AGE_FLAG, path: [namespace, 'age_over_18'] },
          { id: BIRTHDATE, path: [namespace, 'birth_date'] },
        ],
        claim_sets: [[AGE_FLAG], [BIRTHDATE]],
      },
    ],
    // Either credential answers the question. Without this the wallet would be
    // asked for *both* (OID4VP 1.0 §6.4.2), which no holder has, and it would
    // return nothing at all.
    credential_sets: [
      { options: [[AGE_OVER_18_SD_JWT_QUERY_ID], [AGE_OVER_18_MDOC_QUERY_ID]] },
    ],
  };
}

/**
 * Evaluate the predicate over whichever credential answered.
 *
 * Dispatches on `format` rather than on the query id, so it holds for any query
 * asking the same question of the same claims — including one that offers only
 * a single format. The formats are not interchangeable here: mdoc spells the
 * flag `age_over_18` and the date `birth_date`, SD-JWT VC spells them
 * `age_equal_or_over.18` and `birthdate`, which is why `predicate/age.ts` has
 * two evaluators and not one.
 *
 * The rejection reported is the *last* one, not the first. With a query that
 * offers two formats exactly one credential arrives, so it is the only one; if
 * a caller offers several and none satisfies the predicate, the reason of the
 * last is at least a reason from a credential that was actually presented.
 */
export const ageOver18Predicate: PresentationPredicate<AgeResult> = (presented, now) => {
  let last: Rejected | undefined;

  for (const credential of presented.credentials) {
    const result =
      credential.format === 'dc+sd-jwt'
        ? evaluateAgeOver18SdJwt(credential.claims, now)
        : evaluateAgeOver18Mdoc(mdocElements(credential.claims), now);
    if (result.verified) return accept({ value: result.value, evidence: result.value.evidence });
    last = result;
  }

  return last ?? reject('PREDICATE_CLAIM_MISSING', 'No credential was presented');
};

/**
 * An mdoc's elements, flattened across namespaces.
 *
 * `claims` for an mdoc is `{ namespace: { element: value } }` — the structure
 * OID4VP 1.0 §7.2 addresses with a two-step path. The age elements are
 * unambiguous across namespaces (nothing else defines `age_over_18`), so
 * flattening lets the predicate read them without being told which namespace to
 * look in, and without this preset carrying a PID constant that a query for an
 * mDL would make wrong.
 */
function mdocElements(claims: Record<string, unknown>): Record<string, unknown> {
  const elements: Record<string, unknown> = {};
  for (const namespace of Object.values(claims)) {
    if (namespace && typeof namespace === 'object' && !Array.isArray(namespace)) {
      Object.assign(elements, namespace);
    }
  }
  return elements;
}
