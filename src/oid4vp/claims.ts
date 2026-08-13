/**
 * Claims paths: reading an answer with the pointer that asked for it.
 *
 * OID4VP 1.0 §7 defines one pointer over both formats. A string selects an
 * object member, a number an array index, and `null` every element of an array.
 * §7.2 maps it onto mdoc as exactly two steps, `[namespace, element]`.
 *
 * That mapping is why one walker serves both: an mdoc's verified claims are
 * `{ namespace: { element: value } }`, so a two-step path over it is an
 * ordinary object walk. `PresentedCredential.claims` keeps each format's own
 * structure for this reason rather than normalising to something neither
 * format's query addresses.
 *
 * Selection produces a *set*, not a value — `null` matches every element of an
 * array — so `selectClaims` is the honest primitive and `readClaim` is the
 * convenience over it.
 */

import type { ClaimsPath, ClaimsQuery, CredentialQuery } from './query.ts';

/**
 * Every value `path` selects, in document order. Empty when it selects nothing.
 *
 * A component that does not fit what it is applied to — a member name against
 * an array, an index against an object — selects nothing rather than throwing.
 * The question this answers is "did the wallet deliver this claim", and a
 * response shaped unlike the query did not.
 */
export function selectClaims(claims: Record<string, unknown>, path: ClaimsPath): readonly unknown[] {
  let selected: unknown[] = [claims];

  for (const component of path) {
    const next: unknown[] = [];
    for (const value of selected) {
      if (component === null) {
        if (Array.isArray(value)) next.push(...value);
      } else if (typeof component === 'number') {
        if (Array.isArray(value) && component >= 0 && component < value.length) {
          next.push(value[component]);
        }
      } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        // hasOwn rather than a truthiness check: `false` and `null` are values a
        // wallet can legitimately have disclosed, and the age flag is a boolean.
        if (Object.hasOwn(value, component)) next.push((value as Record<string, unknown>)[component]);
      }
    }
    selected = next;
    if (selected.length === 0) return selected;
  }

  return selected;
}

/**
 * The single value `path` selects, or undefined if it selects none or several.
 *
 * Undefined for "several" on purpose: a path with a `null` in it asks for every
 * element of an array, and quietly handing back the first would make a caller's
 * one-value assumption look correct. Use `selectClaims` where that is the
 * question being asked.
 */
export function readClaim(claims: Record<string, unknown>, path: ClaimsPath): unknown {
  const selected = selectClaims(claims, path);
  return selected.length === 1 ? selected[0] : undefined;
}

/**
 * Whether a credential carries the claims its Credential Query asked for.
 *
 * The gap this closes is one the age predicate used to cover by accident. It
 * returned `PREDICATE_CLAIM_MISSING` when the claim it needed was absent, which
 * happened to be the only thing checking that a wallet had answered with the
 * attributes requested. A caller with no predicate — the ordinary case for a
 * query that asks for attributes rather than a decision — got `verified: true`
 * beside `claims['given_name'] === undefined`, and no way to tell a wallet that
 * withheld a claim from a holder who never had it.
 *
 * OID4VP 1.0 §6.4.1: with `claims` and no `claim_sets` every listed claim is
 * requested; with `claim_sets` the wallet satisfies one option, in the
 * verifier's order of preference. Both are checked here, in that order.
 *
 * `values` (§6.3) is checked too, and it is a matching constraint rather than a
 * separate failure: a claim whose value is not one the query would accept has
 * not been delivered as asked, and one description covers both. A wallet that
 * returns a non-matching value has ignored the query rather than answered it,
 * and either way the operator's next step is the same.
 *
 * Returns a description of the first unmet requirement, or undefined. A query
 * naming no claims asks for the whole credential and is satisfied by anything.
 */
export function unsatisfiedClaims(
  query: CredentialQuery,
  claims: Record<string, unknown>,
): string | undefined {
  const requested = query.claims;
  if (!requested || requested.length === 0) return undefined;

  const delivered = (claim: ClaimsQuery): boolean => {
    const selected = selectClaims(claims, claim.path);
    if (selected.length === 0) return false;
    if (!claim.values) return true;
    // `some`, because `null` in a path selects every element of an array and
    // "one of the nationalities is DE" is what such a query means.
    return selected.some((value) => claim.values!.includes(value as string | number | boolean));
  };

  if (!query.claim_sets) {
    const missing = requested.find((claim) => !delivered(claim));
    return missing && `claim ${describe(missing)} was requested and not disclosed`;
  }

  const byId = new Map(requested.filter((claim) => claim.id !== undefined).map((c) => [c.id!, c]));
  for (const option of query.claim_sets) {
    // An id with no matching claims entry cannot be satisfied by anything, so
    // the option it appears in is not an option.
    if (option.every((id) => byId.has(id) && delivered(byId.get(id)!))) return undefined;
  }

  const options = query.claim_sets.map((option) => `[${option.join(', ')}]`).join(' or ');
  return `no claim set was disclosed; needed ${options}`;
}

/** A claim query in a message: its id where it has one, else its path. */
function describe(claim: ClaimsQuery): string {
  return claim.id ?? `"${claim.path.map((component) => String(component)).join('.')}"`;
}
