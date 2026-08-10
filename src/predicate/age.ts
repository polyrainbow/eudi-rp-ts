import { type Outcome, accept, reject } from '../result.ts';

/**
 * How the age-over-18 predicate was satisfied.
 *
 * `age_equal_or_over` is the privacy-preserving form: the issuer asserts the
 * boolean and the holder discloses nothing else. `birthdate` is a fallback that
 * requires the holder to disclose their full date of birth, which is strictly
 * more information than the verifier asked for.
 */
export type AgeEvidence = 'age_equal_or_over.18' | 'birthdate';

export type AgeResult = {
  ageOver18: true;
  evidence: AgeEvidence;
};

/**
 * Evaluate "is the subject at least 18" over the disclosed claims.
 *
 * Encoding is per the EUDI PID Rulebook (ARF 2.4, chapter 4): the SD-JWT VC
 * form of `age_over_18` is `age_equal_or_over.18` as a boolean, and `birth_date`
 * maps to the OIDC registered claim `birthdate` as `YYYY-MM-DD`.
 *
 * NOTE: PID Rulebook v1.1 (4 Sep 2025) removed the age attributes entirely
 * following CIR 2024/2977, so `age_equal_or_over` may be absent from
 * `urn:eudi:pid:1` credentials issued against newer rulebooks. That is why the
 * birthdate fallback exists. See README "Open questions".
 */
export function evaluateAgeOver18(claims: Record<string, unknown>, now: Date): Outcome<AgeResult> {
  const bucket = claims['age_equal_or_over'];
  if (bucket !== undefined && bucket !== null) {
    if (typeof bucket !== 'object' || Array.isArray(bucket)) {
      return reject('PREDICATE_CLAIM_MISSING', '`age_equal_or_over` is present but is not an object');
    }
    const value = (bucket as Record<string, unknown>)['18'];
    if (typeof value === 'boolean') {
      return value
        ? accept({ ageOver18: true, evidence: 'age_equal_or_over.18' })
        : reject('PREDICATE_NOT_SATISFIED', 'Issuer asserts age_equal_or_over["18"] === false');
    }
    if (value !== undefined) {
      return reject('PREDICATE_CLAIM_MISSING', '`age_equal_or_over["18"]` is present but not a boolean');
    }
    // Object present without the "18" property: fall through to birthdate.
  }

  const birthdate = claims['birthdate'];
  if (typeof birthdate === 'string') {
    const age = ageInYears(birthdate, now);
    if (age === undefined) {
      return reject('PREDICATE_CLAIM_MISSING', `\`birthdate\` is not a YYYY-MM-DD date: ${birthdate}`);
    }
    return age >= 18
      ? accept({ ageOver18: true, evidence: 'birthdate' })
      : reject('PREDICATE_NOT_SATISFIED', `Subject is ${age}, which is under 18`);
  }

  return reject(
    'PREDICATE_CLAIM_MISSING',
    'Neither `age_equal_or_over["18"]` nor `birthdate` was disclosed',
  );
}

/** Completed years between an ISO `YYYY-MM-DD` birth date and `now`, in UTC. */
function ageInYears(birthdate: string, now: Date): number | undefined {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(birthdate);
  if (!match) return undefined;
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];

  // Reject dates that JS would silently roll over, e.g. 2000-02-31.
  const asDate = new Date(Date.UTC(year, month - 1, day));
  if (
    asDate.getUTCFullYear() !== year ||
    asDate.getUTCMonth() !== month - 1 ||
    asDate.getUTCDate() !== day
  ) {
    return undefined;
  }

  let age = now.getUTCFullYear() - year;
  const monthDelta = now.getUTCMonth() - (month - 1);
  if (monthDelta < 0 || (monthDelta === 0 && now.getUTCDate() < day)) age -= 1;
  return age;
}
