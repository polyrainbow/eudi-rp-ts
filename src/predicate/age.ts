import { type Outcome, accept, reject } from '../result.ts';

/**
 * How the age-over-18 predicate was satisfied.
 *
 * `age_equal_or_over` is the privacy-preserving form: the issuer asserts the
 * boolean and the holder discloses nothing else. `birthdate` is a fallback that
 * requires the holder to disclose their full date of birth, which is strictly
 * more information than the verifier asked for.
 */
export type AgeEvidence = 'age_equal_or_over.18' | 'birthdate' | 'age_over_18';

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
export function evaluateAgeOver18SdJwt(claims: Record<string, unknown>, now: Date): Outcome<AgeResult> {
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

/**
 * Evaluate the predicate over mdoc elements.
 *
 * mdoc encodes the same information differently from SD-JWT VC: a flat boolean
 * `age_over_18` rather than an object keyed by age, and `birth_date` rather
 * than `birthdate`. Both spellings matter — see the table in the README.
 */
export function evaluateAgeOver18Mdoc(
  elements: Record<string, unknown>,
  now: Date,
): Outcome<AgeResult> {
  const flag = elements['age_over_18'];
  if (typeof flag === 'boolean') {
    return flag
      ? accept({ ageOver18: true, evidence: 'age_over_18' })
      : reject('PREDICATE_NOT_SATISFIED', 'Issuer asserts age_over_18 === false');
  }

  const birthDate = elements['birth_date'];
  if (typeof birthDate === 'string') {
    // `YYYY-MM-DD` already: `decodeCbor` keeps RFC 8943 tag 1004 a full-date
    // rather than letting it become an instant at midnight. The slice is for an
    // issuer that emits a date-time where the rulebook says full-date, which is
    // still a birth date and still answers the question.
    return evaluateAgeOver18SdJwt({ birthdate: birthDate.slice(0, 10) }, now);
  }

  return reject(
    'PREDICATE_CLAIM_MISSING',
    'Neither `age_over_18` nor `birth_date` was disclosed',
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
