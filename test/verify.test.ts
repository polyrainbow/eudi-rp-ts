import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { verifyAgeOver18SdJwtVc, verifySdJwtVc } from '../src/verify.ts';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';

const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const read = (name: string) => readFileSync(`${dir}${name}`, 'utf8');

const fixtures = JSON.parse(read('credentials.json')) as {
  audience: string;
  nonce: string;
  vct: string;
  credentials: Record<string, string>;
};

const anchors = TrustAnchors.fromPem(read('trust-anchor.pem'));
const rogueAnchors = TrustAnchors.fromPem(read('rogue-anchor.pem'));

/** A moment inside every fixture's validity window. */
const NOW = new Date('2026-06-01T00:00:00Z');

const credential = (name: string): string => {
  const value = fixtures.credentials[name];
  assert.ok(value, `missing fixture: ${name}`);
  return value;
};

const baseOptions = {
  anchors,
  expectedVct: fixtures.vct,
  keyBinding: { nonce: fixtures.nonce, audience: fixtures.audience },
  now: NOW,
};

function assertRejected(
  outcome: Outcome<unknown>,
  reason: ReasonCode,
): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected rejection with ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

describe('verifyAgeOver18SdJwtVc', () => {
  it('accepts a valid presentation and reports the privacy-preserving evidence', async () => {
    const result = await verifyAgeOver18SdJwtVc({ ...baseOptions, credential: credential('over18') });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.ageOver18, true);
    assert.equal(result.value.evidence, 'age_equal_or_over.18');
    assert.equal(result.value.vct, 'urn:eudi:pid:1');
    assert.equal(result.value.keyBinding?.audience, fixtures.audience);
  });

  it('does not learn anything the holder did not disclose', async () => {
    const result = await verifyAgeOver18SdJwtVc({ ...baseOptions, credential: credential('over18') });

    assert.equal(result.verified, true);
    // The holder disclosed only age_equal_or_over["18"]. Everything else in the
    // credential must stay hidden behind its digest.
    for (const claim of ['family_name', 'given_name', 'birthdate', 'issuing_authority']) {
      assert.ok(!(claim in result.value.claims), `${claim} leaked into the verified claims`);
    }
    assert.deepEqual(result.value.claims['age_equal_or_over'], { '18': true });
  });

  it('rejects a holder who is under 18', async () => {
    const result = await verifyAgeOver18SdJwtVc({ ...baseOptions, credential: credential('under18') });
    assertRejected(result, 'PREDICATE_NOT_SATISFIED');
  });

  it('falls back to birthdate when the issuer omits age_equal_or_over', async () => {
    const result = await verifyAgeOver18SdJwtVc({
      ...baseOptions,
      credential: credential('birthdateOnly'),
    });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.evidence, 'birthdate');
  });

  it('reports a missing predicate rather than guessing', async () => {
    // Verified credential, but nothing age-related was disclosed.
    const result = await verifySdJwtVc({ ...baseOptions, credential: credential('over18') });
    assert.equal(result.verified, true);

    const { evaluateAgeOver18SdJwt } = await import('../src/predicate/age.ts');
    assertRejected(evaluateAgeOver18SdJwt({ vct: 'urn:eudi:pid:1' }, NOW), 'PREDICATE_CLAIM_MISSING');
  });
});

describe('issuer trust', () => {
  it('rejects a credential whose chain does not reach a trust anchor', async () => {
    const result = await verifyAgeOver18SdJwtVc({
      ...baseOptions,
      credential: credential('untrustedIssuer'),
    });
    assertRejected(result, 'ISSUER_UNTRUSTED');
  });

  it('rejects a valid credential when checked against the wrong anchor set', async () => {
    const result = await verifyAgeOver18SdJwtVc({
      ...baseOptions,
      anchors: rogueAnchors,
      credential: credential('over18'),
    });
    assertRejected(result, 'ISSUER_UNTRUSTED');
  });

  it('rejects a tampered issuer signature', async () => {
    const [jwt, ...rest] = credential('over18').split('~');
    const [header, payload, signature] = jwt!.split('.');
    const flipped = `${signature!.slice(0, -2)}${signature!.slice(-2) === 'AA' ? 'BB' : 'AA'}`;
    const tampered = [`${header}.${payload}.${flipped}`, ...rest].join('~');

    assertRejected(
      await verifyAgeOver18SdJwtVc({ ...baseOptions, credential: tampered }),
      'ISSUER_SIGNATURE_INVALID',
    );
  });

  it('rejects a tampered disclosure', async () => {
    // Re-encode the disclosure so it claims `true` for someone who is under 18.
    const parts = credential('under18').split('~');
    const forged = Buffer.from(
      JSON.stringify([...(JSON.parse(Buffer.from(parts[1]!, 'base64url').toString()) as [string, string, boolean]).slice(0, 2), true]),
    ).toString('base64url');
    const tampered = [parts[0], forged, ...parts.slice(2)].join('~');

    const result = await verifyAgeOver18SdJwtVc({ ...baseOptions, credential: tampered });
    // The forged disclosure no longer hashes to any digest in the signed payload.
    assertRejected(result, 'CREDENTIAL_MALFORMED');
    assert.match(result.detail, /Unreferenced disclosure/);
  });

  it('rejects an expired credential', async () => {
    const result = await verifyAgeOver18SdJwtVc({
      ...baseOptions,
      credential: credential('over18'),
      now: new Date('2028-01-01T00:00:00Z'),
    });
    assertRejected(result, 'CREDENTIAL_EXPIRED');
  });

  it('rejects an unexpected vct', async () => {
    const result = await verifySdJwtVc({
      ...baseOptions,
      credential: credential('over18'),
      expectedVct: 'urn:eudi:something-else:1',
    });
    assertRejected(result, 'UNEXPECTED_VCT');
  });
});

describe('key binding', () => {
  it('rejects a presentation bound to a different verifier', async () => {
    const result = await verifyAgeOver18SdJwtVc({
      ...baseOptions,
      credential: credential('wrongAudience'),
    });
    assertRejected(result, 'KEY_BINDING_AUDIENCE_MISMATCH');
  });

  it('rejects a replayed nonce', async () => {
    const result = await verifyAgeOver18SdJwtVc({ ...baseOptions, credential: credential('wrongNonce') });
    assertRejected(result, 'KEY_BINDING_NONCE_MISMATCH');
  });

  it('rejects a presentation with no key binding at all', async () => {
    const result = await verifyAgeOver18SdJwtVc({ ...baseOptions, credential: credential('noKeyBinding') });
    assertRejected(result, 'KEY_BINDING_MISSING');
  });

  it('refuses to run without a key binding expectation', async () => {
    // @sd-jwt silently skips key binding when no nonce is supplied, so making
    // this a hard error is the only thing standing between a caller and an
    // unbound presentation being accepted.
    await assert.rejects(
      () =>
        verifySdJwtVc({
          anchors,
          credential: credential('over18'),
          now: NOW,
        } as never),
      /keyBinding is required/,
    );
  });
});
