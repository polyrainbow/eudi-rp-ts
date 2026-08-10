import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { evaluateAgeOver18 } from '../src/predicate/age.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { verifyAgeOver18, verifyCredential } from '../src/verify.ts';

/**
 * Verification of a genuine credential from the EU reference issuer.
 *
 * Every other test signs its fixtures with a CA the fixture script invents,
 * which can only show that our verifier agrees with our own issuer. This one
 * shows it agrees with the EUDI ecosystem. See test/fixtures/real/README.md.
 */
const dir = fileURLToPath(new URL('./fixtures/real/', import.meta.url));
const credential = readFileSync(`${dir}eudiw-pid-sd-jwt-vc.txt`, 'utf8').trim();
const anchors = TrustAnchors.fromPem(readFileSync(`${dir}eudiw-pid-issuer-ca.pem`, 'utf8'));

/** Inside the credential's validity window (issued 2026-08-09, expires 2026-11-08). */
const NOW = new Date('2026-09-01T00:00:00Z');

/** It was issued, never presented, so it carries no Key Binding JWT. */
const options = { credential, anchors, expectedVct: 'urn:eudi:pid:1', requireKeyBinding: false, now: NOW };

describe('real EUDI reference credential', () => {
  it('verifies against the real PID Issuer CA', async () => {
    const result = await verifyCredential(options);

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.vct, 'urn:eudi:pid:1');
    assert.match(result.value.issuerCertificateSubject, /CN=PID DS - 002/);
  });

  it('is rejected against an unrelated anchor set', async () => {
    const ours = TrustAnchors.fromPem(
      readFileSync(fileURLToPath(new URL('./fixtures/trust-anchor.pem', import.meta.url)), 'utf8'),
    );
    const result = await verifyCredential({ ...options, anchors: ours });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'ISSUER_UNTRUSTED');
  });

  it('proves age over 18 from birthdate, because the issuer emits no age claim', async () => {
    const result = await verifyAgeOver18(options);

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.ageOver18, true);
    // PID Rulebook v1.1 removed the age attributes (CIR 2024/2977), and the
    // live issuer reflects that. birthdate is the real path, not a fallback.
    assert.equal(result.value.evidence, 'birthdate');
    assert.ok(!('age_equal_or_over' in result.value.claims));
  });

  it('carries revocation information we do not yet check', async () => {
    const result = await verifyCredential(options);
    assert.equal(result.verified, true);

    // Documented gap: status list verification is disabled. Real credentials
    // do carry a status claim, so this is a live shortcoming rather than a
    // theoretical one.
    const status = result.value.claims['status'] as { status_list?: { uri?: string } } | undefined;
    assert.ok(status?.status_list?.uri, 'reference credentials carry a token status list');
  });

  it('would reject the holder as under 18 if the birth date said so', () => {
    // Same credential, evaluated as though "now" were shortly after the birth
    // date — guards against the predicate passing on presence rather than value.
    const claims = { birthdate: '1990-06-12' };
    assert.equal(evaluateAgeOver18(claims, new Date('2005-01-01T00:00:00Z')).verified, false);
    assert.equal(evaluateAgeOver18(claims, new Date('2008-06-12T00:00:00Z')).verified, true);
  });
});
