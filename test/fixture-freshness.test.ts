import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import type { TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';
import { decode, get, toBytes, untag } from '../src/mdoc/cbor.ts';
import { parseCoseSign1 } from '../src/mdoc/cose.ts';

/**
 * When the genuine EU credentials stop being genuine.
 *
 * `test/fixtures/real/` holds the only artefacts in this repository that prove
 * interoperability rather than self-consistency. They expire, and when they do
 * the round-trip test in `real-credential.test.ts` skips itself — which is the
 * right thing for that test to do, since a skipped test is clearer than a dozen
 * failures that all mean "the credential is old". But a skip is silent, and a
 * suite that quietly stops proving its most important claim is worse than one
 * that breaks.
 *
 * So this test fails, loudly and on purpose, once either credential expires.
 * It is not measuring the verification logic; it is measuring whether the
 * evidence still exists. There is nothing to fix in `src/` when it goes red —
 * see the message it prints.
 */

const dir = fileURLToPath(new URL('./fixtures/real/', import.meta.url));

/** Start warning this long before expiry, so the break is never a surprise. */
const WARN_WITHIN_DAYS = 30;
const DAY = 24 * 60 * 60 * 1000;

function howToRefresh(what: string, flag: string): string {
  return [
    `The ${what} in test/fixtures/real/ has expired.`,
    '',
    'Nothing in src/ is broken. What has lapsed is the evidence: this repository',
    'no longer holds a genuine EU credential, so the suite proves only that the',
    'verifier agrees with its own fixture issuer.',
    '',
    'To restore it:',
    `  npm run fetch-credential -- ${flag}`,
    '  # then move the output into test/fixtures/real/ and update the dates in',
    '  # its README.md and in REPRODUCE.md, "Time-sensitive material".',
    '',
    'See REPRODUCE.md for what the fetch involves; it drives the EU reference',
    'issuer and needs the FormEU test identity provider.',
  ].join('\n');
}

/** Fail once `expiresAt` has passed, and say so in advance while it has not. */
function assertFresh(t: TestContext, expiresAt: Date, what: string, flag: string): void {
  const remaining = expiresAt.getTime() - Date.now();
  assert.ok(remaining > 0, `${howToRefresh(what, flag)}\n\nExpired ${expiresAt.toISOString()}.`);

  const days = Math.floor(remaining / DAY);
  if (days <= WARN_WITHIN_DAYS) {
    t.diagnostic(`${what} expires in ${days} day(s), on ${expiresAt.toISOString().slice(0, 10)}`);
  }
}

describe('the real EU credentials still prove something', () => {
  it('the SD-JWT VC has not expired', (t) => {
    const credential = readFileSync(`${dir}eudiw-pid-sd-jwt-vc.txt`, 'utf8').trim();
    const payload = JSON.parse(
      Buffer.from(credential.split('~')[0]!.split('.')[1]!, 'base64url').toString(),
    );
    assertFresh(t, new Date(payload.exp * 1000), 'SD-JWT VC', 'sd-jwt');
  });

  it('the mdoc has not expired', (t) => {
    // Neither `verifyMdoc` nor the decoded CBOR can answer this. The issuer
    // emits `2026-11-09T11:51:46+00:00Z`, carrying both an offset and a Z,
    // which is not valid RFC 3339 (upstream issue #177): the verifier reports
    // no validity window rather than guessing at one, and cbor2 turns the tag-0
    // value into an Invalid Date, discarding the text on the way.
    //
    // So the text is read out of the encoded MobileSecurityObject, positionally
    // from the `validUntil` key rather than by picking whichever date looks
    // latest, and repaired just enough to parse. That is a liberty a test may
    // take about a known fixture and the verifier may not take about a
    // credential.
    const issuerSigned = decode(
      new Uint8Array(Buffer.from(readFileSync(`${dir}eudiw-pid-mdoc.txt`, 'utf8').trim(), 'base64url')),
    );
    const sign1 = parseCoseSign1(get(issuerSigned, 'issuerAuth'));
    assert.ok(sign1.payload, 'issuerAuth has a detached payload');
    // MobileSecurityObjectBytes is `#6.24(bstr .cbor MobileSecurityObject)`.
    const encoded = Buffer.from(toBytes(untag(decode(sign1.payload)))).toString('latin1');

    const key = encoded.indexOf('validUntil');
    assert.notEqual(key, -1, 'the MobileSecurityObject has no validUntil');
    const raw = /\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2})?Z?/.exec(encoded.slice(key))?.[0];

    // `+00:00Z` -> `+00:00`. A well-formed date is left alone, so this keeps
    // working if the issuer ever fixes #177.
    const validUntil = new Date(String(raw).replace(/([+-]\d{2}:\d{2})Z$/, '$1'));
    assert.ok(
      raw && !Number.isNaN(validUntil.getTime()),
      `cannot read the mdoc's validUntil (${String(raw)}), so its freshness cannot be judged`,
    );
    assertFresh(t, validUntil, 'mdoc', 'mdoc');
  });
});
