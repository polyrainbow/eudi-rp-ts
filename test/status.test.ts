import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { createStatusListCache } from '../src/trust/status.ts';
import { verifyAgeOver18 } from '../src/verify.ts';

const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const fixtures = JSON.parse(readFileSync(`${dir}credentials.json`, 'utf8'));
const anchors = TrustAnchors.fromPem(readFileSync(`${dir}trust-anchor.pem`, 'utf8'));

const NOW = new Date('2026-06-01T00:00:00Z');
const base = {
  credential: fixtures.credentials.withStatus as string,
  anchors,
  expectedVct: 'urn:eudi:pid:1',
  keyBinding: { nonce: fixtures.nonce as string, audience: fixtures.audience as string },
  now: NOW,
};

/** Serves a given status list token, as the issuer's status endpoint would. */
function serving(token: string, contentType = 'application/statuslist+jwt'): typeof fetch {
  return (async () =>
    new Response(token, { status: 200, headers: { 'content-type': contentType } })) as typeof fetch;
}

const failing = (status: number): typeof fetch =>
  (async () => new Response('nope', { status })) as typeof fetch;

function assertRejected(outcome: Outcome<unknown>, reason: ReasonCode): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

describe('status list', () => {
  it('accepts a credential whose status bit is clear', async () => {
    const result = await verifyAgeOver18({ ...base, statusFetch: serving(fixtures.statusLists.valid) });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.ageOver18, true);
  });

  it('rejects a revoked credential', async () => {
    const result = await verifyAgeOver18({ ...base, statusFetch: serving(fixtures.statusLists.revoked) });

    assertRejected(result, 'CREDENTIAL_REVOKED');
  });

  it('rejects a status list signed by an untrusted key', async () => {
    // The whole point of verifying the list: otherwise anyone who can answer
    // the HTTP request could declare a revoked credential valid.
    const result = await verifyAgeOver18({
      ...base,
      statusFetch: serving(fixtures.statusLists.untrustedSigner),
    });

    assertRejected(result, 'STATUS_UNAVAILABLE');
  });

  it('rejects a status list served under the wrong content type', async () => {
    const result = await verifyAgeOver18({
      ...base,
      statusFetch: serving(fixtures.statusLists.valid, 'text/html'),
    });

    assertRejected(result, 'STATUS_UNAVAILABLE');
  });

  it('fails closed when the status endpoint is unreachable', async () => {
    // A verifier that accepts a credential it could not check has no revocation
    // at all, so an unavailable list must not degrade into success.
    const result = await verifyAgeOver18({ ...base, statusFetch: failing(503) });

    assertRejected(result, 'STATUS_UNAVAILABLE');
  });

  it('does not fetch anything for a credential with no status claim', async () => {
    let fetched = false;
    const spy: typeof fetch = (async () => {
      fetched = true;
      return new Response('', { status: 500 });
    }) as typeof fetch;

    const result = await verifyAgeOver18({
      ...base,
      credential: fixtures.credentials.over18,
      statusFetch: spy,
    });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(fetched, false, 'no status claim means no status request');
  });

  it('is on by default', async () => {
    // Guards the default: this credential has a status claim, so verification
    // must attempt a fetch unless explicitly told not to.
    let fetched = false;
    const spy: typeof fetch = (async () => {
      fetched = true;
      return new Response('', { status: 503 });
    }) as typeof fetch;

    await verifyAgeOver18({ ...base, statusFetch: spy });
    assert.equal(fetched, true);

    fetched = false;
    await verifyAgeOver18({ ...base, statusFetch: spy, checkStatus: false });
    assert.equal(fetched, false, 'checkStatus: false must skip the fetch');
  });

  it('does not refetch a dead status endpoint once per credential', async () => {
    // Both verifications still fail closed; the point is that the second one
    // does not pay another request and another timeout. A shared cache is what
    // keeps an issuer's outage from becoming one here.
    const cache = createStatusListCache();
    let requests = 0;
    const down: typeof fetch = (async () => {
      requests += 1;
      return new Response('', { status: 503 });
    }) as typeof fetch;

    const first = await verifyAgeOver18({ ...base, statusFetch: down, statusCache: cache });
    const second = await verifyAgeOver18({ ...base, statusFetch: down, statusCache: cache });

    assertRejected(first, 'STATUS_UNAVAILABLE');
    assertRejected(second, 'STATUS_UNAVAILABLE');
    assert.equal(requests, 1, 'the second verification must reuse the remembered failure');
  });
});
