import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { checkStatusList, createStatusListCache } from '../src/trust/status.ts';
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

  it('rejects a correctly signed status list published for another URI', async () => {
    // The signature only proves a trusted issuer produced some status list.
    // Binding `sub` to the URI the credential named is what proves it is *this*
    // credential's list — without it, anyone who can answer at that URI can
    // substitute another list the same anchors validate, and we index into it.
    const result = await verifyAgeOver18({
      ...base,
      statusFetch: serving(fixtures.statusLists.wrongSubject),
    });

    assertRejected(result, 'STATUS_UNAVAILABLE');
    assert.match(result.detail, /sub/);
  });

  it('rejects an expired status list as unavailable, not as a malformed credential', async () => {
    // `@sd-jwt/core` checks the status list's own `exp` before it calls our
    // verifier and throws, so a check made in the verifier callback would run
    // too late to record anything — and the rejection would surface as
    // CREDENTIAL_MALFORMED, blaming the credential for the issuer's stale list.
    const result = await verifyAgeOver18({
      ...base,
      statusFetch: serving(fixtures.statusLists.expired),
    });

    assertRejected(result, 'STATUS_UNAVAILABLE');
    assert.match(result.detail, /expired/i);
  });

  it('rechecks expiry on a cache hit', async () => {
    // A token cached while fresh can expire before its cache entry does, so the
    // freshness check has to run on the hit as well as on the miss. This one
    // expires 2026-07-01, long before the credential does.
    const cache = createStatusListCache();
    const statusFetch = serving(fixtures.statusLists.expiringSoon);

    const fresh = await verifyAgeOver18({ ...base, statusFetch, statusCache: cache });
    assert.equal(fresh.verified, true, JSON.stringify(fresh));

    const stale = await verifyAgeOver18({
      ...base,
      statusFetch,
      statusCache: cache,
      now: new Date('2026-08-01T00:00:00Z'),
    });
    assertRejected(stale, 'STATUS_UNAVAILABLE');
    assert.match(stale.detail, /expired/i);
  });

  it('unpacks every permitted status size', async () => {
    // The bitstring is read here rather than by a dependency, so this checks
    // our unpacking against the reference implementation's packing: statuses
    // are `bits` wide, first status in the *least* significant bits of the
    // first byte (draft-ietf-oauth-status-list §4.1).
    for (const [bits, { uri, token }] of Object.entries<{ uri: string; token: string }>(
      fixtures.statusListWidths,
    )) {
      const width = Number(bits);
      const check = (index: number) =>
        checkStatusList({ uri, index }, { anchors, now: NOW, fetchImpl: serving(token) });

      assert.deepEqual(await check(3), { kind: 'revoked', status: 1 }, `bits ${bits}, index 3`);
      assert.deepEqual(
        await check(7),
        { kind: 'revoked', status: 2 ** width - 1 },
        `bits ${bits}, index 7 must read the widest value the size allows`,
      );
      assert.deepEqual(await check(5), { kind: 'valid' }, `bits ${bits}, index 5`);
    }
  });

  it('refuses an index past the end of the list', async () => {
    // Reading a bit the issuer never published is not evidence of anything, so
    // it cannot resolve to "not revoked".
    const outcome = await checkStatusList(
      { uri: fixtures.statusUri, index: 100_000 },
      { anchors, now: NOW, fetchImpl: serving(fixtures.statusLists.valid) },
    );

    assert.equal(outcome.kind, 'unavailable');
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
