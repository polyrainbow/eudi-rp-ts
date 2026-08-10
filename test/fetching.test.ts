import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { TtlCache, fetchText } from '../src/fetching.ts';

describe('fetchText', () => {
  it('returns the body and content type', async () => {
    const stub: typeof fetch = (async () =>
      new Response('hello', { headers: { 'content-type': 'text/plain' } })) as typeof fetch;

    const { body, contentType } = await fetchText('https://example.test/x', { fetchImpl: stub });
    assert.equal(body, 'hello');
    assert.equal(contentType, 'text/plain');
  });

  it('throws on a non-2xx rather than returning an error page as content', async () => {
    const stub: typeof fetch = (async () => new Response('nope', { status: 503 })) as typeof fetch;

    await assert.rejects(() => fetchText('https://example.test/x', { fetchImpl: stub }), /HTTP 503/);
  });

  it('gives up rather than hanging forever', async () => {
    // A status endpoint that never answers must not stall a verification. The
    // signal has to reach fetch itself, which is what this asserts.
    const hanging: typeof fetch = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, rejectPromise) => {
        init?.signal?.addEventListener('abort', () => rejectPromise(new Error('aborted')));
      })) as typeof fetch;

    await assert.rejects(
      () => fetchText('https://example.test/slow', { fetchImpl: hanging, timeoutMs: 25 }),
      /abort/i,
    );
  });
});

describe('TtlCache', () => {
  it('serves a cached value until it expires', async () => {
    let clock = 1000;
    let loads = 0;
    const cache = new TtlCache<string>({ ttlMs: 100, now: () => clock });
    const load = async () => {
      loads += 1;
      return `v${loads}`;
    };

    assert.equal(await cache.get('k', load), 'v1');
    assert.equal(await cache.get('k', load), 'v1');
    assert.equal(loads, 1);

    clock += 101;
    assert.equal(await cache.get('k', load), 'v2');
    assert.equal(loads, 2);
  });

  it('collapses concurrent misses into one load', async () => {
    // Without this, a burst of verifications against one status list issues a
    // request each — the case that hurts the issuer most.
    let loads = 0;
    const cache = new TtlCache<string>({ ttlMs: 1000 });
    const load = async () => {
      loads += 1;
      await new Promise((r) => setTimeout(r, 10));
      return 'value';
    };

    const results = await Promise.all([cache.get('k', load), cache.get('k', load), cache.get('k', load)]);
    assert.deepEqual(results, ['value', 'value', 'value']);
    assert.equal(loads, 1);
  });

  it('does not cache a failed load', async () => {
    const cache = new TtlCache<string>({ ttlMs: 1000 });
    let attempt = 0;
    const load = async () => {
      attempt += 1;
      if (attempt === 1) throw new Error('transient');
      return 'ok';
    };

    await assert.rejects(() => cache.get('k', load), /transient/);
    assert.equal(await cache.get('k', load), 'ok', 'a failure must not be remembered as a value');
  });

  it('evicts the oldest entries past its limit', async () => {
    const cache = new TtlCache<string>({ ttlMs: 10_000, maxEntries: 2 });
    await cache.get('a', async () => 'a');
    await cache.get('b', async () => 'b');
    await cache.get('c', async () => 'c');

    assert.equal(cache.size, 2);
  });
});
