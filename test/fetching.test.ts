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
        // A real request holds a socket, which keeps the event loop alive.
        // AbortSignal.timeout's own timer is unref'd on purpose, so a stub that
        // merely waits leaves Node 22 with nothing pending and the loop exits
        // before the abort ever fires. This timer stands in for the socket, and
        // doubles as a backstop: if the signal never arrives, the test fails on
        // the wrong message rather than hanging.
        const socket = setTimeout(() => rejectPromise(new Error('the signal never arrived')), 1000);
        init?.signal?.addEventListener('abort', () => {
          clearTimeout(socket);
          rejectPromise(new Error('aborted'));
        });
      })) as typeof fetch;

    await assert.rejects(
      () => fetchText('https://example.test/slow', { fetchImpl: hanging, timeoutMs: 25 }),
      /abort/i,
    );
  });

  it('stops reading a body past the limit', async () => {
    // A deadline bounds nothing on its own: a body that arrives steadily for
    // the whole timeout is still unbounded memory.
    const streaming: typeof fetch = (async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('a'.repeat(10)));
            controller.enqueue(new TextEncoder().encode('b'.repeat(10)));
            controller.close();
          },
        }),
      )) as typeof fetch;

    await assert.rejects(
      () => fetchText('https://example.test/big', { fetchImpl: streaming, maxBytes: 15 }),
      /exceeds 15 bytes/,
    );
  });

  it('refuses a declared length over the limit without transferring it', async () => {
    const stub: typeof fetch = (async () =>
      new Response('short', { headers: { 'content-length': '99999999' } })) as typeof fetch;

    await assert.rejects(
      () => fetchText('https://example.test/big', { fetchImpl: stub, maxBytes: 1000 }),
      /declared 99999999 bytes/,
    );
  });

  it('follows a redirect', async () => {
    const routes = router({
      'https://example.test/a': () =>
        new Response(null, { status: 302, headers: { location: 'https://example.test/b' } }),
      'https://example.test/b': () => new Response('final'),
    });

    const { body } = await fetchText('https://example.test/a', { fetchImpl: routes.fetch });
    assert.equal(body, 'final');
    assert.deepEqual(routes.visited, ['https://example.test/a', 'https://example.test/b']);
  });

  it('does not follow a redirect off https', async () => {
    // A trust list served over http cannot be forged, but it can be replayed —
    // and a stale list still grants a CA that has since been withdrawn.
    const routes = router({
      'https://example.test/a': () =>
        new Response(null, { status: 302, headers: { location: 'http://example.test/b' } }),
      'http://example.test/b': () => new Response('downgraded'),
    });

    await assert.rejects(
      () => fetchText('https://example.test/a', { fetchImpl: routes.fetch }),
      /http:\/\/ is not allowed/,
    );
    assert.deepEqual(routes.visited, ['https://example.test/a'], 'the http hop must never be requested');
  });

  it('gives up past the redirect budget', async () => {
    const routes = router({
      'https://example.test/1': () =>
        new Response(null, { status: 302, headers: { location: 'https://example.test/2' } }),
      'https://example.test/2': () =>
        new Response(null, { status: 302, headers: { location: 'https://example.test/3' } }),
      'https://example.test/3': () =>
        new Response(null, { status: 302, headers: { location: 'https://example.test/4' } }),
    });

    await assert.rejects(
      () => fetchText('https://example.test/1', { fetchImpl: routes.fetch, maxRedirects: 2 }),
      /more than 2 redirects/,
    );
  });

  it('refuses a plain http URL before asking for it', async () => {
    let called = false;
    const stub: typeof fetch = (async () => {
      called = true;
      return new Response('x');
    }) as typeof fetch;

    await assert.rejects(
      () => fetchText('http://example.test/x', { fetchImpl: stub }),
      /http:\/\/ is not allowed/,
    );
    assert.equal(called, false);
  });
});

/** A stub fetch that answers by URL and records what it was asked for. */
function router(routes: Record<string, () => Response>): { fetch: typeof fetch; visited: string[] } {
  const visited: string[] = [];
  const impl = (async (input: string) => {
    const url = String(input);
    visited.push(url);
    return routes[url]?.() ?? new Response('no route', { status: 404 });
  }) as typeof fetch;
  return { fetch: impl, visited };
}

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

  it('remembers a failure for as long as it is told to', async () => {
    // Status checking fails closed, so a dead endpoint rejects every credential
    // either way. Without a negative TTL each of those rejections first waits
    // out the full timeout, which turns the issuer's outage into ours.
    let clock = 1000;
    let attempts = 0;
    const cache = new TtlCache<string>({ ttlMs: 10_000, errorTtlMs: 100, now: () => clock });
    const load = async () => {
      attempts += 1;
      if (attempts < 3) throw new Error('endpoint down');
      return 'ok';
    };

    await assert.rejects(() => cache.get('k', load), /endpoint down/);
    await assert.rejects(() => cache.get('k', load), /endpoint down/);
    assert.equal(attempts, 1, 'the endpoint must not be asked again within the negative TTL');

    clock += 101;
    await assert.rejects(() => cache.get('k', load), /endpoint down/);
    assert.equal(attempts, 2);

    clock += 101;
    assert.equal(await cache.get('k', load), 'ok', 'and it recovers once the endpoint does');
  });

  it('evicts the oldest entries past its limit', async () => {
    const cache = new TtlCache<string>({ ttlMs: 10_000, maxEntries: 2 });
    await cache.get('a', async () => 'a');
    await cache.get('b', async () => 'b');
    await cache.get('c', async () => 'c');

    assert.equal(cache.size, 2);
  });
});
