import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { type AddressInfo, type Socket, connect } from 'node:net';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Config } from '../app/config.ts';
import { createVerifierServer } from '../app/http/server.ts';
import { RateLimiter, clientKey } from '../app/http/rate-limit.ts';
import { MemorySessionStore, SessionCapacityError } from '../app/http/session.ts';
import { installShutdownHandlers } from '../app/http/shutdown.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { ageOver18Query } from '../src/presets/age-over-18.ts';

/**
 * The operational surface of the demo server: what it will hold, how fast it
 * will let itself be asked, what it tells an orchestrator, and how it stops.
 *
 * None of this is credential verification, which is exactly why it needs tests
 * of its own — a verifier that is correct and falls over under a trivial flood,
 * or that drops in-flight presentations on every redeploy, is not usable for
 * the thing it is correct about.
 */

const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const anchors = TrustAnchors.fromPem(readFileSync(`${dir}trust-anchor.pem`, 'utf8'));

function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    port: 0,
    baseUrl: 'https://verifier.test',
    walletScheme: 'eudi-openid4vp://',
    clientIdPrefix: 'redirect_uri',
    clientDnsName: undefined,
    accessCertificateChainPem: undefined,
    accessCertificatePrivateKeyPem: undefined,
    requestedVct: 'urn:eudi:pid:1',
    query: ageOver18Query({ vct: 'urn:eudi:pid:1' }),
    requestTtlSeconds: 300,
    checkStatus: false,
    checkCertificateRevocation: false,
    tolerateMalformedMdocValidity: false,
    verificationTimeoutMs: 30_000,
    limits: { sessions: 100, requestsPerWindow: 0, windowMs: 60_000, trustedProxyHops: 0 },
    shutdown: { drainMs: 0, graceMs: 1_000 },
    trustRefresh: { intervalMs: 60_000, retryMs: 1_000 },
    trust: {
      mode: 'pinned',
      pinnedAnchorsPem: undefined,
      lotlUrl: '',
      serviceTypes: [],
      territories: [],
      lotlSigningAnchorsPem: undefined,
      insecureSkipSignatureCheck: false,
    },
    ...overrides,
  };
}

/** Start a server on a loopback port and hand back its URL plus a closer. */
async function serving(
  config: Config,
  options: Parameters<typeof createVerifierServer>[2] = {},
): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createVerifierServer(config, anchors, options);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe('health and readiness', () => {
  it('reports liveness regardless of trust anchors or shutdown', async () => {
    const server = await serving(testConfig(), {
      draining: () => true,
      trustUnusable: () => 'the lists lapsed yesterday',
    });
    try {
      const response = await fetch(`${server.url}/healthz`);
      // Both conditions below make readiness fail. Neither is fixed by a
      // restart, so neither may reach a liveness probe.
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { status: 'ok' });
    } finally {
      await server.close();
    }
  });

  it('is ready when the anchors are current and nothing is draining', async () => {
    const server = await serving(testConfig());
    try {
      const response = await fetch(`${server.url}/readyz`);
      assert.equal(response.status, 200);
      const body = (await response.json()) as { status: string; anchors: number };
      assert.equal(body.status, 'ready');
      assert.equal(body.anchors, anchors.certificates.length);
    } finally {
      await server.close();
    }
  });

  it('is not ready once the trust lists have lapsed', async () => {
    const server = await serving(testConfig(), { trustUnusable: () => 'lapsed 2026-08-01' });
    try {
      const response = await fetch(`${server.url}/readyz`);
      assert.equal(response.status, 503);
      const body = (await response.json()) as { status: string; detail: string };
      assert.equal(body.status, 'trust_anchors_stale');
      assert.match(body.detail, /lapsed/);
    } finally {
      await server.close();
    }
  });

  it('is not ready while draining, before the listener closes', async () => {
    let draining = false;
    const server = await serving(testConfig(), { draining: () => draining });
    try {
      assert.equal((await fetch(`${server.url}/readyz`)).status, 200);
      draining = true;
      const response = await fetch(`${server.url}/readyz`);
      assert.equal(response.status, 503);
      assert.equal(((await response.json()) as { status: string }).status, 'draining');
      // Still serving: that separation is the whole point of a drain phase.
      assert.equal((await fetch(`${server.url}/healthz`)).status, 200);
    } finally {
      await server.close();
    }
  });
});

describe('rate limiting', () => {
  it('allows up to the limit and then refuses with a retry hint', () => {
    let now = 0;
    const limiter = new RateLimiter({ limit: 3, windowMs: 60_000, now: () => now });
    for (let i = 0; i < 3; i += 1) assert.equal(limiter.take('a').allowed, true);

    const refused = limiter.take('a');
    assert.equal(refused.allowed, false);
    assert.equal(refused.allowed === false && refused.retryAfterSeconds, 60);

    // Other clients are unaffected — a per-client limit that is not per client
    // is a global one wearing a disguise.
    assert.equal(limiter.take('b').allowed, true);

    now += 60_000;
    assert.equal(limiter.take('a').allowed, true);
  });

  it('never rounds the retry hint down to zero', () => {
    let now = 0;
    const limiter = new RateLimiter({ limit: 1, windowMs: 60_000, now: () => now });
    limiter.take('a');
    now += 59_900;
    const refused = limiter.take('a');
    // 100ms left rounds to 0 seconds, which would advise a retry that is still
    // inside the window and gets refused again.
    assert.equal(refused.allowed === false && refused.retryAfterSeconds, 1);
  });

  it('is disabled by a limit of zero', () => {
    const limiter = new RateLimiter({ limit: 0, windowMs: 60_000 });
    for (let i = 0; i < 100; i += 1) assert.equal(limiter.take('a').allowed, true);
    assert.equal(limiter.size, 0);
  });

  it('bounds the number of clients it remembers', () => {
    const limiter = new RateLimiter({ limit: 5, windowMs: 60_000, maxKeys: 10 });
    for (let i = 0; i < 1_000; i += 1) limiter.take(`client-${i}`);
    // The table is the limiter's own memory-exhaustion surface; without a cap,
    // rotating the key is enough to grow it without bound.
    assert.ok(limiter.size <= 10, `tracked ${limiter.size} keys`);
  });

  it('refuses over HTTP with a Retry-After header', async () => {
    const config = testConfig({
      limits: { sessions: 100, requestsPerWindow: 1, windowMs: 60_000, trustedProxyHops: 0 },
    });
    const server = await serving(config);
    try {
      assert.equal((await fetch(`${server.url}/presentations`, { method: 'POST' })).status, 201);
      const refused = await fetch(`${server.url}/presentations`, { method: 'POST' });
      assert.equal(refused.status, 429);
      assert.equal(refused.headers.get('retry-after'), '60');
      assert.deepEqual(await refused.json(), { error: 'rate_limited' });
    } finally {
      await server.close();
    }
  });

  it('does not limit polling', async () => {
    const config = testConfig({
      limits: { sessions: 100, requestsPerWindow: 1, windowMs: 60_000, trustedProxyHops: 0 },
    });
    const server = await serving(config);
    try {
      const created = (await (await fetch(`${server.url}/presentations`, { method: 'POST' })).json()) as {
        id: string;
      };
      // A browser polls about once a second for the life of a presentation.
      for (let i = 0; i < 5; i += 1) {
        assert.equal((await fetch(`${server.url}/presentations/${created.id}`)).status, 200);
      }
    } finally {
      await server.close();
    }
  });
});

describe('identifying the client behind a proxy', () => {
  const request = (headers: Record<string, string>, remoteAddress = '10.0.0.1') =>
    ({ headers, socket: { remoteAddress } }) as never;

  it('uses the socket address when no proxy is trusted', () => {
    // The header is present and is ignored: it is whatever the caller typed,
    // so trusting it here would let one client be a new client every request.
    assert.equal(clientKey(request({ 'x-forwarded-for': '1.2.3.4' }), 0), '10.0.0.1');
  });

  it('takes the nth entry from the right for n trusted hops', () => {
    const headers = { 'x-forwarded-for': 'spoofed, 203.0.113.7, 192.0.2.1' };
    assert.equal(clientKey(request(headers), 1), '192.0.2.1');
    assert.equal(clientKey(request(headers), 2), '203.0.113.7');
  });

  it('falls back to the socket address when the header is too short to trust', () => {
    // Two hops configured, one entry present: the header did not come from
    // those proxies, so nothing in it has been vouched for.
    assert.equal(clientKey(request({ 'x-forwarded-for': '1.2.3.4' }), 2), '10.0.0.1');
    assert.equal(clientKey(request({}), 1), '10.0.0.1');
  });
});

describe('session capacity', () => {
  it('refuses a new session rather than evicting a live one', async () => {
    const store = new MemorySessionStore({ maxSessions: 1 });
    const input = {
      nonce: 'n',
      state: 's',
      responseId: 'r1',
      requestPayload: {},
      decryptionJwk: undefined,
      requestObject: undefined,
      expiresAt: Date.now() + 60_000,
    };
    const first = await store.create(input);
    await assert.rejects(() => store.create({ ...input, responseId: 'r2' }), SessionCapacityError);
    // The point of refusing: whoever is flooding cannot cancel the check of
    // someone who has already scanned a code.
    assert.equal((await store.get(first.id))?.id, first.id);
  });

  it('makes room as sessions expire', async () => {
    let now = 1_000;
    const store = new MemorySessionStore({ maxSessions: 1, now: () => now });
    const input = {
      nonce: 'n',
      state: 's',
      responseId: 'r1',
      requestPayload: {},
      decryptionJwk: undefined,
      requestObject: undefined,
      expiresAt: 2_000,
    };
    await store.create(input);
    now = 3_000;
    await store.create({ ...input, responseId: 'r2', expiresAt: 4_000 });
    assert.equal(store.size, 1);
  });

  it('answers 503 with a retry hint, not 429', async () => {
    const config = testConfig({
      limits: { sessions: 1, requestsPerWindow: 0, windowMs: 60_000, trustedProxyHops: 0 },
    });
    const server = await serving(config);
    try {
      assert.equal((await fetch(`${server.url}/presentations`, { method: 'POST' })).status, 201);
      const refused = await fetch(`${server.url}/presentations`, { method: 'POST' });
      // 429 would blame this caller for a shared resource being full, and
      // slowing them down would not free it.
      assert.equal(refused.status, 503);
      assert.equal(refused.headers.get('retry-after'), String(config.requestTtlSeconds));
      assert.deepEqual(await refused.json(), { error: 'at_capacity' });
    } finally {
      await server.close();
    }
  });
});

describe('single-use response URI', () => {
  it('is claimed, so a second post finds nothing', async () => {
    const store = new MemorySessionStore({ maxSessions: 10 });
    const session = await store.create({
      nonce: 'n',
      state: 's',
      responseId: 'response-1',
      requestPayload: {},
      decryptionJwk: undefined,
      requestObject: undefined,
      expiresAt: Date.now() + 60_000,
    });

    // Concurrently, because sequential replay was already refused: the gap this
    // closes is two posts arriving while the first verification is still
    // fetching a status list.
    const [a, b] = await Promise.all([
      store.claimByResponseId('response-1'),
      store.claimByResponseId('response-1'),
    ]);
    assert.equal([a, b].filter(Boolean).length, 1);
    assert.equal((a ?? b)?.id, session.id);

    // The session itself stays readable — the browser is still polling it.
    assert.equal((await store.get(session.id))?.status, 'pending');
  });

  it('rejects a wallet posting twice to the same response URI', async () => {
    const server = await serving(testConfig());
    try {
      const created = (await (await fetch(`${server.url}/presentations`, { method: 'POST' })).json()) as {
        walletUri: string;
      };
      const params = new URL(
        created.walletUri.replace('eudi-openid4vp://', 'https://wallet.invalid/'),
      ).searchParams;
      const responseUri = params.get('response_uri')!.replace('https://verifier.test', server.url);
      const post = () =>
        fetch(responseUri, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ vp_token: '{}', state: params.get('state')! }),
        });

      // The first is answered — badly, since the token is empty, but answered.
      assert.equal((await post()).status, 200);
      const second = await post();
      assert.equal(second.status, 400);
      assert.equal(((await second.json()) as { reason: string }).reason, 'SESSION_UNKNOWN');
    } finally {
      await server.close();
    }
  });
});

describe('graceful shutdown', () => {
  /** A bare server, so nothing here depends on the verifier's routes. */
  async function listening(): Promise<Server> {
    const server = createServer((_req, res) => res.end('ok'));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    return server;
  }

  it('fails readiness first, then closes, then exits zero', async () => {
    const server = await listening();
    const order: string[] = [];
    let exitCode: number | undefined;
    const remove = installShutdownHandlers(server, {
      drainMs: 0,
      graceMs: 1_000,
      onDraining: () => order.push('draining'),
      exit: (code) => {
        order.push(`exit:${code}`);
        exitCode = code;
      },
      log: () => {},
    });

    try {
      process.emit('SIGTERM');
      // The close callback is a turn or two away; wait for it rather than for a
      // fixed delay.
      const deadline = Date.now() + 2_000;
      while (exitCode === undefined && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      assert.deepEqual(order, ['draining', 'exit:0']);
      assert.equal(server.listening, false);
    } finally {
      remove();
      server.close();
    }
  });

  it('exits non-zero on a second signal rather than waiting out the grace period', async () => {
    const server = await listening();
    const codes: number[] = [];
    // Never resolves on its own: an open connection holds `close` open, which
    // is the situation an impatient operator is in.
    const held = await new Promise<Socket>((resolve) => {
      const { port } = server.address() as AddressInfo;
      const socket = connect(port, '127.0.0.1', () => resolve(socket));
    });

    const remove = installShutdownHandlers(server, {
      drainMs: 0,
      // Long enough that reaching it would mean this test is asserting nothing.
      graceMs: 60_000,
      exit: (code) => void codes.push(code),
      log: () => {},
    });

    try {
      process.emit('SIGTERM');
      await new Promise((resolve) => setTimeout(resolve, 20));
      assert.deepEqual(codes, []);
      process.emit('SIGINT');
      assert.deepEqual(codes, [1]);
    } finally {
      remove();
      held.destroy();
      server.closeAllConnections();
      server.close();
    }
  });
});
