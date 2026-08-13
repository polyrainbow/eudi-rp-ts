import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { fetchBytes } from '../src/fetching.ts';
import { verifyMdoc } from '../src/mdoc/verify.ts';
import { verifyPresentationResponse } from '../src/oid4vp/response.ts';
import { PID_MDOC_NAMESPACE } from '../src/presets/eudi-pid.ts';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { createStatusListCache } from '../src/trust/status.ts';
import { verifyAgeOver18SdJwtVc, verifySdJwtVc } from '../src/verify.ts';

const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const fixtures = JSON.parse(readFileSync(`${dir}credentials.json`, 'utf8'));
const anchors = TrustAnchors.fromPem(readFileSync(`${dir}trust-anchor.pem`, 'utf8'));

const real = fileURLToPath(new URL('./fixtures/real/', import.meta.url));
const issuerSigned = readFileSync(`${real}eudiw-pid-mdoc.txt`, 'utf8').trim();
const mdocAnchors = TrustAnchors.fromPem(
  readFileSync(fileURLToPath(new URL('../anchors/eudiw-pid-issuer-ca.pem', import.meta.url)), 'utf8'),
);

const NOW = new Date('2026-06-01T00:00:00Z');
const MDOC_NOW = new Date('2026-09-01T00:00:00Z');

const base = {
  credential: fixtures.credentials.withStatus as string,
  anchors,
  expectedVct: 'urn:eudi:pid:1',
  keyBinding: { nonce: fixtures.nonce as string, audience: fixtures.audience as string },
  checkCertificateRevocation: false,
  now: NOW,
};

const mdocBase = {
  issuerSigned,
  anchors: mdocAnchors,
  expectedDocType: PID_MDOC_NAMESPACE,
  tolerateMalformedValidityDates: true,
  checkStatus: false,
  checkCertificateRevocation: false,
  now: MDOC_NOW,
};

function assertRejected(outcome: Outcome<unknown>, reason: ReasonCode): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

/**
 * An endpoint that never answers, and only stops when it is aborted.
 *
 * The point of the whole feature: without a signal reaching it, this is
 * indistinguishable from an endpoint that is merely slow, and the only thing
 * that ends the wait is a deadline somebody set.
 */
const hangs: typeof fetch = ((_url: string, init?: RequestInit) =>
  new Promise((_resolve, rejectPromise) => {
    // A real pending request holds a socket, and a socket keeps the event loop
    // alive. This fake held nothing, which is a difference that matters: every
    // other timer these tests depend on is *unref'd* — `AbortSignal.timeout` is
    // by Node's design, and so is anything this file schedules — so the loop
    // had nothing to keep it running, drained, and node:test reported every
    // promise as "still pending but the event loop has already resolved".
    //
    // Node 24 happened to hold the loop open and hid it; 22.18.0, the floor
    // `engines` promises, did not. Holding a handle while pending is both the
    // fix and the more faithful imitation of a request that never answers.
    const socket = setInterval(() => {}, 1_000);
    init?.signal?.addEventListener('abort', () => {
      clearInterval(socket);
      rejectPromise(init.signal?.reason ?? new Error('aborted'));
    });
  })) as typeof fetch;

/** Serves a status list token, as the issuer's endpoint would. */
const serving = (token: string): typeof fetch =>
  (async () =>
    new Response(token, {
      status: 200,
      headers: { 'content-type': 'application/statuslist+jwt' },
    })) as typeof fetch;

/**
 * Aborted a tick from now, so the abort lands while a fetch is in flight.
 *
 * Deliberately *not* `.unref()`ed: this timer is the only thing that makes the
 * test progress, and unref'ing it — which an earlier version did — told Node it
 * was free to exit before the abort ever fired.
 */
function abortingSoon(ms = 5): AbortSignal {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

describe('the caller\'s signal reaches the fetch', () => {
  it('aborts a request that would otherwise never return', async () => {
    // Before this, FetchOptions accepted a `signal` through RequestInit and
    // then overwrote it with the internal timeout — taken, ignored, no error.
    await assert.rejects(
      fetchBytes('https://status.test/list', {
        fetchImpl: hangs,
        signal: abortingSoon(),
        // Far beyond the test, so only the caller's signal can end this.
        timeoutMs: 60_000,
      }),
    );
  });

  it('still applies its own deadline when a caller signal is supplied', async () => {
    // Combined, not replaced. A caller signal that never fires must not
    // disable the per-request bound this module sets.
    const never = new AbortController().signal;
    await assert.rejects(
      fetchBytes('https://status.test/list', { fetchImpl: hangs, signal: never, timeoutMs: 20 }),
    );
  });
});

describe('cancelling a verification', () => {
  it('does no work at all when the signal has already fired', async () => {
    let called = false;
    const result = await verifySdJwtVc({
      ...base,
      statusFetch: (() => {
        called = true;
        return Promise.reject(new Error('should not be reached'));
      }) as typeof fetch,
      signal: AbortSignal.abort(),
    });

    assertRejected(result, 'VERIFICATION_ABORTED');
    assert.equal(called, false, 'an aborted verification must not start work');
  });

  it('does the same on the mdoc path', async () => {
    const result = await verifyMdoc({ ...mdocBase, signal: AbortSignal.abort() });
    assertRejected(result, 'VERIFICATION_ABORTED');
  });

  it('does the same before an OID4VP envelope is decrypted', async () => {
    const result = await verifyPresentationResponse(
      {
        config: {
          baseUrl: 'https://verifier.test',
          walletScheme: 'eudi-openid4vp://',
          clientIdPrefix: 'redirect_uri' as const,
          clientDnsName: undefined,
          accessCertificateChainPem: undefined,
          accessCertificatePrivateKeyPem: undefined,
          requestTtlSeconds: 300,
          checkStatus: false,
          checkCertificateRevocation: false,
        },
        anchors,
        nonce: 'n',
        requestPayload: { client_id: 'redirect_uri:https://verifier.test/r' },
        decryptionJwk: undefined,
        signal: AbortSignal.abort(),
      },
      { vp_token: {} },
    );

    assertRejected(result, 'VERIFICATION_ABORTED');
  });

  it('reports a cancelled status fetch as cancelled, not as the issuer being down', async () => {
    // The distinction the reason code exists for: blaming STATUS_UNAVAILABLE on
    // an issuer whose endpoint was answering fine, for a deadline we set,
    // sends an operator to look at the wrong system.
    const result = await verifyAgeOver18SdJwtVc({ ...base, statusFetch: hangs, signal: abortingSoon() });

    assertRejected(result, 'VERIFICATION_ABORTED');
  });

  it('still reports a genuinely unreachable status endpoint as unavailable', async () => {
    // The other half of the pair. Same hanging endpoint, no caller signal —
    // only the per-request deadline — and the blame goes back to the issuer.
    const result = await verifyAgeOver18SdJwtVc({ ...base, statusFetch: hangs, statusTimeoutMs: 20 });

    assertRejected(result, 'STATUS_UNAVAILABLE');
  });

  it('reports a cancelled CRL fetch as cancelled, not as revocation unavailable', async () => {
    // The real reference chain publishes a CRL distribution point and no OCSP
    // responder, so this exercises one real CRL fetch.
    const result = await verifyMdoc({
      ...mdocBase,
      checkCertificateRevocation: true,
      revocationFetch: hangs,
      signal: abortingSoon(),
    });

    assertRejected(result, 'VERIFICATION_ABORTED');
  });

  it('still reports an unreachable CRL as revocation unavailable', async () => {
    const result = await verifyMdoc({
      ...mdocBase,
      checkCertificateRevocation: true,
      revocationFetch: hangs,
      revocationTimeoutMs: 20,
    });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
  });
});

describe('a cancellation is not remembered as an outage', () => {
  it('does not let one caller\'s abort answer for every other caller', async () => {
    // createStatusListCache remembers failures for 30 seconds, which is right
    // for an endpoint that is down and catastrophic for a client that hung up:
    // the entry is shared, so without the fix this second verification is
    // served the first one's cancellation and fails for a reason that has
    // nothing to do with it.
    const cache = createStatusListCache();

    const cancelled = await verifyAgeOver18SdJwtVc({
      ...base,
      statusFetch: hangs,
      statusCache: cache,
      signal: abortingSoon(),
    });
    assertRejected(cancelled, 'VERIFICATION_ABORTED');

    const next = await verifyAgeOver18SdJwtVc({
      ...base,
      statusFetch: serving(fixtures.statusLists.valid as string),
      statusCache: cache,
    });

    assert.equal(next.verified, true, JSON.stringify(next));
  });

  it('still remembers a real failure, which is what the cache is for', async () => {
    // The fix must not have turned the error cache off: an endpoint that is
    // genuinely down should not cost a full timeout per credential.
    const cache = createStatusListCache();
    let calls = 0;
    const failing: typeof fetch = (async () => {
      calls += 1;
      return new Response('nope', { status: 503 });
    }) as typeof fetch;

    await verifyAgeOver18SdJwtVc({ ...base, statusFetch: failing, statusCache: cache });
    await verifyAgeOver18SdJwtVc({ ...base, statusFetch: failing, statusCache: cache });

    assert.equal(calls, 1, 'the second verification should have been served the remembered failure');
  });
});
