import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createRevocationCache } from '../src/trust/revocation.ts';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { verifyCredential } from '../src/verify.ts';

/**
 * Certificate revocation: CRL and OCSP.
 *
 * A different question from the Token Status List in `status.test.ts`. That one
 * asks whether *this credential* was withdrawn; these ask whether the key that
 * signed it is still trusted to have signed anything at all. A credential can
 * be perfectly good and its issuer's certificate compromised.
 *
 * The fixture credential's issuer certificate is the only one in the set that
 * publishes both mechanisms — the others deliberately publish neither, which is
 * what makes them exercise the "nothing published, nothing to check" path.
 */
const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const fixtures = JSON.parse(readFileSync(`${dir}credentials.json`, 'utf8'));
const anchors = TrustAnchors.fromPem(readFileSync(`${dir}trust-anchor.pem`, 'utf8'));
const revocation = fixtures.certificateRevocation;

const NOW = new Date('2026-06-01T00:00:00Z');
const base = {
  credential: revocation.credential as string,
  anchors,
  expectedVct: 'urn:eudi:pid:1',
  keyBinding: { nonce: fixtures.nonce as string, audience: fixtures.audience as string },
  // The credential's own status list is a separate concern, tested elsewhere.
  checkStatus: false,
  now: NOW,
};

/**
 * Serve CRL and OCSP separately, so a test that means to exercise one is not
 * quietly satisfied by the other.
 */
function serving(documents: { crl?: string; ocsp?: string }): typeof fetch {
  return (async (url: string) => {
    const target = String(url);
    if (target === revocation.ocspUrl) {
      return documents.ocsp
        ? new Response(Buffer.from(documents.ocsp, 'base64'), {
            headers: { 'content-type': 'application/ocsp-response' },
          })
        : new Response('no responder', { status: 503 });
    }
    if (target === revocation.crlUrl) {
      return documents.crl
        ? new Response(Buffer.from(documents.crl, 'base64'), {
            headers: { 'content-type': 'application/pkix-crl' },
          })
        : new Response('no crl', { status: 503 });
    }
    throw new Error(`unexpected request to ${target}`);
  }) as unknown as typeof fetch;
}

function assertRejected(outcome: Outcome<unknown>, reason: ReasonCode): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

describe('certificate revocation by CRL', () => {
  it('accepts a certificate the CRL does not list', async () => {
    const result = await verifyCredential({ ...base, revocationFetch: serving({ crl: revocation.crls.good }) });

    assert.equal(result.verified, true, JSON.stringify(result));
  });

  it('rejects a certificate the CRL lists', async () => {
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ crl: revocation.crls.revoked }),
    });

    assertRejected(result, 'ISSUER_CERTIFICATE_REVOKED');
    // Reason 1 is keyCompromise, which is the case that matters: the signature
    // on the credential is no longer evidence of anything.
    assert.match(result.detail, /reason 1/);
    assert.match(result.detail, /CRL/);
  });

  it('accepts when the CRL lists a different certificate', async () => {
    // Without this the previous test would pass against an implementation that
    // rejects any CRL with entries in it, never comparing serial numbers.
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ crl: revocation.crls.someoneElseRevoked }),
    });

    assert.equal(result.verified, true, JSON.stringify(result));
  });

  it('refuses a CRL that is past its nextUpdate', async () => {
    // A stale CRL says nothing about revocations since it was published, so
    // accepting one turns "the CA stopped publishing" into "nothing revoked".
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ crl: revocation.crls.expired }),
    });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
    assert.match(result.detail, /expired/);
  });

  it('refuses a CRL with no nextUpdate at all', async () => {
    // Its freshness cannot be bounded, so a replayed copy from any point in the
    // past would be indistinguishable from the current one.
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ crl: revocation.crls.noNextUpdate }),
    });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
    assert.match(result.detail, /nextUpdate/);
  });

  it('refuses a CRL signed by anyone but the issuing CA', async () => {
    // The whole point of verifying it: otherwise anyone who can answer the
    // request could declare a revoked certificate good.
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ crl: revocation.crls.wrongSigner }),
    });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
    assert.match(result.detail, /signature/);
  });

  it('fails closed when the distribution point is unreachable', async () => {
    const result = await verifyCredential({ ...base, revocationFetch: serving({}) });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
  });
});

describe('certificate revocation by OCSP', () => {
  it('accepts a good response', async () => {
    const result = await verifyCredential({ ...base, revocationFetch: serving({ ocsp: revocation.ocsp.good }) });

    assert.equal(result.verified, true, JSON.stringify(result));
  });

  it('rejects a revoked response', async () => {
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ ocsp: revocation.ocsp.revoked }),
    });

    assertRejected(result, 'ISSUER_CERTIFICATE_REVOKED');
    assert.match(result.detail, /OCSP/);
  });

  it('treats "unknown" as unavailable rather than good', async () => {
    // The responder saying it does not vouch for this certificate is not a
    // clean bill of health.
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ ocsp: revocation.ocsp.unknown }),
    });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
    assert.match(result.detail, /unknown/);
  });

  it('refuses a response past its nextUpdate', async () => {
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ ocsp: revocation.ocsp.expired }),
    });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
    assert.match(result.detail, /expired/);
  });

  it('reports a responder that declines to answer', async () => {
    // responseStatus 3 is tryLater — a well-formed refusal, not a status.
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ ocsp: revocation.ocsp.tryLater }),
    });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
    assert.match(result.detail, /status 3/);
  });

  it('accepts a delegated responder the CA authorised', async () => {
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ ocsp: revocation.ocsp.delegated }),
    });

    assert.equal(result.verified, true, JSON.stringify(result));
  });

  it('rejects a revocation from a delegated responder', async () => {
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ ocsp: revocation.ocsp.delegatedRevoked }),
    });

    assertRejected(result, 'ISSUER_CERTIFICATE_REVOKED');
  });

  it('refuses a delegate without the OCSPSigning extended key usage', async () => {
    // Otherwise any certificate the CA ever issued could answer for every
    // certificate the CA ever issued — including for itself.
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ ocsp: revocation.ocsp.delegatedWithoutEku }),
    });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
    assert.match(result.detail, /OCSPSigning/);
  });
});

describe('choosing between the two mechanisms', () => {
  it('prefers OCSP when the certificate publishes both', async () => {
    // The CRL here would say revoked. OCSP says good and is asked first, so a
    // fresher answer wins over a staler one.
    const requested: string[] = [];
    const result = await verifyCredential({
      ...base,
      revocationFetch: (async (url: string, init: RequestInit) => {
        requested.push(String(url));
        return serving({ ocsp: revocation.ocsp.good, crl: revocation.crls.revoked })(url as never, init as never);
      }) as unknown as typeof fetch,
    });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.deepEqual(requested, [revocation.ocspUrl], 'the CRL must not be fetched once OCSP answered');
  });

  it('falls back to the CRL when the responder is down', async () => {
    // Two mechanisms both being unreachable is a different situation from one
    // being unreachable, and only the first should sink the verification.
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ crl: revocation.crls.good }),
    });

    assert.equal(result.verified, true, JSON.stringify(result));
  });

  it('still rejects when the responder is down and the CRL says revoked', async () => {
    const result = await verifyCredential({
      ...base,
      revocationFetch: serving({ crl: revocation.crls.revoked }),
    });

    assertRejected(result, 'ISSUER_CERTIFICATE_REVOKED');
  });
});

describe('when there is nothing to check', () => {
  it('fetches nothing for a chain that publishes no revocation information', async () => {
    // The other fixture certificates carry neither extension. A CA that
    // published nothing has not told us something we are ignoring, so this is
    // a pass rather than a failure — the one case that is not fail-closed.
    let fetched = false;
    const result = await verifyCredential({
      ...base,
      credential: fixtures.credentials.over18,
      revocationFetch: (async () => {
        fetched = true;
        return new Response('', { status: 200 });
      }) as typeof fetch,
    });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(fetched, false, 'nothing published means nothing to fetch');
  });

  it('fetches nothing when the check is turned off', async () => {
    let fetched = false;
    const result = await verifyCredential({
      ...base,
      checkCertificateRevocation: false,
      revocationFetch: (async () => {
        fetched = true;
        return new Response('', { status: 200 });
      }) as typeof fetch,
    });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(fetched, false);
  });
});

describe('the mdoc path checks the same thing', () => {
  // The two formats drifting apart on revocation is exactly how mdoc came to
  // skip credential status entirely. Same certificate, same CRL, same answer.
  const mdocBase = {
    issuerSigned: fixtures.mdoc.revocableIssuer as string,
    anchors,
    expectedDocType: fixtures.mdoc.docType as string,
    checkStatus: false,
    now: NOW,
  };

  it('accepts an mdoc whose issuer the CRL does not list', async () => {
    const { verifyMdoc } = await import('../src/mdoc/verify.ts');
    const result = await verifyMdoc({ ...mdocBase, revocationFetch: serving({ crl: revocation.crls.good }) });

    assert.equal(result.verified, true, JSON.stringify(result));
  });

  it('rejects an mdoc whose issuer certificate has been revoked', async () => {
    const { verifyMdoc } = await import('../src/mdoc/verify.ts');
    const result = await verifyMdoc({
      ...mdocBase,
      revocationFetch: serving({ crl: revocation.crls.revoked }),
    });

    assertRejected(result, 'ISSUER_CERTIFICATE_REVOKED');
  });

  it('fails closed on the mdoc path too', async () => {
    const { verifyMdoc } = await import('../src/mdoc/verify.ts');
    const result = await verifyMdoc({ ...mdocBase, revocationFetch: serving({}) });

    assertRejected(result, 'ISSUER_REVOCATION_UNAVAILABLE');
  });
});

describe('caching', () => {
  it('reuses one CRL across verifications', async () => {
    // A CRL covers every certificate its CA ever issued, so refetching it per
    // credential is the difference between one request and one per holder.
    const cache = createRevocationCache();
    let requests = 0;
    const counting: typeof fetch = (async (url: string, init: RequestInit) => {
      requests += 1;
      return serving({ crl: revocation.crls.good })(url as never, init as never);
    }) as unknown as typeof fetch;

    const first = await verifyCredential({ ...base, revocationFetch: counting, revocationCache: cache });
    const second = await verifyCredential({ ...base, revocationFetch: counting, revocationCache: cache });

    assert.equal(first.verified, true, JSON.stringify(first));
    assert.equal(second.verified, true);
    // Two requests for the first verification — the responder, which fails,
    // then the CRL — and nothing at all for the second.
    assert.equal(requests, 2, 'the second verification must reuse both cached results');
  });
});
