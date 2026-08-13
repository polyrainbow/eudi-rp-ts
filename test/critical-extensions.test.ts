import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import {
  RECOGNISED_CRITICAL_EXTENSIONS,
  unrecognisedCriticalExtensions,
} from '../src/trust/critical-extensions.ts';
import { resolveIssuerCertificateChain } from '../src/trust/issuer-key.ts';
import { createCa, issue, type Issued } from './constrained-certs.ts';

const NOW = new Date();

/**
 * `privateKeyUsagePeriod` (RFC 3280 §4.2.1.4, dropped from RFC 5280) — the only
 * unrecognised critical extension in use anywhere on the live trusted lists, so
 * the tests reject on the extension a real CA actually publishes rather than on
 * an OID nobody has ever emitted.
 */
const PRIVATE_KEY_USAGE_PERIOD = '2.5.29.16';

/**
 * Deliberately not a well-formed `PrivateKeyUsagePeriod`.
 *
 * The rejection is on the OID, before anything looks at the value, and it has
 * to be: not parsing the extension is the entire premise. A test that supplied
 * valid DER would pass without proving that.
 */
const GARBAGE = new Uint8Array([0xff, 0xff, 0xff]).buffer;

function assertRejected(outcome: Outcome<unknown>, reason: ReasonCode): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

/** Everything below the anchor, leaf first — the shape x5c arrives in. */
function validate(chain: Issued[], anchor: Issued): Outcome<unknown> {
  return resolveIssuerCertificateChain(
    chain.map((issued) => issued.cert),
    TrustAnchors.fromCertificates([anchor.cert]),
    NOW,
  );
}

describe('reading critical extensions', () => {
  it('finds nothing unrecognised on the live EU PID document signer', () => {
    // Pinned against the committed real credential rather than a generated
    // fixture: whether this rule can be turned on at all is a question about
    // the certificates the deployment publishes, not about ones we mint.
    const fixture = fileURLToPath(new URL('./fixtures/real/eudiw-pid-sd-jwt-vc.txt', import.meta.url));
    const header = JSON.parse(
      Buffer.from(readFileSync(fixture, 'utf8').trim().split('.')[0]!, 'base64url').toString(),
    ) as { x5c: string[] };
    const signer = new X509Certificate(Buffer.from(header.x5c[0]!, 'base64'));

    assert.deepEqual(unrecognisedCriticalExtensions(signer), []);
  });

  it('finds nothing unrecognised on the committed EU PID issuer anchor', () => {
    const pem = readFileSync(fileURLToPath(new URL('../anchors/eudiw-pid-issuer-ca.pem', import.meta.url)), 'utf8');
    assert.deepEqual(unrecognisedCriticalExtensions(new X509Certificate(pem)), []);
  });

  it('reports the OID of a critical extension it does not process', async () => {
    const ca = await createCa('CN=Test Root');
    const leaf = await issue(ca, 'CN=Leaf', {
      policies: { raw: [{ oid: PRIVATE_KEY_USAGE_PERIOD, critical: true, der: GARBAGE }] },
    });

    assert.deepEqual(unrecognisedCriticalExtensions(leaf.cert), [PRIVATE_KEY_USAGE_PERIOD]);
  });

  it('ignores the same extension when it is not critical', async () => {
    // The whole distinction: a non-critical extension is a CA saying "use this
    // if you understand it", which is permission to skip it.
    const ca = await createCa('CN=Test Root');
    const leaf = await issue(ca, 'CN=Leaf', {
      policies: { raw: [{ oid: PRIVATE_KEY_USAGE_PERIOD, critical: false, der: GARBAGE }] },
    });

    assert.deepEqual(unrecognisedCriticalExtensions(leaf.cert), []);
  });

  it('lists exactly the extensions this library acts on', () => {
    // A tripwire, not a restatement. Every OID here is a promise that code
    // elsewhere processes that extension; adding one without the processing
    // reopens §6.1.4 (o) silently, so adding one has to be deliberate enough to
    // edit a test that says so.
    assert.deepEqual(
      [...RECOGNISED_CRITICAL_EXTENSIONS].sort(),
      [
        '1.3.6.1.5.5.7.1.1', // authorityInfoAccess — revocation.ts (OCSP)
        '2.5.29.15', // keyUsage
        '2.5.29.17', // subjectAltName
        '2.5.29.19', // basicConstraints
        '2.5.29.30', // nameConstraints
        '2.5.29.31', // cRLDistributionPoints — revocation.ts
        '2.5.29.32', // certificatePolicies
        '2.5.29.33', // policyMappings
        '2.5.29.36', // policyConstraints
        '2.5.29.37', // extKeyUsage
        '2.5.29.54', // inhibitAnyPolicy
      ].sort(),
    );
  });

  it('does not recognise the extensions RFC 5280 requires to be non-critical', () => {
    // subjectKeyIdentifier, authorityKeyIdentifier, issuerAltName,
    // subjectDirectoryAttributes, freshestCRL. All are read somewhere or by
    // somebody, and none may be critical on a conforming certificate — so a
    // critical one is non-conformance, and rejecting is the rule working rather
    // than a gap in it.
    for (const oid of ['2.5.29.14', '2.5.29.35', '2.5.29.18', '2.5.29.9', '2.5.29.46']) {
      assert.equal(RECOGNISED_CRITICAL_EXTENSIONS.has(oid), false, `${oid} should not be recognised`);
    }
  });
});

describe('path validation rejects unrecognised critical extensions (RFC 5280 §6.1.4 (o))', () => {
  it('rejects a leaf carrying one', async () => {
    const ca = await createCa('CN=Test Root');
    const leaf = await issue(ca, 'CN=Leaf', {
      policies: { raw: [{ oid: PRIVATE_KEY_USAGE_PERIOD, critical: true, der: GARBAGE }] },
    });

    const outcome = validate([leaf], ca);
    assertRejected(outcome, 'ISSUER_EXTENSION_UNRECOGNISED');
    // The OID is the actionable part: it is the only thing about the extension
    // we can claim to have got right.
    assert.match(outcome.detail, /2\.5\.29\.16/);
  });

  it('rejects an intermediate CA carrying one', async () => {
    const root = await createCa('CN=Test Root');
    const intermediate = await issue(root, 'CN=Intermediate', {
      ca: true,
      policies: { raw: [{ oid: PRIVATE_KEY_USAGE_PERIOD, critical: true, der: GARBAGE }] },
    });
    const leaf = await issue(intermediate, 'CN=Leaf');

    assertRejected(validate([leaf, intermediate], root), 'ISSUER_EXTENSION_UNRECOGNISED');
  });

  it('accepts the same chain when the extension is not critical', async () => {
    const ca = await createCa('CN=Test Root');
    const leaf = await issue(ca, 'CN=Leaf', {
      policies: { raw: [{ oid: PRIVATE_KEY_USAGE_PERIOD, critical: false, der: GARBAGE }] },
    });

    assert.equal(validate([leaf], ca).verified, true);
  });

  it('accepts critical extensions it does process', async () => {
    // certificatePolicies and policyConstraints, both critical, both on the
    // live lists in that form (REPRODUCE.md: 72 and 6 certificates). The rule
    // must not reject a certificate for asserting something we handle.
    const root = await createCa('CN=Test Root', undefined, {
      policies: { requireExplicitPolicy: 0 },
    });
    const leaf = await issue(root, 'CN=Leaf', {
      policies: { policies: ['1.3.6.1.4.1.99999.1'], policiesCritical: true },
    });

    assert.equal(validate([leaf], root).verified, true);
  });

  it('exempts the anchor when the anchor is the top of the presented chain', async () => {
    // §6.1 never processes the trust anchor as a certificate, and this codebase
    // reads an anchor's constraints but not its assertions. An anchor is
    // trusted because it was pinned or published, not because every field on it
    // was understood.
    const ca = await createCa('CN=Test Root', undefined, {
      policies: { raw: [{ oid: PRIVATE_KEY_USAGE_PERIOD, critical: true, der: GARBAGE }] },
    });
    const leaf = await issue(ca, 'CN=Leaf');

    assert.equal(validate([leaf, ca], ca).verified, true);
  });

  it('exempts the anchor when the anchor merely signed the top of the chain', async () => {
    // The other shape `resolveIssuerCertificateChain` builds a path in: the
    // anchor is appended rather than presented. The exemption has to be the
    // same, or an identical trust decision would depend on whether the wallet
    // happened to include the root in its x5c.
    const ca = await createCa('CN=Test Root', undefined, {
      policies: { raw: [{ oid: PRIVATE_KEY_USAGE_PERIOD, critical: true, der: GARBAGE }] },
    });
    const leaf = await issue(ca, 'CN=Leaf');

    assert.equal(validate([leaf], ca).verified, true);
  });

  it('is distinct from ISSUER_UNTRUSTED, because nothing is wrong with the issuer', async () => {
    // Same chain twice: once plain, once with a critical extension added. The
    // first verifies, so the second's rejection is attributable to the
    // extension alone — which is what makes the separate code worth having.
    const ca = await createCa('CN=Test Root');
    const plain = await issue(ca, 'CN=Leaf', { serial: '03' });
    const marked = await issue(ca, 'CN=Leaf', {
      serial: '04',
      policies: { raw: [{ oid: PRIVATE_KEY_USAGE_PERIOD, critical: true, der: GARBAGE }] },
    });

    assert.equal(validate([plain], ca).verified, true);
    assertRejected(validate([marked], ca), 'ISSUER_EXTENSION_UNRECOGNISED');
  });
});
