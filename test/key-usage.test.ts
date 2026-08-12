import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { resolveIssuerCertificateChain } from '../src/trust/issuer-key.ts';
import { readKeyUsage } from '../src/trust/key-usage.ts';
import { createCa, issue } from './constrained-certs.ts';

const NOW = new Date();

function assertRejected(outcome: Outcome<unknown>, reason: ReasonCode): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

describe('reading the KeyUsage extension', () => {
  it('reads the bits a certificate asserts', async () => {
    const ca = await createCa('CN=Root', undefined, { keyUsage: ['keyCertSign', 'cRLSign'] });

    const usage = readKeyUsage(ca.cert);
    assert.deepEqual([...usage!.bits].sort(), ['cRLSign', 'keyCertSign']);
    assert.equal(usage!.critical, true);
  });

  it('distinguishes an absent extension from an empty one', async () => {
    // Silence and refusal are different statements, and only the second is a
    // reason to reject: 60 end-entity certificates on the live trusted lists
    // carry no KeyUsage at all.
    const silent = await createCa('CN=Silent');
    assert.equal(readKeyUsage(silent.cert), undefined);

    const refuses = await createCa('CN=Refuses', undefined, { keyUsage: [] });
    assert.deepEqual([...readKeyUsage(refuses.cert)!.bits], []);
  });

  it('does not confuse KeyUsage with the extended key usage Node exposes', async () => {
    // `X509Certificate.keyUsage` is the EKU OID list — a different extension
    // with a name close enough to have caused this gap in the first place.
    const ca = await createCa('CN=Root', undefined, { keyUsage: ['keyCertSign'] });
    assert.equal(ca.cert.keyUsage, undefined);
    assert.deepEqual([...readKeyUsage(ca.cert)!.bits], ['keyCertSign']);
  });

  it('reads what the real EU PID issuer CA and document signer assert', () => {
    // The positive control that matters: the rules below are only defensible
    // while the live EUDI certificates satisfy them.
    const ca = new X509Certificate(
      readFileSync(fileURLToPath(new URL('../anchors/eudiw-pid-issuer-ca.pem', import.meta.url)), 'utf8'),
    );
    assert.deepEqual([...readKeyUsage(ca)!.bits].sort(), ['cRLSign', 'keyCertSign']);

    const sdJwt = readFileSync(
      fileURLToPath(new URL('./fixtures/real/eudiw-pid-sd-jwt-vc.txt', import.meta.url)),
      'utf8',
    ).trim();
    const header = JSON.parse(Buffer.from(sdJwt.split('.')[0]!, 'base64url').toString('utf8')) as {
      x5c: string[];
    };
    const documentSigner = new X509Certificate(Buffer.from(header.x5c[0]!, 'base64'));
    assert.deepEqual([...readKeyUsage(documentSigner)!.bits], ['digitalSignature']);
  });
});

/**
 * What Node already does, so the explicit checks are known to be redundant
 * rather than assumed to be load-bearing.
 *
 * `X509Certificate.ca` is documented as "is this a CA certificate". It is
 * OpenSSL's `X509_check_ca`, which also clears the flag when a KeyUsage
 * extension is present without `keyCertSign` — an undocumented property of the
 * TLS backend that path validation here would otherwise be resting on silently.
 * If these expectations ever fail, nothing is broken: it means the explicit
 * check in `issuer-key.ts` has started carrying weight on its own.
 */
describe('what Node enforces about keyCertSign already', () => {
  const cases: { usage: string[] | undefined; ca: boolean }[] = [
    { usage: undefined, ca: true }, // silence is unrestricted
    { usage: ['keyCertSign'], ca: true },
    { usage: ['keyCertSign', 'cRLSign'], ca: true },
    { usage: [], ca: false },
    { usage: ['cRLSign'], ca: false },
    { usage: ['digitalSignature'], ca: false },
  ];

  for (const { usage, ca } of cases) {
    const label = usage === undefined ? 'no KeyUsage extension' : `[${usage.join('|')}]`;
    it(`reports ca=${ca} for a CA:TRUE certificate with ${label}`, async () => {
      const root = await createCa('CN=Root');
      const cert = await issue(root, 'CN=Sub', {
        ca: true,
        ...(usage === undefined ? {} : { keyUsage: usage as never }),
      });
      assert.equal(cert.cert.ca, ca);
    });
  }
});

/**
 * `basicConstraints` says a certificate *is* a CA; `keyUsage` says what its key
 * may do. They are asserted separately, and RFC 5280 §6.1.4 (n) requires the
 * second to be honoured — a certificate marked CA whose KeyUsage omits
 * `keyCertSign` is refusing the use about to be made of it.
 */
describe('key usage during path validation', () => {
  it('accepts a chain whose certificates assert what they are being used for', async () => {
    const root = await createCa('CN=Root', undefined, { keyUsage: ['keyCertSign', 'cRLSign'] });
    const leaf = await issue(root, 'CN=Signer', { keyUsage: ['digitalSignature'] });

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assert.equal(outcome.verified, true, JSON.stringify(outcome));
  });

  it('accepts a chain that asserts no key usage at all', async () => {
    // An absent extension is unrestricted under §4.2.1.3. Rejecting here would
    // reject certificates for saying nothing.
    const root = await createCa('CN=Root');
    const leaf = await issue(root, 'CN=Signer');

    assert.equal(
      resolveIssuerCertificateChain([leaf.cert], TrustAnchors.fromCertificates([root.cert]), NOW)
        .verified,
      true,
    );
  });

  it('rejects an intermediate CA that does not assert keyCertSign', async () => {
    // Everything else about this chain is correct: it links, every signature
    // verifies, the intermediate is marked CA, and it reaches the anchor. Only
    // the intermediate's own statement about its key says no.
    const root = await createCa('CN=Root', undefined, { keyUsage: ['keyCertSign', 'cRLSign'] });
    const intermediate = await issue(root, 'CN=Sub', {
      ca: true,
      keyUsage: ['digitalSignature', 'cRLSign'],
    });
    const leaf = await issue(intermediate, 'CN=Signer', { keyUsage: ['digitalSignature'] });

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert, intermediate.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assertRejected(outcome, 'ISSUER_UNTRUSTED');
    assert.match(outcome.detail, /x5c position 1 does not assert keyCertSign/);
  });

  it('rejects a trust anchor that signed the chain without asserting keyCertSign', async () => {
    // Not by a check of ours: `findIssuerOf` reaches the anchor through
    // `checkIssued`, which is OpenSSL's X509_check_issued and refuses an issuer
    // whose KeyUsage omits the bit — so the anchor is never matched at all.
    // Pinned because the *reason* is surprising and the outcome is what matters.
    const root = await createCa('CN=Root', undefined, { keyUsage: ['cRLSign'] });
    const leaf = await issue(root, 'CN=Signer', { keyUsage: ['digitalSignature'] });

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assertRejected(outcome, 'ISSUER_UNTRUSTED');
    assert.match(outcome.detail, /does not terminate at a trust anchor/);
  });

  it('rejects a leaf that does not assert digitalSignature', async () => {
    const root = await createCa('CN=Root', undefined, { keyUsage: ['keyCertSign'] });
    const leaf = await issue(root, 'CN=Signer', { keyUsage: ['keyEncipherment'] });

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assertRejected(outcome, 'ISSUER_UNTRUSTED');
    assert.match(outcome.detail, /does not assert digitalSignature/);
  });

  it('does not accept nonRepudiation in place of digitalSignature on the leaf', async () => {
    // nonRepudiation covers a non-repudiation service, not the data-origin
    // signature an issuer makes over a credential — and ISO 18013-5 Annex B
    // requires digitalSignature on a document signer certificate. The live EU
    // PID signer carries exactly that bit and nothing else.
    const root = await createCa('CN=Root', undefined, { keyUsage: ['keyCertSign'] });
    const leaf = await issue(root, 'CN=Signer', { keyUsage: ['nonRepudiation'] });

    assertRejected(
      resolveIssuerCertificateChain([leaf.cert], TrustAnchors.fromCertificates([root.cert]), NOW),
      'ISSUER_UNTRUSTED',
    );
  });

  it('leaves an end-entity anchor usable as the thing the chain terminates at', async () => {
    // More than half the certificates published on the live lists are
    // end-entity ones — timestamping units, responders — and they identify a
    // service rather than issue anything. Terminating at one must not be read
    // as asking it to sign certificates.
    const root = await createCa('CN=Root', undefined, { keyUsage: ['keyCertSign'] });
    const leaf = await issue(root, 'CN=Signer', { keyUsage: ['digitalSignature'] });

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert],
      // The leaf itself is the anchor: matched by equality, never used to sign.
      TrustAnchors.fromCertificates([leaf.cert]),
      NOW,
    );
    assert.equal(outcome.verified, true, JSON.stringify(outcome));
  });
});
