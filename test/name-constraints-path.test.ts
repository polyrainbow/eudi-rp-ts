import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { resolveIssuerCertificateChain } from '../src/trust/issuer-key.ts';
import { createCa, issue } from './constrained-certs.ts';

const NOW = new Date();

function assertRejected(outcome: Outcome<unknown>, reason: ReasonCode): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

describe('name constraints during path validation', () => {
  it('accepts a leaf inside the subtree its CA is permitted', async () => {
    const root = await createCa('C=PT, O=Root', { permitted: [{ directoryName: 'C=PT, O=Root' }] });
    const leaf = await issue(root, 'C=PT, O=Root, CN=Signer');

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assert.equal(outcome.verified, true, JSON.stringify(outcome));
  });

  it('rejects a leaf outside it, even though the chain links and reaches the anchor', async () => {
    // This is the whole point: every signature verifies and the chain
    // terminates at a trusted anchor. Only the constraint says no.
    const root = await createCa('C=PT, O=Root', { permitted: [{ directoryName: 'C=PT, O=Root' }] });
    const leaf = await issue(root, 'C=DE, O=Somewhere Else, CN=Signer');

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assertRejected(outcome, 'ISSUER_NAME_NOT_PERMITTED');
    assert.match(outcome.detail, /does not permit/);
  });

  it('applies an intermediate CA constraint to the leaf below it', async () => {
    const root = await createCa('C=PT, O=Root');
    const intermediate = await issue(root, 'C=PT, O=Root, OU=Sub', {
      constraints: { permitted: [{ dNSName: 'example.test' }] },
    });
    const good = await issue(intermediate, 'CN=Good', {
      subjectAltNames: [{ dNSName: 'signer.example.test' }],
    });
    const bad = await issue(intermediate, 'CN=Bad', {
      subjectAltNames: [{ dNSName: 'signer.other.test' }],
    });

    const anchors = TrustAnchors.fromCertificates([root.cert]);
    assert.equal(
      resolveIssuerCertificateChain([good.cert, intermediate.cert], anchors, NOW).verified,
      true,
    );
    assertRejected(
      resolveIssuerCertificateChain([bad.cert, intermediate.cert], anchors, NOW),
      'ISSUER_NAME_NOT_PERMITTED',
    );
  });

  it('applies a root constraint through an intermediate, not just to it', async () => {
    // RFC 5280 6.1.3: constraints bind every certificate below, not only the
    // one the constrained CA signed directly.
    const root = await createCa('C=PT, O=Root', {
      permitted: [{ directoryName: 'C=PT' }],
    });
    const intermediate = await issue(root, 'C=PT, O=Root, OU=Sub', { ca: true });
    const leaf = await issue(intermediate, 'C=DE, O=Elsewhere, CN=Signer');

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert, intermediate.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assertRejected(outcome, 'ISSUER_NAME_NOT_PERMITTED');
  });

  it('enforces an excluded subtree', async () => {
    const root = await createCa('C=PT, O=Root', {
      excluded: [{ dNSName: 'forbidden.test' }],
    });
    const leaf = await issue(root, 'CN=Signer', {
      subjectAltNames: [{ dNSName: 'a.forbidden.test' }],
    });

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assertRejected(outcome, 'ISSUER_NAME_NOT_PERMITTED');
    assert.match(outcome.detail, /excluded subtree/);
  });

  it('enforces a constraint the anchor itself carries', async () => {
    // The anchor is part of the path. A trust list entry that constrains itself
    // to a namespace means it.
    const root = await createCa('C=PT, O=Root', { permitted: [{ directoryName: 'C=PT' }] });
    const leaf = await issue(root, 'C=DE, CN=Signer');

    // The anchor is not in the presented chain here — it is found by signature.
    const outcome = resolveIssuerCertificateChain(
      [leaf.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assertRejected(outcome, 'ISSUER_NAME_NOT_PERMITTED');
  });

  it('rejects a chain whose CA constrains a form we cannot evaluate', async () => {
    // Fails closed: a constraint we cannot read is not one we may ignore.
    const root = await createCa('C=PT, O=Root', { permitted: [{ registeredID: '1.2.3.4' }] });
    const leaf = await issue(root, 'C=PT, O=Root, CN=Signer');

    const outcome = resolveIssuerCertificateChain(
      [leaf.cert],
      TrustAnchors.fromCertificates([root.cert]),
      NOW,
    );
    assertRejected(outcome, 'ISSUER_NAME_NOT_PERMITTED');
    assert.match(outcome.detail, /registeredID/);
  });

  it('leaves an unconstrained chain alone', async () => {
    const root = await createCa('C=PT, O=Root');
    const leaf = await issue(root, 'C=DE, O=Anywhere, CN=Signer');

    assert.equal(
      resolveIssuerCertificateChain([leaf.cert], TrustAnchors.fromCertificates([root.cert]), NOW)
        .verified,
      true,
      'a CA that constrains nothing constrains nothing',
    );
  });

  it('does not apply a constraint to the certificate carrying it', async () => {
    // The constrained CA's own name is not subject to its own constraint —
    // otherwise a CA could never constrain a namespace it sits outside of.
    const root = await createCa('C=XX, O=Registrar', {
      permitted: [{ directoryName: 'C=PT' }],
    });
    const leaf = await issue(root, 'C=PT, O=Issuer, CN=Signer');

    assert.equal(
      resolveIssuerCertificateChain([leaf.cert], TrustAnchors.fromCertificates([root.cert]), NOW)
        .verified,
      true,
    );
  });
});
