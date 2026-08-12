import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { isSelfIssued, readBasicConstraints } from '../src/trust/basic-constraints.ts';
import { resolveIssuerCertificateChain } from '../src/trust/issuer-key.ts';
import { createCa, issue, type Issued } from './constrained-certs.ts';

const NOW = new Date();

function assertRejected(outcome: Outcome<unknown>, reason: ReasonCode): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

function validate(chain: Issued[], anchor: Issued): Outcome<unknown> {
  return resolveIssuerCertificateChain(
    chain.map((issued) => issued.cert),
    TrustAnchors.fromCertificates([anchor.cert]),
    NOW,
  );
}

describe('reading basic constraints', () => {
  it('reads the path length the EU PID Issuer CA publishes', () => {
    // Zero: it signs document signers and nothing else. Node exposes `.ca` and
    // stops, so this is the half of the extension nothing here could see before.
    const anchor = new X509Certificate(
      readFileSync(fileURLToPath(new URL('../anchors/eudiw-pid-issuer-ca.pem', import.meta.url)), 'utf8'),
    );

    assert.deepEqual(readBasicConstraints(anchor), { critical: true, ca: true, pathLenConstraint: 0 });
  });

  it('keeps an absent constraint distinct from zero', async () => {
    const unlimited = await createCa('C=PT, O=Root', undefined, { pathLength: null });
    const none = await createCa('C=PT, O=Strict', undefined, { pathLength: 0 });

    assert.equal(readBasicConstraints(unlimited.cert)?.pathLenConstraint, undefined);
    assert.equal(readBasicConstraints(none.cert)?.pathLenConstraint, 0);
  });

  it('ignores a path length on a certificate that is not a CA', async () => {
    // RFC 5280 §4.2.1.9: the field means nothing without cA.
    const root = await createCa('C=PT, O=Root');
    const leaf = await issue(root, 'C=PT, CN=Signer', { pathLength: 5 });

    assert.equal(readBasicConstraints(leaf.cert)?.pathLenConstraint, undefined);
  });

  it('recognises a self-issued certificate by name, not by signature', async () => {
    const root = await createCa('C=PT, O=Root');
    const reKeyed = await issue(root, 'C=PT, O=Root', { ca: true });
    const delegated = await issue(root, 'C=PT, O=Somebody Else', { ca: true });

    assert.equal(isSelfIssued(reKeyed.cert), true);
    assert.equal(isSelfIssued(delegated.cert), false);
  });
});

describe('path length during path validation', () => {
  it('accepts a leaf issued directly by a CA that permits no sub-CA', async () => {
    // The shape the EU reference deployment actually uses: pathLen 0 on the
    // anchor, one document signer under it.
    const root = await createCa('C=PT, O=Root', undefined, { pathLength: 0 });
    const leaf = await issue(root, 'C=PT, CN=Signer');

    assert.equal(validate([leaf], root).verified, true);
  });

  it('rejects a sub-CA under an anchor that permits none', async () => {
    // Every signature verifies and the chain reaches the anchor. The anchor's
    // own basicConstraints is the only thing saying no — and nothing here was
    // reading it.
    const root = await createCa('C=PT, O=Root', undefined, { pathLength: 0 });
    const intermediate = await issue(root, 'C=PT, OU=Sub', { ca: true });
    const leaf = await issue(intermediate, 'C=PT, CN=Signer');

    const outcome = validate([leaf, intermediate], root);
    assertRejected(outcome, 'ISSUER_UNTRUSTED');
    assert.match(outcome.detail, /permits no further CA certificates/);
  });

  it('accepts exactly as many intermediates as the anchor allows', async () => {
    const root = await createCa('C=PT, O=Root', undefined, { pathLength: 1 });
    const first = await issue(root, 'C=PT, OU=One', { ca: true });
    const second = await issue(first, 'C=PT, OU=Two', { ca: true });

    assert.equal(validate([await issue(first, 'C=PT, CN=Signer'), first], root).verified, true);
    assertRejected(
      validate([await issue(second, 'C=PT, CN=Signer'), second, first], root),
      'ISSUER_UNTRUSTED',
    );
  });

  it('honours a constraint an intermediate imposes on the path below it', async () => {
    // RFC 5280 §6.1.4 (m): the limit can only ever be tightened on the way down.
    const root = await createCa('C=PT, O=Root', undefined, { pathLength: null });
    const strict = await issue(root, 'C=PT, OU=Strict', { ca: true, pathLength: 0 });
    const under = await issue(strict, 'C=PT, OU=Under', { ca: true });
    const leaf = await issue(under, 'C=PT, CN=Signer');

    const outcome = validate([leaf, under, strict], root);
    assertRejected(outcome, 'ISSUER_UNTRUSTED');
    assert.match(outcome.detail, /OU=Strict/);
  });

  it('treats an absent constraint as unlimited', async () => {
    const root = await createCa('C=PT, O=Root', undefined, { pathLength: null });
    const first = await issue(root, 'C=PT, OU=One', { ca: true, pathLength: null });
    const second = await issue(first, 'C=PT, OU=Two', { ca: true, pathLength: null });
    const leaf = await issue(second, 'C=PT, CN=Signer');

    assert.equal(validate([leaf, second, first], root).verified, true);
  });

  it('does not spend the allowance on a self-issued certificate', async () => {
    // §6.1.4 (l). A CA re-keying itself is not a delegation, so a pathLen of 0
    // still permits it — where a certificate issued to somebody else does not.
    const root = await createCa('C=PT, O=Root', undefined, { pathLength: 0 });
    const reKeyed = await issue(root, 'C=PT, O=Root', { ca: true });
    const delegated = await issue(root, 'C=PT, O=Somebody Else', { ca: true });

    assert.equal(
      validate([await issue(reKeyed, 'C=PT, CN=Signer'), reKeyed], root).verified,
      true,
    );
    assertRejected(
      validate([await issue(delegated, 'C=PT, CN=Signer'), delegated], root),
      'ISSUER_UNTRUSTED',
    );
  });
});
