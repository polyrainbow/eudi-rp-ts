import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { resolveIssuerCertificateChain } from '../src/trust/issuer-key.ts';
import {
  readCertificatePolicies,
  readInhibitAnyPolicy,
  readPolicyConstraints,
  readPolicyMappings,
} from '../src/trust/policies.ts';
import type { CertificatePolicyOptions } from '../src/trust/policy-tree.ts';
import { createCa, issue, type Issued } from './constrained-certs.ts';

const NOW = new Date();

/** Private arcs, so nothing here can be confused with a real eIDAS policy. */
const A = '1.3.6.1.4.1.99999.1';
const B = '1.3.6.1.4.1.99999.2';
const ANY = '2.5.29.32.0';

function assertRejected(outcome: Outcome<unknown>, reason: ReasonCode): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

/** Everything below the anchor, leaf first — the shape x5c arrives in. */
function validate(
  chain: Issued[],
  anchor: Issued,
  certificatePolicies?: CertificatePolicyOptions,
): Outcome<unknown> {
  return resolveIssuerCertificateChain(
    chain.map((issued) => issued.cert),
    TrustAnchors.fromCertificates([anchor.cert]),
    NOW,
    certificatePolicies ? { certificatePolicies } : {},
  );
}

describe('reading the certificate policy extensions', () => {
  it('reads what the live EU PID document signer asserts', () => {
    // Pinned against the committed real credential rather than a fixture we
    // generated, because the shape that matters is the one the deployment
    // publishes: one policy OID, non-critical, with a CPS pointer we ignore.
    const fixture = fileURLToPath(new URL('./fixtures/real/eudiw-pid-sd-jwt-vc.txt', import.meta.url));
    const header = JSON.parse(
      Buffer.from(readFileSync(fixture, 'utf8').trim().split('.')[0]!, 'base64url').toString(),
    ) as { x5c: string[] };
    const signer = new X509Certificate(Buffer.from(header.x5c[0]!, 'base64'));

    const policies = readCertificatePolicies(signer);
    assert.deepEqual(policies, {
      critical: false,
      policies: [{ oid: '1.2.3.4', qualifiers: ['1.3.6.1.5.5.7.2.1'] }],
    });
  });

  it('reports an absent extension as absent, not as an empty set', async () => {
    const ca = await createCa('C=PT, O=Root');
    assert.equal(readCertificatePolicies(ca.cert), undefined);
    assert.equal(readPolicyMappings(ca.cert), undefined);
    assert.equal(readPolicyConstraints(ca.cert), undefined);
    assert.equal(readInhibitAnyPolicy(ca.cert), undefined);
  });

  it('reads a SkipCerts of zero as zero', async () => {
    // The value that means "from the very next certificate", and the one a
    // falsy check would silently turn into "never". Every policyConstraints
    // extension on the live trusted lists is exactly this (REPRODUCE.md).
    const ca = await createCa('C=PT, O=Root', undefined, {
      policies: { requireExplicitPolicy: 0, inhibitPolicyMapping: 0, inhibitAnyPolicy: 0 },
    });

    assert.deepEqual(readPolicyConstraints(ca.cert), {
      critical: true,
      requireExplicitPolicy: 0,
      inhibitPolicyMapping: 0,
    });
    assert.deepEqual(readInhibitAnyPolicy(ca.cert), { critical: true, skipCerts: 0 });
  });

  it('refuses a negative SkipCerts rather than reading it as a huge one', async () => {
    // `SkipCerts ::= INTEGER (0..MAX)`. Two's complement 0xFF is -1, and taking
    // it at face value would turn "no certificate may map policies" into "every
    // certificate may".
    const ca = await createCa('C=PT, O=Root', undefined, {
      policies: {
        raw: [
          { oid: '2.5.29.36', critical: true, der: new Uint8Array([0x30, 0x03, 0x80, 0x01, 0xff]).buffer },
        ],
      },
    });

    assert.throws(() => readPolicyConstraints(ca.cert), /negative/);
  });
});

describe('certificate policies during path validation', () => {
  it('leaves a chain that asserts no policy at all alone', async () => {
    // The default is any-policy, and 103 of the 2439 service certificates on
    // the live lists assert nothing. Demanding a policy nobody asked for would
    // reject them all.
    const root = await createCa('C=PT, O=Root');
    const leaf = await issue(root, 'C=PT, CN=Signer');

    assert.equal(validate([leaf], root).verified, true);
  });

  it('leaves a chain alone when the CAs disagree but the caller asked for nothing', async () => {
    // The intermediate never authorised the leaf's policy, so the policy tree
    // is empty by the end — which matters only to a caller that named policies.
    const root = await createCa('C=PT, O=Root');
    const intermediate = await issue(root, 'C=PT, OU=Sub', { ca: true, policies: { policies: [A] } });
    const leaf = await issue(intermediate, 'C=PT, CN=Signer', { policies: { policies: [B] } });

    assert.equal(validate([leaf, intermediate], root).verified, true);
  });

  it('accepts a leaf issued under a policy the caller accepts', async () => {
    const root = await createCa('C=PT, O=Root');
    const leaf = await issue(root, 'C=PT, CN=Signer', { policies: { policies: [A] } });

    assert.equal(validate([leaf], root, { acceptable: [A] }).verified, true);
  });

  it('rejects the same leaf when the caller accepts a different policy', async () => {
    const root = await createCa('C=PT, O=Root');
    const leaf = await issue(root, 'C=PT, CN=Signer', { policies: { policies: [A] } });

    const outcome = validate([leaf], root, { acceptable: [B] });
    assertRejected(outcome, 'ISSUER_POLICY_NOT_PERMITTED');
    assert.match(outcome.detail, /No certificate policy is valid for the whole path/);
  });

  it('rejects a leaf that asserts no policy when the caller names one', async () => {
    const root = await createCa('C=PT, O=Root');
    const leaf = await issue(root, 'C=PT, CN=Signer');

    const outcome = validate([leaf], root, { acceptable: [A] });
    assertRejected(outcome, 'ISSUER_POLICY_NOT_PERMITTED');
    assert.match(outcome.detail, /asserts no certificate policy/);
  });

  it('accepts it under the RFC 5280 reading, which the caller can ask for', async () => {
    // RFC 5280 §6.1.5 (g) succeeds on `explicit_policy > 0` whatever the
    // user-initial-policy-set says, so naming policies with
    // initial-explicit-policy unset leaves a policy-less path valid. This
    // library requires by default what a caller names, and this is the way back.
    const root = await createCa('C=PT, O=Root');
    const leaf = await issue(root, 'C=PT, CN=Signer');

    assert.equal(validate([leaf], root, { acceptable: [A], requireExplicit: false }).verified, true);
  });

  it('requires the whole path to agree on the policy, not just the leaf', async () => {
    // The point of the tree. Every signature verifies, the chain reaches the
    // anchor, and the leaf asserts exactly what was asked for — but the CA
    // above it never authorised that policy, so nobody vouched for it.
    const root = await createCa('C=PT, O=Root');
    const intermediate = await issue(root, 'C=PT, OU=Sub', { ca: true, policies: { policies: [A] } });
    const leaf = await issue(intermediate, 'C=PT, CN=Signer', { policies: { policies: [B] } });

    const outcome = validate([leaf, intermediate], root, { acceptable: [B] });
    assertRejected(outcome, 'ISSUER_POLICY_NOT_PERMITTED');
    assert.match(outcome.detail, /no certificate above it authorises/);
  });

  it('lets a CA that asserts anyPolicy stand in for the policy asked for', async () => {
    // 625 of the certificates on the live lists assert anyPolicy.
    const root = await createCa('C=PT, O=Root');
    const intermediate = await issue(root, 'C=PT, OU=Sub', { ca: true, policies: { policies: [ANY] } });
    const leaf = await issue(intermediate, 'C=PT, CN=Signer', { policies: { policies: [B] } });

    assert.equal(validate([leaf, intermediate], root, { acceptable: [B] }).verified, true);
  });

  it('stops accepting anyPolicy once a certificate inhibits it', async () => {
    // RFC 5280 §6.1.4 (j): the wildcard is a convenience the path above may
    // withdraw, and after that the leaf must name the policy itself.
    const root = await createCa('C=PT, O=Root');
    const intermediate = await issue(root, 'C=PT, OU=Sub', {
      ca: true,
      policies: { policies: [A], inhibitAnyPolicy: 0 },
    });
    const named = await issue(intermediate, 'C=PT, CN=Named', { policies: { policies: [A] } });
    const wildcarded = await issue(intermediate, 'C=PT, CN=Wildcarded', { policies: { policies: [ANY] } });

    assert.equal(validate([named, intermediate], root, { acceptable: [A] }).verified, true);
    assertRejected(
      validate([wildcarded, intermediate], root, { acceptable: [A] }),
      'ISSUER_POLICY_NOT_PERMITTED',
    );
  });

  it('honours inhibitAnyPolicy on the trust anchor itself', async () => {
    // RFC 5937 §3.2. The anchor's constraints bind the paths below it, as its
    // Name Constraints do.
    const plain = await createCa('C=PT, O=Root');
    const strict = await createCa('C=PT, O=Root', undefined, { policies: { inhibitAnyPolicy: 0 } });
    const under = async (root: Issued) =>
      issue(root, 'C=PT, CN=Signer', { policies: { policies: [ANY] } });

    assert.equal(validate([await under(plain)], plain, { acceptable: [A] }).verified, true);
    assertRejected(
      validate([await under(strict)], strict, { acceptable: [A] }),
      'ISSUER_POLICY_NOT_PERMITTED',
    );
  });

  it('does not read the anchor\'s own policies as a constraint on the path', async () => {
    // The other half of that position, and the reason the anchor is not fed in
    // as certificate 1: an anchor asserting policies is describing itself, and
    // treating that as the path's policy would end the tree at every anchor
    // that asserts none — which is most of them.
    const root = await createCa('C=PT, O=Root', undefined, { policies: { policies: [A] } });
    const leaf = await issue(root, 'C=PT, CN=Signer', { policies: { policies: [B] } });

    assert.equal(validate([leaf], root, { acceptable: [B] }).verified, true);
  });

  it('enforces a CA that requires an explicit policy, with nothing asked of the caller', async () => {
    // Policy processing is not a no-op for a caller that names no policies:
    // this is the CA's own demand, and eight CA certificates on the live lists
    // make it (REPRODUCE.md).
    const root = await createCa('C=PT, O=Root');
    const intermediate = await issue(root, 'C=PT, OU=Sub', {
      ca: true,
      policies: { policies: [A], requireExplicitPolicy: 0 },
    });
    const silent = await issue(intermediate, 'C=PT, CN=Silent');
    const explicit = await issue(intermediate, 'C=PT, CN=Explicit', { policies: { policies: [A] } });

    const outcome = validate([silent, intermediate], root);
    assertRejected(outcome, 'ISSUER_POLICY_NOT_PERMITTED');
    assert.match(outcome.detail, /requires an explicit policy/);
    assert.equal(validate([explicit, intermediate], root).verified, true);
  });

  it('counts the certificates a requireExplicitPolicy skips', async () => {
    // §6.1.4 (i): the value is how many more certificates may stay silent. On a
    // path of two, 1 reaches the leaf and 2 does not.
    const root = await createCa('C=PT, O=Root');
    const strict = await issue(root, 'C=PT, OU=Strict', {
      ca: true,
      policies: { policies: [A], requireExplicitPolicy: 1 },
    });
    const lenient = await issue(root, 'C=PT, OU=Lenient', {
      ca: true,
      policies: { policies: [A], requireExplicitPolicy: 2 },
    });

    assertRejected(
      validate([await issue(strict, 'C=PT, CN=Silent'), strict], root),
      'ISSUER_POLICY_NOT_PERMITTED',
    );
    assert.equal(validate([await issue(lenient, 'C=PT, CN=Silent'), lenient], root).verified, true);
  });

  it('does not spend a skip count on a self-issued certificate', async () => {
    // §6.1.4 (h): a CA re-keying itself is not a delegation, so it does not
    // consume a step of any counter. Both paths below are two certificates
    // long; only the one whose intermediate is somebody else runs out.
    const root = await createCa('C=PT, O=Root', undefined, {
      policies: { requireExplicitPolicy: 2 },
    });
    const selfIssued = await issue(root, 'C=PT, O=Root', { ca: true });
    const delegated = await issue(root, 'C=PT, O=Somebody Else', { ca: true });

    assert.equal(
      validate([await issue(selfIssued, 'C=PT, CN=Silent'), selfIssued], root).verified,
      true,
    );
    assertRejected(
      validate([await issue(delegated, 'C=PT, CN=Silent'), delegated], root),
      'ISSUER_POLICY_NOT_PERMITTED',
    );
  });

  it('follows a policy mapping, so a CA can rename a policy below it', async () => {
    // What Slovakia publishes: a national policy OID mapped onto an EU one
    // (1.3.158.36061701.0.0.0.1.2.2 -> 0.4.0.1456.1.1). The caller asks for the
    // issuer's policy and the leaf asserts the subject's.
    const root = await createCa('C=PT, O=Root');
    const intermediate = await issue(root, 'C=PT, OU=Sub', {
      ca: true,
      policies: { policies: [A], policyMappings: [[A, B]] },
    });
    const leaf = await issue(intermediate, 'C=PT, CN=Signer', { policies: { policies: [B] } });

    assert.equal(validate([leaf, intermediate], root, { acceptable: [A] }).verified, true);
    // And the mapping is what did it: the leaf's own policy was never asked for.
    assertRejected(
      validate([leaf, intermediate], root, { acceptable: [A], inhibitMapping: true }),
      'ISSUER_POLICY_NOT_PERMITTED',
    );
  });

  it('refuses a mapping to or from anyPolicy', async () => {
    // §6.1.4 (a). Otherwise a CA could launder every policy into every other.
    const root = await createCa('C=PT, O=Root');
    const intermediate = await issue(root, 'C=PT, OU=Sub', {
      ca: true,
      policies: { policies: [A], policyMappings: [[A, ANY]] },
    });
    const leaf = await issue(intermediate, 'C=PT, CN=Signer', { policies: { policies: [B] } });

    const outcome = validate([leaf, intermediate], root, { acceptable: [A] });
    assertRejected(outcome, 'ISSUER_POLICY_NOT_PERMITTED');
    assert.match(outcome.detail, /anyPolicy/);
  });

  it('fails closed on a policy extension it cannot read', async () => {
    // The rule Name Constraints follows: an unreadable statement is not an
    // absent one, and a path validated by ignoring it is not validated.
    const root = await createCa('C=PT, O=Root');
    const leaf = await issue(root, 'C=PT, CN=Signer', {
      policies: { raw: [{ oid: '2.5.29.32', der: new Uint8Array([0x30, 0x7f, 0x02]).buffer }] },
    });

    const outcome = validate([leaf], root, { acceptable: [A] });
    assertRejected(outcome, 'ISSUER_POLICY_NOT_PERMITTED');
    assert.match(outcome.detail, /Cannot read the policy extensions/);
  });
});
