/**
 * Certificate policy processing against OpenSSL.
 *
 * RFC 5280 §6.1 policy processing is a state machine — a tree and three
 * counters — and `test/certificate-policies.test.ts` proves it does what this
 * project believes the RFC says. That is worth less than it looks: the tests
 * and the implementation were written by the same hand, so on their own they
 * prove the two agree rather than that either is right. Nothing in the EUDI
 * deployment exercises the interesting cases either, since no certificate on
 * the live trusted lists inhibits mapping or anyPolicy (REPRODUCE.md).
 *
 * So the same chains are put to an implementation nobody here wrote.
 * `openssl verify` implements §6.1 in full and exposes each initial input as a
 * flag: `-policy` (user-initial-policy-set), `-explicit_policy`,
 * `-inhibit_map`, `-inhibit_any`. Every case below is generated, validated both
 * ways, and compared on the verdict alone — the two disagreeing is the finding.
 *
 * Run: `node scripts/check-policy-tree.ts` (needs `openssl` on PATH).
 *
 * The certificates come from `test/constrained-certs.ts`, which is where this
 * project builds test PKI material; nothing here ships.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { resolveIssuerCertificateChain } from '../src/trust/issuer-key.ts';
import type { CertificatePolicyOptions } from '../src/trust/policy-tree.ts';
import { createCa, issue, type Issued } from '../test/constrained-certs.ts';

/** Private arcs: nothing here can collide with a real eIDAS policy. */
const A = '1.3.6.1.4.1.99999.1';
const B = '1.3.6.1.4.1.99999.2';
const ANY_POLICY = '2.5.29.32.0';

type Case = {
  name: string;
  anchor: Issued;
  /** Leaf first, anchor excluded — the shape x5c arrives in. */
  chain: Issued[];
  options: CertificatePolicyOptions;
  /** The same inputs, spelled the way `openssl verify` spells them. */
  openssl: string[];
};

async function cases(): Promise<Case[]> {
  const built: Case[] = [];
  const unlimited = { pathLength: null } as const;

  const direct = await createCa('C=PT, O=Direct', undefined, unlimited);
  const directLeaf = await issue(direct, 'C=PT, CN=Signer', { policies: { policies: [A] } });
  built.push({
    name: 'the leaf asserts the accepted policy',
    anchor: direct,
    chain: [directLeaf],
    options: { acceptable: [A] },
    openssl: ['-policy_check', '-explicit_policy', '-policy', A],
  });
  built.push({
    name: 'the leaf asserts a policy that was not accepted',
    anchor: direct,
    chain: [directLeaf],
    options: { acceptable: [B] },
    openssl: ['-policy_check', '-explicit_policy', '-policy', B],
  });

  const disagreeing = await createCa('C=PT, O=Disagreeing', undefined, unlimited);
  const authorisesA = await issue(disagreeing, 'C=PT, OU=Sub', {
    ca: true,
    policies: { policies: [A] },
  });
  built.push({
    name: 'no CA above the leaf authorised its policy',
    anchor: disagreeing,
    chain: [await issue(authorisesA, 'C=PT, CN=Signer', { policies: { policies: [B] } }), authorisesA],
    options: { acceptable: [B] },
    openssl: ['-policy_check', '-explicit_policy', '-policy', B],
  });

  const wildcarding = await createCa('C=PT, O=Wildcarding', undefined, unlimited);
  const anyPolicyCa = await issue(wildcarding, 'C=PT, OU=Sub', {
    ca: true,
    policies: { policies: [ANY_POLICY] },
  });
  const underWildcard = [
    await issue(anyPolicyCa, 'C=PT, CN=Signer', { policies: { policies: [B] } }),
    anyPolicyCa,
  ];
  built.push({
    name: 'a CA asserts anyPolicy',
    anchor: wildcarding,
    chain: underWildcard,
    options: { acceptable: [B] },
    openssl: ['-policy_check', '-explicit_policy', '-policy', B],
  });
  built.push({
    name: 'a CA asserts anyPolicy, and the caller inhibits it',
    anchor: wildcarding,
    chain: underWildcard,
    options: { acceptable: [B], inhibitAnyPolicy: true },
    openssl: ['-policy_check', '-explicit_policy', '-inhibit_any', '-policy', B],
  });

  const inhibiting = await createCa('C=PT, O=Inhibiting', undefined, unlimited);
  const inhibitsAnyPolicy = await issue(inhibiting, 'C=PT, OU=Sub', {
    ca: true,
    policies: { policies: [A], inhibitAnyPolicy: 0 },
  });
  built.push({
    name: 'the leaf wildcards after a CA withdrew anyPolicy',
    anchor: inhibiting,
    chain: [
      await issue(inhibitsAnyPolicy, 'C=PT, CN=Signer', { policies: { policies: [ANY_POLICY] } }),
      inhibitsAnyPolicy,
    ],
    options: { acceptable: [A] },
    openssl: ['-policy_check', '-explicit_policy', '-policy', A],
  });

  const mapping = await createCa('C=PT, O=Mapping', undefined, unlimited);
  const mapsAToB = await issue(mapping, 'C=PT, OU=Sub', {
    ca: true,
    policies: { policies: [A], policyMappings: [[A, B]] },
  });
  const underMapping = [
    await issue(mapsAToB, 'C=PT, CN=Signer', { policies: { policies: [B] } }),
    mapsAToB,
  ];
  built.push({
    name: 'a CA maps the accepted policy onto its own',
    anchor: mapping,
    chain: underMapping,
    options: { acceptable: [A] },
    openssl: ['-policy_check', '-explicit_policy', '-policy', A],
  });
  built.push({
    name: 'the same mapping, inhibited by the caller',
    anchor: mapping,
    chain: underMapping,
    options: { acceptable: [A], inhibitMapping: true },
    openssl: ['-policy_check', '-explicit_policy', '-inhibit_map', '-policy', A],
  });

  const demanding = await createCa('C=PT, O=Demanding', undefined, unlimited);
  const requiresExplicit = await issue(demanding, 'C=PT, OU=Sub', {
    ca: true,
    policies: { policies: [A], requireExplicitPolicy: 0 },
  });
  built.push({
    // No caller policy at all: this is the CA's own demand, and the case that
    // shows policy processing is not a no-op for a caller that names nothing.
    name: 'a CA requires an explicit policy and the leaf is silent',
    anchor: demanding,
    chain: [await issue(requiresExplicit, 'C=PT, CN=Silent'), requiresExplicit],
    options: {},
    openssl: ['-policy_check'],
  });

  const shallow = await createCa('C=PT, O=Shallow', undefined, { pathLength: 0 });
  const subCa = await issue(shallow, 'C=PT, OU=Sub', { ca: true });
  built.push({
    // Not policy processing, but the other half of §6.1.4 that Node cannot see.
    name: 'a sub-CA under an anchor whose pathLenConstraint is zero',
    anchor: shallow,
    chain: [await issue(subCa, 'C=PT, CN=Signer'), subCa],
    options: {},
    openssl: [],
  });

  return built;
}

const directory = mkdtempSync(join(tmpdir(), 'policy-tree-'));
let disagreements = 0;

try {
  for (const [index, testCase] of (await cases()).entries()) {
    const ours = resolveIssuerCertificateChain(
      testCase.chain.map((issued) => issued.cert),
      TrustAnchors.fromCertificates([testCase.anchor.cert]),
      new Date(),
      { certificatePolicies: testCase.options },
    );

    const anchorFile = join(directory, `anchor${index}.pem`);
    const leafFile = join(directory, `leaf${index}.pem`);
    const untrustedFile = join(directory, `untrusted${index}.pem`);
    writeFileSync(anchorFile, testCase.anchor.cert.toString());
    writeFileSync(leafFile, testCase.chain[0]!.cert.toString());
    writeFileSync(untrustedFile, testCase.chain.slice(1).map((i) => i.cert.toString()).join(''));

    let openssl: boolean;
    try {
      execFileSync(
        'openssl',
        [
          'verify',
          '-CAfile',
          anchorFile,
          ...(testCase.chain.length > 1 ? ['-untrusted', untrustedFile] : []),
          ...testCase.openssl,
          leafFile,
        ],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );
      openssl = true;
    } catch {
      openssl = false;
    }

    const agree = openssl === ours.verified;
    if (!agree) disagreements += 1;
    const verdict = (accepted: boolean) => (accepted ? 'accept' : 'reject');
    console.log(
      `  ${agree ? 'ok  ' : 'DIFF'}  ours=${verdict(ours.verified)}  openssl=${verdict(openssl)}  ${testCase.name}`,
    );
    if (!ours.verified) console.log(`          ${ours.reason}: ${ours.detail.replace(/\n/g, ' ')}`);
  }
} finally {
  rmSync(directory, { recursive: true, force: true });
}

console.log(
  disagreements === 0
    ? '\nEvery case agrees with OpenSSL.'
    : `\n${disagreements} case(s) disagree with OpenSSL.`,
);
process.exitCode = disagreements === 0 ? 0 : 1;
