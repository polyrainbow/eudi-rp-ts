import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { verifyMdoc } from '../src/mdoc/verify.ts';
import { evaluateAgeOver18SdJwt } from '../src/predicate/age.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { ageOver18Query } from '../src/presets/age-over-18.ts';
import { verifyAgeOver18SdJwtVc, verifySdJwtVc } from '../src/verify.ts';

/**
 * Verification of a genuine credential from the EU reference issuer.
 *
 * Every other test signs its fixtures with a CA the fixture script invents,
 * which can only show that our verifier agrees with our own issuer. This one
 * shows it agrees with the EUDI ecosystem. See test/fixtures/real/README.md.
 */
const dir = fileURLToPath(new URL('./fixtures/real/', import.meta.url));
const anchorDir = fileURLToPath(new URL('../anchors/', import.meta.url));
const credential = readFileSync(`${dir}eudiw-pid-sd-jwt-vc.txt`, 'utf8').trim();
const anchors = TrustAnchors.fromPem(readFileSync(`${anchorDir}eudiw-pid-issuer-ca.pem`, 'utf8'));

/** Inside the credential's validity window (issued 2026-08-09, expires 2026-11-08). */
const NOW = new Date('2026-09-01T00:00:00Z');

/** It was issued, never presented, so it carries no Key Binding JWT. */
/**
 * `checkStatus: false` and `checkCertificateRevocation: false` keep these
 * offline: the credential names a live status list, and its issuer's chain a
 * live CRL. Both are exercised separately, network-gated, at the bottom.
 */
const options = {
  credential,
  anchors,
  expectedVct: 'urn:eudi:pid:1',
  requireKeyBinding: false,
  checkStatus: false,
  checkCertificateRevocation: false,
  now: NOW,
};

describe('real EUDI reference credential', () => {
  it('verifies against the real PID Issuer CA', async () => {
    const result = await verifySdJwtVc(options);

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.credentialType, 'urn:eudi:pid:1');
    assert.match(result.value.issuerCertificateSubject, /CN=PID DS - 002/);
  });

  it('is rejected against an unrelated anchor set', async () => {
    const ours = TrustAnchors.fromPem(
      readFileSync(fileURLToPath(new URL('./fixtures/trust-anchor.pem', import.meta.url)), 'utf8'),
    );
    const result = await verifySdJwtVc({ ...options, anchors: ours });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'ISSUER_UNTRUSTED');
  });

  it('proves age over 18 from birthdate, because the issuer emits no age claim', async () => {
    const result = await verifyAgeOver18SdJwtVc(options);

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.ageOver18, true);
    // PID Rulebook v1.1 removed the age attributes (CIR 2024/2977), and the
    // live issuer reflects that. birthdate is the real path, not a fallback.
    assert.equal(result.value.evidence, 'birthdate');
    assert.ok(!('age_equal_or_over' in result.value.claims));
  });

  it('carries a token status list', async () => {
    const result = await verifySdJwtVc(options);
    assert.equal(result.verified, true);

    const status = result.value.claims['status'] as
      | { status_list?: { uri?: string; idx?: number } }
      | undefined;
    assert.ok(status?.status_list?.uri, 'reference credentials carry a token status list');
    assert.equal(typeof status.status_list.idx, 'number');
  });

  it('would reject the holder as under 18 if the birth date said so', () => {
    // Same credential, evaluated as though "now" were shortly after the birth
    // date — guards against the predicate passing on presence rather than value.
    const claims = { birthdate: '1990-06-12' };
    assert.equal(evaluateAgeOver18SdJwt(claims, new Date('2005-01-01T00:00:00Z')).verified, false);
    assert.equal(evaluateAgeOver18SdJwt(claims, new Date('2008-06-12T00:00:00Z')).verified, true);
  });
});

/**
 * The real credential can only satisfy the second `claim_sets` option, since
 * the reference issuer emits no age attribute. This is the case that a
 * single-path DCQL query could not have matched at all.
 */
const expiresAt = new Date(
  JSON.parse(Buffer.from(credential.split('~')[0]!.split('.')[1]!, 'base64url').toString()).exp * 1000,
);
const expired = Date.now() > expiresAt.getTime();

describe('real credential over OID4VP', { skip: expired ? `credential expired ${expiresAt.toISOString().slice(0, 10)}` : false }, () => {
  it('is accepted end to end, disclosing only birthdate', async () => {
    const { createVerifierServer } = await import('../app/http/server.ts');
    const { presentAgeOver18 } = await import('./wallet.ts');
    const holderPrivateJwk = JSON.parse(readFileSync(`${dir}holder-private-jwk.json`, 'utf8'));

    const config = {
      port: 0,
      baseUrl: 'https://verifier.test',
      walletScheme: 'eudi-openid4vp://',
      clientIdPrefix: 'redirect_uri' as const,
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
        mode: 'pinned' as const,
        pinnedAnchorsPem: undefined,
        lotlUrl: '',
        serviceTypes: [],
        territories: [],
        lotlSigningAnchorsPem: undefined,
        insecureSkipSignatureCheck: false,
      },
    };

    const server = createVerifierServer(config, anchors);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as import('node:net').AddressInfo).port;
    const local = `http://127.0.0.1:${port}`;

    try {
      const created = (await (await fetch(`${local}/presentations`, { method: 'POST' })).json()) as {
        id: string;
        walletUri: string;
      };
      const params = new URL(
        created.walletUri.replace('eudi-openid4vp://', 'https://w.invalid/'),
      ).searchParams;

      // A wallet holding this credential can only offer birthdate.
      const presentation = await presentAgeOver18({
        issuedCredential: credential,
        holderPrivateJwk,
        nonce: params.get('nonce')!,
        audience: params.get('client_id')!,
        presentationFrame: { birthdate: true },
      });
      // NOTE: the server checks the status list, so this leg does reach the
      // issuer's status endpoint. Skipped when offline.

      const posted = await fetch(params.get('response_uri')!.replace('https://verifier.test', local), {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          vp_token: JSON.stringify({ age_over_18: [presentation] }),
          state: params.get('state')!,
        }),
      });
      assert.equal(posted.status, 200);

      const outcome = (await (await fetch(`${local}/presentations/${created.id}`)).json()) as {
        status: string;
        result: Record<string, unknown>;
      };
      assert.equal(outcome.status, 'verified', JSON.stringify(outcome));
      assert.equal(outcome.result['evidence'], 'birthdate');
      assert.deepEqual(
        (outcome.result['credentials'] as { credentialType: string }[]).map((c) => c.credentialType),
        ['urn:eudi:pid:1'],
      );
    } finally {
      server.close();
    }
  });
});


describe('real status list (network)', { skip: process.env['RUN_NETWORK_TESTS'] === '1' ? false : 'set RUN_NETWORK_TESTS=1' }, () => {
  it('fetches and verifies the issuer\'s live status list', async () => {
    // Exercises the whole path against real infrastructure: fetch with the
    // statuslist+jwt content type, verify the list's own signature against the
    // same PID Issuer CA, and read the bit for this credential.
    const result = await verifySdJwtVc({
      credential,
      anchors,
      expectedVct: 'urn:eudi:pid:1',
      requireKeyBinding: false,
      checkStatus: true,
      checkCertificateRevocation: true,
      now: new Date(),
    });

    // Either it is still valid, or the issuer has revoked it since — both
    // prove the list was fetched, authenticated and read.
    if (!result.verified) {
      assert.equal(result.reason, 'CREDENTIAL_REVOKED', result.detail);
    }
  });

  it('fetches and verifies the issuer chain\'s live CRL', async () => {
    // Both the PID document signer and its CA publish a CRL, and neither runs
    // an OCSP responder — so this is the only revocation mechanism the real EU
    // infrastructure offers, and the only one this can exercise for real.
    const result = await verifySdJwtVc({
      credential,
      anchors,
      expectedVct: 'urn:eudi:pid:1',
      requireKeyBinding: false,
      checkStatus: false,
      checkCertificateRevocation: true,
      now: new Date(),
    });

    // Either the chain is still good, or the CA has revoked it since — both
    // prove the CRL was fetched, its signature checked against the CA, its
    // freshness bounded by nextUpdate, and the serial looked up.
    if (!result.verified) {
      assert.equal(result.reason, 'ISSUER_CERTIFICATE_REVOKED', result.detail);
    }
  });

  it('fetches and verifies the live status list for the mdoc too', async () => {
    // The reference issuer publishes a status list for its mdoc PIDs as well,
    // at a different URI, and the MSO carries the reference. Offline fixtures
    // prove the logic; this proves the real endpoint answers and the real list
    // authenticates against the real PID Issuer CA.
    const result = await verifyMdoc({
      issuerSigned: readFileSync(`${dir}eudiw-pid-mdoc.txt`, 'utf8').trim(),
      anchors,
      expectedDocType: 'eu.europa.ec.eudi.pid.1',
      tolerateMalformedValidityDates: true,
      checkStatus: true,
      checkCertificateRevocation: true,
      now: new Date(),
    });

    if (!result.verified) {
      assert.equal(result.reason, 'CREDENTIAL_REVOKED', result.detail);
    }
  });
});
