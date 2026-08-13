import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { VerificationEvent } from '../src/events.ts';
import { verifyAgeOver18Mdoc, verifyDeviceResponse } from '../src/mdoc/device-response.ts';
import { buildSessionTranscript } from '../src/mdoc/session-transcript.ts';
import { verifyMdoc } from '../src/mdoc/verify.ts';
import { verifyPresentationResponse } from '../src/oid4vp/response.ts';
import { PID_MDOC_NAMESPACE } from '../src/presets/eudi-pid.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { resolveIssuerKeyFromX5c } from '../src/trust/issuer-key.ts';
import { verifyAgeOver18SdJwtVc, verifySdJwtVc } from '../src/verify.ts';
import { buildDeviceResponse } from './mdoc-wallet.ts';

const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const fixtures = JSON.parse(readFileSync(`${dir}credentials.json`, 'utf8'));
const anchors = TrustAnchors.fromPem(readFileSync(`${dir}trust-anchor.pem`, 'utf8'));

const NOW = new Date('2026-06-01T00:00:00Z');
const base = {
  credential: fixtures.credentials.over18 as string,
  anchors,
  expectedVct: 'urn:eudi:pid:1',
  keyBinding: { nonce: fixtures.nonce as string, audience: fixtures.audience as string },
  checkStatus: false,
  checkCertificateRevocation: false,
  now: NOW,
};

// The mdoc half of the event contract, against the same real credential
// test/mdoc.test.ts uses — offline, with both revocation paths off.
const real = fileURLToPath(new URL('./fixtures/real/', import.meta.url));
const issuerSigned = readFileSync(`${real}eudiw-pid-mdoc.txt`, 'utf8').trim();
const devicePrivateJwk = JSON.parse(readFileSync(`${real}mdoc-device-private-jwk.json`, 'utf8'));
const mdocAnchors = TrustAnchors.fromPem(
  readFileSync(fileURLToPath(new URL('../anchors/eudiw-pid-issuer-ca.pem', import.meta.url)), 'utf8'),
);

/** Inside the credential's window (issued 2026-08-11, expires 2026-11-09). */
const MDOC_NOW = new Date('2026-09-01T00:00:00Z');
const MDOC_CLIENT_ID = 'redirect_uri:https://verifier.test/oid4vp/response/abc';
const MDOC_RESPONSE_URI = 'https://verifier.test/oid4vp/response/abc';
const MDOC_NONCE = 'n-0S6_WzA2Mj';

const mdocBase = {
  issuerSigned,
  anchors: mdocAnchors,
  expectedDocType: PID_MDOC_NAMESPACE,
  // The reference issuer emits a malformed validUntil; see test/mdoc.test.ts.
  tolerateMalformedValidityDates: true,
  checkStatus: false,
  checkCertificateRevocation: false,
  now: MDOC_NOW,
};

const mdocIdentity = {
  baseUrl: 'https://verifier.test',
  walletScheme: 'eudi-openid4vp://',
  clientIdPrefix: 'redirect_uri' as const,
  clientDnsName: undefined,
  accessCertificateChainPem: undefined,
  accessCertificatePrivateKeyPem: undefined,
  requestedVct: 'urn:eudi:pid:1',
  requestTtlSeconds: 300,
  checkStatus: false,
  checkCertificateRevocation: false,
};

const transcriptFor = (clientId: string) =>
  buildSessionTranscript({ clientId, nonce: MDOC_NONCE, responseUri: MDOC_RESPONSE_URI });

const deviceResponseFor = (clientId: string) =>
  Buffer.from(
    buildDeviceResponse({
      issuerSigned,
      devicePrivateJwk,
      sessionTranscript: transcriptFor(clientId),
      docType: PID_MDOC_NAMESPACE,
    }),
  ).toString('base64url');

describe('reason codes are derived from state, not error text', () => {
  it('reports a structural defect as malformed, not as a bad signature', async () => {
    // An unreferenced disclosure makes the library give up before it checks any
    // signature. "Not verified" is not "verified and wrong", and conflating the
    // two blames the issuer for a holder's tampering.
    const parts = (fixtures.credentials.under18 as string).split('~');
    const disclosure = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString()) as [string, string, boolean];
    const forged = Buffer.from(JSON.stringify([disclosure[0], disclosure[1], true])).toString('base64url');

    const result = await verifySdJwtVc({
      ...base,
      credential: [parts[0], forged, ...parts.slice(2)].join('~'),
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'CREDENTIAL_MALFORMED');
  });

  it('still reports a genuinely bad issuer signature as such', async () => {
    const [jwt, ...rest] = (fixtures.credentials.over18 as string).split('~');
    const [header, payload, signature] = jwt!.split('.');
    const flipped = `${signature!.slice(0, -2)}${signature!.slice(-2) === 'AA' ? 'BB' : 'AA'}`;

    const result = await verifySdJwtVc({
      ...base,
      credential: [`${header}.${payload}.${flipped}`, ...rest].join('~'),
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'ISSUER_SIGNATURE_INVALID');
  });
});

describe('certificate path validation', () => {
  const x5cOf = (credential: string) =>
    JSON.parse(Buffer.from(credential.split('~')[0]!.split('.')[0]!, 'base64url').toString())
      .x5c as string[];

  it('refuses a chain whose issuing certificate is not a CA', () => {
    // Without this, any leaf could sign a certificate for any subject and the
    // chain would still verify.
    const chain = x5cOf(fixtures.credentials.over18);
    const leaf = new X509Certificate(Buffer.from(chain[0]!, 'base64'));
    assert.equal(leaf.ca, false, 'fixture leaf should not be a CA');

    // Present the leaf as though it were the issuing certificate.
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [chain[0], chain[0]] }))
      .toString('base64url');
    const forged = `${header}.e30.AA`;

    const result = resolveIssuerKeyFromX5c(forged, anchors, NOW);
    assert.equal(result.verified, false);
    assert.match((result as { detail: string }).detail, /not a CA/);
  });

  it('rejects an absurdly long chain before doing the cryptography', () => {
    const chain = x5cOf(fixtures.credentials.over18);
    const header = Buffer.from(
      JSON.stringify({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: Array(20).fill(chain[0]) }),
    ).toString('base64url');

    const result = resolveIssuerKeyFromX5c(`${header}.e30.AA`, anchors, NOW, { maxChainLength: 8 });
    assert.equal(result.verified, false);
    assert.match((result as { detail: string }).detail, /chain is 20 long/);
  });

  it('can require an extended key usage on the issuer certificate', async () => {
    const result = await verifySdJwtVc({
      ...base,
      pathValidation: { requiredExtendedKeyUsage: ['1.0.18013.5.1.2'] },
    });

    // The fixture signer carries no EKU, so a policy demanding one rejects it.
    assert.equal(result.verified, false);
    assert.equal(result.reason, 'ISSUER_UNTRUSTED');
  });
});

describe('algorithm policy', () => {
  it('rejects an algorithm outside the allowed set', async () => {
    const result = await verifySdJwtVc({ ...base, allowedAlgs: ['ES384'] });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'UNSUPPORTED_ALGORITHM');
  });

  it('accepts when the credential\'s algorithm is allowed', async () => {
    const result = await verifySdJwtVc({ ...base, allowedAlgs: ['ES256', 'ES384'] });
    assert.equal(result.verified, true, JSON.stringify(result));
  });
});

describe('verification events', () => {
  it('reports the sequence of an accepted verification', async () => {
    const events: VerificationEvent[] = [];
    const result = await verifySdJwtVc({ ...base, onEvent: (e) => events.push(e) });

    assert.equal(result.verified, true);
    assert.deepEqual(
      events.map((e) => e.type),
      ['verification.started', 'issuer.resolved', 'verification.accepted'],
    );
  });

  it('reports a rejection with its reason', async () => {
    const events: VerificationEvent[] = [];
    await verifySdJwtVc({ ...base, expectedVct: 'urn:eudi:other:1', onEvent: (e) => events.push(e) });

    const rejected = events.find((e) => e.type === 'verification.rejected');
    assert.ok(rejected, 'a rejection must be observable');
    assert.equal((rejected as { reason: string }).reason, 'UNEXPECTED_CREDENTIAL_TYPE');
  });

  it('reports whether the status answer came from cache, not whether one exists', async () => {
    // The bug this replaces: `cached` was `statusCache !== undefined`, so it
    // said "cached" for a cold fetch and was constant for a given deployment —
    // no information at all. A live run against the reference issuer reported
    // `cached: true` on the first lookup after a deploy (REPRODUCE.md §7).
    const { createStatusListCache } = await import('../src/trust/status.ts');
    const cache = createStatusListCache();
    const serving: typeof fetch = (async () =>
      new Response(fixtures.statusLists.valid as string, {
        status: 200,
        headers: { 'content-type': 'application/statuslist+jwt' },
      })) as typeof fetch;

    const withStatus = {
      ...base,
      credential: fixtures.credentials.withStatus as string,
      checkStatus: true,
      statusFetch: serving,
      statusCache: cache,
    };

    const first: VerificationEvent[] = [];
    await verifySdJwtVc({ ...withStatus, onEvent: (e) => first.push(e) });
    const second: VerificationEvent[] = [];
    await verifySdJwtVc({ ...withStatus, onEvent: (e) => second.push(e) });

    const cachedFlag = (events: VerificationEvent[]) =>
      (events.find((e) => e.type === 'status.checked') as { cached: boolean } | undefined)?.cached;

    assert.equal(cachedFlag(first), false, 'the first lookup fetched, so it was not cached');
    assert.equal(cachedFlag(second), true, 'the second was served from the cache');
  });

  it('reports no cache hit when no cache is configured at all', async () => {
    const serving: typeof fetch = (async () =>
      new Response(fixtures.statusLists.valid as string, {
        status: 200,
        headers: { 'content-type': 'application/statuslist+jwt' },
      })) as typeof fetch;

    const events: VerificationEvent[] = [];
    await verifySdJwtVc({
      ...base,
      credential: fixtures.credentials.withStatus as string,
      checkStatus: true,
      statusFetch: serving,
      onEvent: (e) => events.push(e),
    });

    const checked = events.find((e) => e.type === 'status.checked') as { cached: boolean };
    assert.equal(checked.cached, false);
  });

  it('carries no personal data', async () => {
    // An audit trail that accumulates dates of birth is worse than none.
    const events: VerificationEvent[] = [];
    await verifySdJwtVc({ ...base, onEvent: (e) => events.push(e) });

    const serialised = JSON.stringify(events);
    for (const secret of ['Mustermann', 'Erika', '1990-06-12', 'age_equal_or_over']) {
      assert.ok(!serialised.includes(secret), `event stream leaked ${secret}`);
    }
  });
});

describe('the audit trail does not depend on the credential format', () => {
  // The format a wallet happens to answer in decides nothing about whether a
  // verification is auditable, on the same reasoning that keeps it from
  // deciding whether the credential's status is checked. Before this, an mdoc
  // presentation emitted nothing at all.

  const record = () => {
    const events: VerificationEvent[] = [];
    return { events, onEvent: (e: VerificationEvent) => events.push(e) };
  };
  const types = (events: VerificationEvent[]) => events.map((e) => e.type);

  it('emits the same sequence for mdoc as for SD-JWT VC', async () => {
    const sd = record();
    await verifySdJwtVc({ ...base, onEvent: sd.onEvent });

    const md = record();
    const result = await verifyMdoc({ ...mdocBase, onEvent: md.onEvent });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.deepEqual(types(md.events), ['verification.started', 'issuer.resolved', 'verification.accepted']);
    assert.deepEqual(types(md.events), types(sd.events));
  });

  it('names the format, so a mixed stream stays readable', async () => {
    const sd = record();
    await verifySdJwtVc({ ...base, onEvent: sd.onEvent });
    const md = record();
    await verifyMdoc({ ...mdocBase, onEvent: md.onEvent });

    assert.deepEqual(
      sd.events.map((e) => ('format' in e ? e.format : null)),
      ['dc+sd-jwt', 'dc+sd-jwt', 'dc+sd-jwt'],
    );
    assert.deepEqual(
      md.events.map((e) => ('format' in e ? e.format : null)),
      ['mso_mdoc', 'mso_mdoc', 'mso_mdoc'],
    );
  });

  it('reports an mdoc rejection with its reason', async () => {
    const { events, onEvent } = record();
    await verifyMdoc({ ...mdocBase, expectedDocType: 'org.iso.18013.5.1.mDL', onEvent });

    const rejected = events.find((e) => e.type === 'verification.rejected');
    assert.ok(rejected, 'a rejection must be observable');
    assert.equal((rejected as { reason: string }).reason, 'UNEXPECTED_CREDENTIAL_TYPE');
    assert.equal((rejected as { format: string }).format, 'mso_mdoc');
  });

  it('carries no personal data on the mdoc path either', async () => {
    const { events, onEvent } = record();
    await verifyMdoc({ ...mdocBase, onEvent });

    const serialised = JSON.stringify(events);
    for (const secret of ['Tester', 'Porto', '1990-06-12', 'portrait']) {
      assert.ok(!serialised.includes(secret), `event stream leaked ${secret}`);
    }
  });
});

describe('exactly one verdict, and the outermost verifier owns it', () => {
  // A credential can verify perfectly and still be rejected afterwards — by the
  // age predicate, or by mdoc device authentication. Recording
  // verification.accepted for a presentation the caller was told to reject
  // would make the audit trail wrong about the one thing it exists to record.

  const record = () => {
    const events: VerificationEvent[] = [];
    return { events, onEvent: (e: VerificationEvent) => events.push(e) };
  };
  const verdicts = (events: VerificationEvent[]) =>
    events.filter((e) => e.type === 'verification.accepted' || e.type === 'verification.rejected');

  it('records a rejection, not an acceptance, when the predicate fails', async () => {
    const { events, onEvent } = record();
    const result = await verifyAgeOver18SdJwtVc({
      ...base,
      credential: fixtures.credentials.under18 as string,
      onEvent,
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'PREDICATE_NOT_SATISFIED');
    // The credential itself verified, so issuer resolution is still on the
    // stream — it is only the verdict that belongs to the outer call.
    assert.ok(events.some((e) => e.type === 'issuer.resolved'));
    assert.deepEqual(verdicts(events).map((e) => e.type), ['verification.rejected']);
  });

  it('records a rejection when mdoc device authentication fails', async () => {
    // The issuer's credential verifies; the device signature was made for a
    // different verifier, which verifyMdoc has no way of knowing.
    const { events, onEvent } = record();
    const result = await verifyDeviceResponse({
      deviceResponse: deviceResponseFor('redirect_uri:https://attacker.test/collect'),
      anchors: mdocAnchors,
      sessionTranscript: transcriptFor(MDOC_CLIENT_ID),
      tolerateMalformedValidityDates: true,
      checkStatus: false,
      checkCertificateRevocation: false,
      now: MDOC_NOW,
      onEvent,
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'KEY_BINDING_INVALID');
    assert.ok(events.some((e) => e.type === 'issuer.resolved'));
    assert.deepEqual(verdicts(events).map((e) => e.type), ['verification.rejected']);
  });

  it('gives the mdoc counterpart the same verdict discipline', async () => {
    // verifyAgeOver18Mdoc is the mirror of verifyAgeOver18SdJwtVc, and the
    // reason it exists is that response.ts used to hand-compose it — carrying
    // its own copy of the rule this test is about.
    const { events, onEvent } = record();
    const result = await verifyAgeOver18Mdoc({
      deviceResponse: deviceResponseFor(MDOC_CLIENT_ID),
      anchors: mdocAnchors,
      sessionTranscript: transcriptFor(MDOC_CLIENT_ID),
      expectedDocType: PID_MDOC_NAMESPACE,
      tolerateMalformedValidityDates: true,
      checkStatus: false,
      checkCertificateRevocation: false,
      now: MDOC_NOW,
      onEvent,
    });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.ageOver18, true);
    // The reference PID carries no age attribute, so this is the birth_date route.
    assert.equal(result.value.evidence, 'birthdate');
    const accepted = events.find((e) => e.type === 'verification.accepted');
    assert.equal((accepted as { evidence?: string }).evidence, 'birthdate');
    assert.deepEqual(verdicts(events).map((e) => e.type), ['verification.accepted']);
  });

  it('defaults the age namespace to the doc type, which is right for the PID', async () => {
    // Deliberately no `namespace`. The EUDI PID's namespace and doc type are
    // both eu.europa.ec.eudi.pid.1; an mDL's are not, which is why the option
    // exists at all.
    const result = await verifyAgeOver18Mdoc({
      deviceResponse: deviceResponseFor(MDOC_CLIENT_ID),
      anchors: mdocAnchors,
      sessionTranscript: transcriptFor(MDOC_CLIENT_ID),
      tolerateMalformedValidityDates: true,
      checkStatus: false,
      checkCertificateRevocation: false,
      now: MDOC_NOW,
    });

    assert.equal(result.verified, true, JSON.stringify(result));
  });

  it('reports a predicate it cannot evaluate rather than an acceptance', async () => {
    // A namespace with no elements in it: the device response is perfectly
    // good and the predicate has nothing to read, which must not be recorded
    // as an acceptance.
    const { events, onEvent } = record();
    const result = await verifyAgeOver18Mdoc({
      deviceResponse: deviceResponseFor(MDOC_CLIENT_ID),
      anchors: mdocAnchors,
      sessionTranscript: transcriptFor(MDOC_CLIENT_ID),
      namespace: 'org.iso.18013.5.1',
      tolerateMalformedValidityDates: true,
      checkStatus: false,
      checkCertificateRevocation: false,
      now: MDOC_NOW,
      onEvent,
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'PREDICATE_CLAIM_MISSING');
    assert.deepEqual(verdicts(events).map((e) => e.type), ['verification.rejected']);
  });

  it('puts the predicate evidence on the acceptance', async () => {
    // Which of the two ways the predicate was satisfied is the privacy
    // question: the boolean discloses nothing else, the birthdate discloses a
    // date of birth. A relying party auditing what it learned needs to see it.
    const { events, onEvent } = record();
    const result = await verifyAgeOver18SdJwtVc({ ...base, onEvent });

    assert.equal(result.verified, true);
    const accepted = events.find((e) => e.type === 'verification.accepted');
    assert.equal((accepted as { evidence?: string }).evidence, 'age_equal_or_over.18');
    assert.deepEqual(verdicts(events).map((e) => e.type), ['verification.accepted']);
  });

  it('emits an envelope rejection with no format at all', async () => {
    // The wallet declined, so no credential was ever seen. Claiming a format
    // here would be inventing one.
    const { events, onEvent } = record();
    const result = await verifyPresentationResponse(
      {
        config: mdocIdentity,
        anchors: mdocAnchors,
        nonce: MDOC_NONCE,
        requestPayload: { client_id: MDOC_CLIENT_ID, response_uri: MDOC_RESPONSE_URI },
        decryptionJwk: undefined,
        onEvent,
      },
      { error: 'access_denied', error_description: 'user refused' },
    );

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'WALLET_ERROR');
    assert.deepEqual(verdicts(events).map((e) => e.type), ['verification.rejected']);
    assert.equal((verdicts(events)[0] as { format: undefined }).format, undefined);
  });
});
