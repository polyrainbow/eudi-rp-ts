import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildSessionTranscript } from '../src/mdoc/session-transcript.ts';
import {
  CREDENTIAL_QUERY_ID,
  MDOC_CREDENTIAL_QUERY_ID,
  PID_MDOC_NAMESPACE,
  ageOver18Query,
} from '../src/oid4vp/query.ts';
import { verifyPresentationResponse } from '../src/oid4vp/response.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { buildDeviceResponse } from './mdoc-wallet.ts';

const real = fileURLToPath(new URL('./fixtures/real/', import.meta.url));
const anchorDir = fileURLToPath(new URL('../anchors/', import.meta.url));
const issuerSigned = readFileSync(`${real}eudiw-pid-mdoc.txt`, 'utf8').trim();
const devicePrivateJwk = JSON.parse(readFileSync(`${real}mdoc-device-private-jwk.json`, 'utf8'));
const anchors = TrustAnchors.fromPem(readFileSync(`${anchorDir}eudiw-pid-issuer-ca.pem`, 'utf8'));

const CLIENT_ID = 'redirect_uri:https://verifier.test/oid4vp/response/abc';
const RESPONSE_URI = 'https://verifier.test/oid4vp/response/abc';
const NONCE = 'n-0S6_WzA2Mj';

const identity = {
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

const requestPayload = {
  response_type: 'vp_token',
  client_id: CLIENT_ID,
  response_uri: RESPONSE_URI,
  response_mode: 'direct_post',
  nonce: NONCE,
  state: 'st',
  dcql_query: ageOver18Query('urn:eudi:pid:1'),
};

const context = {
  config: identity,
  anchors,
  nonce: NONCE,
  requestPayload,
  decryptionJwk: undefined,
  // The reference credential's validUntil is malformed; strict handling of
  // that is covered in mdoc.test.ts.
  tolerateMalformedMdocValidity: true,
};

const present = (overrides = {}) =>
  Buffer.from(
    buildDeviceResponse({
      issuerSigned,
      devicePrivateJwk,
      sessionTranscript: buildSessionTranscript({
        clientId: CLIENT_ID,
        nonce: NONCE,
        responseUri: RESPONSE_URI,
      }),
      docType: PID_MDOC_NAMESPACE,
      ...overrides,
    }),
  ).toString('base64url');

describe('the DCQL query offers both formats', () => {
  it('asks for either credential, not both', () => {
    const query = ageOver18Query('urn:eudi:pid:1');

    assert.deepEqual(query.credentials.map((c) => c.format), ['dc+sd-jwt', 'mso_mdoc']);
    // Without credential_sets the wallet is asked for *all* listed credentials
    // (OID4VP 1.0 §6.4.2), which no holder has — so it returns nothing.
    assert.deepEqual(query.credential_sets, [
      { options: [[CREDENTIAL_QUERY_ID], [MDOC_CREDENTIAL_QUERY_ID]] },
    ]);
  });

  it('uses the mdoc spelling for the mdoc alternative', () => {
    const mdoc = ageOver18Query('urn:eudi:pid:1').credentials[1]!;

    assert.equal(mdoc.meta.doctype_value, PID_MDOC_NAMESPACE);
    assert.deepEqual(
      mdoc.claims.map((c) => c.path),
      [
        [PID_MDOC_NAMESPACE, 'age_over_18'],
        [PID_MDOC_NAMESPACE, 'birth_date'],
      ],
    );
  });
});

describe('mdoc through the OID4VP response handler', () => {
  it('rejects a response replayed from another verifier', async () => {
    // The handler rebuilds the transcript from the request it sent, so a
    // device signature made for a different client id cannot verify here.
    const elsewhere = buildSessionTranscript({
      clientId: 'redirect_uri:https://attacker.test/collect',
      nonce: NONCE,
      responseUri: 'https://attacker.test/collect',
    });

    const result = await verifyPresentationResponse(context as never, {
      vp_token: { [MDOC_CREDENTIAL_QUERY_ID]: [present({ signOverTranscript: elsewhere })] },
      state: 'st',
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'KEY_BINDING_INVALID');
  });

  it('satisfies the predicate from a genuine reference credential', async () => {
    // The whole chain against a real credential: envelope, issuer signature,
    // element digests, device signature over the SessionTranscript, and the
    // age predicate resolved from birth_date — the mdoc PID carries no
    // age_over_18, so this is the only route.
    const result = await verifyPresentationResponse(context as never, {
      vp_token: { [MDOC_CREDENTIAL_QUERY_ID]: [present()] },
      state: 'st',
    });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.evidence, 'birthdate');
  });

  it('refuses a response answering both credential queries', async () => {
    const result = await verifyPresentationResponse(context as never, {
      vp_token: {
        [CREDENTIAL_QUERY_ID]: ['not-a-real-sd-jwt'],
        [MDOC_CREDENTIAL_QUERY_ID]: [present()],
      },
      state: 'st',
    });

    assert.equal(result.verified, false);
    assert.match(result.detail, /both credential queries/);
  });

  it('rejects the reference credential when strict about validity', async () => {
    const strict = { ...context, tolerateMalformedMdocValidity: false };
    const result = await verifyPresentationResponse(strict as never, {
      vp_token: { [MDOC_CREDENTIAL_QUERY_ID]: [present()] },
      state: 'st',
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'CREDENTIAL_MALFORMED');
    assert.match(result.detail, /validUntil/);
  });

  it('refuses a response answering neither', async () => {
    const result = await verifyPresentationResponse(context as never, {
      vp_token: { something_else: ['x'] },
      state: 'st',
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'RESPONSE_INVALID');
  });
});
