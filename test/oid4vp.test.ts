import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';
import type { Config } from '../src/config.ts';
import { createVerifierServer } from '../src/http/server.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { CREDENTIAL_QUERY_ID } from '../src/oid4vp/query.ts';
import { presentAgeOver18 } from './wallet.ts';

const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const fixtures = JSON.parse(readFileSync(`${dir}credentials.json`, 'utf8'));
const anchors = TrustAnchors.fromPem(readFileSync(`${dir}trust-anchor.pem`, 'utf8'));

let server: Server;
/** Where the test talks to the server. */
let localUrl: string;
/** What the verifier advertises to wallets; OID4VP requires https. */
const PUBLIC_BASE = 'https://verifier.test';
let config: Config;

before(async () => {
  config = {
    port: 0,
    baseUrl: PUBLIC_BASE,
    walletScheme: 'haip-vp://',
    clientIdPrefix: 'redirect_uri',
    clientDnsName: undefined,
    accessCertificateChainPem: undefined,
    accessCertificatePrivateKeyPem: undefined,
    requestedVct: 'urn:eudi:pid:1',
    requestTtlSeconds: 300,
    trust: {
      mode: 'pinned',
      pinnedAnchorsPem: undefined,
      lotlUrl: '',
      serviceTypes: [],
      territories: [],
      lotlSigningAnchorsPem: undefined,
      insecureSkipSignatureCheck: false,
    },
  };

  server = createVerifierServer(config, anchors);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  localUrl = `http://127.0.0.1:${port}`;
});

after(() => void server.close());

async function startSession() {
  const response = await fetch(`${localUrl}/presentations`, { method: 'POST' });
  assert.equal(response.status, 201);
  return (await response.json()) as { id: string; walletUri: string; qrCodeDataUri: string };
}

/** Pull the request parameters back out of the URI we hand to the wallet. */
function requestParams(walletUri: string): URLSearchParams {
  return new URL(walletUri.replace('haip-vp://', 'https://wallet.invalid/')).searchParams;
}

/** Post as the wallet would, to the per-session response URI. */
async function postToWallet(vpToken: unknown, params: URLSearchParams) {
  const responseUri = params.get('response_uri')!.replace(PUBLIC_BASE, localUrl);
  return await fetch(responseUri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ vp_token: JSON.stringify(vpToken), state: params.get('state')! }),
  });
}

async function outcome(id: string) {
  const response = await fetch(`${localUrl}/presentations/${id}`);
  return (await response.json()) as { status: string; result: Record<string, unknown> | null };
}

describe('OID4VP round trip', () => {
  it('builds a request the wallet can act on', async () => {
    const session = await startSession();
    const params = requestParams(session.walletUri);

    assert.equal(params.get('response_type'), 'vp_token');
    assert.equal(params.get('response_mode'), 'direct_post');
    assert.equal(params.get('client_id'), `redirect_uri:${params.get('response_uri')}`);
    assert.ok(params.get('nonce'), 'request must carry a nonce');
    assert.ok(session.qrCodeDataUri.startsWith('data:image/png;base64,'));

    // The DCQL query must ask for the single claim and nothing more.
    const query = JSON.parse(params.get('dcql_query')!);
    assert.equal(query.credentials[0].id, CREDENTIAL_QUERY_ID);
    assert.equal(query.credentials[0].format, 'dc+sd-jwt');
    assert.deepEqual(query.credentials[0].meta.vct_values, ['urn:eudi:pid:1']);
    // Two acceptable answers, ranked. Asking only for age_equal_or_over.18
    // matches nothing from the real EU issuer, which emits no age attribute.
    assert.deepEqual(query.credentials[0].claims, [
      { id: 'age_equal_or_over_18', path: ['age_equal_or_over', '18'] },
      { id: 'birthdate', path: ['birthdate'] },
    ]);
    assert.deepEqual(query.credentials[0].claim_sets, [['age_equal_or_over_18'], ['birthdate']]);
  });

  it('verifies a presentation from a wallet end to end', async () => {
    const session = await startSession();
    const params = requestParams(session.walletUri);

    const presentation = await presentAgeOver18({
      issuedCredential: fixtures.issued.over18,
      holderPrivateJwk: fixtures.holderPrivateJwk,
      nonce: params.get('nonce')!,
      audience: params.get('client_id')!,
    });

    const posted = await postToWallet({ [CREDENTIAL_QUERY_ID]: [presentation] }, params);
    assert.equal(posted.status, 200);

    const { status, result } = await outcome(session.id);
    assert.equal(status, 'verified', JSON.stringify(result));
    assert.equal(result?.['verified'], true);
    assert.equal(result?.['evidence'], 'age_equal_or_over.18');
    assert.equal(result?.['vct'], 'urn:eudi:pid:1');
  });

  it('rejects a presentation bound to a nonce from a different session', async () => {
    const victim = await startSession();
    const other = await startSession();

    // The wallet answers the victim session using the other session's nonce.
    const presentation = await presentAgeOver18({
      issuedCredential: fixtures.issued.over18,
      holderPrivateJwk: fixtures.holderPrivateJwk,
      nonce: requestParams(other.walletUri).get('nonce')!,
      audience: `redirect_uri:${requestParams(victim.walletUri).get('response_uri')}`,
    });

    await postToWallet({ [CREDENTIAL_QUERY_ID]: [presentation] }, requestParams(victim.walletUri));

    const { status, result } = await outcome(victim.id);
    assert.equal(status, 'rejected');
    assert.equal(result?.['reason'], 'KEY_BINDING_NONCE_MISMATCH');
  });

  it('rejects a presentation minted for a different verifier', async () => {
    const session = await startSession();
    const params = requestParams(session.walletUri);

    const presentation = await presentAgeOver18({
      issuedCredential: fixtures.issued.over18,
      holderPrivateJwk: fixtures.holderPrivateJwk,
      nonce: params.get('nonce')!,
      audience: 'redirect_uri:https://attacker.example/oid4vp/response',
    });

    await postToWallet({ [CREDENTIAL_QUERY_ID]: [presentation] }, params);

    const { result } = await outcome(session.id);
    assert.equal(result?.['reason'], 'KEY_BINDING_AUDIENCE_MISMATCH');
  });

  it('refuses a response that quotes no known state', async () => {
    const response = await fetch(`${localUrl}/oid4vp/response/not-a-real-session`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ vp_token: '{}', state: 'x' }),
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).reason, 'SESSION_UNKNOWN');
  });

  it('does not accept the same state twice', async () => {
    const session = await startSession();
    const params = requestParams(session.walletUri);
    const presentation = await presentAgeOver18({
      issuedCredential: fixtures.issued.over18,
      holderPrivateJwk: fixtures.holderPrivateJwk,
      nonce: params.get('nonce')!,
      audience: params.get('client_id')!,
    });

    const first = await postToWallet({ [CREDENTIAL_QUERY_ID]: [presentation] }, params);
    assert.equal(first.status, 200);

    // A nonce is single use. Replaying the same response must not be processed.
    const replay = await postToWallet({ [CREDENTIAL_QUERY_ID]: [presentation] }, params);
    assert.equal(replay.status, 400);
    assert.equal((await replay.json()).reason, 'SESSION_UNKNOWN');
  });

  it('rejects a vp_token with no entry for our credential query', async () => {
    const session = await startSession();
    const params = requestParams(session.walletUri);

    await postToWallet({ some_other_query: ['x'] }, params);

    const { result } = await outcome(session.id);
    assert.equal(result?.['verified'], false);
    assert.equal(result?.['reason'], 'RESPONSE_INVALID');
  });
});
