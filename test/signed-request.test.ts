import assert from 'node:assert/strict';
import { X509Certificate, verify as nodeVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { Config } from '../app/config.ts';
import { createVerifierServer } from '../app/http/server.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { createAccessCertificate } from '../scripts/make-access-cert.ts';
import { CREDENTIAL_QUERY_ID } from '../src/oid4vp/query.ts';
import { encryptResponse, presentAgeOver18 } from './wallet.ts';

const DNS_NAME = 'verifier.test';
const fixtures = JSON.parse(
  readFileSync(fileURLToPath(new URL('./fixtures/credentials.json', import.meta.url)), 'utf8'),
);
const anchors = TrustAnchors.fromPem(
  readFileSync(fileURLToPath(new URL('./fixtures/trust-anchor.pem', import.meta.url)), 'utf8'),
);

let server: Server;
let localUrl: string;

before(async () => {
  const cert = await createAccessCertificate(DNS_NAME);

  const config: Config = {
    port: 0,
    baseUrl: `https://${DNS_NAME}`,
    walletScheme: 'eudi-openid4vp://',
    clientIdPrefix: 'x509_san_dns',
    clientDnsName: DNS_NAME,
    accessCertificateChainPem: cert.chainPem,
    accessCertificatePrivateKeyPem: cert.keyPem,
    requestedVct: 'urn:eudi:pid:1',
    requestTtlSeconds: 300,
    checkStatus: false,
    tolerateMalformedMdocValidity: false,
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
  localUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => void server.close());

async function startSession() {
  const response = await fetch(`${localUrl}/presentations`, { method: 'POST' });
  assert.equal(response.status, 201);
  const body = (await response.json()) as { id: string; walletUri: string; qrCodeDataUri: string };
  const params = new URL(body.walletUri.replace('eudi-openid4vp://', 'https://w.invalid/')).searchParams;
  return { ...body, params };
}

describe('signed request (x509_san_dns)', () => {
  it('passes the request by reference so the QR code stays encodable', async () => {
    const { walletUri, params, qrCodeDataUri } = await startSession();

    // A JAR carries the whole x5c chain. Embedding it by value produced a
    // request too large for a QR code at all, which is why request_uri exists.
    assert.ok(walletUri.length < 500, `wallet URI is ${walletUri.length} chars`);
    assert.ok(qrCodeDataUri.startsWith('data:image/png;base64,'));

    assert.deepEqual([...params.keys()].sort(), ['client_id', 'request_uri']);
    assert.equal(params.get('client_id'), `x509_san_dns:${DNS_NAME}`);
  });

  it('serves a signed request object the wallet can verify', async () => {
    const { params } = await startSession();

    const requestUri = params.get('request_uri')!.replace(`https://${DNS_NAME}`, localUrl);
    const response = await fetch(requestUri);

    assert.equal(response.status, 200);
    // RFC 9101 media type for a JWT-Secured Authorization Request.
    assert.equal(response.headers.get('content-type'), 'application/oauth-authz-req+jwt');

    const jwt = await response.text();
    const [headerB64, payloadB64, signatureB64] = jwt.split('.');
    const header = JSON.parse(Buffer.from(headerB64!, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(payloadB64!, 'base64url').toString());

    assert.equal(header.alg, 'ES256');
    assert.ok(Array.isArray(header.x5c) && header.x5c.length >= 1, 'JAR must carry the chain');
    assert.equal(payload.client_id, `x509_san_dns:${DNS_NAME}`);
    assert.equal(payload.response_mode, 'direct_post.jwt');

    // What the wallet does: take the leaf from x5c, check the DNS name in the
    // client_id matches a dNSName SAN, then verify the signature with its key.
    const leaf = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
    assert.match(leaf.subjectAltName ?? '', new RegExp(`DNS:${DNS_NAME}\\b`));

    const verified = nodeVerify(
      'sha256',
      Buffer.from(`${headerB64}.${payloadB64}`),
      { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signatureB64!, 'base64url'),
    );
    assert.ok(verified, 'JAR signature must verify against the leaf certificate');
  });

  it('publishes an ephemeral key for response encryption', async () => {
    const { params } = await startSession();
    const requestUri = params.get('request_uri')!.replace(`https://${DNS_NAME}`, localUrl);
    const jwt = await (await fetch(requestUri)).text();
    const payload = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString());

    // OID4VP 1.0 describes encryption through the JWK itself. The pre-1.0
    // authorization_encrypted_response_* names appear nowhere in the final spec.
    assert.ok(!('authorization_encrypted_response_alg' in payload.client_metadata));
    assert.ok(!('authorization_encrypted_response_enc' in payload.client_metadata));

    const key = payload.client_metadata.jwks?.keys?.[0];
    assert.equal(key?.kty, 'EC');
    assert.equal(key?.use, 'enc');
    assert.equal(key?.alg, 'ECDH-ES', 'the wallet picks its JWE alg from this');
    assert.ok(key?.kid, 'kid identifies which key encrypted the response');
    assert.ok(!('d' in (key ?? {})), 'the private half must never leave the server');
  });

  it('does not serve a request object for an unknown id', async () => {
    const response = await fetch(`${localUrl}/oid4vp/request/does-not-exist`);
    assert.equal(response.status, 404);
  });

  it('verifies an encrypted response end to end', async () => {
    const { id, params } = await startSession();
    const requestUri = params.get('request_uri')!.replace(`https://${DNS_NAME}`, localUrl);
    const jwt = await (await fetch(requestUri)).text();
    const request = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString());

    const presentation = await presentAgeOver18({
      issuedCredential: fixtures.issued.over18,
      holderPrivateJwk: fixtures.holderPrivateJwk,
      nonce: request.nonce,
      audience: request.client_id,
    });

    // direct_post.jwt: the whole response is sealed to the verifier's ephemeral
    // key, so `state` is not visible in the body. The session is identified by
    // the response_uri path instead — which is the bug this test pins.
    const response = await encryptResponse({
      vpToken: { [CREDENTIAL_QUERY_ID]: [presentation] },
      state: request.state,
      encryptionJwk: request.client_metadata.jwks.keys[0],
      ...(request.client_metadata.encrypted_response_enc_values_supported?.[0]
        ? { enc: request.client_metadata.encrypted_response_enc_values_supported[0] }
        : {}),
    });

    const posted = await fetch(request.response_uri.replace(`https://${DNS_NAME}`, localUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response }),
    });
    assert.equal(posted.status, 200);

    const outcome = (await (await fetch(`${localUrl}/presentations/${id}`)).json()) as {
      status: string;
      result: Record<string, unknown>;
    };
    assert.equal(outcome.status, 'verified', JSON.stringify(outcome));
    assert.equal(outcome.result['evidence'], 'age_equal_or_over.18');
  });

  /**
   * The rule the EU reference wallet enforced, and that our simulated wallet
   * never did: a Verifier may only ask for formats it declares support for.
   * Asking for `mso_mdoc` in the DCQL query while `vp_formats_supported` listed
   * only `dc+sd-jwt` got the entire request refused with
   * `InvalidClientMetaData`, before any credential was ever considered.
   */
  it('declares vp_formats_supported for every format the DCQL query asks for', async () => {
    const { params } = await startSession();
    const requestUri = params.get('request_uri')!.replace(`https://${DNS_NAME}`, localUrl);
    const jwt = await (await fetch(requestUri)).text();
    const request = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString());

    const requested = new Set<string>(
      request.dcql_query.credentials.map((c: { format: string }) => c.format),
    );
    const declared = new Set(Object.keys(request.client_metadata.vp_formats_supported));

    assert.ok(requested.size > 0, 'the query should ask for at least one format');
    for (const format of requested) {
      assert.ok(
        declared.has(format),
        `DCQL asks for ${format}, which client_metadata.vp_formats_supported does not declare`,
      );
    }
  });

  /**
   * The EU reference wallet declines this way, and the failure was worth a
   * test: an encrypted refusal decrypts to `{error, error_description, state}`
   * with no `vp_token`, so the DCQL schema check reported a malformed
   * `vp_token` and the wallet's actual reason never reached the user.
   */
  it("reports a wallet's encrypted refusal as WALLET_ERROR, not a bad vp_token", async () => {
    const { id, params } = await startSession();
    const requestUri = params.get('request_uri')!.replace(`https://${DNS_NAME}`, localUrl);
    const jwt = await (await fetch(requestUri)).text();
    const request = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString());

    const response = await encryptResponse({
      state: request.state,
      encryptionJwk: request.client_metadata.jwks.keys[0],
      error: { code: 'access_denied', description: 'User rejected the request' },
    });

    const posted = await fetch(request.response_uri.replace(`https://${DNS_NAME}`, localUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response }),
    });
    assert.equal(posted.status, 200);

    const outcome = (await (await fetch(`${localUrl}/presentations/${id}`)).json()) as {
      status: string;
      result: Record<string, unknown>;
    };
    assert.equal(outcome.result['verified'], false);
    assert.equal(outcome.result['reason'], 'WALLET_ERROR');
    assert.match(String(outcome.result['detail']), /access_denied/);
    assert.match(String(outcome.result['detail']), /User rejected the request/);
  });
});
