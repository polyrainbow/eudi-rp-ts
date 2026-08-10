import assert from 'node:assert/strict';
import { X509Certificate, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { clientId, x509Hash } from '../src/oid4vp/identity.ts';
import { buildAuthorizationRequest } from '../src/oid4vp/request.ts';
import { createAccessCertificate } from '../scripts/make-access-cert.ts';

/**
 * A certificate whose SAN is a URI rather than a dNSName — the shape the EU
 * reference verifier uses, and the case x509_san_dns cannot express.
 */
const cert = await createAccessCertificate('verifier.test');
const real = fileURLToPath(new URL('./fixtures/real/', import.meta.url));

const identity = {
  baseUrl: 'https://verifier.test',
  walletScheme: 'eudi-openid4vp://',
  clientIdPrefix: 'x509_hash' as const,
  clientDnsName: undefined,
  accessCertificateChainPem: cert.chainPem,
  accessCertificatePrivateKeyPem: cert.keyPem,
  requestedVct: 'urn:eudi:pid:1',
  requestTtlSeconds: 300,
  checkStatus: false,
};

describe('x509_hash client identifier', () => {
  it('is the base64url SHA-256 of the DER leaf certificate', () => {
    // OID4VP 1.0 §5.10, restated independently here so the implementation is
    // checked against the rule rather than against itself.
    const leaf = /-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/.exec(cert.chainPem)![0];
    const expected = createHash('sha256').update(new X509Certificate(leaf).raw).digest('base64url');

    assert.equal(x509Hash(cert.chainPem), expected);
    assert.equal(expected.length, 43, 'a base64url sha-256 is 43 characters');
  });

  it('reproduces the identifier the EU reference verifier publishes', () => {
    // A fixed vector: the certificate verifier-backend.eudiw.dev signed its
    // authorization request with on 2026-08-10, and the client_id it advertised
    // alongside it. Hashing fixed bytes gives a fixed answer, so this does not
    // depend on the live service and will not rot when the certificate rotates.
    //
    // This is the test that proves the rule was implemented rather than guessed.
    const leafPem = readFileSync(`${real}eudiw-verifier-leaf.pem`, 'utf8');
    const published = readFileSync(`${real}eudiw-verifier-client-id.txt`, 'utf8').trim();

    assert.equal(`x509_hash:${x509Hash(leafPem)}`, published);
    assert.equal(published, 'x509_hash:FTTP4DJV_P7icSZwBAo8cifSpYy8Sph0K1gZdbmaQh4');
  });

  it('derives the client_id from the certificate, not from a name', () => {
    const id = clientId(identity, 'https://verifier.test/oid4vp/response/abc');

    assert.match(id, /^x509_hash:[A-Za-z0-9_-]{43}$/);
    assert.equal(id, `x509_hash:${x509Hash(cert.chainPem)}`);
  });

  it('does not depend on the response URI, unlike redirect_uri', () => {
    // Which is what makes it usable with a per-session response URI.
    const a = clientId(identity, 'https://verifier.test/oid4vp/response/one');
    const b = clientId(identity, 'https://verifier.test/oid4vp/response/two');

    assert.equal(a, b);
  });

  it('refuses to invent an identifier without a certificate', () => {
    assert.throws(
      () => clientId({ ...identity, accessCertificateChainPem: undefined }, 'https://verifier.test/r'),
      /requires the access certificate chain/,
    );
  });

  it('signs the request, and the wallet can recompute the identifier from x5c', async () => {
    const request = await buildAuthorizationRequest(identity);

    // Passed by reference, because a JAR carrying x5c exceeds QR capacity.
    const params = new URL(
      request.walletUri.replace('eudi-openid4vp://', 'https://w.invalid/'),
    ).searchParams;
    assert.deepEqual([...params.keys()].sort(), ['client_id', 'request_uri']);

    const jwt = request.requestObject!.jwt;
    const header = JSON.parse(Buffer.from(jwt.split('.')[0]!, 'base64url').toString());

    // This is the wallet's side of the contract: hash the leaf it was given and
    // check it equals the client_id it was told.
    const recomputed = createHash('sha256')
      .update(Buffer.from(header.x5c[0], 'base64'))
      .digest('base64url');
    assert.equal(params.get('client_id'), `x509_hash:${recomputed}`);
  });
});
