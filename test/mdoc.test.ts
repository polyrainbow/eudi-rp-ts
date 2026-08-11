import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { decode, encode, get } from '../src/mdoc/cbor.ts';
import { coseAlg, coseX5Chain, parseCoseSign1, verifyCoseSign1 } from '../src/mdoc/cose.ts';
import { buildSessionTranscript, jwkThumbprint } from '../src/mdoc/session-transcript.ts';
import { verifyDeviceResponse } from '../src/mdoc/device-response.ts';
import { verifyMdoc } from '../src/mdoc/verify.ts';
import { buildDeviceResponse } from './mdoc-wallet.ts';
import { evaluateAgeOver18Mdoc } from '../src/predicate/age.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';

const dir = fileURLToPath(new URL('./fixtures/real/', import.meta.url));
const anchorDir = fileURLToPath(new URL('../anchors/', import.meta.url));
const issuerSigned = readFileSync(`${dir}eudiw-pid-mdoc.txt`, 'utf8').trim();
const anchors = TrustAnchors.fromPem(readFileSync(`${anchorDir}eudiw-pid-issuer-ca.pem`, 'utf8'));
const ourAnchors = TrustAnchors.fromPem(
  readFileSync(fileURLToPath(new URL('./fixtures/trust-anchor.pem', import.meta.url)), 'utf8'),
);

/** Inside the credential's window (issued 2026-08-11, expires 2026-11-09). */
const NOW = new Date('2026-09-01T00:00:00Z');
const base = {
  issuerSigned,
  anchors,
  expectedDocType: 'eu.europa.ec.eudi.pid.1',
  // The reference issuer emits a malformed validUntil; see the assertions below.
  tolerateMalformedValidityDates: true,
  now: NOW,
};

describe('mdoc from the EU reference issuer', () => {
  it('verifies the issuer signature and every element digest', async () => {
    const result = await verifyMdoc(base);

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.docType, 'eu.europa.ec.eudi.pid.1');
    assert.match(result.value.issuerCertificateSubject, /CN=PID DS - 002/);

    const elements = result.value.claims['eu.europa.ec.eudi.pid.1']!;
    assert.equal(elements['family_name'], 'Tester');
    assert.equal(elements['given_name'], 'Test');
  });

  it('is rejected against unrelated trust anchors', async () => {
    const result = await verifyMdoc({ ...base, anchors: ourAnchors });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'ISSUER_UNTRUSTED');
  });

  it('rejects an unexpected doc type', async () => {
    const result = await verifyMdoc({ ...base, expectedDocType: 'org.iso.18013.5.1.mDL' });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'UNEXPECTED_VCT');
  });

  it('detects a tampered element value', async () => {
    // Rewrite a disclosed value in place, leaving the MSO untouched. The issuer
    // signature still verifies — only the digest check catches this, which is
    // precisely what makes selective disclosure safe.
    const raw = Buffer.from(issuerSigned, 'base64url');
    const at = raw.indexOf(Buffer.from('Tester', 'utf8'));
    assert.ok(at > 0, 'fixture should contain the family name');

    const tampered = Buffer.from(raw);
    tampered.write('Tastar', at, 'utf8'); // same length, so the CBOR stays valid

    const result = await verifyMdoc({ ...base, issuerSigned: new Uint8Array(tampered) });
    assert.equal(result.verified, false, 'a rewritten element must not verify');
    assert.match(result.detail, /Digest mismatch/);
  });

  it('rejects the malformed validUntil by default', async () => {
    // A validity window that cannot be read is not a validity window. The
    // reference issuer emits "...+00:00Z", carrying both an offset and a Z.
    const strict = await verifyMdoc({ ...base, tolerateMalformedValidityDates: false });

    assert.equal(strict.verified, false);
    assert.equal(strict.reason, 'CREDENTIAL_MALFORMED');
    assert.match(strict.detail, /validUntil/);
  });

  it('carries no age attribute, so the predicate resolves through birth_date', async () => {
    const result = await verifyMdoc(base);
    assert.equal(result.verified, true);

    const elements = result.value.claims['eu.europa.ec.eudi.pid.1']!;
    // PID Rulebook v1.1 removed the age attributes (CIR 2024/2977), and the
    // issuer's mdoc form offers no age field — so birth_date is the only route,
    // exactly as `birthdate` is for the SD-JWT VC.
    assert.ok(!('age_over_18' in elements));
    assert.ok('birth_date' in elements);

    const age = evaluateAgeOver18Mdoc(elements, NOW);
    assert.equal(age.verified, true);
    assert.equal(age.value.evidence, 'birthdate');
  });
});

describe('mdoc age predicate', () => {
  it('accepts the flat age_over_18 boolean mdoc uses', () => {
    const result = evaluateAgeOver18Mdoc({ age_over_18: true }, NOW);
    assert.equal(result.verified, true);
    assert.equal(result.value.evidence, 'age_over_18');
  });

  it('rejects when the issuer says the holder is under 18', () => {
    const result = evaluateAgeOver18Mdoc({ age_over_18: false }, NOW);
    assert.equal(result.verified, false);
    assert.equal(result.reason, 'PREDICATE_NOT_SATISFIED');
  });

  it('falls back to birth_date, mdoc\'s spelling of the claim', () => {
    const result = evaluateAgeOver18Mdoc({ birth_date: '1990-06-12' }, NOW);
    assert.equal(result.verified, true);
    assert.equal(result.value.evidence, 'birthdate');
  });
});

describe('COSE_Sign1', () => {
  it('rejects a signature moved to a different key', () => {
    const doc = decode(Buffer.from(issuerSigned, 'base64url'));
    const sign1 = parseCoseSign1(get(doc, 'issuerAuth'));
    const real = new X509Certificate(Buffer.from(coseX5Chain(sign1)[0]!));
    const unrelated = new X509Certificate(
      readFileSync(fileURLToPath(new URL('./fixtures/trust-anchor.pem', import.meta.url)), 'utf8'),
    );

    assert.equal(verifyCoseSign1(sign1, real.publicKey, coseAlg(sign1)!), true);
    assert.equal(verifyCoseSign1(sign1, unrelated.publicKey, coseAlg(sign1)!), false);
  });

  it('fails when the protected header is altered', () => {
    // The Sig_structure commits to the protected header bytes, so changing
    // them must invalidate the signature even though the payload is untouched.
    const doc = decode(Buffer.from(issuerSigned, 'base64url'));
    const sign1 = parseCoseSign1(get(doc, 'issuerAuth'));
    const real = new X509Certificate(Buffer.from(coseX5Chain(sign1)[0]!));

    const tampered = { ...sign1, protectedBytes: new Uint8Array([0xa1, 0x01, 0x27]) };
    assert.equal(verifyCoseSign1(tampered, real.publicKey, 'ES256'), false);
  });
});

describe('OID4VP session transcript', () => {
  const parameters = {
    clientId: 'x509_san_dns:verifier.example',
    nonce: 'n-0S6_WzA2Mj',
    responseUri: 'https://verifier.example/oid4vp/response',
  };

  it('has the shape OID4VP 1.0 B.2.6.1 defines', () => {
    const transcript = decode(buildSessionTranscript(parameters)) as unknown[];

    assert.equal(transcript.length, 3);
    // DeviceEngagementBytes and EReaderKeyBytes MUST be null: there is no
    // proximity engagement to commit to.
    assert.equal(transcript[0], null);
    assert.equal(transcript[1], null);

    const handover = transcript[2] as unknown[];
    assert.equal(handover[0], 'OpenID4VPHandover');
    assert.equal((handover[1] as Uint8Array).length, 32, 'a sha-256 hash');
  });

  it('changes when any bound parameter changes', () => {
    // This is what stops a presentation being replayed at another verifier.
    const baseline = Buffer.from(buildSessionTranscript(parameters)).toString('hex');

    for (const variant of [
      { ...parameters, clientId: 'x509_san_dns:attacker.example' },
      { ...parameters, nonce: 'different' },
      { ...parameters, responseUri: 'https://attacker.example/collect' },
      { ...parameters, encryptionKeyThumbprint: new Uint8Array(32).fill(7) },
    ]) {
      assert.notEqual(Buffer.from(buildSessionTranscript(variant)).toString('hex'), baseline);
    }
  });

  it('computes an RFC 7638 thumbprint over the canonical member order', () => {
    // RFC 7638 example key and its published thumbprint would be RSA; for EC
    // the contract is the same: crv, kty, x, y, lexicographic, no whitespace.
    const a = jwkThumbprint({ kty: 'EC', crv: 'P-256', x: 'aaa', y: 'bbb' });
    const b = jwkThumbprint({ crv: 'P-256', y: 'bbb', x: 'aaa', kty: 'EC' } as never);

    assert.equal(a.length, 32);
    assert.deepEqual(a, b, 'member order in the input must not affect the thumbprint');
  });
});

describe('device authentication', () => {
  const devicePrivateJwk = JSON.parse(readFileSync(`${dir}mdoc-device-private-jwk.json`, 'utf8'));
  const request = {
    clientId: 'x509_san_dns:verifier.example',
    nonce: 'n-0S6_WzA2Mj',
    responseUri: 'https://verifier.example/oid4vp/response',
  };
  const sessionTranscript = buildSessionTranscript(request);
  const verifierOptions = {
    anchors,
    sessionTranscript,
    expectedDocType: 'eu.europa.ec.eudi.pid.1',
    tolerateMalformedValidityDates: true,
    now: NOW,
  };
  const present = (overrides = {}) =>
    buildDeviceResponse({
      issuerSigned,
      devicePrivateJwk,
      sessionTranscript,
      docType: 'eu.europa.ec.eudi.pid.1',
      ...overrides,
    });

  it('accepts a response signed by the bound device key', async () => {
    const result = await verifyDeviceResponse({ ...verifierOptions, deviceResponse: present() });

    assert.equal(result.verified, true, JSON.stringify(result));
    assert.equal(result.value.docType, 'eu.europa.ec.eudi.pid.1');
    assert.equal(result.value.claims['eu.europa.ec.eudi.pid.1']?.['family_name'], 'Tester');
  });

  it('rejects a response replayed at a different verifier', async () => {
    // The device signature commits to the session transcript, which commits to
    // the client id, nonce and response URI. This is the property that makes a
    // captured response useless to anyone else.
    const elsewhere = buildSessionTranscript({
      clientId: 'x509_san_dns:attacker.example',
      nonce: request.nonce,
      responseUri: 'https://attacker.example/collect',
    });

    const result = await verifyDeviceResponse({
      ...verifierOptions,
      sessionTranscript: elsewhere,
      deviceResponse: present(),
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'KEY_BINDING_INVALID');
  });

  it('rejects a response bound to a nonce we never issued', async () => {
    const result = await verifyDeviceResponse({
      ...verifierOptions,
      deviceResponse: present({
        signOverTranscript: buildSessionTranscript({ ...request, nonce: 'some-other-nonce' }),
      }),
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'KEY_BINDING_INVALID');
  });

  it('rejects a response signed by the wrong device key', async () => {
    // Issuer signature and digests are untouched; only the holder is wrong.
    const { generateKeyPairSync } = await import('node:crypto');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const impostor = privateKey.export({ format: 'jwk' });

    const result = await verifyDeviceResponse({
      ...verifierOptions,
      deviceResponse: present({ devicePrivateJwk: impostor }),
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'KEY_BINDING_INVALID');
  });

  it('still enforces issuer trust', async () => {
    const result = await verifyDeviceResponse({
      ...verifierOptions,
      anchors: ourAnchors,
      deviceResponse: present(),
    });

    assert.equal(result.verified, false);
    assert.equal(result.reason, 'ISSUER_UNTRUSTED');
  });
});
