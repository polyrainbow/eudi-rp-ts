import 'reflect-metadata';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import * as x509 from '@peculiar/x509';
import assert from 'node:assert/strict';
import { type KeyObject, generateKeyPairSync, sign as nodeSign, webcrypto } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { describe, it } from 'node:test';
import {
  DEFAULT_ALLOWED_ALGS,
  type JwsAlg,
  base64urlEncode,
  hasher,
  importPublicJwk,
  keyUnusableFor,
  unsupportedKeyReason,
  verifyJws,
} from '../src/crypto.ts';
import { requestSigningAlg } from '../src/oid4vp/callbacks.ts';
import type { Outcome, ReasonCode, Rejected } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { resolveIssuerCertificateChain } from '../src/trust/issuer-key.ts';
import { verifyCredential } from '../src/verify.ts';

x509.cryptoProvider.set(webcrypto as never);

function assertRejected(outcome: Outcome<unknown>, reason: ReasonCode): asserts outcome is Rejected {
  assert.equal(outcome.verified, false, `expected ${reason}, but it verified`);
  assert.equal((outcome as Rejected).reason, reason, `detail was: ${(outcome as Rejected).detail}`);
}

/**
 * RSA is not decoration here.
 *
 * 2013 of the 2305 certificates on the live eIDAS trusted lists carry RSA keys,
 * against 274 EC ones (REPRODUCE.md). Verifying ECDSA alone meant a chain could
 * terminate at a trusted qualified CA and still be unverifiable because the
 * issuer signed the way most of eIDAS signs.
 */
describe('RSA signatures', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });

  const signWith = (alg: JwsAlg, key: KeyObject, data: string): string => {
    const hash = { '256': 'sha256', '384': 'sha384', '512': 'sha512' }[alg.slice(2)]!;
    return nodeSign(
      hash,
      Buffer.from(data, 'utf8'),
      alg.startsWith('PS')
        ? { key, padding: 6 /* RSA_PKCS1_PSS_PADDING */, saltLength: -1 /* DIGEST */ }
        : { key, padding: 1 /* RSA_PKCS1_PADDING */ },
    ).toString('base64url');
  };

  for (const alg of ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'] as const) {
    it(`verifies ${alg}`, () => {
      const signature = signWith(alg, rsa.privateKey, 'header.payload');

      assert.equal(verifyJws(rsa.publicKey, 'header.payload', signature, alg), true);
      assert.equal(verifyJws(rsa.publicKey, 'other.payload', signature, alg), false);
    });
  }

  it('does not read a PSS signature as PKCS#1, or the reverse', () => {
    // Both are "RSA with SHA-256" and the padding is the whole difference. Read
    // the wrong one and a perfectly good signature comes back as invalid — the
    // JOSE equivalent of the DER-versus-r‖s trap in lotl.ts.
    const pss = signWith('PS256', rsa.privateKey, 'data');
    const pkcs1 = signWith('RS256', rsa.privateKey, 'data');

    assert.equal(verifyJws(rsa.publicKey, 'data', pss, 'RS256'), false);
    assert.equal(verifyJws(rsa.publicKey, 'data', pkcs1, 'PS256'), false);
    assert.equal(verifyJws(rsa.publicKey, 'data', pss, 'PS256'), true);
    assert.equal(verifyJws(rsa.publicKey, 'data', pkcs1, 'RS256'), true);
  });

  it('refuses an RSA key below the size RFC 7518 requires', () => {
    const small = generateKeyPairSync('rsa', { modulusLength: 1024 });

    // Four certificates on the live lists are 1024-bit, so this refuses
    // something real rather than something hypothetical.
    assert.match(keyUnusableFor(small.publicKey, 'RS256')!, /at least 2048 bits/);
    assert.match(unsupportedKeyReason(small.publicKey)!, /RFC 7518/);
    // And it fails closed rather than verifying, whatever the caller checked.
    const signature = signWith('RS256', small.privateKey, 'data');
    assert.equal(verifyJws(small.publicKey, 'data', signature, 'RS256'), false);
  });

  it('will not let an rsa-pss key stand in for a PKCS#1 signature', () => {
    // An rsa-pss key carries its parameters in the key (RFC 4055) and is
    // restricted to PSS. 13 of the live anchors are of this type.
    const pssKey = generateKeyPairSync('rsa-pss', { modulusLength: 2048 });

    assert.equal(keyUnusableFor(pssKey.publicKey, 'PS256'), undefined);
    assert.match(keyUnusableFor(pssKey.publicKey, 'RS256')!, /needs rsa, got rsa-pss/);
  });
});

describe('pairing a key with an algorithm', () => {
  const ec256 = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });

  it('refuses an algorithm the key cannot perform', () => {
    assert.match(keyUnusableFor(rsa.publicKey, 'ES256')!, /needs an EC key, got rsa/);
    assert.match(keyUnusableFor(ec256.publicKey, 'RS256')!, /needs rsa, got ec/);
    assert.match(keyUnusableFor(ec256.publicKey, 'ES384')!, /needs curve secp384r1/);
    assert.equal(keyUnusableFor(ec256.publicKey, 'ES256'), undefined);
  });

  it('refuses a curve JOSE has no algorithm for', () => {
    // 24 certificates on the live lists use brainpool curves, which chain and
    // validate as certificates but have no JWS algorithm to be verified under.
    const brainpool = generateKeyPairSync('ec', { namedCurve: 'brainpoolP256r1' });

    assert.match(unsupportedKeyReason(brainpool.publicKey)!, /brainpoolP256r1 has no JWS algorithm/);
    assert.equal(unsupportedKeyReason(ec256.publicKey), undefined);
    assert.equal(unsupportedKeyReason(rsa.publicKey), undefined);
  });

  it('refuses a key type with no signature algorithm here at all', () => {
    const ed = generateKeyPairSync('ed25519');

    assert.match(unsupportedKeyReason(ed.publicKey)!, /ed25519 is not supported/);
  });

  it('imports an RSA holder key only when an RSA algorithm is allowed', async () => {
    const { exportJWK } = await import('jose');
    const jwk = await exportJWK(rsa.publicKey);

    assert.equal(importPublicJwk(jwk, DEFAULT_ALLOWED_ALGS), undefined);
    assert.ok(importPublicJwk(jwk, ['ES256', 'PS256']));
  });
});

/**
 * The signing side: the access certificate's key belongs to whoever registered
 * this relying party, so the algorithm follows the key rather than the reverse.
 */
describe('choosing an algorithm for our own request object', () => {
  const pem = (key: KeyObject) => key.export({ type: 'pkcs8', format: 'pem' }) as string;

  it('follows the access certificate key', () => {
    assert.equal(requestSigningAlg(pem(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey)), 'ES256');
    assert.equal(requestSigningAlg(pem(generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey)), 'ES384');
    // PS256 rather than RS256: the one choice valid for rsa and rsa-pss alike.
    assert.equal(requestSigningAlg(pem(generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey)), 'PS256');
    assert.equal(requestSigningAlg(pem(generateKeyPairSync('rsa-pss', { modulusLength: 2048 }).privateKey)), 'PS256');
  });

  it('refuses a key it cannot sign a JWS with', () => {
    assert.throws(() => requestSigningAlg(pem(generateKeyPairSync('ed25519').privateKey)), /ed25519/);
  });
});

/**
 * End to end, with an issuer that signs the way most of eIDAS signs.
 *
 * The pieces above can each be right while the wiring is wrong, and the wiring
 * is the point: an RSA credential has to survive path validation, the algorithm
 * policy and the signature check together.
 */
describe('an RSA-issued credential', () => {
  const YEAR = 365 * 24 * 60 * 60 * 1000;
  const NOW = new Date();
  const RSA_ALG = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) } as const;

  async function issueRsaCredential(): Promise<{ credential: string; anchors: TrustAnchors }> {
    const caKeys = (await webcrypto.subtle.generateKey(RSA_ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
    const ca = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: 'CN=RSA Test Root',
      notBefore: new Date(Date.now() - YEAR),
      notAfter: new Date(Date.now() + YEAR),
      signingAlgorithm: RSA_ALG,
      keys: caKeys as never,
      extensions: [
        new x509.BasicConstraintsExtension(true, 2, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      ],
    });

    const issuerKeys = (await webcrypto.subtle.generateKey(RSA_ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
    const issuerCert = await x509.X509CertificateGenerator.create({
      serialNumber: '02',
      subject: 'CN=RSA Test Issuer',
      issuer: ca.subject,
      notBefore: new Date(Date.now() - YEAR),
      notAfter: new Date(Date.now() + YEAR),
      signingAlgorithm: RSA_ALG,
      publicKey: issuerKeys.publicKey as never,
      signingKey: caKeys.privateKey as never,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      ],
    });

    const holderKeys = (await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;

    const sdjwt = new SDJwtVcInstance({
      hasher,
      signAlg: 'RS256',
      signer: async (data: string) =>
        base64urlEncode(
          new Uint8Array(
            await webcrypto.subtle.sign('RSASSA-PKCS1-v1_5', issuerKeys.privateKey, new TextEncoder().encode(data)),
          ),
        ),
      saltGenerator: (length: number) =>
        base64urlEncode(webcrypto.getRandomValues(new Uint8Array(length))).slice(0, length),
    });

    const credential = await sdjwt.issue(
      {
        iss: 'https://issuer.test',
        vct: 'urn:eudi:pid:1',
        // A minute back, so `now` in the test is inside the window whatever
        // order the certificate generation and the assertion happen in.
        iat: Math.floor(Date.now() / 1000) - 60,
        cnf: { jwk: await webcrypto.subtle.exportKey('jwk', holderKeys.publicKey) },
        age_equal_or_over: { '18': true },
      } as never,
      { age_equal_or_over: { '18': true } } as never,
      { header: { x5c: [Buffer.from(issuerCert.rawData).toString('base64')] } } as never,
    );

    return {
      credential,
      anchors: TrustAnchors.fromPem(ca.toString('pem')),
    };
  }

  it('verifies when the caller allows RS256, and is refused by default', async () => {
    const { credential, anchors } = await issueRsaCredential();
    const options = {
      credential,
      anchors,
      expectedVct: 'urn:eudi:pid:1',
      requireKeyBinding: false as const,
      checkStatus: false,
      checkCertificateRevocation: false,
      now: NOW,
    };

    const accepted = await verifyCredential({ ...options, allowedAlgs: ['RS256'] });
    assert.equal(accepted.verified, true, JSON.stringify(accepted));

    // The default policy is still ES256: capability is the library's, policy is
    // the caller's, and widening one must not widen the other.
    assertRejected(await verifyCredential(options), 'UNSUPPORTED_ALGORITHM');
  });

  it('reports a key that cannot perform the stated alg as unsupported, not as a bad signature', async () => {
    // The credential is signed with RS256 by an RSA key; the caller allows
    // ES256 *and* RS256, so policy passes, and only the pairing of key with
    // algorithm can catch a header claiming ES256 over an RSA key.
    const { credential, anchors } = await issueRsaCredential();
    const [header, ...rest] = credential.split('.');
    const decoded = JSON.parse(Buffer.from(header!, 'base64url').toString('utf8')) as Record<string, unknown>;
    const relabelled = [
      Buffer.from(JSON.stringify({ ...decoded, alg: 'ES256' })).toString('base64url'),
      ...rest,
    ].join('.');

    const outcome = await verifyCredential({
      credential: relabelled,
      anchors,
      expectedVct: 'urn:eudi:pid:1',
      requireKeyBinding: false,
      checkStatus: false,
      checkCertificateRevocation: false,
      allowedAlgs: ['ES256', 'RS256'],
      now: NOW,
    });

    assertRejected(outcome, 'UNSUPPORTED_ALGORITHM');
    assert.match(outcome.detail, /needs an EC key, got rsa/);
  });

  it('accepts the RSA issuer certificate in path validation', async () => {
    // The check this replaced rejected any leaf that was not EC, before any
    // algorithm had been named.
    const { credential, anchors } = await issueRsaCredential();
    const header = JSON.parse(
      Buffer.from(credential.split('.')[0]!, 'base64url').toString('utf8'),
    ) as { x5c: string[] };
    const { X509Certificate } = await import('node:crypto');
    const leaf = new X509Certificate(Buffer.from(header.x5c[0]!, 'base64'));

    const outcome = resolveIssuerCertificateChain([leaf], anchors, NOW);

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
    assert.equal(outcome.value.publicKey.asymmetricKeyType, 'rsa');
  });
});

/**
 * The status list is a second signed statement from the same issuer, and it was
 * held to a hardcoded ES256 whatever the caller's policy said — so an issuer
 * whose credentials were accepted could still have its status list refused.
 */
describe('status list algorithms', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });

  it('verifies a status list token signed with RS256', async () => {
    const { checkStatusList } = await import('../src/trust/status.ts');
    const uri = 'https://issuer.test/status/1';

    const leafPem = await (async () => {
      const keys = {
        privateKey: await webcrypto.subtle.importKey(
          'pkcs8',
          rsa.privateKey.export({ type: 'pkcs8', format: 'der' }),
          { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          false,
          ['sign'],
        ),
        publicKey: await webcrypto.subtle.importKey(
          'spki',
          rsa.publicKey.export({ type: 'spki', format: 'der' }),
          { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          true,
          ['verify'],
        ),
      };
      return x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: '03',
        name: 'CN=RSA Status Signer',
        notBefore: new Date(Date.now() - 86_400_000),
        notAfter: new Date(Date.now() + 86_400_000),
        signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        keys: keys as never,
        extensions: [
          new x509.BasicConstraintsExtension(false, undefined, true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        ],
      });
    })();

    const x5c = [Buffer.from(leafPem.rawData).toString('base64')];
    const header = Buffer.from(
      JSON.stringify({ alg: 'RS256', typ: 'statuslist+jwt', x5c }),
    ).toString('base64url');
    // One byte of status, all bits clear: this credential is not revoked.
    const payload = Buffer.from(
      JSON.stringify({
        sub: uri,
        iat: Math.floor(Date.now() / 1000),
        status_list: { bits: 1, lst: base64urlEncode(deflateStatusByte(0)) },
      }),
    ).toString('base64url');
    const signature = nodeSign(
      'sha256',
      Buffer.from(`${header}.${payload}`, 'utf8'),
      { key: rsa.privateKey, padding: 1 },
    ).toString('base64url');
    const token = `${header}.${payload}.${signature}`;

    const outcome = await checkStatusList(
      { uri, index: 0 },
      {
        anchors: TrustAnchors.fromPem(leafPem.toString('pem')),
        now: new Date(),
        allowedAlgs: ['RS256'],
        fetchImpl: (async () =>
          new Response(token, { headers: { 'content-type': 'application/statuslist+jwt' } })) as typeof fetch,
      },
    );

    assert.equal(outcome.kind, 'valid', JSON.stringify(outcome));
  });

  it('refuses a status list signed outside the allowed set', async () => {
    const { checkStatusList } = await import('../src/trust/status.ts');
    const uri = 'https://issuer.test/status/1';
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'statuslist+jwt' })).toString('base64url');
    const token = `${header}.e30.AAAA`;

    const outcome = await checkStatusList(
      { uri, index: 0 },
      {
        anchors: TrustAnchors.fromCertificates([]),
        now: new Date(),
        // The default policy, against a list signed with something else.
        fetchImpl: (async () =>
          new Response(token, { headers: { 'content-type': 'application/statuslist+jwt' } })) as typeof fetch,
      },
    );

    assert.equal(outcome.kind, 'unavailable');
    assert.match(outcome.kind === 'unavailable' ? outcome.detail : '', /alg RS256 is not in the allowed set/);
  });
});

/** Token Status List carries the bitstring zlib-compressed. */
function deflateStatusByte(value: number): Uint8Array {
  return new Uint8Array(deflateSync(Buffer.from([value])));
}
