/**
 * Generates the Phase 1 test fixtures.
 *
 * Run with `npm run fixtures`. The output is committed, so the test suite is
 * fully offline and does not depend on this script or on key generation.
 *
 * IMPORTANT: these credentials are signed by a throwaway CA created here. They
 * prove that our verification logic is correct. They prove nothing about
 * interoperability with the EUDI ecosystem — that is Phase 2's job.
 */
// @peculiar/x509 resolves to CJS under node, which pulls in tsyringe.
// Dev-only: nothing in src/ depends on it, node's built-in X509Certificate is enough there.
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { webcrypto } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { base64urlEncode, hasher } from '../src/crypto.ts';

x509.cryptoProvider.set(webcrypto as never);

const OUT = fileURLToPath(new URL('../test/fixtures/', import.meta.url));
const ALG = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

/** Fixed instant so the fixtures are stable and the tests can pick a "now". */
const ISSUED_AT = new Date('2026-01-15T12:00:00Z');
const EXPIRES_AT = new Date('2027-01-15T12:00:00Z');
const VERIFIER_AUDIENCE = 'https://verifier.example/oid4vp';
const NONCE = 'nAcE7Uu0S1nJhWnPnKxN2A';

async function makeCa(name: string) {
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${name}`,
    notBefore: new Date('2026-01-01T00:00:00Z'),
    notAfter: new Date('2030-01-01T00:00:00Z'),
    signingAlgorithm: SIGN,
    keys: keys as never,
    extensions: [new x509.BasicConstraintsExtension(true, 1, true)],
  });
  return { keys, cert };
}

async function makeIssuerCert(ca: Awaited<ReturnType<typeof makeCa>>, name: string, notAfter: Date) {
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: `CN=${name}`,
    issuer: ca.cert.subject,
    notBefore: new Date('2026-01-01T00:00:00Z'),
    notAfter,
    signingAlgorithm: SIGN,
    publicKey: keys.publicKey as never,
    signingKey: ca.keys.privateKey as never,
    extensions: [new x509.BasicConstraintsExtension(false, undefined, true)],
  });
  return { keys, cert };
}

function instance(signingKey: webcrypto.CryptoKey, holderKey?: webcrypto.CryptoKey) {
  return new SDJwtVcInstance({
    hasher,
    signAlg: 'ES256',
    signer: async (data) =>
      base64urlEncode(
        new Uint8Array(
          await webcrypto.subtle.sign(SIGN, signingKey, new TextEncoder().encode(data)),
        ),
      ),
    saltGenerator: (length) =>
      base64urlEncode(webcrypto.getRandomValues(new Uint8Array(length))).slice(0, length),
    ...(holderKey
      ? {
          kbSignAlg: 'ES256',
          kbSigner: async (data: string) =>
            base64urlEncode(
              new Uint8Array(
                await webcrypto.subtle.sign(SIGN, holderKey, new TextEncoder().encode(data)),
              ),
            ),
        }
      : {}),
  });
}

/**
 * PID claim encoding per the EUDI PID Rulebook (ARF 2.4, chapter 4):
 * `birth_date` -> `birthdate` (OIDC registered claim, YYYY-MM-DD) and
 * `age_over_NN` -> `age_equal_or_over.NN` (boolean).
 */
function pidPayload(holderJwk: webcrypto.JsonWebKey, over18: boolean, withAgeClaims = true) {
  return {
    iss: 'https://issuer.example',
    vct: 'urn:eudi:pid:1',
    iat: Math.floor(ISSUED_AT.getTime() / 1000),
    exp: Math.floor(EXPIRES_AT.getTime() / 1000),
    cnf: { jwk: holderJwk },
    family_name: 'Mustermann',
    given_name: 'Erika',
    birthdate: over18 ? '1990-06-12' : '2015-06-12',
    issuing_country: 'DE',
    issuing_authority: 'Bundesdruckerei',
    ...(withAgeClaims
      ? { age_equal_or_over: { '14': over18, '16': over18, '18': over18, '21': over18, '65': false } }
      : {}),
  };
}

const DISCLOSURE_FRAME = {
  _sd: ['family_name', 'given_name', 'birthdate', 'issuing_authority'],
  age_equal_or_over: { _sd: ['14', '16', '18', '21', '65'] },
} as const;

const DISCLOSURE_FRAME_NO_AGE = {
  _sd: ['family_name', 'given_name', 'birthdate', 'issuing_authority'],
} as const;

async function main() {
  await mkdir(OUT, { recursive: true });

  const ca = await makeCa('eudi-rp-ts Test Root CA');
  const rogueCa = await makeCa('eudi-rp-ts Rogue Root CA');
  const issuer = await makeIssuerCert(ca, 'eudi-rp-ts Test PID Issuer', new Date('2029-01-01T00:00:00Z'));
  const rogueIssuer = await makeIssuerCert(rogueCa, 'eudi-rp-ts Rogue PID Issuer', new Date('2029-01-01T00:00:00Z'));

  const holder = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const holderJwk = await webcrypto.subtle.exportKey('jwk', holder.publicKey);
  delete holderJwk.d;
  delete holderJwk.key_ops;
  delete holderJwk.ext;
  const holderPrivateJwk = await webcrypto.subtle.exportKey('jwk', holder.privateKey);

  const x5c = (leaf: x509.X509Certificate) => [
    Buffer.from(leaf.rawData).toString('base64'),
    Buffer.from(ca.cert.rawData).toString('base64'),
  ];

  /** Issue, then present with a KB-JWT bound to nonce + audience. */
  async function issueAndPresent(opts: {
    signingKey: webcrypto.CryptoKey;
    header: object;
    payload: object;
    frame: object;
    present: object;
    kb?: { nonce: string; aud: string } | false;
  }) {
    const issued = await instance(opts.signingKey).issue(
      opts.payload as never,
      opts.frame as never,
      { header: opts.header },
    );
    if (opts.kb === false) {
      return { issued, presented: await instance(opts.signingKey).present(issued, opts.present as never) };
    }
    const kb = opts.kb ?? { nonce: NONCE, aud: VERIFIER_AUDIENCE };
    const presented = await instance(opts.signingKey, holder.privateKey).present(
      issued,
      opts.present as never,
      { kb: { payload: { iat: Math.floor(ISSUED_AT.getTime() / 1000), aud: kb.aud, nonce: kb.nonce } } },
    );
    return { issued, presented };
  }

  const header = { x5c: x5c(issuer.cert) };
  const onlyAge18 = { age_equal_or_over: { '18': true } };

  const over18 = await issueAndPresent({
    signingKey: issuer.keys.privateKey,
    header,
    payload: pidPayload(holderJwk, true),
    frame: DISCLOSURE_FRAME,
    present: onlyAge18,
  });

  const under18 = await issueAndPresent({
    signingKey: issuer.keys.privateKey,
    header,
    payload: pidPayload(holderJwk, false),
    frame: DISCLOSURE_FRAME,
    present: onlyAge18,
  });

  const birthdateOnly = await issueAndPresent({
    signingKey: issuer.keys.privateKey,
    header,
    payload: pidPayload(holderJwk, true, false),
    frame: DISCLOSURE_FRAME_NO_AGE,
    present: { birthdate: true },
  });

  const wrongAudience = await issueAndPresent({
    signingKey: issuer.keys.privateKey,
    header,
    payload: pidPayload(holderJwk, true),
    frame: DISCLOSURE_FRAME,
    present: onlyAge18,
    kb: { nonce: NONCE, aud: 'https://other-verifier.example/oid4vp' },
  });

  const wrongNonce = await issueAndPresent({
    signingKey: issuer.keys.privateKey,
    header,
    payload: pidPayload(holderJwk, true),
    frame: DISCLOSURE_FRAME,
    present: onlyAge18,
    kb: { nonce: 'a-nonce-this-verifier-never-issued', aud: VERIFIER_AUDIENCE },
  });

  const noKeyBinding = await issueAndPresent({
    signingKey: issuer.keys.privateKey,
    header,
    payload: pidPayload(holderJwk, true),
    frame: DISCLOSURE_FRAME,
    present: onlyAge18,
    kb: false,
  });

  const untrusted = await issueAndPresent({
    signingKey: rogueIssuer.keys.privateKey,
    header: { x5c: [
      Buffer.from(rogueIssuer.cert.rawData).toString('base64'),
      Buffer.from(rogueCa.cert.rawData).toString('base64'),
    ] },
    payload: pidPayload(holderJwk, true),
    frame: DISCLOSURE_FRAME,
    present: onlyAge18,
  });

  await writeFile(`${OUT}trust-anchor.pem`, ca.cert.toString('pem') + '\n');
  await writeFile(`${OUT}rogue-anchor.pem`, rogueCa.cert.toString('pem') + '\n');
  await writeFile(
    `${OUT}credentials.json`,
    `${JSON.stringify(
      {
        _README:
          'Generated by scripts/make-fixtures.ts. Self-signed test CA; proves our logic, not EUDI interop.',
        issuedAt: ISSUED_AT.toISOString(),
        expiresAt: EXPIRES_AT.toISOString(),
        audience: VERIFIER_AUDIENCE,
        nonce: NONCE,
        vct: 'urn:eudi:pid:1',
        // Key material and an un-presented credential, so a test can act as a
        // wallet and mint a Key Binding JWT for a live nonce and audience.
        holderPrivateJwk,
        issued: { over18: over18.issued },
        credentials: {
          over18: over18.presented,
          under18: under18.presented,
          birthdateOnly: birthdateOnly.presented,
          wrongAudience: wrongAudience.presented,
          wrongNonce: wrongNonce.presented,
          noKeyBinding: noKeyBinding.presented,
          untrustedIssuer: untrusted.presented,
        },
      },
      null,
      2,
    )}\n`,
  );

  console.log(`Wrote fixtures to ${OUT}`);
}

await main();
