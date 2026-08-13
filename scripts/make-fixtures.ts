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
import { createHash, webcrypto } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { StatusList, createHeaderAndPayload } from '@owf/token-status-list';
import { base64urlEncode, hasher } from '../src/crypto.ts';
import { decodeCbor as decode, encode, encodeTag24 } from '../src/mdoc/cbor.ts';

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

/** Index this fixture occupies in the status list. */
const STATUS_INDEX = 7;
const STATUS_URI = 'https://issuer.example/status/1';
/** The mdoc fixture's own index, distinct so a mix-up cannot pass unnoticed. */
const MDOC_STATUS_INDEX = 12;
const MDOC_STATUS_URI = 'https://issuer.example/status/mdoc/1';

/**
 * A signed Token Status List, so revocation can be tested offline.
 *
 * Signed by the same key and carrying the same x5c as the credential, which is
 * what the real EU issuer does — and what makes the list trustworthy rather
 * than merely fetchable.
 */
async function statusListJwt(
  signingKey: webcrypto.CryptoKey,
  x5c: string[],
  revokedIndex: number | undefined,
  overrides: { sub?: string; exp?: number; bits?: 1 | 2 | 4 | 8; statuses?: Record<number, number> } = {},
): Promise<string> {
  const bits = overrides.bits ?? 1;
  const list = new StatusList(new Array(64).fill(0), bits);
  if (revokedIndex !== undefined) list.setStatus(revokedIndex, 1);
  for (const [index, value] of Object.entries(overrides.statuses ?? {})) {
    list.setStatus(Number(index), value);
  }

  const { header, payload } = createHeaderAndPayload(
    list,
    {
      iss: 'https://issuer.example',
      sub: overrides.sub ?? STATUS_URI,
      iat: Math.floor(ISSUED_AT.getTime() / 1000),
      ...(overrides.exp !== undefined ? { exp: overrides.exp } : {}),
    },
    { alg: 'ES256', typ: 'statuslist+jwt', x5c } as never,
  );

  const signingInput = `${base64urlEncode(Buffer.from(JSON.stringify(header)))}.${base64urlEncode(
    Buffer.from(JSON.stringify(payload)),
  )}`;
  const signature = base64urlEncode(
    new Uint8Array(await webcrypto.subtle.sign(SIGN, signingKey, new TextEncoder().encode(signingInput))),
  );
  return `${signingInput}.${signature}`;
}

/**
 * A minimal issued mdoc, so mdoc revocation can be tested offline in both
 * directions.
 *
 * The real credential in `test/fixtures/real/` carries a status list too, but
 * it is signed by the EU reference issuer's CA — whose key we obviously do not
 * have, so no status list we can mint would verify against it. Proving that a
 * revoked mdoc is rejected, and an unrevoked one accepted, needs a credential
 * signed by the throwaway CA here.
 *
 * Only what `verifyMdoc` reads: no device authentication, so the device key is
 * present but never used.
 */
async function issueMdoc(options: {
  signingKey: webcrypto.CryptoKey;
  x5c: string[];
  docType: string;
  deviceKey: webcrypto.JsonWebKey;
  elements: Record<string, unknown>;
  status?: { idx: number; uri: string };
}): Promise<string> {
  const namespace = options.docType;

  // IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem), and the digest
  // covers those exact bytes — so they are built once and both hashed and
  // embedded, never re-encoded.
  const items = Object.entries(options.elements).map(([elementIdentifier, elementValue], index) => {
    const item = encode({
      digestID: index,
      random: webcrypto.getRandomValues(new Uint8Array(16)),
      elementIdentifier,
      elementValue,
    });
    return { digestID: index, tagged: encodeTag24(item) };
  });

  const valueDigests = new Map(
    items.map(({ digestID, tagged }) => [
      digestID,
      new Uint8Array(createHash('sha256').update(tagged).digest()),
    ]),
  );

  const mso = {
    version: '1.0',
    digestAlgorithm: 'SHA-256',
    valueDigests: { [namespace]: valueDigests },
    deviceKeyInfo: {
      // COSE_Key, EC2 / P-256 (RFC 9052 §7).
      deviceKey: new Map<number, unknown>([
        [1, 2],
        [-1, 1],
        [-2, new Uint8Array(Buffer.from(options.deviceKey.x!, 'base64url'))],
        [-3, new Uint8Array(Buffer.from(options.deviceKey.y!, 'base64url'))],
      ]),
    },
    docType: options.docType,
    validityInfo: { signed: ISSUED_AT, validFrom: ISSUED_AT, validUntil: EXPIRES_AT },
    ...(options.status ? { status: { status_list: options.status } } : {}),
  };

  const protectedBytes = encode(new Map<number, unknown>([[1, -7]]));
  const payload = encodeTag24(encode(mso));
  const sigStructure = encode(['Signature1', protectedBytes, new Uint8Array(0), payload]);
  const signature = new Uint8Array(
    await webcrypto.subtle.sign(SIGN, options.signingKey, sigStructure),
  );

  const issuerSigned = {
    nameSpaces: { [namespace]: items.map(({ tagged }) => decode(tagged)) },
    // x5chain (label 33) in the unprotected header, as the EU issuer emits it.
    issuerAuth: [
      protectedBytes,
      new Map<number, unknown>([[33, options.x5c.map((c) => new Uint8Array(Buffer.from(c, 'base64')))]]),
      payload,
      signature,
    ],
  };

  return Buffer.from(encode(issuerSigned)).toString('base64url');
}

/** Where the revocable fixture certificate says to look. */
const CRL_URL = 'https://ca.example/crl/issuer.crl';
const OCSP_URL = 'https://ca.example/ocsp';

/**
 * An issuer certificate that publishes revocation information.
 *
 * The other fixture certificates deliberately carry neither extension, which is
 * what makes them exercise the "nothing published, nothing to check" path. This
 * one carries both, so the CRL and OCSP code has something to point at.
 */
async function makeRevocableIssuerCert(ca: Awaited<ReturnType<typeof makeCa>>, serial: string) {
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial,
    subject: 'CN=eudi-rp-ts Revocable PID Issuer',
    issuer: ca.cert.subject,
    notBefore: new Date('2026-01-01T00:00:00Z'),
    notAfter: new Date('2029-01-01T00:00:00Z'),
    signingAlgorithm: SIGN,
    publicKey: keys.publicKey as never,
    signingKey: ca.keys.privateKey as never,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.CRLDistributionPointsExtension([CRL_URL]),
      new x509.AuthorityInfoAccessExtension({ ocsp: [new x509.GeneralName('url', OCSP_URL)] }),
    ],
  });
  return { keys, cert };
}

/**
 * A CRL signed by the test CA.
 *
 * `nextUpdate` is not optional in practice: a CRL that never expires cannot be
 * distinguished from one replayed from years ago, so the verifier refuses one
 * without it — and a fixture exists for that case too.
 */
async function makeCrl(options: {
  ca: Awaited<ReturnType<typeof makeCa>>;
  revoked?: { serialNumber: string; reason: number }[];
  thisUpdate?: Date;
  nextUpdate?: Date | undefined;
  signWith?: Awaited<ReturnType<typeof makeCa>>;
}): Promise<string> {
  const signer = options.signWith ?? options.ca;
  const crl = await x509.X509CrlGenerator.create({
    issuer: options.ca.cert.subject,
    thisUpdate: options.thisUpdate ?? new Date('2026-05-01T00:00:00Z'),
    ...(options.nextUpdate === undefined && 'nextUpdate' in options
      ? {}
      : { nextUpdate: options.nextUpdate ?? new Date('2026-07-01T00:00:00Z') }),
    signingAlgorithm: SIGN,
    signingKey: signer.keys.privateKey as never,
    entries: (options.revoked ?? []).map((entry) => ({
      serialNumber: entry.serialNumber,
      revocationDate: new Date('2026-04-01T00:00:00Z'),
      reason: entry.reason,
    })),
  } as never);
  return Buffer.from(crl.rawData).toString('base64');
}

/**
 * A signed OCSP response (RFC 6960).
 *
 * Hand-built, because nothing in the dependency tree produces one. The CertID
 * is computed here from the certificate's own issuer field and the issuer's
 * public key, per §4.1.1 — deliberately re-derived rather than borrowed from
 * `src/`, so a mistake in the verifier's copy shows up as a mismatch instead of
 * cancelling out. `scripts/check-ocsp-certid.sh` pins both against OpenSSL.
 */
async function makeOcspResponse(options: {
  certificate: x509.X509Certificate;
  ca: Awaited<ReturnType<typeof makeCa>>;
  status: 'good' | 'revoked' | 'unknown';
  /** Sign with this instead of the CA, to model a delegated responder. */
  responder?: { keys: webcrypto.CryptoKeyPair; cert: x509.X509Certificate };
  producedAt?: Date;
  nextUpdate?: Date;
  responseStatus?: number;
}): Promise<string> {
  const { AsnParser, AsnSerializer, OctetString } = await import('@peculiar/asn1-schema');
  const asn1x509 = await import('@peculiar/asn1-x509');
  const ocsp = await import('@peculiar/asn1-ocsp');
  const { createHash } = await import('node:crypto');

  const parsed = AsnParser.parse(options.certificate.rawData, asn1x509.Certificate);
  const issuerName = AsnSerializer.serialize(parsed.tbsCertificate.issuer);
  const spki = AsnParser.parse(
    Buffer.from(await webcrypto.subtle.exportKey('spki', options.ca.keys.publicKey)),
    asn1x509.SubjectPublicKeyInfo,
  );

  const serial = options.certificate.serialNumber;
  const certID = new ocsp.CertID({
    hashAlgorithm: new asn1x509.AlgorithmIdentifier({ algorithm: '1.3.14.3.2.26', parameters: null }),
    issuerNameHash: new OctetString(createHash('sha1').update(Buffer.from(issuerName)).digest()),
    issuerKeyHash: new OctetString(createHash('sha1').update(Buffer.from(spki.subjectPublicKey)).digest()),
    serialNumber: new Uint8Array(Buffer.from(serial.length % 2 ? `0${serial}` : serial, 'hex')).buffer,
  });

  const certStatus = new ocsp.CertStatus(
    options.status === 'good'
      ? { good: null }
      : options.status === 'unknown'
        ? { unknown: null }
        : {
            revoked: new ocsp.RevokedInfo({
              revocationTime: new Date('2026-04-01T00:00:00Z'),
              // 1 is keyCompromise (RFC 5280 §5.3.1), the reason that matters
              // most here: the issuer's key, not merely its paperwork.
              revocationReason: new asn1x509.CRLReason(1),
            }),
          },
  );

  const signerKeys = options.responder?.keys ?? options.ca.keys;
  const responderSpki = AsnParser.parse(
    Buffer.from(await webcrypto.subtle.exportKey('spki', signerKeys.publicKey)),
    asn1x509.SubjectPublicKeyInfo,
  );

  const tbsResponseData = new ocsp.ResponseData({
    responderID: new ocsp.ResponderID({
      byKey: new OctetString(createHash('sha1').update(Buffer.from(responderSpki.subjectPublicKey)).digest()),
    }),
    producedAt: options.producedAt ?? new Date('2026-05-01T00:00:00Z'),
    responses: [
      new ocsp.SingleResponse({
        certID,
        certStatus,
        thisUpdate: new Date('2026-05-01T00:00:00Z'),
        nextUpdate: options.nextUpdate ?? new Date('2026-07-01T00:00:00Z'),
      }),
    ],
  });

  const signed = AsnSerializer.serialize(tbsResponseData);
  // WebCrypto emits the raw r‖s pair (IEEE P1363); X.509 and OCSP carry ECDSA
  // as a DER SEQUENCE, the opposite of JWS and COSE. A real responder emits
  // DER, so the fixture must too — otherwise it would only prove the verifier
  // agrees with this script about the wrong encoding.
  const signature = p1363ToDer(
    new Uint8Array(await webcrypto.subtle.sign(SIGN, signerKeys.privateKey, signed)),
  );

  const basic = new ocsp.BasicOCSPResponse({
    tbsResponseData,
    signatureAlgorithm: new asn1x509.AlgorithmIdentifier({ algorithm: '1.2.840.10045.4.3.2' }),
    signature: new ArrayBuffer(0),
  });
  basic.signature = signature;
  if (options.responder) {
    basic.certs = [AsnParser.parse(options.responder.cert.rawData, asn1x509.Certificate)];
  }

  const response = new ocsp.OCSPResponse({
    responseStatus: options.responseStatus ?? 0,
    ...(options.responseStatus
      ? {}
      : {
          responseBytes: new ocsp.ResponseBytes({
            responseType: ocsp.id_pkix_ocsp_basic,
            response: new OctetString(AsnSerializer.serialize(basic)),
          }),
        }),
  });

  return Buffer.from(AsnSerializer.serialize(response)).toString('base64');
}

/** Raw r‖s to the DER SEQUENCE { r INTEGER, s INTEGER } that X.509 uses. */
function p1363ToDer(raw: Uint8Array): ArrayBuffer {
  const half = raw.length / 2;
  const integer = (bytes: Uint8Array): number[] => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
    const trimmed = [...bytes.subarray(start)];
    // DER INTEGER is signed, so a leading bit of 1 needs a zero byte in front.
    if (trimmed[0]! & 0x80) trimmed.unshift(0);
    return [0x02, trimmed.length, ...trimmed];
  };

  const body = [...integer(raw.subarray(0, half)), ...integer(raw.subarray(half))];
  return Uint8Array.from([0x30, body.length, ...body]).buffer;
}

/** A delegated OCSP responder: signed by the CA, carrying id-kp-OCSPSigning. */
async function makeOcspResponder(ca: Awaited<ReturnType<typeof makeCa>>, withEku: boolean) {
  const keys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '09',
    subject: `CN=eudi-rp-ts OCSP Responder${withEku ? '' : ' (no EKU)'}`,
    issuer: ca.cert.subject,
    notBefore: new Date('2026-01-01T00:00:00Z'),
    notAfter: new Date('2029-01-01T00:00:00Z'),
    signingAlgorithm: SIGN,
    publicKey: keys.publicKey as never,
    signingKey: ca.keys.privateKey as never,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      // 1.3.6.1.5.5.7.3.9 is id-kp-OCSPSigning: the CA saying this key may
      // answer for its certificates. Without it any leaf could.
      ...(withEku ? [new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.9'])] : []),
    ],
  });
  return { keys, cert };
}

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

  const withStatus = await issueAndPresent({
    signingKey: issuer.keys.privateKey,
    header,
    payload: { ...pidPayload(holderJwk, true), status: { status_list: { idx: STATUS_INDEX, uri: STATUS_URI } } },
    frame: DISCLOSURE_FRAME,
    present: onlyAge18,
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

  // A credential whose issuer certificate publishes both revocation mechanisms.
  const revocable = await makeRevocableIssuerCert(ca, '0A');
  const revocableSerial = revocable.cert.serialNumber;
  const revocableCredential = await issueAndPresent({
    signingKey: revocable.keys.privateKey,
    header: {
      x5c: [
        Buffer.from(revocable.cert.rawData).toString('base64'),
        Buffer.from(ca.cert.rawData).toString('base64'),
      ],
    },
    payload: pidPayload(holderJwk, true),
    frame: DISCLOSURE_FRAME,
    present: onlyAge18,
  });

  const responder = await makeOcspResponder(ca, true);
  const responderNoEku = await makeOcspResponder(ca, false);

  const device = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const deviceJwk = await webcrypto.subtle.exportKey('jwk', device.publicKey);
  const devicePrivateJwk = await webcrypto.subtle.exportKey('jwk', device.privateKey);

  const mdocElements = { family_name: 'Mustermann', given_name: 'Erika', birth_date: '1990-06-12' };
  const mdocDocType = 'eu.europa.ec.eudi.pid.1';

  const mdocWithStatus = await issueMdoc({
    signingKey: issuer.keys.privateKey,
    x5c: x5c(issuer.cert),
    docType: mdocDocType,
    deviceKey: deviceJwk,
    elements: mdocElements,
    status: { idx: MDOC_STATUS_INDEX, uri: MDOC_STATUS_URI },
  });

  // Signed by the certificate that publishes revocation information, so the
  // mdoc path can be shown to check it exactly as the SD-JWT VC path does.
  const mdocRevocableIssuer = await issueMdoc({
    signingKey: revocable.keys.privateKey,
    x5c: [
      Buffer.from(revocable.cert.rawData).toString('base64'),
      Buffer.from(ca.cert.rawData).toString('base64'),
    ],
    docType: mdocDocType,
    deviceKey: deviceJwk,
    elements: mdocElements,
  });

  const mdocWithoutStatus = await issueMdoc({
    signingKey: issuer.keys.privateKey,
    x5c: x5c(issuer.cert),
    docType: mdocDocType,
    deviceKey: deviceJwk,
    elements: mdocElements,
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
        statusIndex: STATUS_INDEX,
        statusUri: STATUS_URI,
        statusLists: {
          valid: await statusListJwt(issuer.keys.privateKey, x5c(issuer.cert), undefined),
          revoked: await statusListJwt(issuer.keys.privateKey, x5c(issuer.cert), STATUS_INDEX),
          untrustedSigner: await statusListJwt(
            rogueIssuer.keys.privateKey,
            [
              Buffer.from(rogueIssuer.cert.rawData).toString('base64'),
              Buffer.from(rogueCa.cert.rawData).toString('base64'),
            ],
            undefined,
          ),
          // Correctly signed by the real issuer, but published for a different
          // URI: what an attacker able to answer at STATUS_URI would serve.
          wrongSubject: await statusListJwt(issuer.keys.privateKey, x5c(issuer.cert), undefined, {
            sub: 'https://issuer.example/status/somebody-else',
          }),
          // Correctly signed and correctly addressed, but stale.
          expired: await statusListJwt(issuer.keys.privateKey, x5c(issuer.cert), undefined, {
            exp: Math.floor(new Date('2026-03-01T00:00:00Z').getTime() / 1000),
          }),
          // Expires between two checks, and well before the credential does, so
          // a test can cache it while fresh and read it back once it is not.
          expiringSoon: await statusListJwt(issuer.keys.privateKey, x5c(issuer.cert), undefined, {
            exp: Math.floor(new Date('2026-07-01T00:00:00Z').getTime() / 1000),
          }),
        },
        /**
         * One list per permitted status size, packed by the reference encoder.
         *
         * We unpack the bitstring ourselves rather than take the dependency, so
         * these pin our reading against their writing. Index 3 holds 1 and
         * index 7 holds the largest value the width allows; everything else is
         * zero. Only `bits: 1` occurs in the wild, which is exactly why the
         * others need fixtures.
         */
        statusListWidths: Object.fromEntries(
          await Promise.all(
            ([1, 2, 4, 8] as const).map(async (bits) => [
              bits,
              {
                uri: `https://issuer.example/status/bits/${bits}`,
                token: await statusListJwt(issuer.keys.privateKey, x5c(issuer.cert), undefined, {
                  sub: `https://issuer.example/status/bits/${bits}`,
                  bits,
                  statuses: { 3: 1, 7: 2 ** bits - 1 },
                }),
              },
            ]),
          ),
        ),
        /**
         * Certificate revocation, which answers a different question from the
         * status lists above: not "was this credential withdrawn" but "is the
         * key that signed it still trusted to have signed anything".
         */
        certificateRevocation: {
          crlUrl: CRL_URL,
          ocspUrl: OCSP_URL,
          issuerSerial: revocableSerial,
          credential: revocableCredential.presented,
          crls: {
            good: await makeCrl({ ca }),
            revoked: await makeCrl({
              ca,
              // 1 is keyCompromise, the reason that matters most here.
              revoked: [{ serialNumber: revocableSerial, reason: 1 }],
            }),
            // Someone else's serial: proves the lookup matches rather than
            // rejecting any CRL that has entries in it at all.
            someoneElseRevoked: await makeCrl({ ca, revoked: [{ serialNumber: '99', reason: 1 }] }),
            expired: await makeCrl({
              ca,
              thisUpdate: new Date('2026-01-01T00:00:00Z'),
              nextUpdate: new Date('2026-02-01T00:00:00Z'),
            }),
            noNextUpdate: await makeCrl({ ca, nextUpdate: undefined }),
            wrongSigner: await makeCrl({ ca, signWith: rogueCa }),
          },
          ocsp: {
            good: await makeOcspResponse({ certificate: revocable.cert, ca, status: 'good' }),
            revoked: await makeOcspResponse({ certificate: revocable.cert, ca, status: 'revoked' }),
            unknown: await makeOcspResponse({ certificate: revocable.cert, ca, status: 'unknown' }),
            expired: await makeOcspResponse({
              certificate: revocable.cert,
              ca,
              status: 'good',
              nextUpdate: new Date('2026-02-01T00:00:00Z'),
            }),
            /** responseStatus 3 is tryLater: the responder declining to answer. */
            tryLater: await makeOcspResponse({ certificate: revocable.cert, ca, status: 'good', responseStatus: 3 }),
            delegated: await makeOcspResponse({ certificate: revocable.cert, ca, status: 'good', responder }),
            delegatedRevoked: await makeOcspResponse({
              certificate: revocable.cert,
              ca,
              status: 'revoked',
              responder,
            }),
            delegatedWithoutEku: await makeOcspResponse({
              certificate: revocable.cert,
              ca,
              status: 'good',
              responder: responderNoEku,
            }),
          },
        },
        mdoc: {
          docType: mdocDocType,
          statusIndex: MDOC_STATUS_INDEX,
          statusUri: MDOC_STATUS_URI,
          devicePrivateJwk,
          withStatus: mdocWithStatus,
          withoutStatus: mdocWithoutStatus,
          revocableIssuer: mdocRevocableIssuer,
          statusLists: {
            valid: await statusListJwt(issuer.keys.privateKey, x5c(issuer.cert), undefined, {
              sub: MDOC_STATUS_URI,
            }),
            revoked: await statusListJwt(
              issuer.keys.privateKey,
              x5c(issuer.cert),
              MDOC_STATUS_INDEX,
              { sub: MDOC_STATUS_URI },
            ),
          },
        },
        credentials: {
          withStatus: withStatus.presented,
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
