import { X509Certificate, createHash, verify as nodeVerify, randomBytes } from 'node:crypto';
import { AsnParser, AsnSerializer, OctetString } from '@peculiar/asn1-schema';
import {
  AlgorithmIdentifier,
  AuthorityInfoAccessSyntax,
  Extension,
  CRLDistributionPoints,
  Certificate,
  CertificateList,
  SubjectPublicKeyInfo,
  id_ce_cRLDistributionPoints,
  id_pe_authorityInfoAccess,
} from '@peculiar/asn1-x509';
import {
  BasicOCSPResponse,
  CertID,
  OCSPRequest,
  OCSPResponse,
  Request,
  TBSRequest,
  id_kp_OCSPSigning,
  id_pkix_ocsp_basic,
  id_pkix_ocsp_nonce,
} from '@peculiar/asn1-ocsp';
import { DEFAULT_TIMEOUT_MS, TtlCache, fetchBytes } from '../fetching.ts';
import { type Rejected, reject } from '../result.ts';

/**
 * Revocation of the issuer's *certificates* — CRL and OCSP.
 *
 * Distinct from Token Status List (`./status.ts`), which revokes a *credential*.
 * The two answer different questions and neither substitutes for the other: a
 * credential can be revoked while its issuer remains impeccable, and an issuer's
 * key can be compromised without any individual credential being withdrawn.
 *
 * **Why this is a separate step rather than part of path validation.** Path
 * validation is synchronous, and has to be: `@sd-jwt`'s `statusVerifier` is a
 * `(data, signature) => boolean` callback with nowhere to await. Revocation
 * needs the network. So `resolveIssuerCertificateChain` establishes the chain
 * and this runs against the chain it returned.
 *
 * **What is checked.** Every certificate in the path except the trust anchor,
 * each against the certificate above it. A self-signed anchor cannot meaningfully
 * revoke itself, and its withdrawal is expressed by leaving the trusted list.
 *
 * **OCSP first, CRL second, when a certificate publishes both.** An OCSP
 * response is one certificate's status now; a CRL is every revocation the CA has
 * ever issued, and is correspondingly staler and larger. If OCSP cannot be
 * reached the CRL is still tried, because two mechanisms both being down is a
 * different situation from one being down.
 *
 * Measured against the EU reference infrastructure on 2026-08-12: both the PID
 * document signer and its CA publish a CRL over https, and **neither runs an
 * OCSP responder** — the leaf's AIA carries `caIssuers` only. So CRL is the path
 * that is exercised against real infrastructure; see REPRODUCE.md.
 */

/** RFC 5280 §4.2.1.13 / RFC 6960. */
const ID_AD_OCSP = '1.3.6.1.5.5.7.48.1';

/**
 * Signature algorithms a CRL or OCSP response may be signed with.
 *
 * Unlike JWS and COSE, X.509 carries an ECDSA signature as a DER sequence, so
 * Node's default encoding is the right one here. An algorithm not in this table
 * is a refusal rather than a skip: a revocation document whose signature we
 * cannot check is one we have not checked.
 */
const SIGNATURE_ALGORITHMS: Record<string, { hash: string }> = {
  '1.2.840.10045.4.3.2': { hash: 'sha256' }, // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3': { hash: 'sha384' }, // ecdsa-with-SHA384
  '1.2.840.10045.4.3.4': { hash: 'sha512' }, // ecdsa-with-SHA512
  '1.2.840.113549.1.1.11': { hash: 'sha256' }, // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12': { hash: 'sha384' }, // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13': { hash: 'sha512' }, // sha512WithRSAEncryption
};

export type RevocationOutcome =
  | { kind: 'not-checked' }
  /** No certificate in the path published a CRL distribution point or a responder. */
  | { kind: 'no-mechanism' }
  | { kind: 'good'; via: 'crl' | 'ocsp' }
  | {
      kind: 'revoked';
      via: 'crl' | 'ocsp';
      /** Uppercase hex, as certificates print it. */
      serialNumber: string;
      subject: string;
      revokedAt: Date | undefined;
      /** RFC 5280 §5.3.1 CRLReason, when the document states one. */
      reason: number | undefined;
    }
  | { kind: 'unavailable'; detail: string }
  /**
   * The caller's signal fired. Separate from `unavailable` for the same reason
   * the status list keeps them apart: a deadline we set is not a CA that failed
   * to answer, and only one of those is the issuer's problem.
   */
  | { kind: 'aborted' };

export type RevocationCheckOptions = {
  now: Date;
  /** Injectable for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Abort a CRL or OCSP request after this long. */
  timeoutMs?: number;
  /**
   * Shared cache, keyed by responder or distribution point. Strongly
   * recommended: a CRL covers every certificate its CA ever issued, so without
   * one every verification refetches the same document.
   */
  cache?: TtlCache<Uint8Array>;
  /** Tolerance for clock differences with the CA, in seconds. */
  clockSkewSeconds?: number;
  /**
   * The caller's cancellation or overall deadline. Distinct from `timeoutMs`,
   * which bounds one request; a chain can need a CRL *and* an OCSP round trip
   * per certificate, so the per-request bound is not a bound on this call.
   */
  signal?: AbortSignal;
};

/**
 * A cache suitable for revocation documents.
 *
 * Shorter than the status list default, because a CRL states its own
 * `nextUpdate` and the EU reference CA republishes every two days: caching past
 * the document's own freshness window would only produce `unavailable` from a
 * document we already knew was stale. Failures are remembered briefly for the
 * same reason as status lists — an unreachable responder must not cost a full
 * timeout per credential.
 */
export function createRevocationCache(ttlMs = 60_000, errorTtlMs = 30_000): TtlCache<Uint8Array> {
  return new TtlCache<Uint8Array>({ ttlMs, errorTtlMs });
}

/**
 * Check every certificate in a resolved path except the anchor.
 *
 * Never throws: everything it can conclude is a `RevocationOutcome` and the
 * caller maps that to a reason code. The first revoked certificate wins — a
 * path with a revoked CA is not improved by the leaf being fine.
 */
export async function checkChainRevocation(
  chain: readonly X509Certificate[],
  options: RevocationCheckOptions,
): Promise<RevocationOutcome> {
  let checkedVia: 'crl' | 'ocsp' | undefined;
  let unavailable: string | undefined;

  // chain is leaf first, anchor last; each certificate is revoked by the one
  // above it, and the anchor has nothing above it.
  for (let index = 0; index < chain.length - 1; index += 1) {
    const certificate = chain[index]!;
    const issuer = chain[index + 1]!;

    // Checked per certificate, not only per request: a chain needs a round trip
    // for each one, so a signal that fired during the last is a reason not to
    // start the next.
    if (options.signal?.aborted) return { kind: 'aborted' };

    const responders = readOcspResponders(certificate);
    const distributionPoints = readCrlDistributionPoints(certificate);
    if (responders.length === 0 && distributionPoints.length === 0) continue;

    const outcome = await checkCertificate(certificate, issuer, responders, distributionPoints, options);
    if (outcome.kind === 'aborted') return outcome;
    if (outcome.kind === 'revoked') return outcome;
    if (outcome.kind === 'good') checkedVia ??= outcome.via;
    // Keep the first reason, then carry on: another certificate in the path may
    // be positively revoked, which is a stronger answer than "could not tell".
    if (outcome.kind === 'unavailable' && unavailable === undefined) unavailable = outcome.detail;
  }

  // One certificate we could not check is enough to sink the path, even if
  // another answered cleanly.
  if (unavailable !== undefined) return { kind: 'unavailable', detail: unavailable };
  return checkedVia ? { kind: 'good', via: checkedVia } : { kind: 'no-mechanism' };
}

/**
 * The rejection a revocation outcome implies, or undefined if it is not one.
 *
 * Shared so the two credential formats cannot drift apart on what a revoked
 * issuer means — the same mistake that let mdoc skip credential revocation
 * entirely.
 *
 * **Fails closed.** `unavailable` is a rejection, not a pass, on the same
 * reasoning as the status list: a verifier that accepts what it could not check
 * has no revocation at all. `no-mechanism` is different and *is* a pass — a CA
 * that published no CRL and no responder has not told us anything we are
 * ignoring.
 */
export function revocationRejection(outcome: RevocationOutcome): Rejected | undefined {
  if (outcome.kind === 'revoked') {
    const when = outcome.revokedAt ? ` on ${outcome.revokedAt.toISOString()}` : '';
    const why = outcome.reason === undefined ? '' : ` (reason ${outcome.reason})`;
    return reject(
      'ISSUER_CERTIFICATE_REVOKED',
      `${outcome.subject.split('\n')[0]} (serial ${outcome.serialNumber}) was revoked${when}${why}, per ${outcome.via.toUpperCase()}`,
    );
  }
  if (outcome.kind === 'unavailable') {
    return reject('ISSUER_REVOCATION_UNAVAILABLE', outcome.detail);
  }
  if (outcome.kind === 'aborted') {
    return reject('VERIFICATION_ABORTED', 'Cancelled while checking issuer certificate revocation');
  }
  return undefined;
}

/** Which mechanism produced an answer, for events and metrics. */
export function revocationVia(outcome: RevocationOutcome): 'crl' | 'ocsp' | undefined {
  return outcome.kind === 'good' || outcome.kind === 'revoked' ? outcome.via : undefined;
}

async function checkCertificate(
  certificate: X509Certificate,
  issuer: X509Certificate,
  responders: string[],
  distributionPoints: string[],
  options: RevocationCheckOptions,
): Promise<RevocationOutcome> {
  const problems: string[] = [];

  // An abort stops the walk rather than joining `problems`: trying the next
  // responder after the caller has given up is work nobody is waiting for, and
  // recording it as one more thing that did not answer would misreport why.
  for (const url of responders) {
    const outcome = await checkOcsp(certificate, issuer, url, options);
    if (outcome.kind === 'aborted') return outcome;
    if (outcome.kind === 'revoked' || outcome.kind === 'good') return outcome;
    if (outcome.kind === 'unavailable') problems.push(outcome.detail);
  }

  for (const url of distributionPoints) {
    const outcome = await checkCrl(certificate, issuer, url, options);
    if (outcome.kind === 'aborted') return outcome;
    if (outcome.kind === 'revoked' || outcome.kind === 'good') return outcome;
    if (outcome.kind === 'unavailable') problems.push(outcome.detail);
  }

  return { kind: 'unavailable', detail: problems.join('; ') || 'No usable revocation mechanism' };
}

/**
 * CRL distribution points that we could actually fetch (RFC 5280 §4.2.1.13).
 *
 * Only the `fullName` URI form is read. A `nameRelativeToCRLIssuer` names a
 * directory entry rather than something retrievable over HTTP, and an indirect
 * CRL issued by someone other than the certificate's own CA is not supported —
 * both are reported as unavailable by the caller rather than skipped, because
 * a distribution point we cannot follow is not one we have checked.
 */
export function readCrlDistributionPoints(certificate: X509Certificate): string[] {
  const extension = findExtension(certificate, id_ce_cRLDistributionPoints);
  if (!extension) return [];

  try {
    const points = AsnParser.parse(extension, CRLDistributionPoints);
    return points
      .flatMap((point) => point.distributionPoint?.fullName ?? [])
      .map((name) => name.uniformResourceIdentifier)
      .filter((uri): uri is string => typeof uri === 'string' && /^https?:/i.test(uri));
  } catch {
    return [];
  }
}

/** OCSP responder URLs from the Authority Information Access extension. */
export function readOcspResponders(certificate: X509Certificate): string[] {
  const extension = findExtension(certificate, id_pe_authorityInfoAccess);
  if (!extension) return [];

  try {
    const accesses = AsnParser.parse(extension, AuthorityInfoAccessSyntax);
    return accesses
      .filter((access) => access.accessMethod === ID_AD_OCSP)
      .map((access) => access.accessLocation.uniformResourceIdentifier)
      .filter((uri): uri is string => typeof uri === 'string' && /^https?:/i.test(uri));
  } catch {
    return [];
  }
}

/**
 * Fetch a CRL and look this certificate's serial number up in it.
 *
 * `http:` is allowed here, unlike almost everywhere else in this library. A CRL
 * is signed by the CA and verified below, so an attacker on the wire cannot
 * forge one — and RFC 5280 §4.2.1.13 distribution points are overwhelmingly
 * http in practice, precisely because the document authenticates itself. What
 * an attacker can still do is serve an *older* signed CRL, which is why
 * `nextUpdate` is enforced: a replayed CRL that has expired is refused, so the
 * replay window is the CA's own publication interval.
 */
async function checkCrl(
  certificate: X509Certificate,
  issuer: X509Certificate,
  url: string,
  options: RevocationCheckOptions,
): Promise<RevocationOutcome> {
  let der: Uint8Array;
  try {
    der = await load(`crl:${url}`, options, () =>
      fetchBytes(url, {
        headers: { Accept: 'application/pkix-crl' },
        timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        allowedProtocols: ['https:', 'http:'],
        ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
        ...(options.signal ? { signal: options.signal } : {}),
      }).then((response) => response.body),
    );
  } catch (error) {
    if (options.signal?.aborted) return { kind: 'aborted' };
    return { kind: 'unavailable', detail: `CRL ${url}: ${message(error)}` };
  }

  let crl: CertificateList;
  try {
    crl = AsnParser.parse(pemToDer(der), CertificateList);
  } catch (error) {
    return { kind: 'unavailable', detail: `CRL ${url} is not a CertificateList: ${message(error)}` };
  }

  // The signature covers the tbsCertList exactly as encoded, so the bytes are
  // sliced out of the document rather than re-serialised from the parse tree.
  const signed = firstInnerElement(pemToDer(der));
  if (!signed) {
    return { kind: 'unavailable', detail: `CRL ${url}: cannot locate the signed region` };
  }
  const verified = verifySignature(
    signed,
    new Uint8Array(crl.signature),
    crl.signatureAlgorithm.algorithm,
    issuer,
  );
  if (verified !== true) return { kind: 'unavailable', detail: `CRL ${url}: ${verified}` };

  const skew = (options.clockSkewSeconds ?? 0) * 1000;
  const thisUpdate = asDate(crl.tbsCertList.thisUpdate);
  const nextUpdate = asDate(crl.tbsCertList.nextUpdate);
  if (thisUpdate && options.now.getTime() + skew < thisUpdate.getTime()) {
    return { kind: 'unavailable', detail: `CRL ${url} is not yet valid (${thisUpdate.toISOString()})` };
  }
  // A CRL past its nextUpdate proves nothing about revocations since: accepting
  // it would turn "the CA stopped publishing" into "nothing has been revoked".
  if (nextUpdate && options.now.getTime() - skew > nextUpdate.getTime()) {
    return { kind: 'unavailable', detail: `CRL ${url} expired at ${nextUpdate.toISOString()}` };
  }
  if (!nextUpdate) {
    return { kind: 'unavailable', detail: `CRL ${url} states no nextUpdate, so its freshness cannot be bounded` };
  }

  const serial = serialHex(certificate);
  for (const entry of crl.tbsCertList.revokedCertificates ?? []) {
    if (hex(new Uint8Array(entry.userCertificate)) !== serial) continue;
    return {
      kind: 'revoked',
      via: 'crl',
      serialNumber: serial,
      subject: certificate.subject,
      revokedAt: asDate(entry.revocationDate),
      reason: crlEntryReason(entry),
    };
  }

  return { kind: 'good', via: 'crl' };
}

/**
 * Ask an OCSP responder about one certificate (RFC 6960).
 *
 * The request carries a nonce. If the response echoes one it must match, which
 * is what makes a captured response unusable later; responders that pre-sign
 * and therefore omit it are accepted, since a signed response bounded by its own
 * `nextUpdate` is the guarantee OCSP actually offers.
 */
async function checkOcsp(
  certificate: X509Certificate,
  issuer: X509Certificate,
  url: string,
  options: RevocationCheckOptions,
): Promise<RevocationOutcome> {
  const certId = buildCertId(certificate, issuer);
  const nonce = new Uint8Array(randomBytes(16));

  let der: Uint8Array;
  try {
    const request = AsnSerializer.serialize(
      new OCSPRequest({
        tbsRequest: new TBSRequest({
          requestList: [new Request({ reqCert: certId })],
          // Nonce ::= OCTET STRING, and extnValue wraps the DER of that value.
          requestExtensions: [
            new Extension({
              extnID: id_pkix_ocsp_nonce,
              critical: false,
              extnValue: new OctetString(derOctetString(nonce)),
            }),
          ],
        }),
      }),
    );

    // Keyed by serial as well as responder: unlike a CRL, an OCSP response
    // answers about one certificate only.
    der = await load(`ocsp:${url}:${serialHex(certificate)}`, options, () =>
      fetchBytes(url, {
        method: 'POST',
        headers: { 'content-type': 'application/ocsp-request', Accept: 'application/ocsp-response' },
        body: new Uint8Array(request),
        timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        allowedProtocols: ['https:', 'http:'],
        ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
        ...(options.signal ? { signal: options.signal } : {}),
      }).then((response) => response.body),
    );
  } catch (error) {
    if (options.signal?.aborted) return { kind: 'aborted' };
    return { kind: 'unavailable', detail: `OCSP ${url}: ${message(error)}` };
  }

  let response: OCSPResponse;
  try {
    response = AsnParser.parse(der, OCSPResponse);
  } catch (error) {
    return { kind: 'unavailable', detail: `OCSP ${url} is not an OCSPResponse: ${message(error)}` };
  }

  // 0 is `successful`; every other value is the responder declining to answer.
  if (response.responseStatus !== 0) {
    return { kind: 'unavailable', detail: `OCSP ${url} returned status ${response.responseStatus}` };
  }
  if (response.responseBytes?.responseType !== id_pkix_ocsp_basic) {
    return {
      kind: 'unavailable',
      detail: `OCSP ${url} returned an unsupported response type ${String(response.responseBytes?.responseType)}`,
    };
  }

  let basic: BasicOCSPResponse;
  let basicDer: Uint8Array;
  try {
    basicDer = new Uint8Array(response.responseBytes.response.buffer);
    basic = AsnParser.parse(basicDer, BasicOCSPResponse);
  } catch (error) {
    return { kind: 'unavailable', detail: `OCSP ${url}: cannot read the basic response: ${message(error)}` };
  }

  const signer = resolveOcspSigner(basic, issuer);
  if (typeof signer === 'string') return { kind: 'unavailable', detail: `OCSP ${url}: ${signer}` };

  const signed = firstInnerElement(basicDer);
  if (!signed) return { kind: 'unavailable', detail: `OCSP ${url}: cannot locate the signed region` };
  const verified = verifySignature(
    signed,
    new Uint8Array(basic.signature),
    basic.signatureAlgorithm.algorithm,
    signer,
  );
  if (verified !== true) return { kind: 'unavailable', detail: `OCSP ${url}: ${verified}` };

  const echoed = basic.tbsResponseData.responseExtensions?.find((e) => e.extnID === id_pkix_ocsp_nonce);
  if (echoed && !containsNonce(new Uint8Array(echoed.extnValue.buffer), nonce)) {
    return { kind: 'unavailable', detail: `OCSP ${url} echoed a nonce we did not send` };
  }

  const wanted = serialHex(certificate);
  for (const single of basic.tbsResponseData.responses) {
    if (hex(new Uint8Array(single.certID.serialNumber)) !== wanted) continue;

    const skew = (options.clockSkewSeconds ?? 0) * 1000;
    const nextUpdate = asDate(single.nextUpdate);
    if (nextUpdate && options.now.getTime() - skew > nextUpdate.getTime()) {
      return { kind: 'unavailable', detail: `OCSP ${url} response expired at ${nextUpdate.toISOString()}` };
    }

    if (single.certStatus.good !== undefined) return { kind: 'good', via: 'ocsp' };
    if (single.certStatus.revoked) {
      return {
        kind: 'revoked',
        via: 'ocsp',
        serialNumber: wanted,
        subject: certificate.subject,
        revokedAt: asDate(single.certStatus.revoked.revocationTime),
        reason:
          single.certStatus.revoked.revocationReason === undefined
            ? undefined
            : Number(single.certStatus.revoked.revocationReason),
      };
    }
    // `unknown` means the responder does not vouch for this certificate. It is
    // not a clean bill of health, so it is not treated as one.
    return { kind: 'unavailable', detail: `OCSP ${url} reports the certificate as unknown` };
  }

  return { kind: 'unavailable', detail: `OCSP ${url} answered about a different certificate` };
}

/**
 * Whose key signed a BasicOCSPResponse.
 *
 * Either the CA itself, or a responder it delegated to. A delegated responder
 * must be signed by that same CA and carry the `id-kp-OCSPSigning` extended key
 * usage — without that check, any certificate the CA ever issued could answer
 * for every certificate it ever issued.
 */
function resolveOcspSigner(basic: BasicOCSPResponse, issuer: X509Certificate): X509Certificate | string {
  for (const embedded of basic.certs ?? []) {
    let candidate: X509Certificate;
    try {
      candidate = new X509Certificate(Buffer.from(AsnSerializer.serialize(embedded)));
    } catch {
      continue;
    }
    if (!candidate.checkIssued(issuer) || !candidate.verify(issuer.publicKey)) continue;
    if (!(candidate.keyUsage ?? []).includes(id_kp_OCSPSigning)) {
      return 'the delegated responder lacks the id-kp-OCSPSigning extended key usage';
    }
    return candidate;
  }
  // No delegate offered: the CA is answering for itself.
  return issuer;
}

/** CertID identifies a certificate by its issuer's name and key, plus its serial. */
function buildCertId(certificate: X509Certificate, issuer: X509Certificate): CertID {
  const parsed = AsnParser.parse(certificate.raw, Certificate);
  // The certificate's own issuer field, encoded as it appears there: RFC 6960
  // hashes the DER of the name, so re-deriving it from the issuer certificate's
  // subject would work only while the two encodings agree.
  const issuerName = AsnSerializer.serialize(parsed.tbsCertificate.issuer);
  const spki = AsnParser.parse(
    issuer.publicKey.export({ type: 'spki', format: 'der' }),
    SubjectPublicKeyInfo,
  );

  return new CertID({
    // SHA-1 is what RFC 6960 §4.1.1 specifies for CertID, and it identifies a
    // name and a key here rather than standing as a security boundary: the
    // answer's integrity comes from the response signature, not this digest.
    hashAlgorithm: new AlgorithmIdentifier({ algorithm: '1.3.14.3.2.26', parameters: null }),
    issuerNameHash: new OctetString(createHash('sha1').update(Buffer.from(issuerName)).digest()),
    issuerKeyHash: new OctetString(createHash('sha1').update(Buffer.from(spki.subjectPublicKey)).digest()),
    serialNumber: evenLengthHex(certificate.serialNumber),
  });
}

/** `Buffer.from(hex)` silently drops a trailing nibble on an odd-length string. */
function evenLengthHex(serial: string): ArrayBuffer {
  const padded = serial.length % 2 === 0 ? serial : `0${serial}`;
  const buffer = Buffer.from(padded, 'hex');
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

/** DER OCTET STRING, for an extension value we build rather than parse. */
function derOctetString(contents: Uint8Array): ArrayBuffer {
  const header =
    contents.length < 0x80
      ? [0x04, contents.length]
      : contents.length < 0x100
        ? [0x04, 0x81, contents.length]
        : [0x04, 0x82, contents.length >> 8, contents.length & 0xff];
  return Uint8Array.from([...header, ...contents]).buffer;
}

function verifySignature(
  signed: Uint8Array,
  signature: Uint8Array,
  algorithmOid: string,
  signer: X509Certificate,
): true | string {
  const algorithm = SIGNATURE_ALGORITHMS[algorithmOid];
  if (!algorithm) return `unsupported signature algorithm ${algorithmOid}`;

  try {
    // X.509 carries ECDSA as a DER sequence, which is Node's default — the
    // opposite of the ieee-p1363 form JWS and COSE use.
    const ok = nodeVerify(algorithm.hash, Buffer.from(signed), signer.publicKey, Buffer.from(signature));
    return ok ? true : `signature does not verify against ${signer.subject.split('\n')[0]}`;
  } catch (error) {
    return `signature could not be checked: ${message(error)}`;
  }
}

/**
 * The complete encoding of the first element inside a DER SEQUENCE.
 *
 * Both `CertificateList` and `BasicOCSPResponse` are a SEQUENCE whose first
 * member is the structure the signature covers. Taking those bytes verbatim is
 * the only way to be sure of what was signed — re-serialising a parse tree
 * reproduces the same value but not necessarily the same bytes, and a
 * difference presents as a bad signature.
 */
function firstInnerElement(der: Uint8Array): Uint8Array | undefined {
  const outer = readTlv(der, 0);
  if (!outer || outer.tag !== 0x30) return undefined;
  const inner = readTlv(der, outer.contentStart);
  if (!inner) return undefined;
  return der.subarray(inner.start, inner.end);
}

function readTlv(
  der: Uint8Array,
  offset: number,
): { tag: number; start: number; contentStart: number; end: number } | undefined {
  if (offset + 1 >= der.length) return undefined;
  const tag = der[offset]!;
  let cursor = offset + 1;
  const first = der[cursor]!;
  cursor += 1;

  let length: number;
  if (first < 0x80) {
    length = first;
  } else {
    const count = first & 0x7f;
    // Indefinite length is not valid DER, and a length field this long would
    // exceed anything we are willing to hold in memory anyway.
    if (count === 0 || count > 4 || cursor + count > der.length) return undefined;
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + der[cursor + i]!;
    cursor += count;
  }

  const end = cursor + length;
  if (end > der.length) return undefined;
  return { tag, start: offset, contentStart: cursor, end };
}

/** Accept a PEM-armoured CRL as well as raw DER; some CAs serve either. */
function pemToDer(bytes: Uint8Array): Uint8Array {
  if (bytes[0] === 0x30) return bytes;
  const text = Buffer.from(bytes).toString('utf8');
  const match = /-----BEGIN X509 CRL-----([\s\S]+?)-----END X509 CRL-----/.exec(text);
  if (!match) return bytes;
  return new Uint8Array(Buffer.from(match[1]!.replace(/\s+/g, ''), 'base64'));
}

/**
 * Fetch through the cache, without letting a cancellation be remembered as one.
 *
 * `createRevocationCache` remembers failures, which is right for a responder
 * that is down and wrong for a caller who hung up: the entry is shared, so one
 * aborted verification would answer `ISSUER_REVOCATION_UNAVAILABLE` for every
 * other caller of the same CRL until it expired. A CRL covers every certificate
 * its CA ever issued, so that is a wide blast radius for one client's timeout.
 */
async function load(
  key: string,
  options: RevocationCheckOptions,
  fetcher: () => Promise<Uint8Array>,
): Promise<Uint8Array> {
  if (!options.cache) return fetcher();
  try {
    return await options.cache.get(key, fetcher);
  } catch (error) {
    if (options.signal?.aborted) options.cache.delete(key);
    throw error;
  }
}

function findExtension(certificate: X509Certificate, oid: string): ArrayBuffer | undefined {
  const parsed = AsnParser.parse(certificate.raw, Certificate);
  const extension = parsed.tbsCertificate.extensions?.find((e) => e.extnID === oid);
  return extension?.extnValue.buffer;
}

function crlEntryReason(entry: { crlEntryExtensions?: { extnID: string; extnValue: { buffer: ArrayBuffer } }[] }): number | undefined {
  const extension = entry.crlEntryExtensions?.find((e) => e.extnID === '2.5.29.21');
  if (!extension) return undefined;
  const der = new Uint8Array(extension.extnValue.buffer);
  // ENUMERATED, one content byte in every reason code RFC 5280 defines.
  return der[0] === 0x0a && der[1] === 0x01 ? der[2] : undefined;
}

function containsNonce(extnValue: Uint8Array, nonce: Uint8Array): boolean {
  return Buffer.from(extnValue).includes(Buffer.from(nonce));
}

function serialHex(certificate: X509Certificate): string {
  return certificate.serialNumber.replace(/^0+/, '').toUpperCase();
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex').replace(/^0+/, '').toUpperCase();
}

function asDate(value: unknown): Date | undefined {
  if (value instanceof Date) return value;
  if (value && typeof value === 'object') {
    const time = value as { utcTime?: Date; generalTime?: Date; getTime?: () => Date };
    const found = time.utcTime ?? time.generalTime ?? time.getTime?.();
    if (found instanceof Date) return found;
  }
  return undefined;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
