import { DOMParser } from '@xmldom/xmldom';
import { type BinaryLike, type KeyLike, X509Certificate, constants, sign, verify } from 'node:crypto';
import { SignedXml } from 'xml-crypto';
import type { SignatureAlgorithm } from 'xml-crypto';
import xpath from 'xpath';
import { DEFAULT_TIMEOUT_MS, fetchText as fetchWithTimeout } from '../fetching.ts';
import { TrustAnchors, type TrustServiceEntry } from './anchors.ts';

/**
 * ETSI TS 119 612 trust list client.
 *
 * There is no Node implementation of this, so it is written here. The shape
 * below was read off the live EU List of Trusted Lists and a national list, not
 * inferred from the prose spec:
 *
 *   TrustServiceStatusList              (xmlns http://uri.etsi.org/02231/v2#)
 *     SchemeInformation/PointersToOtherTSL/OtherTSLPointer
 *       ServiceDigitalIdentities/…/X509Certificate   <- signing certs for that list
 *       TSLLocation                                   <- where the national list lives
 *       AdditionalInformation/…/{TSLType,SchemeTerritory}
 *     TrustServiceProviderList/…/TSPService
 *       ServiceInformation/{ServiceTypeIdentifier,ServiceStatus,StatusStartingTime}
 *         ServiceDigitalIdentity/DigitalId/X509Certificate
 *       ServiceHistory/ServiceHistoryInstance/{…the same, as it was before…}
 *
 * SIMPLIFIED — see README. We check the XML signature, the list's own freshness
 * (`ListIssueDateTime` and `NextUpdate`), and evaluate each service's status *at
 * a given instant* against its declared starting time and status history. We do
 * NOT implement the rest of the TS 119 615 algorithm: no qualifier processing
 * and no `Sie` service information extensions.
 */

const TSL_NS = 'http://uri.etsi.org/02231/v2#';
const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
const LIST_OF_LISTS = 'http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists';
const STATUS_GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const ADDTYPES_NS = 'http://uri.etsi.org/02231/v2/additionaltypes#';
const TSL_MIME_TYPE = 'application/vnd.etsi.tsl+xml';

const select = xpath.useNamespaces({ tsl: TSL_NS, ds: DSIG_NS, add: ADDTYPES_NS });

/**
 * RSASSA-PSS, which xml-crypto does not ship.
 *
 * Several member states sign with it — Germany's list is `sha256-rsa-MGF1` —
 * so without this the largest national lists simply fail to verify. Salt length
 * equals the digest length, per the RFC 4055 default that XMLDSig uses.
 */
class RsaPssSha256 implements SignatureAlgorithm {
  getSignature(signedInfo: BinaryLike, privateKey: KeyLike): string {
    return sign('sha256', Buffer.from(signedInfo as string), {
      key: privateKey as never,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    }).toString('base64');
  }

  verifySignature(material: string, key: KeyLike, signatureValue: string): boolean {
    return verify(
      'sha256',
      Buffer.from(material),
      { key: key as never, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
      Buffer.from(signatureValue, 'base64'),
    );
  }

  getAlgorithmName() {
    return RSA_PSS_SHA256 as never;
  }
}

const RSA_PSS_SHA256 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';

/**
 * ECDSA, which xml-crypto does not ship either.
 *
 * Greece and Slovenia sign with `ecdsa-sha512`, Hungary with `ecdsa-sha256`;
 * without these three lists fail to load and their anchors are simply absent.
 *
 * The detail that matters is the signature encoding. XMLDSig carries an ECDSA
 * signature as the raw r‖s pair (RFC 4051 §2.3.6, IEEE P1363), while Node
 * defaults to the DER sequence — so verification fails on a correct signature
 * unless `dsaEncoding` says otherwise.
 */
function ecdsaAlgorithm(uri: string, hash: 'sha256' | 'sha384' | 'sha512') {
  return class implements SignatureAlgorithm {
    getSignature(signedInfo: BinaryLike, privateKey: KeyLike): string {
      return sign(hash, Buffer.from(signedInfo as string), {
        key: privateKey as never,
        dsaEncoding: 'ieee-p1363',
      }).toString('base64');
    }

    verifySignature(material: string, key: KeyLike, signatureValue: string): boolean {
      return verify(
        hash,
        Buffer.from(material),
        { key: key as never, dsaEncoding: 'ieee-p1363' },
        Buffer.from(signatureValue, 'base64'),
      );
    }

    getAlgorithmName() {
      return uri as never;
    }
  };
}

export const XMLDSIG_ECDSA = ['sha256', 'sha384', 'sha512'].map((hash) => ({
  uri: `http://www.w3.org/2001/04/xmldsig-more#ecdsa-${hash}`,
  implementation: ecdsaAlgorithm(
    `http://www.w3.org/2001/04/xmldsig-more#ecdsa-${hash}`,
    hash as 'sha256' | 'sha384' | 'sha512',
  ),
}));

/** Everything the trust list client needs. The app maps its config onto this. */
export type TrustListOptions = {
  /** Trust list location, e.g. the EU List of Trusted Lists. */
  lotlUrl: string;
  /** Service type URIs to accept. Empty means any. */
  serviceTypes: string[];
  /** Certificates the list's own signature must chain to. Empty means unchecked. */
  lotlSigningAnchorsPem: string | undefined;
  /** Never enable outside development. */
  insecureSkipSignatureCheck: boolean;
  /**
   * Accept a list that is past its own `NextUpdate`, or that declares none.
   *
   * Never enable outside development. It exists because the freshness rule
   * depends on other people republishing on time: if the Commission or a Member
   * State misses a republication, every deployment loses those anchors at once,
   * and an operator who has weighed that against the replay risk needs a local
   * remedy that does not involve waiting for a release.
   */
  insecureSkipFreshnessCheck?: boolean;
};

export type TrustListResult = {
  anchors: TrustAnchors;
  /** Lists that were fetched successfully, for the operator to see. */
  sources: {
    territory: string;
    url: string;
    services: number;
    /** The list's own `ListIssueDateTime`, or undefined if unchecked. */
    issued: Date | undefined;
    /** The list's own `NextUpdate`, or undefined if unchecked. */
    nextUpdate: Date | undefined;
  }[];
  /** Lists that failed, with why. Failures are reported, never silent. */
  failures: { url: string; error: string }[];
  /**
   * When the earliest of these lists stops being current.
   *
   * A caller that holds this anchor set — every service does, between
   * refreshes — needs the same answer the library gives itself: a set built
   * from a list past its `NextUpdate` is exactly the stale copy
   * `checkTrustListFreshness` refuses, so continuing to verify against it after
   * this instant contradicts the check that produced it. Undefined only when
   * freshness was not checked at all.
   */
  validUntil: Date | undefined;
};

export type Pointer = {
  territory: string;
  url: string;
  type: string;
  /** Each list is published as XML and as a human-readable PDF. */
  mimeType: string;
  signingCerts: string[];
};

/**
 * Build a trust anchor set from a trust list.
 *
 * Fetches the LOTL, verifies its signature, follows each national list pointer,
 * verifies each national list against the certificates the LOTL published for
 * it, and collects the certificates of granted services.
 */
export async function fetchTrustAnchors(
  config: TrustListOptions,
  options: { territories?: string[]; fetchImpl?: typeof fetch; now?: Date } = {},
): Promise<TrustListResult> {
  const doFetch = options.fetchImpl ?? fetch;
  const now = options.now ?? new Date();
  const lotlXml = await fetchText(doFetch, config.lotlUrl);

  const lotlAnchors = config.lotlSigningAnchorsPem
    ? TrustAnchors.fromPem(config.lotlSigningAnchorsPem)
    : undefined;
  verifyTrustList(lotlXml, {
    ...(lotlAnchors ? { expectedCerts: [...lotlAnchors.certificates] } : {}),
    skip: config.insecureSkipSignatureCheck,
    label: config.lotlUrl,
  });
  // Before the pointers are read, not after: a stale LOTL names both the
  // locations of the national lists and the certificates that authenticate
  // them, so following it would spread a replayed root through everything below.
  const lotlFreshness = checkTrustListFreshness(lotlXml, {
    now,
    skip: config.insecureSkipFreshnessCheck ?? false,
    label: config.lotlUrl,
  });

  const pointers = parsePointers(lotlXml).filter(
    (pointer) =>
      // The LOTL points at itself; following that would recurse forever.
      pointer.type !== LIST_OF_LISTS &&
      // Every list is also pointed at as a PDF for humans. Skip those.
      pointer.mimeType === TSL_MIME_TYPE,
  );
  const wanted = options.territories?.length
    ? pointers.filter((p) => options.territories!.includes(p.territory))
    : pointers;

  const services: TrustServiceEntry[] = [];
  const sources: TrustListResult['sources'] = [];
  const failures: TrustListResult['failures'] = [];

  for (const pointer of wanted) {
    try {
      const xml = await fetchText(doFetch, pointer.url, NATIONAL_LIST_PROTOCOLS);
      verifyTrustList(xml, {
        // A national list is authenticated by the certificates the (signed)
        // LOTL published for it. That is the whole point of the LOTL.
        expectedCerts: pointer.signingCerts.map((pem) => new X509Certificate(pem)),
        skip: config.insecureSkipSignatureCheck,
        label: pointer.url,
      });
      // A national list that has lapsed costs that territory's anchors and
      // nothing else: the throw lands in `failures` below, where the operator
      // sees which list it was and why.
      const freshness = checkTrustListFreshness(xml, {
        now,
        skip: config.insecureSkipFreshnessCheck ?? false,
        label: pointer.url,
      });
      const parsed = parseTrustServices(xml, config.serviceTypes);
      services.push(...parsed);
      sources.push({
        territory: pointer.territory,
        url: pointer.url,
        services: parsed.length,
        issued: freshness?.issued,
        nextUpdate: freshness?.nextUpdate,
      });
    } catch (error) {
      failures.push({ url: pointer.url, error: error instanceof Error ? error.message : String(error) });
    }
  }

  if (services.length === 0) {
    throw new Error(
      `No trust anchors found in ${config.lotlUrl} (${failures.length} list(s) failed). ` +
        'Check LOTL_SERVICE_TYPES and LOTL_TERRITORIES.',
    );
  }

  // The earliest horizon among every list that contributed, the LOTL included:
  // the set is only as current as its stalest part, and one Member State
  // republishing does not renew another's.
  const horizons = [lotlFreshness?.nextUpdate, ...sources.map((source) => source.nextUpdate)].filter(
    (date): date is Date => date !== undefined,
  );
  const validUntil = horizons.length
    ? new Date(Math.min(...horizons.map((date) => date.getTime())))
    : undefined;

  return { anchors: TrustAnchors.fromTrustServices(services), sources, failures, validUntil };
}

/** Verify a trust list's enveloped XML signature. */
export function verifyTrustList(
  xml: string,
  options: { expectedCerts?: X509Certificate[]; skip?: boolean; label: string },
): void {
  if (options.skip) return;

  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const signatureNode = (select('//ds:Signature', doc as unknown as Node) as Node[])[0];
  if (!signatureNode) throw new Error(`${options.label}: no XML signature`);

  const keyInfo = (select('./ds:KeyInfo', signatureNode) as Node[])[0];
  const signingCertPem = keyInfo ? SignedXml.getCertFromKeyInfo(keyInfo) : null;
  if (!signingCertPem) throw new Error(`${options.label}: signature has no KeyInfo certificate`);

  const signedXml = new SignedXml({ publicCert: signingCertPem });
  // Registered per instance; xml-crypto exposes the table on the object.
  signedXml.SignatureAlgorithms[RSA_PSS_SHA256 as never] = RsaPssSha256;
  for (const { uri, implementation } of XMLDSIG_ECDSA) {
    signedXml.SignatureAlgorithms[uri as never] = implementation;
  }
  signedXml.loadSignature(signatureNode);
  if (!signedXml.checkSignature(xml)) {
    throw new Error(`${options.label}: XML signature is not valid`);
  }

  // A valid self-referential signature proves nothing on its own — the signing
  // certificate must also be one we were told to expect.
  if (options.expectedCerts?.length) {
    const actual = new X509Certificate(signingCertPem);
    const trusted = options.expectedCerts.some((c) => c.fingerprint256 === actual.fingerprint256);
    if (!trusted) {
      throw new Error(`${options.label}: signed by an unexpected certificate (${actual.subject})`);
    }
  }
}

/**
 * Refuse a trust list that is not current.
 *
 * A signature proves who wrote a list, never when. Every list here is fetched
 * from a location named by another document and — for the national lists — may
 * arrive over plain http (see `NATIONAL_LIST_PROTOCOLS`), so a signed copy from
 * last year verifies exactly as well as today's. The difference is what it
 * grants: a service withdrawn since is still granted by the old list, which is
 * the whole point of withdrawing it.
 *
 * TS 119 612 §5.3.13 gives each list the two fields needed to bound that, and
 * this treats them as `src/trust/revocation.ts` treats a CRL's `thisUpdate` and
 * `nextUpdate` — the same problem, and the same answer:
 *
 *  - past `NextUpdate` — refused. The replay window becomes the publisher's own
 *    republication interval, which is six months for every list measured
 *    (REPRODUCE.md) rather than unbounded.
 *  - **no** `NextUpdate` — refused, because freshness cannot be bounded at all.
 *    ETSI requires the element and every live list carries it; exactly one
 *    leaves it *empty*, and it is the United Kingdom's, frozen at
 *    2020-12-31T22:59:59Z on withdrawal from the EU. So the strict reading
 *    costs one list that has been unmaintained for five years — which is the
 *    case the rule is for, not a case against it.
 *  - issued in the future — refused, as a document that cannot be describing
 *    the present.
 *
 * Not covered: replay of an *older but still fresh* list. Catching that means
 * remembering the highest `TSLSequenceNumber` seen per list across restarts,
 * which is persistent state this library deliberately does not hold.
 *
 * Returns the two dates rather than only throwing, because a caller holding the
 * resulting anchors needs to know how long they remain defensible — see
 * `TrustListResult.validUntil`. `undefined` is returned only when the check was
 * skipped, so a caller cannot mistake "not checked" for "fresh forever".
 */
export function checkTrustListFreshness(
  xml: string,
  options: { now?: Date; clockSkewSeconds?: number; skip?: boolean; label: string },
): { issued: Date; nextUpdate: Date } | undefined {
  if (options.skip) return undefined;

  const now = options.now ?? new Date();
  const skew = (options.clockSkewSeconds ?? 0) * 1000;
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  // Anchored at the root rather than `//`: `SchemeInformation` is where the
  // list describes *itself*, and a descendant search would be satisfied by any
  // element of that name a future schema nests somewhere else.
  const scheme = first(select('/tsl:TrustServiceStatusList/tsl:SchemeInformation', doc as unknown as Node));
  if (!scheme) throw new Error(`${options.label}: no SchemeInformation, so its freshness cannot be judged`);

  const issued = new Date(text(first(select('./tsl:ListIssueDateTime', scheme))));
  if (Number.isNaN(issued.getTime())) {
    throw new Error(`${options.label}: no readable ListIssueDateTime`);
  }
  if (issued.getTime() - skew > now.getTime()) {
    throw new Error(`${options.label}: issued in the future (${issued.toISOString()})`);
  }

  const nextUpdateText = text(first(select('./tsl:NextUpdate/tsl:dateTime', scheme)));
  if (!nextUpdateText) {
    throw new Error(
      `${options.label}: states no NextUpdate (issued ${issued.toISOString()}), ` +
        'so its freshness cannot be bounded',
    );
  }
  const nextUpdate = new Date(nextUpdateText);
  if (Number.isNaN(nextUpdate.getTime())) {
    throw new Error(`${options.label}: NextUpdate is not a readable date (${nextUpdateText})`);
  }
  if (now.getTime() - skew > nextUpdate.getTime()) {
    throw new Error(
      `${options.label}: expired at ${nextUpdate.toISOString()} (issued ${issued.toISOString()})`,
    );
  }

  return { issued, nextUpdate };
}

export function parsePointers(xml: string): Pointer[] {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const nodes = select('//tsl:OtherTSLPointer', doc as unknown as Node) as Node[];

  return nodes.map((node) => ({
    url: text(first(select('./tsl:TSLLocation', node))),
    territory: text(first(select('.//tsl:SchemeTerritory', node))),
    type: text(first(select('.//tsl:TSLType', node))),
    mimeType: text(first(select('.//add:MimeType', node))),
    signingCerts: (select('.//tsl:X509Certificate', node) as Node[]).map((c) => toPem(text(c))),
  }));
}

/**
 * Every service certificate, with the periods it was granted for.
 *
 * A `TSPService` carries its current status in `ServiceInformation` and, for
 * two thirds of the services actually published, the statuses that preceded it
 * in `ServiceHistory/ServiceHistoryInstance`. Each of those entries has its own
 * status, its own starting time, and its own digital identity.
 *
 * The entries are read separately rather than flattened, for two reasons.
 *
 * A status only applies from its `StatusStartingTime`, so "granted" is a period
 * rather than a fact — 223 of the services on eight member states' lists became
 * granted during 2026 alone, and none of them vouches for anything signed
 * before that. Sorting the entries turns each one into a half-open interval
 * ending where the next begins.
 *
 * And a certificate belongs to the entry that names it. Scoping the search to
 * the whole `TSPService`, as this once did, harvests the digital identities of
 * *superseded* entries as though they were current — a certificate retired in
 * 2019 would be loaded as a present-day anchor purely because the service that
 * replaced it is granted today.
 */
export function parseTrustServices(xml: string, serviceTypes: string[]): TrustServiceEntry[] {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const services = select('//tsl:TSPService', doc as unknown as Node) as Node[];
  const entries: TrustServiceEntry[] = [];

  for (const service of services) {
    // Deliberately not `.//`: the current status lives in ServiceInformation,
    // and a descendant search would also match every history instance.
    const current = readEntry(first(select('./tsl:ServiceInformation', service)));
    const history = (select('./tsl:ServiceHistory/tsl:ServiceHistoryInstance', service) as Node[])
      .map(readEntry)
      .filter((entry): entry is ParsedEntry => entry !== undefined)
      // Ascending, so each entry runs until the next one starts. The document
      // lists history newest-first, which would otherwise invert every interval.
      .sort((a, b) => a.startingTime.getTime() - b.startingTime.getTime());

    // ServiceInformation is the status in effect, by definition, so it runs to
    // infinity whatever the history says. It is deliberately not sorted in
    // among the historical entries: Poland republishes the current entry as a
    // history instance carrying the *same* StatusStartingTime, which ordering
    // alone would turn into a zero-length interval and silently drop the
    // service. Timestamps in a status history are data, not a source of truth
    // about which entry is current.
    const timeline: { entry: ParsedEntry; until: Date | undefined }[] = history.map((entry, index) => ({
      entry,
      until: history[index + 1]?.startingTime ?? current?.startingTime,
    }));
    if (current) timeline.push({ entry: current, until: undefined });

    for (const { entry, until } of timeline) {
      if (entry.status !== STATUS_GRANTED) continue;
      if (serviceTypes.length > 0 && !serviceTypes.includes(entry.type)) continue;
      // An interval that ends before it begins covers nothing. That means the
      // list contradicts itself — a superseded entry dated at or after the one
      // that replaced it — so the safe reading is that it grants nothing.
      if (until !== undefined && until <= entry.startingTime) continue;

      const granted = [{ from: entry.startingTime, until }];
      for (const certificate of entry.certificates) {
        entries.push({ certificate, granted });
      }
    }
  }

  return entries;
}

type ParsedEntry = {
  status: string;
  type: string;
  startingTime: Date;
  certificates: X509Certificate[];
};

/**
 * One `ServiceInformation` or `ServiceHistoryInstance`.
 *
 * An entry with no readable `StatusStartingTime` is dropped rather than assumed
 * to have applied forever: it is the only thing that says when the status began,
 * and inventing one would make up the answer to the question being asked. ETSI
 * requires the element, and across 2797 services on eight member states' lists —
 * plus 3330 history instances — every single one carries it, so nothing real is
 * lost by insisting. See REPRODUCE.md.
 */
function readEntry(node: Node | undefined): ParsedEntry | undefined {
  if (!node) return undefined;
  const startingTime = new Date(text(first(select('./tsl:StatusStartingTime', node))));
  if (Number.isNaN(startingTime.getTime())) return undefined;

  const certificates: X509Certificate[] = [];
  for (const certificate of select('.//tsl:X509Certificate', node) as Node[]) {
    try {
      certificates.push(new X509Certificate(toPem(text(certificate))));
    } catch {
      // A single unparseable entry must not discard the rest of the list.
    }
  }

  return {
    status: text(first(select('./tsl:ServiceStatus', node))),
    type: text(first(select('./tsl:ServiceTypeIdentifier', node))),
    startingTime,
    certificates,
  };
}

/**
 * Certificates of every service granted *now*.
 *
 * The historical view is `parseTrustServices`; this is the answer to the
 * narrower question, kept because it is the one most callers have.
 */
export function parseServiceCertificates(xml: string, serviceTypes: string[]): X509Certificate[] {
  const now = new Date();
  return parseTrustServices(xml, serviceTypes)
    .filter((entry) =>
      entry.granted.some(({ from, until }) => now >= from && (until === undefined || now < until)),
    )
    .map((entry) => entry.certificate);
}

/**
 * Headroom over the largest list actually published.
 *
 * Germany's was 5.4 MB on 2026-08-11, the largest of the set; see REPRODUCE.md.
 * The general ceiling in `fetching.ts` is sized for status lists and would leave
 * a growing national list less than a factor of two before it broke.
 */
const TRUST_LIST_MAX_BYTES = 20_000_000;

/**
 * National lists may be served over http; the LOTL may not.
 *
 * Slovakia publishes its `TSLLocation` as `http://tl.nbu.gov.sk/...`, and
 * refusing it costs every Slovak anchor. Allowing it is defensible for a
 * national list and only for a national list: its content is authenticated by
 * an XML signature made with a certificate that the LOTL — fetched over https
 * and signature-checked itself — published for exactly that list. An attacker
 * on an http hop therefore cannot forge one.
 *
 * What they *can* still do is replay an older signed copy, and a stale list may
 * still grant a service that has since been withdrawn. That residual risk is
 * the price of Slovakia being in the set at all, and `checkTrustListFreshness`
 * bounds it: a replayed copy is refused once it passes the `NextUpdate` the
 * publisher itself declared. What remains is replay of a copy still inside that
 * window — six months, for every list measured.
 *
 * The LOTL keeps the https-only default because it is the root: it is where
 * both the locations and the signing certificates come from, so an attacker who
 * can rewrite it can point at anything.
 */
const NATIONAL_LIST_PROTOCOLS = ['https:', 'http:'];

async function fetchText(
  doFetch: typeof fetch,
  url: string,
  allowedProtocols?: readonly string[],
): Promise<string> {
  // Trust lists are fetched from 40-odd national endpoints; one that never
  // answers must not stall startup indefinitely. A list that trips the size
  // limit or the redirect budget is recorded in `failures` rather than failing
  // the whole run.
  const { body } = await fetchWithTimeout(url, {
    fetchImpl: doFetch,
    timeoutMs: DEFAULT_TIMEOUT_MS * 3,
    maxBytes: TRUST_LIST_MAX_BYTES,
    ...(allowedProtocols ? { allowedProtocols } : {}),
  });
  return body;
}

function first(nodes: unknown): Node | undefined {
  return Array.isArray(nodes) ? (nodes[0] as Node | undefined) : undefined;
}

function text(node: unknown): string {
  return ((node as Node | undefined)?.textContent ?? '').trim();
}

function toPem(base64Der: string): string {
  const body = base64Der.replace(/\s+/g, '').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
}
