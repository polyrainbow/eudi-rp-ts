import { DOMParser } from '@xmldom/xmldom';
import { type BinaryLike, type KeyLike, X509Certificate, constants, sign, verify } from 'node:crypto';
import { SignedXml } from 'xml-crypto';
import type { SignatureAlgorithm } from 'xml-crypto';
import xpath from 'xpath';
import { DEFAULT_TIMEOUT_MS, fetchText as fetchWithTimeout } from '../fetching.ts';
import { TrustAnchors } from './anchors.ts';

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
 *       ServiceInformation/{ServiceTypeIdentifier,ServiceStatus}
 *       ServiceDigitalIdentity/DigitalId/X509Certificate
 *
 * SIMPLIFIED — see README. We check the XML signature and that each service is
 * `granted`. We do NOT implement the full TS 119 615 algorithm: no service
 * status history, no validity-time evaluation against the credential date, no
 * qualifier processing, no `Sie` service information extensions.
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
};

export type TrustListResult = {
  anchors: TrustAnchors;
  /** Lists that were fetched successfully, for the operator to see. */
  sources: { territory: string; url: string; services: number }[];
  /** Lists that failed, with why. Failures are reported, never silent. */
  failures: { url: string; error: string }[];
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
  options: { territories?: string[]; fetchImpl?: typeof fetch } = {},
): Promise<TrustListResult> {
  const doFetch = options.fetchImpl ?? fetch;
  const lotlXml = await fetchText(doFetch, config.lotlUrl);

  const lotlAnchors = config.lotlSigningAnchorsPem
    ? TrustAnchors.fromPem(config.lotlSigningAnchorsPem)
    : undefined;
  verifyTrustList(lotlXml, {
    ...(lotlAnchors ? { expectedCerts: [...lotlAnchors.certificates] } : {}),
    skip: config.insecureSkipSignatureCheck,
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

  const certificates: X509Certificate[] = [];
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
      const services = parseServiceCertificates(xml, config.serviceTypes);
      certificates.push(...services);
      sources.push({ territory: pointer.territory, url: pointer.url, services: services.length });
    } catch (error) {
      failures.push({ url: pointer.url, error: error instanceof Error ? error.message : String(error) });
    }
  }

  if (certificates.length === 0) {
    throw new Error(
      `No trust anchors found in ${config.lotlUrl} (${failures.length} list(s) failed). ` +
        'Check LOTL_SERVICE_TYPES and LOTL_TERRITORIES.',
    );
  }

  return { anchors: TrustAnchors.fromCertificates(certificates), sources, failures };
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

/** Certificates of every `granted` service whose type passes the filter. */
export function parseServiceCertificates(xml: string, serviceTypes: string[]): X509Certificate[] {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const services = select('//tsl:TSPService', doc as unknown as Node) as Node[];
  const certificates: X509Certificate[] = [];

  for (const service of services) {
    if (text(first(select('.//tsl:ServiceStatus', service))) !== STATUS_GRANTED) continue;

    const type = text(first(select('.//tsl:ServiceTypeIdentifier', service)));
    if (serviceTypes.length > 0 && !serviceTypes.includes(type)) continue;

    for (const node of select('.//tsl:X509Certificate', service) as Node[]) {
      try {
        certificates.push(new X509Certificate(toPem(text(node))));
      } catch {
        // A single unparseable entry must not discard the rest of the list.
      }
    }
  }
  return certificates;
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
 * the price of Slovakia being in the set at all, and it is bounded by nothing
 * here today — this implementation does not evaluate list issue dates (see
 * "Trust lists are not fully TS 119 615" in the README).
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
