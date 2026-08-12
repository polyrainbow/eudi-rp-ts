import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { X509Certificate, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { resolveIssuerKeyFromX5c } from '../src/trust/issuer-key.ts';
import {
  XMLDSIG_ECDSA,
  parsePointers,
  parseServiceCertificates,
  parseTrustServices,
  verifyTrustList,
} from '../src/trust/lotl.ts';

/** Network tests are opt-in: RUN_NETWORK_TESTS=1 npm test */
const online = process.env['RUN_NETWORK_TESTS'] === '1';

const TSL = 'http://uri.etsi.org/02231/v2#';
const ADD = 'http://uri.etsi.org/02231/v2/additionaltypes#';
const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const WITHDRAWN = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn';
const CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';
const TSA = 'http://uri.etsi.org/TrstSvc/Svctype/TSA';

/** A real certificate, so a service that should be collected actually can be. */
const anchorPem = readFileSync(
  fileURLToPath(new URL('./fixtures/trust-anchor.pem', import.meta.url)),
  'utf8',
);
const ANCHOR = new X509Certificate(anchorPem);
const ANCHOR_B64 = anchorPem.replace(/-----[^-]+-----|\s/g, '');

/**
 * `StatusStartingTime` is not decoration: a status applies from an instant, and
 * every one of the 2797 services on the live lists carries it (REPRODUCE.md).
 * Defaulted here so each test states only the part it is about.
 */
function entryXml(status: string, type: string, certB64: string, startingTime = '2020-01-01T00:00:00Z') {
  return `<ServiceTypeIdentifier>${type}</ServiceTypeIdentifier>
      <ServiceStatus>${status}</ServiceStatus>
      <StatusStartingTime>${startingTime}</StatusStartingTime>
      <ServiceDigitalIdentity><DigitalId><X509Certificate>${certB64}</X509Certificate></DigitalId></ServiceDigitalIdentity>`;
}

function serviceXml(status: string, type: string, certB64: string, startingTime?: string) {
  return `<TSPService><ServiceInformation>
      ${entryXml(status, type, certB64, startingTime)}
    </ServiceInformation></TSPService>`;
}

/** A service with a status history, newest entry first as the lists publish it. */
function serviceWithHistoryXml(
  current: { status: string; startingTime: string; cert?: string },
  history: { status: string; startingTime: string; cert?: string }[],
) {
  const instances = history
    .map(
      (h) =>
        `<ServiceHistoryInstance>${entryXml(h.status, CA_QC, h.cert ?? ANCHOR_B64, h.startingTime)}</ServiceHistoryInstance>`,
    )
    .join('');
  return `<TSPService>
      <ServiceInformation>${entryXml(current.status, CA_QC, current.cert ?? ANCHOR_B64, current.startingTime)}</ServiceInformation>
      <ServiceHistory>${instances}</ServiceHistory>
    </TSPService>`;
}

function listXml(...services: string[]) {
  return `<TrustServiceStatusList xmlns="${TSL}"><TrustServiceProviderList><TrustServiceProvider><TSPServices>
      ${services.join('')}
    </TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`;
}

describe('trust list parsing', () => {
  it('reads national list pointers, including the certificates that sign them', () => {
    const xml = `<TrustServiceStatusList xmlns="${TSL}" xmlns:add="${ADD}"><SchemeInformation><PointersToOtherTSL>
      <OtherTSLPointer>
        <ServiceDigitalIdentities><ServiceDigitalIdentity><DigitalId>
          <X509Certificate>AAAA</X509Certificate>
        </DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>
        <TSLLocation>https://example.test/tl-de.xml</TSLLocation>
        <AdditionalInformation>
          <OtherInformation><TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</TSLType></OtherInformation>
          <OtherInformation><SchemeTerritory>DE</SchemeTerritory></OtherInformation>
          <OtherInformation><add:MimeType>application/vnd.etsi.tsl+xml</add:MimeType></OtherInformation>
        </AdditionalInformation>
      </OtherTSLPointer>
    </PointersToOtherTSL></SchemeInformation></TrustServiceStatusList>`;

    const pointers = parsePointers(xml);
    assert.equal(pointers.length, 1);
    assert.equal(pointers[0]!.territory, 'DE');
    assert.equal(pointers[0]!.url, 'https://example.test/tl-de.xml');
    assert.match(pointers[0]!.signingCerts[0]!, /^-----BEGIN CERTIFICATE-----/);
    // Each list is also pointed at as a PDF; the MIME type is how we tell them
    // apart, so it has to survive parsing.
    assert.equal(pointers[0]!.mimeType, 'application/vnd.etsi.tsl+xml');
  });

  it('collects a granted service', () => {
    // The positive control the two exclusion tests below need: without it they
    // would pass just as well against a parser that collects nothing at all.
    const certificates = parseServiceCertificates(listXml(serviceXml(GRANTED, CA_QC, ANCHOR_B64)), []);

    assert.equal(certificates.length, 1);
    assert.equal(certificates[0]!.fingerprint256, ANCHOR.fingerprint256);
  });

  it('ignores services that are not granted', () => {
    const xml = listXml(serviceXml(WITHDRAWN, CA_QC, ANCHOR_B64));

    assert.equal(parseServiceCertificates(xml, []).length, 0);
  });

  it('filters by service type', () => {
    const xml = listXml(serviceXml(GRANTED, TSA, ANCHOR_B64));

    assert.equal(parseServiceCertificates(xml, [CA_QC]).length, 0);
  });

  it('drops an entry with no StatusStartingTime rather than assuming one', () => {
    // The starting time is the only thing that says when a status began, so
    // inventing one would be making up the answer to the question being asked.
    const xml = listXml(`<TSPService><ServiceInformation>
        <ServiceTypeIdentifier>${CA_QC}</ServiceTypeIdentifier>
        <ServiceStatus>${GRANTED}</ServiceStatus>
        <ServiceDigitalIdentity><DigitalId><X509Certificate>${ANCHOR_B64}</X509Certificate></DigitalId></ServiceDigitalIdentity>
      </ServiceInformation></TSPService>`);

    assert.equal(parseTrustServices(xml, []).length, 0);
  });

  it('rejects a list with no signature', () => {
    assert.throws(
      () => verifyTrustList(`<TrustServiceStatusList xmlns="${TSL}"/>`, { label: 'sample' }),
      /no XML signature/,
    );
  });

  it('honours the skip flag only when explicitly set', () => {
    // Guards the insecure escape hatch: it must do nothing unless asked.
    verifyTrustList(`<TrustServiceStatusList xmlns="${TSL}"/>`, { label: 'sample', skip: true });
  });
});

/**
 * Status is a period, not a fact.
 *
 * A service is granted from a stated instant and can be withdrawn later, so
 * "is this a trust anchor" is only answerable against a time. 223 of the
 * services on eight member states' lists became granted during 2026 alone —
 * none of them vouches for anything signed earlier. See REPRODUCE.md.
 */
describe('trust list validity time', () => {
  const at = (iso: string) => new Date(iso);

  it('does not grant a service before its status started', () => {
    const xml = listXml(serviceXml(GRANTED, CA_QC, ANCHOR_B64, '2026-06-01T00:00:00Z'));
    const anchors = TrustAnchors.fromTrustServices(parseTrustServices(xml, []));

    assert.equal(anchors.findEqual(ANCHOR, at('2026-05-31T23:59:59Z')), undefined);
    assert.ok(anchors.findEqual(ANCHOR, at('2026-06-01T00:00:00Z')), 'granted from the stated instant');
    assert.ok(anchors.findEqual(ANCHOR, at('2027-01-01T00:00:00Z')));
  });

  it('keeps a withdrawn service as an anchor for the period it was granted', () => {
    // Today this service is withdrawn, so it is not an anchor now. What it was
    // *then* is a different question, and one the old parser threw away by
    // reducing each service to its current status.
    const xml = listXml(
      serviceWithHistoryXml(
        { status: WITHDRAWN, startingTime: '2026-03-01T00:00:00Z' },
        [{ status: GRANTED, startingTime: '2024-01-01T00:00:00Z' }],
      ),
    );
    const anchors = TrustAnchors.fromTrustServices(parseTrustServices(xml, []));

    assert.ok(anchors.findEqual(ANCHOR, at('2025-06-01T00:00:00Z')), 'granted while it was granted');
    assert.equal(anchors.findEqual(ANCHOR, at('2026-06-01T00:00:00Z')), undefined, 'withdrawn since');
    assert.equal(anchors.findEqual(ANCHOR, at('2023-01-01T00:00:00Z')), undefined, 'before it began');
  });

  it('ends a granted period where the next entry begins', () => {
    // Half-open, so the instant of withdrawal is not covered by both entries.
    const xml = listXml(
      serviceWithHistoryXml(
        { status: WITHDRAWN, startingTime: '2026-03-01T00:00:00Z' },
        [{ status: GRANTED, startingTime: '2024-01-01T00:00:00Z' }],
      ),
    );
    const anchors = TrustAnchors.fromTrustServices(parseTrustServices(xml, []));

    assert.ok(anchors.findEqual(ANCHOR, at('2026-02-28T23:59:59Z')));
    assert.equal(anchors.findEqual(ANCHOR, at('2026-03-01T00:00:00Z')), undefined);
  });

  it('reads history newest-first, as the lists publish it', () => {
    // The document order is descending. Sorting is what makes each entry run
    // until the *next* one starts rather than until the previous one did.
    const xml = listXml(
      serviceWithHistoryXml({ status: GRANTED, startingTime: '2026-01-01T00:00:00Z' }, [
        { status: WITHDRAWN, startingTime: '2025-01-01T00:00:00Z' },
        { status: GRANTED, startingTime: '2023-01-01T00:00:00Z' },
      ]),
    );
    const anchors = TrustAnchors.fromTrustServices(parseTrustServices(xml, []));

    assert.ok(anchors.findEqual(ANCHOR, at('2024-01-01T00:00:00Z')), 'first granted period');
    assert.equal(anchors.findEqual(ANCHOR, at('2025-06-01T00:00:00Z')), undefined, 'the gap');
    assert.ok(anchors.findEqual(ANCHOR, at('2026-06-01T00:00:00Z')), 'granted again');
  });

  it('survives a history instance that repeats the current entry', () => {
    // Poland republishes the current entry as a history instance carrying the
    // *same* StatusStartingTime. Ordering the two by time alone gives the
    // current entry a zero-length interval, which silently drops the service —
    // it cost 14 real anchors before this was pinned. ServiceInformation is
    // the status in effect by definition, whatever the history repeats.
    const xml = listXml(
      serviceWithHistoryXml({ status: GRANTED, startingTime: '2017-02-13T10:38:44Z' }, [
        { status: GRANTED, startingTime: '2017-02-13T10:38:44Z' },
      ]),
    );
    const anchors = TrustAnchors.fromTrustServices(parseTrustServices(xml, []));

    assert.ok(anchors.findEqual(ANCHOR, at('2026-06-01T00:00:00Z')), 'still granted today');
    assert.equal(anchors.findEqual(ANCHOR, at('2017-01-01T00:00:00Z')), undefined, 'not before it began');
  });

  it('ignores a superseded entry dated at or after the one replacing it', () => {
    // A list contradicting itself grants nothing for that entry, rather than
    // an interval that runs backwards.
    const xml = listXml(
      serviceWithHistoryXml({ status: WITHDRAWN, startingTime: '2020-01-01T00:00:00Z' }, [
        { status: GRANTED, startingTime: '2024-01-01T00:00:00Z' },
      ]),
    );
    const anchors = TrustAnchors.fromTrustServices(parseTrustServices(xml, []));

    assert.equal(anchors.findEqual(ANCHOR, at('2024-06-01T00:00:00Z')), undefined);
    assert.equal(anchors.findEqual(ANCHOR, at('2022-01-01T00:00:00Z')), undefined);
  });

  it('does not treat a superseded digital identity as a current anchor', () => {
    // Scoping the certificate search to the whole TSPService, as this once did,
    // harvests the identities of retired entries alongside the live one.
    const retired = new X509Certificate(
      readFileSync(fileURLToPath(new URL('./fixtures/rogue-anchor.pem', import.meta.url)), 'utf8'),
    );
    const retiredB64 = readFileSync(
      fileURLToPath(new URL('./fixtures/rogue-anchor.pem', import.meta.url)),
      'utf8',
    ).replace(/-----[^-]+-----|\s/g, '');

    const xml = listXml(
      serviceWithHistoryXml({ status: GRANTED, startingTime: '2026-01-01T00:00:00Z' }, [
        { status: GRANTED, startingTime: '2020-01-01T00:00:00Z', cert: retiredB64 },
      ]),
    );
    const anchors = TrustAnchors.fromTrustServices(parseTrustServices(xml, []));

    assert.ok(anchors.findEqual(ANCHOR, at('2026-06-01T00:00:00Z')), 'the current identity');
    assert.equal(
      anchors.findEqual(retired, at('2026-06-01T00:00:00Z')),
      undefined,
      'the superseded identity must not be an anchor today',
    );
    assert.ok(anchors.findEqual(retired, at('2021-01-01T00:00:00Z')), 'but it was, then');
  });

  it('unions the periods of two services sharing one certificate', () => {
    const xml = listXml(
      serviceWithHistoryXml(
        { status: WITHDRAWN, startingTime: '2024-01-01T00:00:00Z' },
        [{ status: GRANTED, startingTime: '2022-01-01T00:00:00Z' }],
      ),
      serviceXml(GRANTED, TSA, ANCHOR_B64, '2026-01-01T00:00:00Z'),
    );
    const anchors = TrustAnchors.fromTrustServices(parseTrustServices(xml, []));

    assert.ok(anchors.findEqual(ANCHOR, at('2023-01-01T00:00:00Z')), 'granted by the first service');
    assert.equal(anchors.findEqual(ANCHOR, at('2025-01-01T00:00:00Z')), undefined, 'by neither');
    assert.ok(anchors.findEqual(ANCHOR, at('2026-06-01T00:00:00Z')), 'granted by the second');
  });

  it('reaches path validation, so a credential is rejected outside the granted period', () => {
    // The unit assertions above are about the anchor set; this is the one that
    // matters, that the instant reaches the code deciding whether a chain
    // terminates at an anchor. The fixture credential chains to this anchor.
    const credential = JSON.parse(
      readFileSync(fileURLToPath(new URL('./fixtures/credentials.json', import.meta.url)), 'utf8'),
    ).credentials.over18 as string;

    const grantedFrom = (from: string) =>
      TrustAnchors.fromTrustServices(
        parseTrustServices(listXml(serviceXml(GRANTED, CA_QC, ANCHOR_B64, from)), []),
      );

    const inside = resolveIssuerKeyFromX5c(credential, grantedFrom('2020-01-01T00:00:00Z'), at('2026-06-01T00:00:00Z'));
    assert.equal(inside.verified, true, JSON.stringify(inside));

    const before = resolveIssuerKeyFromX5c(credential, grantedFrom('2027-01-01T00:00:00Z'), at('2026-06-01T00:00:00Z'));
    assert.equal(before.verified, false, 'the service was not granted yet');
    assert.equal(before.reason, 'ISSUER_UNTRUSTED');
    // Distinguished from an issuer that is on no list at all, because the two
    // send an operator looking in different places.
    assert.match(before.detail, /not a granted trust service at/);
  });

  it('can be evaluated at the credential\'s signing time instead of now', () => {
    // The other reading, the one eIDAS uses for long-term signatures: a
    // withdrawal is not retroactive, so what matters is that the service was
    // granted when it signed. Opt-in, because for a credential presented live
    // the safer default is that a withdrawn service stops vouching entirely.
    const credential = JSON.parse(
      readFileSync(fileURLToPath(new URL('./fixtures/credentials.json', import.meta.url)), 'utf8'),
    ).credentials.over18 as string;

    const anchors = TrustAnchors.fromTrustServices(
      parseTrustServices(
        listXml(
          serviceWithHistoryXml({ status: WITHDRAWN, startingTime: '2026-05-01T00:00:00Z' }, [
            { status: GRANTED, startingTime: '2020-01-01T00:00:00Z' },
          ]),
        ),
        [],
      ),
    );
    const now = at('2026-06-01T00:00:00Z');

    const atValidationTime = resolveIssuerKeyFromX5c(credential, anchors, now);
    assert.equal(atValidationTime.verified, false, 'withdrawn by now');

    const atSigningTime = resolveIssuerKeyFromX5c(credential, anchors, now, {
      trustListEvaluationTime: at('2026-01-15T12:00:00Z'),
    });
    assert.equal(atSigningTime.verified, true, JSON.stringify(atSigningTime));
  });

  it('leaves pinned anchors unconditional', () => {
    // A PEM file is an operator's decision with no list to qualify it, so there
    // is no status to evaluate and no instant at which it stops applying.
    const pinned = TrustAnchors.fromPem(anchorPem);

    assert.ok(pinned.findEqual(ANCHOR, at('1999-01-01T00:00:00Z')));
    assert.ok(pinned.findEqual(ANCHOR, at('2099-01-01T00:00:00Z')));
  });
});

describe('ECDSA, which xml-crypto does not ship', () => {
  // The plumbing is one line; the encoding is the part that is easy to get
  // wrong and silent when wrong. XMLDSig carries an ECDSA signature as the raw
  // r‖s pair (RFC 4051 §2.3.6), while Node produces and expects the DER
  // sequence unless told otherwise — so a correct signature fails to verify.
  //
  // Signing and verifying with the same encoding would pass either way and
  // prove nothing, which is why each case also asserts that the DER form of the
  // *same* signature over the *same* bytes is refused.
  const cases = [
    { hash: 'sha256', curve: 'prime256v1' },
    { hash: 'sha384', curve: 'secp384r1' },
    { hash: 'sha512', curve: 'secp521r1' },
  ] as const;

  for (const { hash, curve } of cases) {
    it(`verifies the r‖s form of ecdsa-${hash} and refuses the DER form`, () => {
      const uri = `http://www.w3.org/2001/04/xmldsig-more#ecdsa-${hash}`;
      const implementation = XMLDSIG_ECDSA.find((entry) => entry.uri === uri);
      assert.ok(implementation, `no implementation registered for ${uri}`);
      const algorithm = new implementation.implementation();

      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: curve });
      const material = '<SignedInfo>whatever was canonicalised</SignedInfo>';

      const p1363 = sign(hash, Buffer.from(material), { key: privateKey, dsaEncoding: 'ieee-p1363' });
      const der = sign(hash, Buffer.from(material), { key: privateKey, dsaEncoding: 'der' });

      assert.equal(algorithm.verifySignature(material, publicKey as never, p1363.toString('base64')), true);
      assert.equal(
        algorithm.verifySignature(material, publicKey as never, der.toString('base64')),
        false,
        'accepting DER would mean the encoding is not being enforced at all',
      );
      assert.equal(algorithm.getAlgorithmName(), uri);
    });
  }

  it('signs in the same encoding it verifies', () => {
    const entry = XMLDSIG_ECDSA[0]!;
    const algorithm = new entry.implementation();
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

    const signature = algorithm.getSignature('material', privateKey as never);
    assert.equal(algorithm.verifySignature('material', publicKey as never, signature), true);
  });
});

describe('trust list signatures (network)', { skip: online ? false : 'set RUN_NETWORK_TESTS=1' }, () => {
  it('verifies the live EU List of Trusted Lists', async () => {
    const response = await fetch('https://ec.europa.eu/tools/lotl/eu-lotl.xml');
    const xml = await response.text();

    verifyTrustList(xml, { label: 'EU LOTL' });

    const pointers = parsePointers(xml).filter((p) => p.territory !== 'EU');
    assert.ok(pointers.length > 20, `expected many national lists, got ${pointers.length}`);
  });

  it('verifies a national list against the certificates the LOTL publishes for it', async () => {
    const lotl = await (await fetch('https://ec.europa.eu/tools/lotl/eu-lotl.xml')).text();
    // Austria is pointed at twice — once as XML, once as a PDF for humans.
    const pointer = parsePointers(lotl).find(
      (p) => p.territory === 'AT' && p.mimeType === 'application/vnd.etsi.tsl+xml',
    );
    assert.ok(pointer, 'Austria should be listed as XML');

    const xml = await (await fetch(pointer.url)).text();
    const { X509Certificate } = await import('node:crypto');

    verifyTrustList(xml, {
      expectedCerts: pointer.signingCerts.map((pem) => new X509Certificate(pem)),
      label: pointer.url,
    });

    assert.ok(parseServiceCertificates(xml, [CA_QC]).length > 0);
  });
});
