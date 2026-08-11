import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import {
  XMLDSIG_ECDSA,
  parsePointers,
  parseServiceCertificates,
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

function serviceXml(status: string, type: string, certB64: string) {
  return `<TSPService><ServiceInformation>
      <ServiceTypeIdentifier>${type}</ServiceTypeIdentifier>
      <ServiceStatus>${status}</ServiceStatus>
      <ServiceDigitalIdentity><DigitalId><X509Certificate>${certB64}</X509Certificate></DigitalId></ServiceDigitalIdentity>
    </ServiceInformation></TSPService>`;
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

  it('ignores services that are not granted', () => {
    const xml = `<TrustServiceStatusList xmlns="${TSL}"><TrustServiceProviderList><TrustServiceProvider><TSPServices>
      ${serviceXml(WITHDRAWN, CA_QC, 'not-a-cert')}
    </TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`;

    assert.equal(parseServiceCertificates(xml, []).length, 0);
  });

  it('filters by service type', () => {
    const xml = `<TrustServiceStatusList xmlns="${TSL}"><TrustServiceProviderList><TrustServiceProvider><TSPServices>
      ${serviceXml(GRANTED, TSA, 'not-a-cert')}
    </TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`;

    // Present but the wrong type, so it is skipped before parsing is attempted.
    assert.equal(parseServiceCertificates(xml, [CA_QC]).length, 0);
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
