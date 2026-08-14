import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { resolveIssuerCertificateChain } from '../src/trust/issuer-key.ts';
import { parseTrustServices } from '../src/trust/lotl.ts';
import {
  RECOGNISED_SERVICE_EXTENSIONS,
  type QualificationElement,
  qualifiersFor,
  readServiceExtensions,
} from '../src/trust/service-extensions.ts';
import { createCa, issue } from './constrained-certs.ts';
import { DOMParser } from '@xmldom/xmldom';
import xpath from 'xpath';

/**
 * ETSI TS 119 612 §5.5.9 service information extensions, and the qualifier
 * derivation of TS 119 615 §4.4.
 *
 * A trusted list says more about a service than "granted": what it is provided
 * for, and — as a rule set over the certificates it issues, not a property of
 * the CA — which of those are qualified certificates, for what, and whether
 * their keys sit in a QSCD. Every shape asserted here was read off the live
 * lists; see REPRODUCE.md for what is actually published.
 */

const TSL = 'http://uri.etsi.org/02231/v2#';
const SIE = 'http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#';
const ADD = 'http://uri.etsi.org/02231/v2/additionaltypes#';
const XADES = 'http://uri.etsi.org/01903/v1.3.2#';
const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';

/** The qualifier URIs, which differ only in their last segment. */
const q = (name: string) => `http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/${name}`;

const anchorPem = readFileSync(
  fileURLToPath(new URL('./fixtures/trust-anchor.pem', import.meta.url)),
  'utf8',
);
const ANCHOR = new X509Certificate(anchorPem);
const ANCHOR_B64 = anchorPem.replace(/-----[^-]+-----|\s/g, '');

function listXml(services: string) {
  return `<TrustServiceStatusList xmlns="${TSL}" xmlns:sie="${SIE}" xmlns:add="${ADD}" xmlns:xades="${XADES}">
    <TrustServiceProviderList><TrustServiceProvider><TSPServices>
      ${services}
    </TSPServices></TrustServiceProvider></TrustServiceProviderList>
  </TrustServiceStatusList>`;
}

function serviceXml(extensions: string, certB64 = ANCHOR_B64) {
  return `<TSPService><ServiceInformation>
    <ServiceTypeIdentifier>${CA_QC}</ServiceTypeIdentifier>
    <ServiceStatus>${GRANTED}</ServiceStatus>
    <StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>
    <ServiceDigitalIdentity><DigitalId><X509Certificate>${certB64}</X509Certificate></DigitalId></ServiceDigitalIdentity>
    ${extensions ? `<ServiceInformationExtensions>${extensions}</ServiceInformationExtensions>` : ''}
  </ServiceInformation></TSPService>`;
}

/** A `QualificationElement`, in the shape the lists publish it. */
function qualificationXml(qualifiers: string[], criteria: string) {
  return `<sie:Qualifications><sie:QualificationElement>
    <sie:Qualifiers>${qualifiers.map((uri) => `<sie:Qualifier uri="${uri}"/>`).join('')}</sie:Qualifiers>
    ${criteria}
  </sie:QualificationElement></sie:Qualifications>`;
}

const criteriaXml = (assert_: string, body: string) =>
  `<sie:CriteriaList assert="${assert_}">${body}</sie:CriteriaList>`;
const policySetXml = (...oids: string[]) =>
  `<sie:PolicySet>${oids.map((oid) => `<sie:PolicyIdentifier><xades:Identifier>${oid}</xades:Identifier></sie:PolicyIdentifier>`).join('')}</sie:PolicySet>`;
const keyUsageXml = (bits: Record<string, boolean>) =>
  `<sie:KeyUsage>${Object.entries(bits)
    .map(([name, value]) => `<sie:KeyUsageBit name="${name}">${value}</sie:KeyUsageBit>`)
    .join('')}</sie:KeyUsage>`;
const ekuXml = (...oids: string[]) =>
  `<sie:otherCriteriaList><add:ExtendedKeyUsage>${oids.map((oid) => `<add:KeyPurposeId><xades:Identifier>${oid}</xades:Identifier></add:KeyPurposeId>`).join('')}</add:ExtendedKeyUsage></sie:otherCriteriaList>`;
const dnAttributeXml = (...oids: string[]) =>
  `<sie:otherCriteriaList><add:CertSubjectDNAttribute>${oids.map((oid) => `<add:AttributeOID><xades:Identifier>${oid}</xades:Identifier></add:AttributeOID>`).join('')}</add:CertSubjectDNAttribute></sie:otherCriteriaList>`;
const extension = (content: string, critical = false) =>
  `<Extension Critical="${critical}">${content}</Extension>`;

/**
 * The `ServiceInformation` node of one service, for the reads that never reach
 * a `TrustServiceEntry` — `TakenOverBy` and `ExpiredCertsRevocationInfo` are on
 * the recognised set because they are read, and that is only checkable here.
 */
function serviceInformationOf(serviceXmlText: string): Node {
  const document = new DOMParser().parseFromString(listXml(serviceXmlText), 'text/xml');
  const node = (
    xpath.useNamespaces({ tsl: TSL })('//tsl:ServiceInformation', document as unknown as Node) as Node[]
  )[0];
  assert.ok(node, 'the sample should contain a ServiceInformation');
  return node;
}

/** The rules a service publishes, as `parseTrustServices` reads them. */
function qualificationsFrom(extensions: string): QualificationElement[] {
  const entries = parseTrustServices(listXml(serviceXml(extensions)), []);
  assert.equal(entries.length, 1, 'the service should have survived parsing');
  return entries[0]!.qualification?.qualifications ?? [];
}

/** Certificates to evaluate rules against. Built once; none of it is secret. */
const ca = await createCa('CN=Qualified CA', undefined, { keyUsage: ['keyCertSign'] });
const POLICY_A = '0.4.0.194112.1.2';
const POLICY_B = '1.3.6.1.4.1.99999.1';
const DN_MARKER = '1.3.6.1.4.1.18838.1.1';

const plain = await issue(ca, 'CN=Plain Leaf', { keyUsage: ['digitalSignature'] });
const qualified = await issue(ca, 'CN=Qualified Leaf', {
  keyUsage: ['digitalSignature', 'nonRepudiation'],
  policies: { policies: [POLICY_A] },
  extendedKeyUsage: ['1.3.6.1.5.5.7.3.1'],
});
const legalPerson = await issue(ca, `CN=Legal Person, ${DN_MARKER}=marker`, {
  keyUsage: ['digitalSignature'],
});

describe('service information extensions', () => {
  it('reads what a service is provided for', () => {
    const entries = parseTrustServices(
      listXml(
        serviceXml(
          extension(`<AdditionalServiceInformation><URI>${q('ForeSeals')}</URI></AdditionalServiceInformation>`) +
            extension(
              `<AdditionalServiceInformation><URI>${q('ForeSignatures')}</URI></AdditionalServiceInformation>`,
            ),
        ),
      ),
      [],
    );

    assert.deepEqual(entries[0]!.qualification?.serviceInformation, [q('ForeSeals'), q('ForeSignatures')]);
  });

  it('drops a service carrying a critical extension it cannot process', () => {
    // TS 119 612 §5.5.9: critical is the member state saying the entry may not
    // be used by anyone who does not understand this. The same inversion
    // RFC 5280 §6.1.4 (o) makes for X.509, and the same answer — stop.
    const entries = parseTrustServices(
      listXml(serviceXml(extension('<sk:Whatever xmlns:sk="urn:example:sk"/>', true))),
      [],
    );

    assert.equal(entries.length, 0);
  });

  it('ignores an unrecognised extension that is not critical', () => {
    // Not tolerance for its own sake: Slovakia publishes exactly this, an
    // extension of its own marked non-critical, and refusing it would cost
    // every Slovak anchor for a statement its author said was optional.
    const entries = parseTrustServices(
      listXml(serviceXml(extension('<sk:Whatever xmlns:sk="urn:example:sk"/>', false))),
      [],
    );

    assert.equal(entries.length, 1);
  });

  it('names the extensions it claims to process, and no others', () => {
    // The set is the security-relevant part, exactly as with
    // RECOGNISED_CRITICAL_EXTENSIONS: every name on it asserts that code
    // elsewhere reads that extension, so an addition without one silently
    // reopens the hole the critical flag exists to close.
    assert.deepEqual(
      [...RECOGNISED_SERVICE_EXTENSIONS].sort(),
      [
        `{${TSL}}AdditionalServiceInformation`,
        `{${TSL}}ExpiredCertsRevocationInfo`,
        `{${ADD}}TakenOverBy`,
        `{${SIE}}Qualifications`,
      ].sort(),
    );
  });

  it('drops a service whose criteria list carries no criteria', () => {
    // Vacuous truth is the trap: `assert="all"` over nothing is satisfied by
    // every certificate in existence, so an unreadable rule must not degrade
    // into an empty one. There is no safe direction to guess in either, since
    // QCStatement grants where NotQualified takes away — so the entry goes.
    const entries = parseTrustServices(
      listXml(serviceXml(extension(qualificationXml([q('QCStatement')], criteriaXml('all', ''))))),
      [],
    );

    assert.equal(entries.length, 0);
  });

  it('drops a service whose criteria list asserts something undefined', () => {
    const entries = parseTrustServices(
      listXml(
        serviceXml(
          extension(qualificationXml([q('QCStatement')], criteriaXml('most', policySetXml(POLICY_A)))),
        ),
      ),
      [],
    );

    assert.equal(entries.length, 0);
  });

  it('reads TakenOverBy as the operator it names', () => {
    // 60 granted services on the live lists mark this critical (REPRODUCE.md).
    // It re-attributes the service and restricts nothing, which is the whole
    // argument for recognising it — and that argument is only honest if the
    // name is actually read, so this asserts the reading and not just survival.
    const xml = serviceXml(
      extension(
        `<add:TakenOverBy><add:URI>https://example.test/tsp</add:URI>
          <add:TSPName><Name xml:lang="en">Successor TSP</Name></add:TSPName>
        </add:TakenOverBy>`,
        true,
      ),
    );

    assert.equal(readServiceExtensions(serviceInformationOf(xml)).takenOverBy, 'Successor TSP');
    assert.equal(parseTrustServices(listXml(xml), []).length, 1, 'and it must not cost the anchor');
  });

  it('reads ExpiredCertsRevocationInfo as the date it states', () => {
    const xml = serviceXml(
      extension('<ExpiredCertsRevocationInfo>2016-06-30T22:00:00Z</ExpiredCertsRevocationInfo>'),
    );

    assert.equal(
      readServiceExtensions(serviceInformationOf(xml)).expiredCertsRevocationInfo?.toISOString(),
      '2016-06-30T22:00:00.000Z',
    );
  });

  it('refuses an ExpiredCertsRevocationInfo that is not a date', () => {
    // Recognised means read. An extension on the set that cannot be read is
    // exactly the case the set is a promise against.
    const xml = serviceXml(extension('<ExpiredCertsRevocationInfo>whenever</ExpiredCertsRevocationInfo>'));

    assert.throws(() => readServiceExtensions(serviceInformationOf(xml)), /not a readable date/);
    assert.equal(parseTrustServices(listXml(xml), []).length, 0);
  });
});

describe('qualification criteria', () => {
  it('derives a qualifier when the certificate asserts the policy', () => {
    const rules = qualificationsFrom(
      extension(qualificationXml([q('QCStatement')], criteriaXml('atLeastOne', policySetXml(POLICY_A)))),
    );

    assert.deepEqual(qualifiersFor(qualified.cert, rules), [q('QCStatement')]);
    assert.deepEqual(qualifiersFor(plain.cert, rules), []);
  });

  it('wants every OID in one PolicySet, not just one of them', () => {
    // A PolicySet is a conjunction; `assert` combines the sets, not the OIDs
    // inside one. Getting this backwards would qualify a certificate that
    // asserts any single policy of a set the CA meant as a whole.
    const rules = qualificationsFrom(
      extension(
        qualificationXml([q('QCStatement')], criteriaXml('atLeastOne', policySetXml(POLICY_A, POLICY_B))),
      ),
    );

    assert.deepEqual(qualifiersFor(qualified.cert, rules), []);
  });

  it('reads a KeyUsage bit, and reads its absence as false', () => {
    const wantsNonRepudiation = qualificationsFrom(
      extension(
        qualificationXml([q('QCWithQSCD')], criteriaXml('atLeastOne', keyUsageXml({ nonRepudiation: true }))),
      ),
    );
    const wantsNoNonRepudiation = qualificationsFrom(
      extension(
        qualificationXml([q('QCNoQSCD')], criteriaXml('atLeastOne', keyUsageXml({ nonRepudiation: false }))),
      ),
    );

    assert.deepEqual(qualifiersFor(qualified.cert, wantsNonRepudiation), [q('QCWithQSCD')]);
    assert.deepEqual(qualifiersFor(plain.cert, wantsNonRepudiation), []);
    // The certificate carries KeyUsage without the bit, which is a certificate
    // saying no — the criterion asks what the certificate states, not what
    // RFC 5280 would permit an absent extension to mean.
    assert.deepEqual(qualifiersFor(plain.cert, wantsNoNonRepudiation), [q('QCNoQSCD')]);
  });

  it('reads an ExtendedKeyUsage criterion', () => {
    // Slovakia qualifies QCForWSA by server authentication EKU (REPRODUCE.md).
    const rules = qualificationsFrom(
      extension(qualificationXml([q('QCForWSA')], criteriaXml('all', ekuXml('1.3.6.1.5.5.7.3.1')))),
    );

    assert.deepEqual(qualifiersFor(qualified.cert, rules), [q('QCForWSA')]);
    assert.deepEqual(qualifiersFor(plain.cert, rules), []);
  });

  it('reads a CertSubjectDNAttribute criterion', () => {
    // Spain qualifies QCForLegalPerson by a private DN attribute (REPRODUCE.md).
    const rules = qualificationsFrom(
      extension(qualificationXml([q('QCForLegalPerson')], criteriaXml('atLeastOne', dnAttributeXml(DN_MARKER)))),
    );

    assert.deepEqual(qualifiersFor(legalPerson.cert, rules), [q('QCForLegalPerson')]);
    assert.deepEqual(qualifiersFor(qualified.cert, rules), []);
  });

  it('distinguishes all from atLeastOne across criteria', () => {
    const body = policySetXml(POLICY_A) + policySetXml(POLICY_B);
    const all = qualificationsFrom(extension(qualificationXml([q('QCStatement')], criteriaXml('all', body))));
    const atLeastOne = qualificationsFrom(
      extension(qualificationXml([q('QCStatement')], criteriaXml('atLeastOne', body))),
    );

    assert.deepEqual(qualifiersFor(qualified.cert, all), []);
    assert.deepEqual(qualifiersFor(qualified.cert, atLeastOne), [q('QCStatement')]);
  });

  it('reads assert="none" over a nested list, as Belgium publishes NotQualified', () => {
    // The live shape: NotQualified asserted as "none of the following", where
    // the following is itself an atLeastOne over the qualifying policies.
    const rules = qualificationsFrom(
      extension(
        qualificationXml(
          [q('NotQualified')],
          criteriaXml('none', criteriaXml('atLeastOne', policySetXml(POLICY_A))),
        ),
      ),
    );

    assert.deepEqual(qualifiersFor(plain.cert, rules), [q('NotQualified')]);
    assert.deepEqual(qualifiersFor(qualified.cert, rules), []);
  });

  it('unions the qualifiers of every element the certificate matches', () => {
    // How the lists express the two axes independently: what the certificate is
    // for, and whether its key is in a QSCD, are separate QualificationElements.
    const rules = qualificationsFrom(
      extension(qualificationXml([q('QCForESeal')], criteriaXml('atLeastOne', policySetXml(POLICY_A)))) +
        extension(
          qualificationXml([q('QCWithQSCD')], criteriaXml('atLeastOne', keyUsageXml({ nonRepudiation: true }))),
        ),
    );

    assert.deepEqual(qualifiersFor(qualified.cert, rules).sort(), [q('QCForESeal'), q('QCWithQSCD')].sort());
  });
});

describe('qualifiers reaching the caller', () => {
  it('reports what the list says about the leaf, not about the anchor', async () => {
    const services = parseTrustServices(
      listXml(
        serviceXml(
          extension(`<AdditionalServiceInformation><URI>${q('ForeSeals')}</URI></AdditionalServiceInformation>`) +
            extension(qualificationXml([q('QCForESeal')], criteriaXml('atLeastOne', policySetXml(POLICY_A)))),
          ca.cert.raw.toString('base64'),
        ),
      ),
      [],
    );
    const anchors = TrustAnchors.fromTrustServices(services);

    const resolved = resolveIssuerCertificateChain([qualified.cert], anchors, new Date());
    assert.ok(resolved.verified, resolved.verified ? '' : resolved.detail);
    assert.deepEqual(resolved.value.qualification?.serviceInformation, [q('ForeSeals')]);
    assert.deepEqual(resolved.value.qualification?.qualifiers, [q('QCForESeal')]);

    // The same anchor, a different leaf: the rules are about the certificates
    // the CA issues, so the answer has to depend on which one is asked about.
    const other = resolveIssuerCertificateChain([plain.cert], anchors, new Date());
    assert.ok(other.verified, other.verified ? '' : other.detail);
    assert.deepEqual(other.value.qualification?.qualifiers, []);
  });

  it('says nothing about a pinned anchor rather than saying nothing qualifies', async () => {
    // Undefined is "no list was consulted"; an empty qualifier list is "the
    // rules were evaluated and none matched". A caller must be able to tell
    // those apart, or a PEM on disk reads as a CA that qualifies nothing.
    const pinnedCa = await createCa('CN=Pinned CA', undefined, { keyUsage: ['keyCertSign'] });
    const leaf = await issue(pinnedCa, 'CN=Leaf', { keyUsage: ['digitalSignature'] });
    const anchors = TrustAnchors.fromCertificates([pinnedCa.cert]);

    const resolved = resolveIssuerCertificateChain([leaf.cert], anchors, new Date());
    assert.ok(resolved.verified, resolved.verified ? '' : resolved.detail);
    assert.equal(resolved.value.qualification, undefined);
  });

  it('merges the extensions of two services sharing one certificate', () => {
    // The merge `granted` already gets: one certificate can identify a
    // qualified certificate service and something else, and neither one's
    // silence contradicts the other's statement.
    const services = parseTrustServices(
      listXml(
        serviceXml(
          extension(`<AdditionalServiceInformation><URI>${q('ForeSignatures')}</URI></AdditionalServiceInformation>`),
        ) +
          serviceXml(
            extension(`<AdditionalServiceInformation><URI>${q('ForeSeals')}</URI></AdditionalServiceInformation>`) +
              extension(qualificationXml([q('QCStatement')], criteriaXml('atLeastOne', policySetXml(POLICY_A)))),
          ),
      ),
      [],
    );
    const anchors = TrustAnchors.fromTrustServices(services);

    const qualification = anchors.qualify(ANCHOR, qualified.cert);
    assert.deepEqual(qualification?.serviceInformation.sort(), [q('ForeSeals'), q('ForeSignatures')].sort());
    assert.deepEqual(qualification?.qualifiers, [q('QCStatement')]);
  });
});
