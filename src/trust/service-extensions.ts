import { AsnConvert } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import type { X509Certificate } from 'node:crypto';
import xpath from 'xpath';
import { readCertificatePolicies } from './policies.ts';
import { readKeyUsage, type KeyUsageBit } from './key-usage.ts';

/**
 * ETSI TS 119 612 §5.5.9 `ServiceInformationExtensions`, and the qualifier
 * derivation TS 119 615 §4.4 builds on them.
 *
 * A trusted list says more about a service than "granted". It says what the
 * service is provided *for* (`AdditionalServiceInformation`), and — for a CA
 * issuing qualified certificates — which of the certificates *it* issues are
 * qualified, for what, and whether their keys sit in a QSCD
 * (`Qualifications`). That last part is a rule set evaluated against an
 * end-entity certificate, not a property of the service, which is why nothing
 * here can be reduced to a flag on the anchor.
 *
 * `Qualifications` is the extension usually meant by "the Sie", after the
 * `SvcInfoExt` namespace it lives in. It has been left unread by this project
 * until now, and 453 of the 941 published are marked critical (REPRODUCE.md) —
 * which is a member state saying the service entry may not be used by anyone
 * who does not understand them.
 *
 * Two halves, and they are separate on purpose:
 *
 *  - `readServiceExtensions` reads the extensions off one `ServiceInformation`
 *    or `ServiceHistoryInstance`, and refuses the entry outright if a critical
 *    one is unrecognised. That is §5.5.9's own rule and the exact inverse of
 *    the other readers here — not "does this satisfy us" but "was anything
 *    left unread". Same shape as `critical-extensions.ts` for X.509.
 *  - `qualifiersFor` evaluates the rules against a certificate.
 *
 * **This library derives qualifiers; it never decides what they oblige.**
 * `NotQualified` on a credential issuer is not a rejection — an EUDI PID
 * Provider need not be a QTSP at all — so the derived set is reported to the
 * caller, whose policy it is, exactly as `requiredExtendedKeyUsage` is.
 */

const TSL_NS = 'http://uri.etsi.org/02231/v2#';
const SIE_NS = 'http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#';
const ADD_NS = 'http://uri.etsi.org/02231/v2/additionaltypes#';
/** XAdES, where the `Identifier` element inside every criterion comes from. */
const XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#';

const select = xpath.useNamespaces({ tsl: TSL_NS, sie: SIE_NS, add: ADD_NS, xades: XADES_NS });

/** Clark notation, `{namespace}localName` — an element's identity in one string. */
function qualifiedName(element: { namespaceURI: string | null; localName: string | null }): string {
  return `{${element.namespaceURI ?? ''}}${element.localName ?? ''}`;
}

/**
 * The service information extensions this library processes.
 *
 * The membership rule is `critical-extensions.ts`'s, and for the same reason:
 * every name here is a promise that the code below reads the extension, and a
 * name added without one turns §5.5.9's critical flag into decoration. Two of
 * the four are read and *acted on*; the other two are here on a narrower claim,
 * which is stated rather than buried:
 *
 *  - `AdditionalServiceInformation` and `Qualifications` reach the caller as
 *    `ServiceQualification`, to be required or ignored by the caller's policy.
 *    The same conditional processing RFC 5280 §4.2.1.12 leaves to the
 *    application for Extended Key Usage, and the hook is the processing.
 *  - `TakenOverBy` (§5.5.9.3) names the TSP now operating the service. It
 *    re-attributes; it restricts nothing, and the certificates and the status
 *    are unchanged by it. The operator is read out and carried, so this is not
 *    a claim to have understood it made without looking. Refusing it instead
 *    would cost 60 granted services on the live lists (REPRODUCE.md) for an
 *    extension that narrows nothing.
 *  - `ExpiredCertsRevocationInfo` (§5.5.9.1) is a date before which the
 *    service's CRLs do not carry expired certificates. It widens what
 *    revocation data covers rather than narrowing what the service certifies,
 *    and `revocation.ts` reads each CRL directly regardless. Read and carried
 *    on the same terms. Not one of the 137 published is critical.
 */
export const RECOGNISED_SERVICE_EXTENSIONS: ReadonlySet<string> = new Set([
  `{${TSL_NS}}AdditionalServiceInformation`,
  `{${SIE_NS}}Qualifications`,
  `{${ADD_NS}}TakenOverBy`,
  `{${TSL_NS}}ExpiredCertsRevocationInfo`,
]);

/**
 * How a `CriteriaList` combines the criteria under it (TS 119 612 §5.5.9.2).
 *
 * All three occur on the live lists — `atLeastOne` 729 times, `all` 339 and
 * `none` 22 (REPRODUCE.md) — so none of them is a case that can be skipped.
 */
export type CriteriaAssert = 'all' | 'atLeastOne' | 'none';

/** One `KeyUsageBit`: the bit, and the value the certificate must carry. */
export type KeyUsageCriterion = { bit: KeyUsageBit; value: boolean };

/**
 * A `CriteriaList`, as a tree.
 *
 * Each field is a *list of criteria of that kind*, and each criterion is
 * satisfied only when everything inside it matches — a `PolicySet` naming three
 * OIDs wants all three. `assert` then combines the criteria across all the
 * fields. Nesting is real: Belgium expresses "not qualified" as
 * `assert="none"` over an inner `atLeastOne` (REPRODUCE.md).
 */
export type Criteria = {
  assert: CriteriaAssert;
  keyUsages: KeyUsageCriterion[][];
  policySets: string[][];
  extendedKeyUsages: string[][];
  subjectDnAttributes: string[][];
  nested: Criteria[];
};

/** One rule: the qualifiers that apply to a certificate matching `criteria`. */
export type QualificationElement = { qualifiers: string[]; criteria: Criteria };

/** What one service entry's extensions say. */
export type ServiceExtensions = {
  /** `AdditionalServiceInformation` URIs: what the service is provided for. */
  additionalServiceInformation: string[];
  qualifications: QualificationElement[];
  /** The TSP named by `TakenOverBy`, if the service was taken over. */
  takenOverBy: string | undefined;
  /** `ExpiredCertsRevocationInfo`, if the service declares one. */
  expiredCertsRevocationInfo: Date | undefined;
};

/**
 * Read the extensions off a `ServiceInformation` or `ServiceHistoryInstance`.
 *
 * Throws rather than returning a partial reading, in three cases: a critical
 * extension outside the recognised set, an extension inside it whose content
 * cannot be read, and a `CriteriaList` carrying no criteria at all.
 *
 * The third deserves its own sentence, because vacuous truth is a trap here. An
 * `assert="all"` over an empty list is satisfied by every certificate in
 * existence, so reading an unparseable criterion as "no criteria" would apply
 * its qualifiers universally. And guessing the other way is no safer, since
 * qualifiers cut both ways: `QCStatement` grants where `NotQualified` takes
 * away, so there is no direction to fail in that is safe for both. The only
 * safe answer is to stop using the entry, which is what a throw does — the
 * caller in `lotl.ts` drops that service and reports it.
 */
export function readServiceExtensions(node: Node): ServiceExtensions {
  const result: ServiceExtensions = {
    additionalServiceInformation: [],
    qualifications: [],
    takenOverBy: undefined,
    expiredCertsRevocationInfo: undefined,
  };

  for (const extension of select('./tsl:ServiceInformationExtensions/tsl:Extension', node) as Node[]) {
    const critical = (extension as unknown as Element).getAttribute('Critical') === 'true';

    for (const child of elementsOf(extension)) {
      const name = qualifiedName(child);
      if (!RECOGNISED_SERVICE_EXTENSIONS.has(name)) {
        // Non-critical is the extension's author saying it may be ignored, and
        // TS 119 612 §5.5.9 means that literally. Slovakia's own
        // `URLContentTypeAndAuthorizedServiceList` is the live example.
        if (critical) {
          throw new Error(`unrecognised critical service extension ${name}`);
        }
        continue;
      }

      switch (name) {
        case `{${TSL_NS}}AdditionalServiceInformation`: {
          const uri = text(first(select('./tsl:URI', child as unknown as Node)));
          if (!uri) throw new Error('AdditionalServiceInformation carries no URI');
          result.additionalServiceInformation.push(uri);
          break;
        }
        case `{${SIE_NS}}Qualifications`:
          result.qualifications.push(...readQualifications(child as unknown as Node));
          break;
        case `{${ADD_NS}}TakenOverBy`:
          // §5.5.9.3. The operator's name is what the extension is for; the
          // rest of it repeats scheme details already read elsewhere.
          result.takenOverBy =
            text(first(select('.//add:TSPName//*[local-name(.)="Name"]', child as unknown as Node))) ||
            text(first(select('.//add:URI', child as unknown as Node))) ||
            '(unnamed)';
          break;
        case `{${TSL_NS}}ExpiredCertsRevocationInfo`: {
          const date = new Date(text(child as unknown as Node));
          if (Number.isNaN(date.getTime())) {
            throw new Error('ExpiredCertsRevocationInfo is not a readable date');
          }
          result.expiredCertsRevocationInfo = date;
          break;
        }
      }
    }
  }

  return result;
}

function readQualifications(node: Node): QualificationElement[] {
  const elements: QualificationElement[] = [];

  for (const element of select('./sie:QualificationElement', node) as Node[]) {
    const qualifiers = (select('./sie:Qualifiers/sie:Qualifier', element) as Node[]).map((qualifier) => {
      const uri = (qualifier as unknown as Element).getAttribute('uri');
      if (!uri) throw new Error('Qualifier carries no uri');
      return uri;
    });
    if (qualifiers.length === 0) throw new Error('QualificationElement asserts no qualifier');

    const list = first(select('./sie:CriteriaList', element));
    if (!list) throw new Error('QualificationElement carries no CriteriaList');
    elements.push({ qualifiers, criteria: readCriteria(list) });
  }

  return elements;
}

function readCriteria(node: Node): Criteria {
  const asserted = (node as unknown as Element).getAttribute('assert');
  if (asserted !== 'all' && asserted !== 'atLeastOne' && asserted !== 'none') {
    throw new Error(`CriteriaList asserts ${asserted ?? 'nothing'}, which TS 119 612 does not define`);
  }

  const criteria: Criteria = {
    assert: asserted,
    keyUsages: (select('./sie:KeyUsage', node) as Node[]).map(readKeyUsageCriterion),
    policySets: (select('./sie:PolicySet', node) as Node[]).map((set) =>
      identifiers(select('./sie:PolicyIdentifier/xades:Identifier', set)),
    ),
    extendedKeyUsages: (select('./sie:otherCriteriaList/add:ExtendedKeyUsage', node) as Node[]).map((usage) =>
      identifiers(select('./add:KeyPurposeId/xades:Identifier', usage)),
    ),
    subjectDnAttributes: (
      select('./sie:otherCriteriaList/add:CertSubjectDNAttribute', node) as Node[]
    ).map((attribute) => identifiers(select('./add:AttributeOID/xades:Identifier', attribute))),
    nested: (select('./sie:CriteriaList', node) as Node[]).map(readCriteria),
  };

  if (countCriteria(criteria) === 0) {
    throw new Error(`CriteriaList asserts ${asserted} over no criteria`);
  }
  return criteria;
}

function readKeyUsageCriterion(node: Node): KeyUsageCriterion[] {
  const bits = (select('./sie:KeyUsageBit', node) as Node[]).map((bit) => {
    const name = (bit as unknown as Element).getAttribute('name');
    if (!name) throw new Error('KeyUsageBit carries no name');
    const value = text(bit);
    if (value !== 'true' && value !== 'false') {
      throw new Error(`KeyUsageBit ${name} is neither true nor false`);
    }
    return { bit: name as KeyUsageBit, value: value === 'true' };
  });
  if (bits.length === 0) throw new Error('KeyUsage criterion names no bit');
  return bits;
}

function identifiers(nodes: unknown): string[] {
  const values = (nodes as Node[]).map((node) => text(node));
  if (values.length === 0 || values.some((value) => !value)) {
    throw new Error('criterion carries an empty Identifier');
  }
  // Some lists write an OID as the URN form TS 119 612 §5.5.9.2 permits.
  return values.map((value) => value.replace(/^urn:oid:/, ''));
}

function countCriteria(criteria: Criteria): number {
  return (
    criteria.keyUsages.length +
    criteria.policySets.length +
    criteria.extendedKeyUsages.length +
    criteria.subjectDnAttributes.length +
    criteria.nested.length
  );
}

/**
 * The qualifier URIs a service's `Qualifications` derive for one certificate.
 *
 * TS 119 615 §4.4. Every `QualificationElement` whose criteria the certificate
 * meets contributes its qualifiers, and the results union: a certificate can be
 * `QCForESig` under one element and `QCWithQSCD` under another, which is how the
 * live lists express the two independently.
 *
 * The certificate is the *end-entity* one — here, the credential issuer's leaf
 * — not the anchor. Qualifications say what the CA's issued certificates are,
 * never what the CA is.
 */
export function qualifiersFor(
  certificate: X509Certificate,
  elements: readonly QualificationElement[],
): string[] {
  const qualifiers = new Set<string>();
  for (const element of elements) {
    if (satisfiesCriteria(certificate, element.criteria)) {
      for (const qualifier of element.qualifiers) qualifiers.add(qualifier);
    }
  }
  return [...qualifiers];
}

/** Whether a certificate meets a `CriteriaList` (TS 119 612 §5.5.9.2). */
export function satisfiesCriteria(certificate: X509Certificate, criteria: Criteria): boolean {
  const outcomes = [
    ...criteria.keyUsages.map((bits) => matchesKeyUsage(certificate, bits)),
    ...criteria.policySets.map((oids) => containsAll(certificatePolicies(certificate), oids)),
    ...criteria.extendedKeyUsages.map((oids) => containsAll(certificate.keyUsage ?? [], oids)),
    ...criteria.subjectDnAttributes.map((oids) => containsAll(subjectAttributeOids(certificate), oids)),
    ...criteria.nested.map((nested) => satisfiesCriteria(certificate, nested)),
  ];

  // `readCriteria` refuses an empty list, so none of these is the vacuous case.
  switch (criteria.assert) {
    case 'all':
      return outcomes.every(Boolean);
    case 'atLeastOne':
      return outcomes.some(Boolean);
    case 'none':
      return !outcomes.some(Boolean);
  }
}

/**
 * A `KeyUsage` criterion, which names bits and the value each must have.
 *
 * A certificate with no KeyUsage extension asserts no bit, so `true` is unmet
 * and `false` is met. That is not the same reading RFC 5280 gives an absent
 * extension for path validation — there, absent means unrestricted — but the
 * question here is what the certificate *says*, not what it permits.
 */
function matchesKeyUsage(certificate: X509Certificate, criterion: KeyUsageCriterion[]): boolean {
  const bits = readKeyUsage(certificate)?.bits;
  return criterion.every(({ bit, value }) => (bits?.has(bit) ?? false) === value);
}

function certificatePolicies(certificate: X509Certificate): string[] {
  return (readCertificatePolicies(certificate)?.policies ?? []).map((policy) => policy.oid);
}

/** The attribute type OIDs present in the subject DN, for `CertSubjectDNAttribute`. */
function subjectAttributeOids(certificate: X509Certificate): string[] {
  const parsed = AsnConvert.parse(certificate.raw, Certificate);
  return parsed.tbsCertificate.subject.flatMap((rdn) => rdn.map((attribute) => attribute.type));
}

/** Every criterion of a kind is met only when the certificate carries all of it. */
function containsAll(present: readonly string[], required: readonly string[]): boolean {
  return required.every((value) => present.includes(value));
}

function elementsOf(node: Node): Element[] {
  return Array.from((node as unknown as Element).childNodes ?? []).filter(
    (child) => (child as unknown as Node).nodeType === 1,
  ) as unknown as Element[];
}

function first(nodes: unknown): Node | undefined {
  return Array.isArray(nodes) ? (nodes[0] as Node | undefined) : undefined;
}

function text(node: unknown): string {
  return ((node as Node | undefined)?.textContent ?? '').trim();
}
