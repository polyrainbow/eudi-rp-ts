import { AsnConvert } from '@peculiar/asn1-schema';
import {
  Certificate,
  CertificatePolicies,
  InhibitAnyPolicy,
  PolicyConstraints,
  PolicyMappings,
  id_ce_certificatePolicies,
  id_ce_certificatePolicies_anyPolicy,
  id_ce_inhibitAnyPolicy,
  id_ce_policyConstraints,
  id_ce_policyMappings,
} from '@peculiar/asn1-x509';
import type { X509Certificate } from 'node:crypto';

/**
 * Reading the four certificate policy extensions (RFC 5280 §4.2.1.4, §4.2.1.5,
 * §4.2.1.11, §4.2.1.14).
 *
 * A certificate policy is a CA stating *under which rules* it issued a
 * certificate — the identity proofing, the key protection, the audit regime. In
 * eIDAS that is the load-bearing statement: an ETSI policy OID is what separates
 * a qualified certificate from one a CA issued to anybody who asked, and both
 * can sit under the same trusted list entry. Without policy processing a relying
 * party that means to accept only one of them cannot say so.
 *
 * Node's `X509Certificate` reaches none of these, so the DER is parsed here —
 * the third use of `@peculiar/asn1-x509` after Name Constraints and KeyUsage,
 * under the same rule: that dependency reads structures, `node:crypto` does
 * every cryptographic operation.
 *
 * This module only *reads*. The RFC 5280 §6.1 state machine that gives these
 * extensions their meaning is `policy-tree.ts`, and applying its verdict to a
 * chain is `issuer-key.ts`.
 */

/** RFC 5280 §4.2.1.4: the wildcard `2.5.29.32.0`. */
export const ANY_POLICY: string = id_ce_certificatePolicies_anyPolicy;

export type PolicyInformationValue = {
  oid: string;
  /**
   * Qualifier *identifiers* only — `id-qt-cps` (a CPS URI) or `id-qt-unotice`
   * (a notice to display). RFC 5280 §6.1.5 (f) makes acting on qualifiers a
   * local matter, and nothing here acts on them; they are read so that the
   * omission is visible rather than invisible, and so a drift test can see what
   * the live deployment publishes. The EU PID document signer carries one CPS
   * pointer (REPRODUCE.md).
   */
  qualifiers: string[];
};

export type CertificatePolicySet = {
  /**
   * RFC 5280 §4.2.1.4 leaves this to the CA. Both live EUDI signers publish the
   * extension non-critical, which changes nothing: §6.1 processes it either way.
   */
  critical: boolean;
  policies: PolicyInformationValue[];
};

export type PolicyMappingValue = { issuerDomainPolicy: string; subjectDomainPolicy: string };

export type PolicyMappingSet = {
  critical: boolean;
  mappings: PolicyMappingValue[];
};

export type PolicyConstraintSet = {
  critical: boolean;
  /** §6.1.4 (i)(1): certificates after this many must assert a policy. */
  requireExplicitPolicy: number | undefined;
  /** §6.1.4 (i)(2): mappings by certificates after this many are not honoured. */
  inhibitPolicyMapping: number | undefined;
};

/**
 * The policies a certificate asserts, or undefined if it asserts none.
 *
 * Absent is not the same as empty, and the difference decides paths: under
 * §6.1.3 (e) a certificate with no extension sets the policy tree to NULL,
 * which ends the path unless nothing was requiring a policy in the first place.
 *
 * Throws on DER it cannot read. The rule `readKeyUsage` and
 * `readNameConstraints` follow holds here too — an unreadable extension is not
 * an absent one, and a path validated by ignoring the question is not
 * validated.
 */
export function readCertificatePolicies(cert: X509Certificate): CertificatePolicySet | undefined {
  const extension = findExtension(cert, id_ce_certificatePolicies);
  if (!extension) return undefined;

  const parsed = AsnConvert.parse(extension.extnValue, CertificatePolicies);
  return {
    critical: extension.critical,
    // Duplicate OIDs are left as they are read. RFC 5280 §4.2.1.4 forbids a CA
    // from emitting them, but they are harmless to process: the tree refuses to
    // create two children with the same policy under one parent, so a duplicate
    // reaches the same tree as a single mention.
    policies: Array.from(parsed, (information) => ({
      oid: information.policyIdentifier,
      qualifiers: (information.policyQualifiers ?? []).map((q) => q.policyQualifierId),
    })),
  };
}

/** The policy mappings a CA declares (RFC 5280 §4.2.1.5), or undefined. */
export function readPolicyMappings(cert: X509Certificate): PolicyMappingSet | undefined {
  const extension = findExtension(cert, id_ce_policyMappings);
  if (!extension) return undefined;

  const parsed = AsnConvert.parse(extension.extnValue, PolicyMappings);
  return {
    critical: extension.critical,
    mappings: Array.from(parsed, (mapping) => ({
      issuerDomainPolicy: mapping.issuerDomainPolicy,
      subjectDomainPolicy: mapping.subjectDomainPolicy,
    })),
  };
}

/** The policy constraints a CA imposes (RFC 5280 §4.2.1.11), or undefined. */
export function readPolicyConstraints(cert: X509Certificate): PolicyConstraintSet | undefined {
  const extension = findExtension(cert, id_ce_policyConstraints);
  if (!extension) return undefined;

  const parsed = AsnConvert.parse(extension.extnValue, PolicyConstraints);
  return {
    critical: extension.critical,
    requireExplicitPolicy:
      parsed.requireExplicitPolicy === undefined
        ? undefined
        : skipCerts(parsed.requireExplicitPolicy, 'requireExplicitPolicy'),
    inhibitPolicyMapping:
      parsed.inhibitPolicyMapping === undefined
        ? undefined
        : skipCerts(parsed.inhibitPolicyMapping, 'inhibitPolicyMapping'),
  };
}

/** How many more certificates may still use anyPolicy (RFC 5280 §4.2.1.14). */
export function readInhibitAnyPolicy(
  cert: X509Certificate,
): { critical: boolean; skipCerts: number } | undefined {
  const extension = findExtension(cert, id_ce_inhibitAnyPolicy);
  if (!extension) return undefined;

  const parsed = AsnConvert.parse(extension.extnValue, InhibitAnyPolicy);
  return { critical: extension.critical, skipCerts: skipCerts(parsed.value, 'inhibitAnyPolicy') };
}

/**
 * `SkipCerts ::= INTEGER (0..MAX)`, which `@peculiar/asn1-schema` hands over as
 * the INTEGER's content octets rather than a number.
 *
 * A negative value is a syntax violation, not a very large skip count, and
 * silently reading it as one would turn "no certificate may map policies" into
 * "every certificate may".
 */
function skipCerts(value: ArrayBuffer, field: string): number {
  const bytes = new Uint8Array(value);
  if (bytes.length === 0) throw new Error(`${field} is an empty INTEGER`);
  if ((bytes[0]! & 0x80) !== 0) throw new Error(`${field} is negative`);

  let count = 0;
  for (const byte of bytes) count = count * 256 + byte;
  // These counters are only ever compared with `<` against a value bounded by
  // the length of the path, so anything past a safe integer is indistinguishable
  // from "never" and can be clamped without changing an outcome.
  return Number.isSafeInteger(count) ? count : Number.MAX_SAFE_INTEGER;
}

function findExtension(
  cert: X509Certificate,
  oid: string,
): { critical: boolean; extnValue: ArrayBuffer } | undefined {
  const parsed = AsnConvert.parse(cert.raw, Certificate);
  const found = (parsed.tbsCertificate.extensions ?? []).find((ext) => ext.extnID === oid);
  if (!found) return undefined;
  // `critical` is DEFAULT FALSE; the value is an OCTET STRING wrapping the DER
  // the caller actually wants.
  return { critical: found.critical ?? false, extnValue: found.extnValue.buffer };
}
