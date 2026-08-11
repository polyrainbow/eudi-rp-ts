import { AsnConvert } from '@peculiar/asn1-schema';
import {
  type AttributeValue,
  Certificate,
  GeneralName,
  GeneralNames,
  Name,
  NameConstraints,
} from '@peculiar/asn1-x509';
import type { X509Certificate } from 'node:crypto';

/**
 * Reading the Name Constraints extension (RFC 5280 §4.2.1.10).
 *
 * A CA that carries this extension is stating which names it is entitled to
 * certify. Without checking it, any CA in any Member State's trusted list can
 * vouch for any subject — which is the whole point of a federated PKI having
 * constraints in the first place.
 *
 * Node's `X509Certificate` cannot help here: it exposes `subject`,
 * `subjectAltName` and *extended* key usage, but no access to arbitrary
 * extensions, so the DER has to be parsed. That is what `@peculiar/asn1-x509`
 * is for, and it is the only thing it is used for — every cryptographic
 * operation in this codebase stays on `node:crypto`. The narrower
 * `@peculiar/asn1-x509` is deliberate: `@peculiar/x509` would bring a
 * dependency-injection container along with it.
 *
 * This module only *reads*. Matching a name against a constraint is
 * `name-matching.ts`, and applying the result to a chain is `issuer-key.ts`.
 */

/** RFC 5280 §4.2.1.10. */
const NAME_CONSTRAINTS = '2.5.29.30';
/** RFC 5280 §4.2.1.6. */
const SUBJECT_ALT_NAME = '2.5.29.17';

/**
 * One RDN: a *set* of attributes, which is why it is an array. Almost always
 * of length one, but `CN=Leaf+OU=Unit` is a single RDN with two attributes and
 * comparing it as if it were two would be wrong.
 */
export type RelativeDistinguishedName = { type: string; value: string | undefined }[];

/**
 * A GeneralName reduced to what constraint checking needs.
 *
 * `unsupported` is a name form this code does not evaluate. It is kept rather
 * than dropped: a constraint we cannot evaluate must fail the chain, and a
 * silently ignored one would be worse than no constraint checking at all.
 */
export type GeneralNameValue =
  | { form: 'dNSName'; value: string }
  | { form: 'rfc822Name'; value: string }
  | { form: 'uniformResourceIdentifier'; value: string }
  /**
   * Decoded by `@peculiar/asn1-x509` rather than left as bytes, and the two
   * uses look different: a name carries an address (`10.0.0.1`), a constraint
   * carries the address and mask that the DER holds as a double-length octet
   * string, rendered as CIDR (`10.0.0.0/8`).
   */
  | { form: 'iPAddress'; value: string }
  | { form: 'directoryName'; rdns: RelativeDistinguishedName[] }
  | { form: 'unsupported'; label: string };

export type Subtree = {
  base: GeneralNameValue;
  /**
   * RFC 5280 §4.2.1.10 requires `minimum` to be zero and `maximum` absent, and
   * says applications MUST treat a subtree with either as an error. They are
   * carried here so that the check can be made where it belongs rather than
   * silently discarded.
   */
  minimum: number;
  maximum: number | undefined;
};

export type NameConstraintSet = {
  /** RFC 5280 requires this extension to be critical when present. */
  critical: boolean;
  permitted: Subtree[];
  excluded: Subtree[];
};

/** The Name Constraints of a certificate, or undefined if it carries none. */
export function readNameConstraints(cert: X509Certificate): NameConstraintSet | undefined {
  const extension = findExtension(cert, NAME_CONSTRAINTS);
  if (!extension) return undefined;

  const parsed = AsnConvert.parse(extension.extnValue, NameConstraints);
  // `Array.from` rather than `map`, for the reason given on `toRdns`.
  return {
    critical: extension.critical,
    permitted: Array.from(parsed.permittedSubtrees ?? [], toSubtree),
    excluded: Array.from(parsed.excludedSubtrees ?? [], toSubtree),
  };
}

/**
 * The names a certificate presents, which are what constraints apply to.
 *
 * RFC 5280 §6.1.3 (b) and (c): both the subject distinguished name and every
 * Subject Alternative Name entry are subject to the constraints in force. An
 * empty subject DN contributes nothing — that is the shape used by certificates
 * that carry their identity entirely in the SAN.
 */
export function certificateNames(cert: X509Certificate): GeneralNameValue[] {
  const parsed = AsnConvert.parse(cert.raw, Certificate);

  const names: GeneralNameValue[] = [];
  const subject = parsed.tbsCertificate.subject;
  if (subject.length > 0) names.push({ form: 'directoryName', rdns: toRdns(subject) });

  const san = findExtension(cert, SUBJECT_ALT_NAME);
  if (san) {
    for (const entry of AsnConvert.parse(san.extnValue, GeneralNames)) {
      names.push(toGeneralNameValue(entry));
    }
  }
  return names;
}

function findExtension(
  cert: X509Certificate,
  oid: string,
): { critical: boolean; extnValue: ArrayBuffer } | undefined {
  const parsed = AsnConvert.parse(cert.raw, Certificate);
  const found = (parsed.tbsCertificate.extensions ?? []).find((ext) => ext.extnID === oid);
  if (!found) return undefined;
  // `critical` is DEFAULT FALSE, so an absent field means non-critical. The
  // extension value is an OCTET STRING wrapping the real DER, which is what
  // callers need to parse.
  return { critical: found.critical ?? false, extnValue: found.extnValue.buffer };
}

function toSubtree(subtree: { base: GeneralName; minimum: number; maximum?: number }): Subtree {
  return {
    base: toGeneralNameValue(subtree.base),
    minimum: subtree.minimum,
    maximum: subtree.maximum,
  };
}

function toGeneralNameValue(name: GeneralName): GeneralNameValue {
  if (name.dNSName !== undefined) return { form: 'dNSName', value: name.dNSName };
  if (name.rfc822Name !== undefined) return { form: 'rfc822Name', value: name.rfc822Name };
  if (name.uniformResourceIdentifier !== undefined) {
    return { form: 'uniformResourceIdentifier', value: name.uniformResourceIdentifier };
  }
  if (name.iPAddress !== undefined) return { form: 'iPAddress', value: name.iPAddress };
  if (name.directoryName !== undefined) {
    return { form: 'directoryName', rdns: toRdns(name.directoryName) };
  }

  // otherName, x400Address, ediPartyName, registeredID. Named rather than
  // collapsed to "unknown" so a rejection can say which form defeated it.
  for (const label of ['otherName', 'x400Address', 'ediPartyName', 'registeredID'] as const) {
    if (name[label] !== undefined) return { form: 'unsupported', label };
  }
  return { form: 'unsupported', label: 'empty' };
}

/**
 * `Array.from`, not `map`: `Name` and `RelativeDistinguishedName` are Array
 * subclasses, and `map` on a subclass returns that subclass — which would leak
 * the ASN.1 library's types out through this module's public shape.
 */
function toRdns(name: Name): RelativeDistinguishedName[] {
  return Array.from(name, (rdn) =>
    Array.from(rdn, (attribute) => ({ type: attribute.type, value: attributeText(attribute.value) })),
  );
}

/**
 * The text of a DN attribute, or undefined if it is not a string at all.
 *
 * The string alternatives are read by name rather than through `toString()`,
 * which renders an unrecognised `anyValue` as hex — so an attribute this code
 * cannot read would otherwise come back as text and could compare equal to a
 * constraint. `undefined` is not an empty string and must match nothing.
 */
function attributeText(value: AttributeValue): string | undefined {
  return (
    value.utf8String ??
    value.printableString ??
    value.ia5String ??
    value.teletexString ??
    value.universalString ??
    value.bmpString
  );
}
