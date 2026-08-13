import { AsnConvert } from '@peculiar/asn1-schema';
import {
  Certificate,
  id_ce_basicConstraints,
  id_ce_cRLDistributionPoints,
  id_ce_certificatePolicies,
  id_ce_extKeyUsage,
  id_ce_inhibitAnyPolicy,
  id_ce_keyUsage,
  id_ce_nameConstraints,
  id_ce_policyConstraints,
  id_ce_policyMappings,
  id_ce_subjectAltName,
  id_pe_authorityInfoAccess,
} from '@peculiar/asn1-x509';
import type { X509Certificate } from 'node:crypto';

/**
 * The last step of RFC 5280 §6.1.4: (o) recognize and process any other
 * critical extension present in the certificate.
 *
 * A critical extension is a CA saying *this changes what the certificate
 * means, and you may not use it without understanding me*. A validator that
 * skips one it does not know has not validated a weaker path — it has
 * validated a different certificate from the one the CA issued. The extension
 * could be narrowing the certificate to a purpose this is not, and silence
 * reads identically to permission.
 *
 * So the rule is inverted from every other check here: those ask whether a
 * certificate satisfies something, this asks whether anything on it was left
 * unread. Which makes the *recognised set below the security-relevant part of
 * this module* — every OID added to it is a promise that the code elsewhere
 * acts on that extension, and an OID added without one silently reopens the
 * hole this closes.
 *
 * This module only *reads*. Applying it to a chain is `issuer-key.ts`.
 */

/**
 * The critical extensions this library processes.
 *
 * The membership rule is: **this library reads the extension and lets it
 * change an outcome.** Nothing is here because it is common, harmless, or
 * expected — that reasoning is how §6.1.4 (o) becomes decoration.
 *
 * Two entries deserve their qualification stated rather than buried, because
 * in both the processing is real but conditional:
 *
 *  - `extKeyUsage` is read as the leaf's purpose and enforced against
 *    `requiredExtendedKeyUsage`, which is the caller's to set and unset by
 *    default. RFC 5280 §4.2.1.12 leaves the purpose check to the application
 *    in exactly this way — §6.1 does not process EKU at all — so the hook is
 *    the processing. It is also the one entry where the alternative is not
 *    arguable: 1002 certificates on the live trusted lists mark EKU critical
 *    (REPRODUCE.md), and a verifier that rejected all of them would be
 *    enforcing the rule by refusing eIDAS.
 *  - `cRLDistributionPoints` and `authorityInfoAccess` are read by
 *    `revocation.ts` to find a CRL or an OCSP responder, and that check fails
 *    closed — but only while `checkCertificateRevocation` is on, which is the
 *    default and a caller may turn off.
 *
 * The set is deliberately *not* computed from the caller's options. A
 * certificate that validates under one configuration and is malformed under
 * another would make this rejection unreproducible, and the two entries above
 * are the whole of the conditionality.
 *
 * Absent on purpose: `subjectKeyIdentifier`, `authorityKeyIdentifier`,
 * `issuerAltName`, `subjectDirectoryAttributes`, `freshestCRL` and
 * `privateKeyUsagePeriod`. RFC 5280 requires the first five to be
 * non-critical, so a critical one is non-conforming and rejecting it is the
 * rule working. `privateKeyUsagePeriod` is the sixth (RFC 3280 §4.2.1.4,
 * dropped from RFC 5280) and the only unrecognised critical extension in use
 * anywhere on the live trusted lists — four certificates, measured
 * 2026-08-12. That number is what this rule costs today, and
 * `test/ecosystem-drift.test.ts` re-measures it.
 */
export const RECOGNISED_CRITICAL_EXTENSIONS: ReadonlySet<string> = new Set([
  // Path validation proper (§6.1.3, §6.1.4).
  id_ce_basicConstraints, // basic-constraints.ts, and Node's `.ca`
  id_ce_keyUsage, // key-usage.ts
  id_ce_nameConstraints, // name-constraints.ts + name-matching.ts
  id_ce_certificatePolicies, // policies.ts + policy-tree.ts
  id_ce_policyMappings, // policy-tree.ts
  id_ce_policyConstraints, // policy-tree.ts
  id_ce_inhibitAnyPolicy, // policy-tree.ts
  // Read as the subject's names, which is what Name Constraints constrain.
  // Legitimately critical: RFC 5280 §4.2.1.6 requires it when the subject DN
  // is empty, which is the case that makes it load-bearing rather than extra.
  id_ce_subjectAltName, // name-constraints.ts (certificateNames)
  // Conditional processing; see the note above.
  id_ce_extKeyUsage, // issuer-key.ts (requiredExtendedKeyUsage)
  id_ce_cRLDistributionPoints, // revocation.ts
  id_pe_authorityInfoAccess, // revocation.ts
]);

/**
 * The critical extension OIDs on this certificate that nothing here processes.
 *
 * Empty is the passing answer. Returns the OIDs rather than a boolean so the
 * rejection can name what it did not understand — an operator meeting this
 * needs to know which extension to go and read, and the OID is the only part
 * of it we can claim to have got right.
 *
 * Throws on DER it cannot read, following `readKeyUsage` and
 * `readNameConstraints`: a certificate whose extension list will not parse is
 * not one with no critical extensions, and this check above all others must
 * not treat "could not look" as "nothing there".
 */
export function unrecognisedCriticalExtensions(cert: X509Certificate): string[] {
  const parsed = AsnConvert.parse(cert.raw, Certificate);
  // Accumulated rather than filtered: `Extensions` is an Array *subclass*, so
  // `.filter().map()` would hand back an `Extensions` holding strings.
  const unrecognised: string[] = [];
  for (const extension of parsed.tbsCertificate.extensions ?? []) {
    if (extension.critical && !RECOGNISED_CRITICAL_EXTENSIONS.has(extension.extnID)) {
      unrecognised.push(extension.extnID);
    }
  }
  return unrecognised;
}
