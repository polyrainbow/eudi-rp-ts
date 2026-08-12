import { AsnConvert } from '@peculiar/asn1-schema';
import { BasicConstraints, Certificate, id_ce_basicConstraints } from '@peculiar/asn1-x509';
import type { X509Certificate } from 'node:crypto';

/**
 * Reading the Basic Constraints extension (RFC 5280 §4.2.1.9).
 *
 * Node exposes the `cA` boolean as `X509Certificate.ca` and stops there, but the
 * extension carries a second field: `pathLenConstraint`, the number of CA
 * certificates a CA permits between itself and an end entity. Zero means "I sign
 * end-entity certificates only", and 692 of the 1165 CA certificates on the live
 * trusted lists say exactly that (REPRODUCE.md) — including the EU PID Issuer
 * CA. Ignoring it lets any of them appear to have issued a sub-CA that then
 * vouches for anybody.
 *
 * This module only *reads*. Applying it to a chain is `issuer-key.ts`.
 */

export type BasicConstraintSet = {
  /** RFC 5280 requires this extension to be critical in a CA certificate. */
  critical: boolean;
  ca: boolean;
  /** Absent means unlimited, which is not the same as zero. */
  pathLenConstraint: number | undefined;
};

/** Throws on DER it cannot read, for the reason `readKeyUsage` gives. */
export function readBasicConstraints(cert: X509Certificate): BasicConstraintSet | undefined {
  const parsed = AsnConvert.parse(cert.raw, Certificate);
  const extension = parsed.tbsCertificate.extensions?.find((e) => e.extnID === id_ce_basicConstraints);
  if (!extension) return undefined;

  const value = AsnConvert.parse(extension.extnValue, BasicConstraints);
  return {
    critical: extension.critical ?? false,
    ca: value.cA,
    // RFC 5280 §4.2.1.9: the field means nothing without cA, and a CA that sets
    // it there is stating something the syntax does not let it state.
    pathLenConstraint: value.cA ? value.pathLenConstraint : undefined,
  };
}

/**
 * Is this certificate self-issued (RFC 5280 §3.2 — subject equals issuer)?
 *
 * Three steps of §6.1 turn on it: path length (§6.1.4 (l)) and the two policy
 * counters (§6.1.3 (d)(2), §6.1.4 (h)) all skip a self-issued certificate,
 * because a CA re-keying or re-naming itself is not a delegation to somebody
 * else and should not spend an allowance meant for one.
 *
 * Compared as DER rather than as Node's `subject`/`issuer` strings, which are a
 * rendering: two different names can render alike, and one name can render two
 * ways.
 */
export function isSelfIssued(cert: X509Certificate): boolean {
  const { subject, issuer } = AsnConvert.parse(cert.raw, Certificate).tbsCertificate;
  return Buffer.from(AsnConvert.serialize(subject)).equals(Buffer.from(AsnConvert.serialize(issuer)));
}
