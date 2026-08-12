import { AsnConvert } from '@peculiar/asn1-schema';
import { Certificate, KeyUsage, KeyUsageFlags, id_ce_keyUsage } from '@peculiar/asn1-x509';
import type { X509Certificate } from 'node:crypto';

/**
 * Reading the KeyUsage extension (RFC 5280 §4.2.1.3).
 *
 * A certificate carrying this extension is stating what its key may be used
 * for. Path validation cares about two of the nine bits: `keyCertSign`, without
 * which a certificate may not sign other certificates (§6.1.4 (n)), and
 * `digitalSignature`, without which a key may not verify a signature over
 * anything but a certificate or a CRL.
 *
 * Node's `X509Certificate` is no help. Its `keyUsage` property is the *extended*
 * key usage OID list — a different extension with a confusingly similar name —
 * and it exposes no way to reach the KeyUsage bit string, so the DER has to be
 * parsed. `@peculiar/asn1-x509` already does that here for Name Constraints;
 * this is the second use, and the rule is unchanged: that dependency reads
 * structures, `node:crypto` does every cryptographic operation.
 *
 * This module only *reads*. Applying the bits to a chain is `issuer-key.ts`.
 */

export type KeyUsageBit =
  | 'digitalSignature'
  | 'nonRepudiation'
  | 'keyEncipherment'
  | 'dataEncipherment'
  | 'keyAgreement'
  | 'keyCertSign'
  | 'cRLSign'
  | 'encipherOnly'
  | 'decipherOnly';

export type KeyUsageSet = {
  /**
   * RFC 5280 §4.2.1.3 says the extension SHOULD be critical, and it usually is.
   * Carried because "the certificate insisted" and "the certificate mentioned"
   * are different statements, even though nothing rejects on it today.
   */
  critical: boolean;
  bits: ReadonlySet<KeyUsageBit>;
};

/**
 * The KeyUsage bits a certificate asserts, or undefined if it asserts none.
 *
 * Undefined means the extension is absent, which RFC 5280 leaves as "no
 * restriction" — deliberately different from an extension present with a bit
 * clear, which is the certificate refusing that use. Callers must keep the two
 * apart: 60 of the end-entity certificates on the live trusted lists carry no
 * KeyUsage at all (REPRODUCE.md), and treating that as a denial would reject
 * them for saying nothing.
 *
 * Throws on DER it cannot read, rather than returning undefined. An unreadable
 * extension is not an absent one, and a path validated by ignoring the question
 * is not validated — the same rule `readNameConstraints` follows.
 */
export function readKeyUsage(cert: X509Certificate): KeyUsageSet | undefined {
  const parsed = AsnConvert.parse(cert.raw, Certificate);
  const extension = parsed.tbsCertificate.extensions?.find((e) => e.extnID === id_ce_keyUsage);
  if (!extension) return undefined;

  const value = AsnConvert.parse(extension.extnValue, KeyUsage).toNumber();
  const bits = new Set<KeyUsageBit>();
  for (const [flag, name] of Object.entries(KeyUsageFlags)) {
    const mask = Number(flag);
    // The enum is bidirectional — TypeScript emits both name->value and
    // value->name entries — so half of what this iterates is the reverse map.
    if (!Number.isInteger(mask) || mask === 0) continue;
    if (value & mask) bits.add(name as KeyUsageBit);
  }

  return { critical: extension.critical, bits };
}
