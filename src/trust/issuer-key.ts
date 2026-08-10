import { type KeyObject, X509Certificate } from 'node:crypto';
import { decodeProtectedHeader } from '../crypto.ts';
import { type Outcome, accept, reject } from '../result.ts';
import type { TrustAnchors } from './anchors.ts';

/**
 * Resolve the public key that must have signed an SD-JWT VC, and prove that key
 * chains to a trust anchor.
 *
 * `@sd-jwt/*` never does this: its `verifier` callback is `(data, sig) => boolean`,
 * so key discovery and trust are entirely the relying party's problem. This
 * module is that missing half, and it is the substance of the project.
 *
 * We resolve via the `x5c` header, which is what the EUDI ecosystem uses — the
 * reference verifier's client id prefixes are `x509_san_dns` and `x509_hash`.
 *
 * SIMPLIFIED, deliberately — see README "Spec-compliant vs simplified":
 *   - no revocation checking (no CRL, no OCSP)
 *   - no name constraints, path length, key usage or EKU enforcement
 *   - no certificate policy processing
 * Validity windows and signature linkage between certificates ARE checked.
 */
export type ResolvedIssuer = {
  publicKey: KeyObject;
  leaf: X509Certificate;
  /** Leaf first, anchor last. */
  chain: X509Certificate[];
};

export function resolveIssuerKeyFromX5c(
  credentialJwt: string,
  anchors: TrustAnchors,
  now: Date,
): Outcome<ResolvedIssuer> {
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(credentialJwt);
  } catch (error) {
    return reject('CREDENTIAL_MALFORMED', `Cannot decode JWT header: ${String(error)}`);
  }

  const x5c = header['x5c'];
  if (!Array.isArray(x5c) || x5c.length === 0 || !x5c.every((c) => typeof c === 'string')) {
    return reject(
      'ISSUER_KEY_UNRESOLVABLE',
      'Credential header has no usable x5c chain; only x5c resolution is implemented in Phase 1',
    );
  }

  let chain: X509Certificate[];
  try {
    // RFC 7515 x5c entries are standard base64 DER, not base64url.
    chain = x5c.map((c) => new X509Certificate(Buffer.from(c, 'base64')));
  } catch (error) {
    return reject('ISSUER_KEY_UNRESOLVABLE', `Cannot parse x5c certificate: ${String(error)}`);
  }

  for (const cert of chain) {
    if (now < cert.validFromDate) {
      return reject('ISSUER_UNTRUSTED', `Certificate not yet valid: ${cert.subject}`);
    }
    if (now > cert.validToDate) {
      return reject('ISSUER_UNTRUSTED', `Certificate expired: ${cert.subject}`);
    }
  }

  // Each certificate must be signed by the next one in the chain.
  for (let i = 0; i < chain.length - 1; i++) {
    const child = chain[i]!;
    const parent = chain[i + 1]!;
    if (!child.checkIssued(parent) || !child.verify(parent.publicKey)) {
      return reject('ISSUER_UNTRUSTED', `Broken x5c chain at position ${i}: ${child.subject}`);
    }
  }

  // The chain must terminate at an anchor: either the top certificate IS an
  // anchor, or an anchor signed it.
  const top = chain.at(-1)!;
  const equalAnchor = anchors.findEqual(top);
  const signingAnchor = equalAnchor ?? anchors.findIssuerOf(top);
  if (!signingAnchor) {
    return reject(
      'ISSUER_UNTRUSTED',
      `x5c chain does not terminate at a trust anchor: ${top.subject}`,
    );
  }

  const leaf = chain[0]!;
  if (leaf.publicKey.asymmetricKeyType !== 'ec') {
    return reject(
      'UNSUPPORTED_ALGORITHM',
      `Issuer key is ${String(leaf.publicKey.asymmetricKeyType)}, expected an EC P-256 key`,
    );
  }

  return accept({
    publicKey: leaf.publicKey,
    leaf,
    chain: equalAnchor ? chain : [...chain, signingAnchor],
  });
}
