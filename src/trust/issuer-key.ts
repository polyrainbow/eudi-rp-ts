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
 * Checked here: validity windows, signature linkage between certificates, that
 * every issuing certificate is a CA, path length, an optional Extended Key
 * Usage allowlist, and termination at a trust anchor.
 *
 * NOT checked, and why:
 *   - **KeyUsage bits.** Node's `X509Certificate.keyUsage` exposes *extended*
 *     key usage OIDs, not the KeyUsage bit string, and Node offers no access to
 *     it. Enforcing it would mean parsing the DER extension by hand.
 *   - **Name constraints** and **certificate policies**, for the same reason.
 *   - **Revocation of the certificates themselves** (CRL, OCSP). Credential
 *     revocation is handled by Token Status List; issuer certificate revocation
 *     is a separate mechanism this does not implement. In the EUDI model a
 *     withdrawn issuer is expected to leave the trusted list, which the trust
 *     list refresh picks up — that is weaker than CRL and worth knowing.
 */
export type ResolvedIssuer = {
  publicKey: KeyObject;
  leaf: X509Certificate;
  /** Leaf first, anchor last. */
  chain: X509Certificate[];
};

export type PathValidationOptions = {
  /**
   * Extended Key Usage OIDs the leaf must carry at least one of. Empty means
   * unenforced. The EU reference PID signer carries `1.0.18013.5.1.2`
   * (ISO 18013-5 document signer) and `1.0.23220.4.1.2`.
   */
  requiredExtendedKeyUsage?: string[];
  /** Reject chains longer than this, anchor excluded. */
  maxChainLength?: number;
};

export function resolveIssuerKeyFromX5c(
  credentialJwt: string,
  anchors: TrustAnchors,
  now: Date,
  options: PathValidationOptions = {},
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

  const maxChainLength = options.maxChainLength ?? 8;
  if (chain.length > maxChainLength) {
    return reject('ISSUER_UNTRUSTED', `x5c chain is ${chain.length} long, limit ${maxChainLength}`);
  }

  for (const cert of chain) {
    if (now < cert.validFromDate) {
      return reject('ISSUER_UNTRUSTED', `Certificate not yet valid: ${cert.subject}`);
    }
    if (now > cert.validToDate) {
      return reject('ISSUER_UNTRUSTED', `Certificate expired: ${cert.subject}`);
    }
  }

  // Each certificate must be signed by the next, and the next must be entitled
  // to sign certificates at all. Without the CA check, a leaf could issue a
  // certificate for any subject and the chain would still verify.
  for (let i = 0; i < chain.length - 1; i++) {
    const child = chain[i]!;
    const parent = chain[i + 1]!;
    if (!parent.ca) {
      return reject('ISSUER_UNTRUSTED', `x5c position ${i + 1} is not a CA: ${parent.subject}`);
    }
    if (!child.checkIssued(parent) || !child.verify(parent.publicKey)) {
      return reject('ISSUER_UNTRUSTED', `Broken x5c chain at position ${i}: ${child.subject}`);
    }
  }

  // The chain must terminate at an anchor: either the top certificate IS an
  // anchor, or an anchor signed it. An anchor that signs must itself be a CA.
  const top = chain.at(-1)!;
  const equalAnchor = anchors.findEqual(top);
  const signingAnchor = equalAnchor ?? anchors.findIssuerOf(top);
  if (!equalAnchor && signingAnchor && !signingAnchor.ca) {
    return reject('ISSUER_UNTRUSTED', `Trust anchor is not a CA: ${signingAnchor.subject}`);
  }
  if (!signingAnchor) {
    return reject(
      'ISSUER_UNTRUSTED',
      `x5c chain does not terminate at a trust anchor: ${top.subject}`,
    );
  }

  const leaf = chain[0]!;

  const requiredEku = options.requiredExtendedKeyUsage ?? [];
  if (requiredEku.length > 0) {
    const present = leaf.keyUsage ?? [];
    if (!requiredEku.some((oid) => present.includes(oid))) {
      return reject(
        'ISSUER_UNTRUSTED',
        `Issuer certificate lacks a required extended key usage (has ${present.join(', ') || 'none'})`,
      );
    }
  }

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
