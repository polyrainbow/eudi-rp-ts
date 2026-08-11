import { type KeyObject, X509Certificate } from 'node:crypto';
import { decodeProtectedHeader } from '../crypto.ts';
import { type Outcome, accept, reject } from '../result.ts';
import type { TrustAnchors } from './anchors.ts';
import { certificateNames, readNameConstraints } from './name-constraints.ts';
import { checkNames } from './name-matching.ts';

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
 * Usage allowlist, Name Constraints, and termination at a trust anchor.
 *
 * NOT checked, and why:
 *   - **KeyUsage bits.** Node's `X509Certificate.keyUsage` exposes *extended*
 *     key usage OIDs, not the KeyUsage bit string, and Node offers no access to
 *     it. Enforcing it would mean parsing the DER extension by hand.
 *   - **Certificate policies**, for the same reason.
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

  return resolveIssuerCertificateChain(chain, anchors, now, options);
}

/**
 * Validate a decoded certificate chain and return the leaf's key.
 *
 * Separate from the JOSE-specific decoding above because mdoc carries the same
 * chain in a COSE `x5chain` header. One trust implementation, two carriers.
 */
export function resolveIssuerCertificateChain(
  chain: X509Certificate[],
  anchors: TrustAnchors,
  now: Date,
  options: PathValidationOptions = {},
): Outcome<ResolvedIssuer> {
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

  const fullChain = equalAnchor ? chain : [...chain, signingAnchor];

  // Applied to the chain including the anchor: a trust anchor that constrains
  // itself to a namespace means it, and RFC 5280 §6.1 applies constraints from
  // every certificate in the path.
  const notPermitted = checkChainNameConstraints(fullChain);
  if (notPermitted) return reject('ISSUER_NAME_NOT_PERMITTED', notPermitted);

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

  return accept({ publicKey: leaf.publicKey, leaf, chain: fullChain });
}

/**
 * Name Constraints across a whole path (RFC 5280 §4.2.1.10, §6.1.3).
 *
 * A CA that carries this extension is stating which names it is entitled to
 * certify, and that statement binds every certificate below it — not just the
 * one it signed directly. Without the check, any CA on any Member State's
 * trusted list can vouch for any subject, which is most of what a constrained
 * CA is for.
 *
 * `chain` is leaf-first, so a certificate at index i constrains 0..i-1.
 *
 * Failing to *read* a constraint is a rejection, not a skip. Malformed DER here
 * means we cannot tell what the CA permitted, and a path validated by ignoring
 * the question is not validated.
 */
function checkChainNameConstraints(chain: X509Certificate[]): string | undefined {
  for (let issuer = 1; issuer < chain.length; issuer += 1) {
    const authority = chain[issuer]!;

    let constraints;
    try {
      constraints = readNameConstraints(authority);
    } catch (error) {
      return `Cannot read the name constraints of ${authority.subject}: ${String(error)}`;
    }
    if (!constraints) continue;

    for (let subject = 0; subject < issuer; subject += 1) {
      const constrained = chain[subject]!;
      let failure: string | undefined;
      try {
        failure = checkNames(certificateNames(constrained), constraints);
      } catch (error) {
        return `Cannot read the names of ${constrained.subject}: ${String(error)}`;
      }
      if (failure) {
        return `${authority.subject} does not permit ${constrained.subject}: ${failure}`;
      }
    }
  }
  return undefined;
}
