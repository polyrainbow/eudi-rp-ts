import { type KeyObject, X509Certificate } from 'node:crypto';
import { decodeProtectedHeader, unsupportedKeyReason } from '../crypto.ts';
import { type Outcome, accept, reject } from '../result.ts';
import type { TrustAnchors } from './anchors.ts';
import { readKeyUsage } from './key-usage.ts';
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
 * every issuing certificate is a CA and asserts `keyCertSign`, that the leaf
 * asserts `digitalSignature` if it asserts any KeyUsage at all, path length, an
 * optional Extended Key Usage allowlist, Name Constraints, and termination at a
 * trust anchor.
 *
 * Of those, the *leaf* KeyUsage check is the one nothing else was doing. The
 * issuing-side `keyCertSign` requirement is already inside Node's `.ca` and
 * `checkIssued` (see `checkMaySignCertificates`); a leaf's KeyUsage is looked at
 * by nobody, because no library here knows that this key is about to verify a
 * credential signature rather than a TLS handshake.
 *
 * NOT checked, and why:
 *   - **Certificate policies.** Node exposes no way to reach them, so it means
 *     parsing DER — which `key-usage.ts` and `name-constraints.ts` now do for
 *     their extensions, making this a matter of nobody having needed policy
 *     processing rather than of it being out of reach.
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
  /**
   * The instant to evaluate trust list status at. Defaults to `now`.
   *
   * A service's entry on a trusted list is granted from a stated time, not
   * forever, so "is this anchor trusted" is only answerable against an instant.
   * The default is the validation time, which is the safest reading for a
   * credential being presented live: a service withdrawn since issuance stops
   * vouching for anything, including credentials it signed while granted.
   *
   * Pass the credential's signing time instead for the other reading, the one
   * eIDAS uses for long-term signatures, where a withdrawal is not retroactive
   * and what matters is that the service was granted when it signed. That
   * reading also rejects the converse case the default accepts: a service
   * granted *after* the credential was signed. Only anchors from a trust list
   * are affected — pinned anchors carry no status to evaluate.
   */
  trustListEvaluationTime?: Date;
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
    // Before the `ca` check, because it is the more specific statement: a
    // certificate marked CA:TRUE whose KeyUsage omits keyCertSign is not "not a
    // CA", it is a CA refusing to sign certificates, and an operator reading
    // the rejection needs to be told which.
    const notEntitled = checkMaySignCertificates(parent, `x5c position ${i + 1}`);
    if (notEntitled) return reject('ISSUER_UNTRUSTED', notEntitled);
    if (!parent.ca) {
      return reject('ISSUER_UNTRUSTED', `x5c position ${i + 1} is not a CA: ${parent.subject}`);
    }
    if (!child.checkIssued(parent) || !child.verify(parent.publicKey)) {
      return reject('ISSUER_UNTRUSTED', `Broken x5c chain at position ${i}: ${child.subject}`);
    }
  }

  // The chain must terminate at an anchor: either the top certificate IS an
  // anchor, or an anchor signed it. An anchor that signs must itself be a CA.
  //
  // "Is an anchor" is a question about an instant, not a standing fact: a trust
  // list grants a service from a stated time and can withdraw it later, so the
  // lookup is made against `evaluationTime`.
  const evaluationTime = options.trustListEvaluationTime ?? now;
  const top = chain.at(-1)!;
  const equalAnchor = anchors.findEqual(top, evaluationTime);
  const signingAnchor = equalAnchor ?? anchors.findIssuerOf(top, evaluationTime);
  if (!equalAnchor && signingAnchor && !signingAnchor.ca) {
    return reject('ISSUER_UNTRUSTED', `Trust anchor is not a CA: ${signingAnchor.subject}`);
  }
  // No explicit keyCertSign check on the anchor: `findIssuerOf` reaches it
  // through `checkIssued`, which is OpenSSL's `X509_check_issued` and already
  // refuses an issuer whose KeyUsage omits the bit. Such an anchor is therefore
  // never found in the first place, and the rejection below reports it as a
  // chain that terminates nowhere trusted. A test pins that.
  if (!signingAnchor) {
    // Distinguish "not on any list" from "on a list, but not at this instant":
    // the second is a service whose grant had not started or had ended, and
    // reporting it as an unknown issuer would send an operator looking for the
    // wrong thing.
    const knownAtAnotherTime = anchors.findEqual(top) ?? anchors.findIssuerOf(top);
    return reject(
      'ISSUER_UNTRUSTED',
      knownAtAnotherTime
        ? `x5c chain terminates at ${top.subject}, which was not a granted trust service at ${evaluationTime.toISOString()}`
        : `x5c chain does not terminate at a trust anchor: ${top.subject}`,
    );
  }

  const fullChain = equalAnchor ? chain : [...chain, signingAnchor];

  // Applied to the chain including the anchor: a trust anchor that constrains
  // itself to a namespace means it, and RFC 5280 §6.1 applies constraints from
  // every certificate in the path.
  const notPermitted = checkChainNameConstraints(fullChain);
  if (notPermitted) return reject('ISSUER_NAME_NOT_PERMITTED', notPermitted);

  const leaf = chain[0]!;

  // The leaf's key is about to verify a credential signature, so a leaf that
  // asserts KeyUsage must include the bit for exactly that. `nonRepudiation`
  // alone does not qualify: it covers a non-repudiation service, not the
  // data-origin signature an issuer makes over a credential, and ISO 18013-5
  // Annex B requires `digitalSignature` on a document signer certificate.
  let leafUsage;
  try {
    leafUsage = readKeyUsage(leaf);
  } catch (error) {
    return reject('ISSUER_UNTRUSTED', `Cannot read the key usage of ${leaf.subject}: ${String(error)}`);
  }
  if (leafUsage && !leafUsage.bits.has('digitalSignature')) {
    return reject(
      'ISSUER_UNTRUSTED',
      `Issuer certificate does not assert digitalSignature (has ${[...leafUsage.bits].join(', ') || 'no usage'}): ${leaf.subject}`,
    );
  }

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

  // Whether *some* supported algorithm could use this key. Which algorithm is
  // acceptable is the caller's policy and the token's claim, checked together
  // where the signature is — see `keyUnusableFor`. Rejecting anything but EC
  // here, as this once did, ruled out the RSA keys 87% of the eIDAS trusted
  // lists are built on before their algorithm was ever named.
  const unusable = unsupportedKeyReason(leaf.publicKey);
  if (unusable) return reject('UNSUPPORTED_ALGORITHM', `Issuer key cannot be used: ${unusable}`);

  return accept({ publicKey: leaf.publicKey, leaf, chain: fullChain });
}

/**
 * May this certificate sign other certificates? (RFC 5280 §4.2.1.3, §6.1.4 (n))
 *
 * `basicConstraints` says a certificate *is* a CA; `keyUsage` says what its key
 * is allowed to do. A certificate marked CA:TRUE whose KeyUsage omits
 * `keyCertSign` is refusing the use about to be made of it, and RFC 5280
 * requires that refusal be honoured.
 *
 * **Node already enforces this, and that is worth stating plainly**: `.ca` is
 * OpenSSL's `X509_check_ca`, which clears the CA flag when a KeyUsage extension
 * is present without `keyCertSign`, and `checkIssued` refuses such an issuer
 * too. So this changes no outcome today. It is here because Node documents `.ca`
 * as "is a CA certificate" and nothing more — the keyCertSign part is an
 * undocumented property of the TLS backend, not a promise, and a path
 * validation resting on it silently would break silently. A test pins Node's
 * behaviour next to this one, so the day the two diverge is a red build rather
 * than a quiet loss.
 *
 * An absent extension is not a refusal — it is silence, which §4.2.1.3 leaves
 * unrestricted, and Node reads it the same way. The distinction costs nothing on
 * the live lists: all 1055 CA certificates published across them carry KeyUsage
 * and all 1055 assert `keyCertSign` (REPRODUCE.md).
 */
function checkMaySignCertificates(cert: X509Certificate, position: string): string | undefined {
  let usage;
  try {
    usage = readKeyUsage(cert);
  } catch (error) {
    return `Cannot read the key usage of ${cert.subject}: ${String(error)}`;
  }
  if (!usage || usage.bits.has('keyCertSign')) return undefined;
  return `${position} does not assert keyCertSign (has ${[...usage.bits].join(', ') || 'no usage'}): ${cert.subject}`;
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
