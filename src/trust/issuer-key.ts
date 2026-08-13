import { type KeyObject, X509Certificate } from 'node:crypto';
import { decodeProtectedHeader, unsupportedKeyReason } from '../crypto.ts';
import { type Outcome, accept, reject } from '../result.ts';
import type { TrustAnchors } from './anchors.ts';
import { isSelfIssued, readBasicConstraints } from './basic-constraints.ts';
import { unrecognisedCriticalExtensions } from './critical-extensions.ts';
import { readKeyUsage } from './key-usage.ts';
import { certificateNames, readNameConstraints } from './name-constraints.ts';
import { checkNames } from './name-matching.ts';
import { type CertificatePolicyOptions, checkCertificatePolicies } from './policy-tree.ts';

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
 * asserts `digitalSignature` if it asserts any KeyUsage at all, path length —
 * the caller's limit and every CA's own `pathLenConstraint` — an optional
 * Extended Key Usage allowlist, Name Constraints, certificate policies,
 * termination at a trust anchor, and that no certificate below the anchor
 * carries a critical extension this library does not process (§6.1.4 (o)).
 *
 * Of those, the *leaf* KeyUsage check is the one nothing else was doing. The
 * issuing-side `keyCertSign` requirement is already inside Node's `.ca` and
 * `checkIssued` (see `checkMaySignCertificates`); a leaf's KeyUsage is looked at
 * by nobody, because no library here knows that this key is about to verify a
 * credential signature rather than a TLS handshake.
 *
 * Not done here, and deliberately: **revocation of the certificates themselves**
 * (CRL, OCSP) is implemented in `revocation.ts` and driven a step later, because
 * this function must stay synchronous — `@sd-jwt`'s callbacks have nowhere to
 * await, so the revocation check runs against the chain this returns.
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
  /**
   * Reject chains longer than this, anchor excluded. The caller's own limit,
   * independent of the `pathLenConstraint` each CA on the chain publishes —
   * which is enforced whatever this says.
   */
  maxChainLength?: number;
  /**
   * Certificate policy processing (RFC 5280 §6.1). Absent means the caller
   * accepts any policy — which is *not* the same as skipping the step: a CA
   * that requires an explicit policy, inhibits anyPolicy or maps policies is
   * obeyed either way. See `policy-tree.ts`.
   */
  certificatePolicies?: CertificatePolicyOptions;
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

  // Before every check below it: those read specific extensions and conclude
  // something, and concluding anything about a certificate carrying an
  // instruction we could not read is the mistake §6.1.4 (o) exists to prevent.
  const unread = checkCriticalExtensions(fullChain);
  if (unread) return reject('ISSUER_EXTENSION_UNRECOGNISED', unread);

  // Applied to the chain including the anchor: a trust anchor that constrains
  // itself to a namespace means it, and RFC 5280 §6.1 applies constraints from
  // every certificate in the path.
  const notPermitted = checkChainNameConstraints(fullChain);
  if (notPermitted) return reject('ISSUER_NAME_NOT_PERMITTED', notPermitted);

  const tooDeep = checkPathLength(fullChain);
  if (tooDeep) return reject('ISSUER_UNTRUSTED', tooDeep);

  // Certificate policies, over the same path and with the same reading of the
  // anchor's role: its constraints bind, its own assertions do not. Which
  // policies are acceptable is the caller's, so by default this enforces only
  // what the certificates themselves demand.
  const policyFailure = checkCertificatePolicies(fullChain, options.certificatePolicies ?? {});
  if (policyFailure) return reject('ISSUER_POLICY_NOT_PERMITTED', policyFailure);

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
 * Unrecognised critical extensions across a whole path (RFC 5280 §6.1.4 (o)).
 *
 * `chain` is leaf-first with the anchor last, and the anchor is exempt. §6.1
 * never processes it as a certificate — it supplies the initial state and the
 * loop that (o) belongs to runs over the certificates below it. RFC 5937 does
 * extend an anchor's influence downward, but only its *constraints*: name
 * constraints, `policyConstraints`, `inhibitAnyPolicy`, `pathLenConstraint`,
 * each of which this library obeys. A critical extension is not a constraint on
 * the path, it is an instruction about the certificate carrying it, and reading
 * the anchor's own assertions is the thing this codebase declines to do
 * everywhere else. Constraints bind, assertions do not.
 *
 * Which leaves the anchor answerable the way an anchor should be: it is trusted
 * because an operator pinned it or a Member State published it, not because we
 * understood every field on it.
 */
function checkCriticalExtensions(chain: X509Certificate[]): string | undefined {
  for (const cert of chain.slice(0, -1)) {
    let unrecognised: string[];
    try {
      unrecognised = unrecognisedCriticalExtensions(cert);
    } catch (error) {
      return `Cannot read the extensions of ${cert.subject}: ${String(error)}`;
    }
    if (unrecognised.length > 0) {
      return `${cert.subject} carries critical extension(s) this library does not process: ${unrecognised.join(', ')}`;
    }
  }
  return undefined;
}

/**
 * Path length across a whole path (RFC 5280 §6.1.2 (k), §6.1.4 (l) and (m)).
 *
 * `pathLenConstraint` is a CA stating how many further CA certificates may sit
 * between it and an end entity, and it is the half of `basicConstraints` that
 * Node does not expose — `.ca` is the other half. Without it a CA that signs
 * end-entity certificates only, which is 692 of the 1165 CA certificates on the
 * live trusted lists and the EU PID Issuer CA among them, can appear to have
 * issued a sub-CA that then vouches for anybody.
 *
 * `chain` is leaf-first with the anchor last; the RFC counts the other way. The
 * anchor's own constraint is applied as an initial limit (RFC 5937 §3.2), on the
 * same reading as Name Constraints and the policy constraints: what a trust
 * anchor says about the paths beneath it binds them.
 *
 * A self-issued certificate does not spend a step (§6.1.4 (l)) — it is a CA
 * re-keying itself, not a delegation. The end certificate's own constraint is
 * not read: it says what *it* may issue, which is not this path's question.
 */
function checkPathLength(chain: X509Certificate[]): string | undefined {
  const anchor = chain.at(-1);
  const path = chain.slice(0, -1).reverse();
  if (path.length === 0 || !anchor) return undefined;

  let remaining = path.length;
  let limitedBy = anchor.subject;
  try {
    const anchorConstraints = readBasicConstraints(anchor);
    if (anchorConstraints?.pathLenConstraint !== undefined) {
      remaining = Math.min(remaining, anchorConstraints.pathLenConstraint);
    }

    // Every certificate but the last: these are the CAs, and the rule is about
    // how many of them there may be.
    for (const cert of path.slice(0, -1)) {
      if (!isSelfIssued(cert)) {
        if (remaining <= 0) {
          return `${cert.subject} is a CA certificate below ${limitedBy}, which permits no further CA certificates`;
        }
        remaining -= 1;
      }
      const constraints = readBasicConstraints(cert);
      if (constraints?.pathLenConstraint !== undefined && constraints.pathLenConstraint < remaining) {
        remaining = constraints.pathLenConstraint;
        limitedBy = cert.subject;
      }
    }
  } catch (error) {
    return `Cannot read the basic constraints of a certificate on the path: ${String(error)}`;
  }
  return undefined;
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
