import type { X509Certificate } from 'node:crypto';
import { isSelfIssued } from './basic-constraints.ts';
import {
  ANY_POLICY,
  readCertificatePolicies,
  readInhibitAnyPolicy,
  readPolicyConstraints,
  readPolicyMappings,
} from './policies.ts';

/**
 * Certificate policy processing (RFC 5280 §6.1.2, §6.1.3 (d)-(f), §6.1.4
 * (a)-(b) and (h)-(j), §6.1.5).
 *
 * This is the one part of §6.1 that is a state machine rather than a check. The
 * question it answers is not "does this certificate assert policy X" — that
 * would be a one-line test and would be wrong. It is "is there a policy that
 * every CA on the path agreed this certificate could be issued under", where
 * each CA may narrow the set, rename it into its own arc (`policyMappings`),
 * forbid renaming further down (`inhibitPolicyMapping`), require its successors
 * to be explicit about it (`requireExplicitPolicy`), or refuse the anyPolicy
 * wildcard (`inhibitAnyPolicy`). The valid_policy_tree carries that agreement,
 * and the counters carry the "…from here on" that each of those statements has.
 *
 * The chain arrives leaf-first with the anchor last, the shape `issuer-key.ts`
 * holds; the RFC numbers a path the other way, from the certificate the anchor
 * issued (1) down to the end entity (n), with **the anchor not in it**. §6.1.2
 * gives the anchor's position to the initial state — a root node valid for
 * anyPolicy — rather than to a certificate, and it has to: an anchor fed in as
 * certificate 1 would set the tree to NULL under §6.1.3 (e) for every anchor
 * that asserts no policy of its own, which is 67 of the 1165 CA certificates on
 * the live trusted lists and the EU PID Issuer CA among them (REPRODUCE.md).
 *
 * What the anchor *does* contribute is its constraints, per RFC 5937 §3.2:
 * `policyConstraints` and `inhibitAnyPolicy` on the anchor are folded into the
 * initial counters. This is the same position `issuer-key.ts` takes on Name
 * Constraints — a trust anchor that constrains the paths beneath it means it —
 * and it can only ever tighten. Its policy *assertions* are deliberately not
 * read the same way: a constraint binds what is below, an assertion is a claim
 * about the anchor itself. Eight CA certificates on the live lists carry
 * `policyConstraints` (four Italian, four Slovak), all of them
 * `requireExplicitPolicy: 0`, and none carries `inhibitAnyPolicy`.
 *
 * Returns a rejection reason, or undefined if the path is policy-valid.
 */

export type CertificatePolicyOptions = {
  /**
   * The policy OIDs the caller will accept — RFC 5280 §6.1.1 (c)
   * user-initial-policy-set. Absent or empty means any-policy: the tree is
   * still built and every certificate's own constraints are still honoured,
   * but no particular policy is demanded.
   *
   * eIDAS is where this earns its place. A trusted list entry says a CA is
   * supervised; the policy OID on the certificate under it says whether this
   * particular certificate was issued as a qualified one. The live EU PID
   * document signer asserts `1.2.3.4` and the reference verifier signer
   * `0.4.0.194118.1.2` (REPRODUCE.md), so the OIDs to name here are a property
   * of the deployment, which is why there is no default.
   */
  acceptable?: string[];
  /**
   * §6.1.1 (f) initial-explicit-policy: every certificate must assert an
   * acceptable policy, rather than only those below a CA that said so.
   *
   * **Defaults to true when `acceptable` is non-empty**, which the RFC does not
   * — there, naming a policy set with initial-explicit-policy unset leaves a
   * path asserting no policy at all valid (§6.1.5 (g), success on
   * `explicit_policy > 0`). A caller that names the policies it accepts is
   * stating a requirement, so it is read as one. Pass `false` for the RFC's
   * own reading.
   */
  requireExplicit?: boolean;
  /** §6.1.1 (g) initial-policy-mapping-inhibit: honour no policy mapping. */
  inhibitMapping?: boolean;
  /** §6.1.1 (h) initial-any-policy-inhibit: treat anyPolicy as any other OID. */
  inhibitAnyPolicy?: boolean;
};

/**
 * A node of the valid_policy_tree (§6.1.2).
 *
 * `qualifier_set` is the one field of the RFC's node that is missing, because
 * nothing here reads it: §6.1.5 (f) makes acting on qualifiers a local matter,
 * and this library takes no local action on a CPS URI or a user notice. What it
 * would carry is still read — see `PolicyInformationValue.qualifiers`.
 */
type PolicyNode = {
  validPolicy: string;
  expectedPolicySet: Set<string>;
  depth: number;
  parent: PolicyNode | undefined;
  children: PolicyNode[];
  /** Set by `removeNode`, so a node deleted mid-step is not consulted again. */
  removed: boolean;
};

export function checkCertificatePolicies(
  chain: X509Certificate[],
  options: CertificatePolicyOptions = {},
): string | undefined {
  const anchor = chain.at(-1);
  const path = chain.slice(0, -1).reverse();
  const n = path.length;
  // The end certificate is itself the trust anchor: there is no path below the
  // anchor to constrain, and being on a trusted list directly is a stronger
  // statement than any policy OID a CA above could have made about it.
  if (n === 0 || !anchor) return undefined;

  const acceptable = new Set(options.acceptable ?? []);
  const anyAcceptable = acceptable.size === 0;
  const requireExplicit = options.requireExplicit ?? !anyAcceptable;

  // §6.1.2 (a): a single root node, valid for anyPolicy and expecting it.
  let root: PolicyNode | undefined = {
    validPolicy: ANY_POLICY,
    expectedPolicySet: new Set([ANY_POLICY]),
    depth: 0,
    parent: undefined,
    children: [],
    removed: false,
  };
  const levels: PolicyNode[][] = [[root]];

  // §6.1.2 (d), (e), (f): each counter is "how many more certificates may pass
  // before this applies", and n+1 means never.
  let explicitPolicy = requireExplicit ? 0 : n + 1;
  let policyMapping = options.inhibitMapping ? 0 : n + 1;
  let inhibitAnyPolicy = options.inhibitAnyPolicy ? 0 : n + 1;
  /** Who demanded it, so a rejection can say. */
  let explicitPolicyBy = requireExplicit ? 'the caller' : undefined;

  // RFC 5937 §3.2: the anchor's own constraints join the initial state. Reading
  // them can only lower a counter, so an anchor carrying none — which is the
  // normal case, and the case for every anchor in the EUDI reference
  // deployment — leaves everything above exactly as it was.
  try {
    const anchorConstraints = readPolicyConstraints(anchor);
    if (anchorConstraints) {
      if (
        anchorConstraints.requireExplicitPolicy !== undefined &&
        anchorConstraints.requireExplicitPolicy < explicitPolicy
      ) {
        explicitPolicy = anchorConstraints.requireExplicitPolicy;
        explicitPolicyBy = anchor.subject;
      }
      if (
        anchorConstraints.inhibitPolicyMapping !== undefined &&
        anchorConstraints.inhibitPolicyMapping < policyMapping
      ) {
        policyMapping = anchorConstraints.inhibitPolicyMapping;
      }
    }
    const anchorAnyPolicyLimit = readInhibitAnyPolicy(anchor);
    if (anchorAnyPolicyLimit && anchorAnyPolicyLimit.skipCerts < inhibitAnyPolicy) {
      inhibitAnyPolicy = anchorAnyPolicyLimit.skipCerts;
    }
  } catch (error) {
    return `Cannot read the policy constraints of the trust anchor ${anchor.subject}: ${String(error)}`;
  }

  const at = (depth: number): PolicyNode[] => levels[depth] ?? [];

  const addChild = (parent: PolicyNode, validPolicy: string, expected: Set<string>): void => {
    const child: PolicyNode = {
      validPolicy,
      expectedPolicySet: expected,
      depth: parent.depth + 1,
      parent,
      children: [],
      removed: false,
    };
    parent.children.push(child);
    (levels[child.depth] ??= []).push(child);
  };

  const removeNode = (node: PolicyNode): void => {
    if (node.removed) return;
    node.removed = true;
    levels[node.depth] = at(node.depth).filter((candidate) => candidate !== node);
    if (node.parent) node.parent.children = node.parent.children.filter((c) => c !== node);
    for (const child of [...node.children]) removeNode(child);
    if (node === root) root = undefined;
  };

  /**
   * §6.1.3 (d)(3): delete every node of `maxDepth` or less that has no
   * children, repeating upwards. A root left childless *is* deleted — that is
   * how the tree becomes NULL.
   */
  const prune = (maxDepth: number): void => {
    for (let depth = maxDepth; depth >= 1; depth -= 1) {
      for (const node of [...at(depth)]) {
        if (node.children.length === 0) removeNode(node);
      }
    }
    if (root && root.children.length === 0) removeNode(root);
  };

  let assertedByEndCertificate: string[] | undefined;

  for (let i = 1; i <= n; i += 1) {
    const cert = path[i - 1]!;

    let policies;
    let mappings;
    let constraints;
    let anyPolicyLimit;
    let selfIssued;
    try {
      policies = readCertificatePolicies(cert);
      mappings = readPolicyMappings(cert);
      constraints = readPolicyConstraints(cert);
      anyPolicyLimit = readInhibitAnyPolicy(cert);
      selfIssued = isSelfIssued(cert);
    } catch (error) {
      // Unreadable DER fails the path, as it does for Name Constraints: we
      // cannot tell what the CA permitted, so we cannot say it permitted this.
      return `Cannot read the policy extensions of ${cert.subject}: ${String(error)}`;
    }
    if (i === n) assertedByEndCertificate = policies?.policies.map((p) => p.oid);

    // §6.1.3 (d): grow the tree with what this certificate asserts.
    if (policies && root) {
      const parents = [...at(i - 1)];

      // (d)(1): a policy the certificate names, placed under every node
      // expecting it — or, failing that, under anyPolicy.
      for (const { oid } of policies.policies) {
        if (oid === ANY_POLICY) continue;
        const expecting = parents.filter((parent) => parent.expectedPolicySet.has(oid));
        if (expecting.length > 0) {
          for (const parent of expecting) {
            if (!parent.children.some((c) => c.validPolicy === oid)) {
              addChild(parent, oid, new Set([oid]));
            }
          }
          continue;
        }
        const wildcard = parents.find((parent) => parent.validPolicy === ANY_POLICY);
        if (wildcard && !wildcard.children.some((c) => c.validPolicy === oid)) {
          addChild(wildcard, oid, new Set([oid]));
        }
      }

      // (d)(2): anyPolicy asserted by this certificate stands in for every
      // policy still expected — unless a CA above has stopped honouring it.
      // A self-issued certificate that is not the end entity is exempt: it is
      // the same CA re-keying, not a delegation, so it does not spend the
      // allowance.
      const assertsAnyPolicy = policies.policies.some((p) => p.oid === ANY_POLICY);
      if (assertsAnyPolicy && (inhibitAnyPolicy > 0 || (i < n && selfIssued))) {
        for (const parent of parents) {
          for (const expected of parent.expectedPolicySet) {
            if (!parent.children.some((c) => c.validPolicy === expected)) {
              addChild(parent, expected, new Set([expected]));
            }
          }
        }
      }

      // (d)(3)
      prune(i - 1);
    } else if (!policies) {
      // §6.1.3 (e): silence about policy ends the tree. Harmless while nothing
      // requires an explicit policy, fatal the moment something does.
      root = undefined;
    }

    // §6.1.3 (f)
    if (explicitPolicy <= 0 && !root) {
      const asserted = policies?.policies.map((p) => p.oid).join(', ');
      const requiredBy = explicitPolicyBy ?? 'the caller';
      return policies
        ? `${cert.subject} asserts certificate policies (${asserted}) that no certificate above it authorises, and ${requiredBy} requires an explicit policy`
        : `${cert.subject} asserts no certificate policy, and ${requiredBy} requires an explicit policy`;
    }

    if (i < n) {
      // §6.1.4 (a): mapping to or from anyPolicy is a syntax error, not a
      // mapping — it would let a CA launder every policy into every other.
      if (mappings) {
        for (const mapping of mappings.mappings) {
          if (mapping.issuerDomainPolicy === ANY_POLICY || mapping.subjectDomainPolicy === ANY_POLICY) {
            return `${cert.subject} maps a certificate policy to or from anyPolicy, which RFC 5280 §6.1.4 (a) forbids`;
          }
        }

        const equivalents = new Map<string, Set<string>>();
        for (const mapping of mappings.mappings) {
          const already = equivalents.get(mapping.issuerDomainPolicy);
          if (already) already.add(mapping.subjectDomainPolicy);
          else equivalents.set(mapping.issuerDomainPolicy, new Set([mapping.subjectDomainPolicy]));
        }

        if (policyMapping > 0) {
          // (b)(1): the issuer's policy continues below under the subject's
          // name for it.
          for (const [issuerPolicy, subjectPolicies] of equivalents) {
            const node = at(i).find((candidate) => candidate.validPolicy === issuerPolicy);
            if (node) {
              node.expectedPolicySet = new Set(subjectPolicies);
              continue;
            }
            if (!at(i).some((candidate) => candidate.validPolicy === ANY_POLICY)) continue;
            const wildcardAbove = at(i - 1).find((candidate) => candidate.validPolicy === ANY_POLICY);
            if (wildcardAbove) addChild(wildcardAbove, issuerPolicy, new Set(subjectPolicies));
          }
        } else {
          // (b)(2): mapping is inhibited, so the mapped policy simply ends here
          // rather than continuing under another name.
          for (const issuerPolicy of equivalents.keys()) {
            for (const node of [...at(i)]) {
              if (node.validPolicy === issuerPolicy) removeNode(node);
            }
          }
          prune(i - 1);
        }
      }

      // §6.1.4 (h): only a delegation to somebody else spends the allowances.
      if (!selfIssued) {
        if (explicitPolicy !== 0) explicitPolicy -= 1;
        if (policyMapping !== 0) policyMapping -= 1;
        if (inhibitAnyPolicy !== 0) inhibitAnyPolicy -= 1;
      }

      // §6.1.4 (i) and (j): a CA may only tighten, never loosen, what it was
      // handed — hence the `<` on each.
      if (constraints) {
        if (
          constraints.requireExplicitPolicy !== undefined &&
          constraints.requireExplicitPolicy < explicitPolicy
        ) {
          explicitPolicy = constraints.requireExplicitPolicy;
          explicitPolicyBy = cert.subject;
        }
        if (
          constraints.inhibitPolicyMapping !== undefined &&
          constraints.inhibitPolicyMapping < policyMapping
        ) {
          policyMapping = constraints.inhibitPolicyMapping;
        }
      }
      if (anyPolicyLimit && anyPolicyLimit.skipCerts < inhibitAnyPolicy) {
        inhibitAnyPolicy = anyPolicyLimit.skipCerts;
      }
    } else {
      // §6.1.5 (a) and (b), the wrap-up for the end certificate.
      if (explicitPolicy !== 0) explicitPolicy -= 1;
      if (constraints?.requireExplicitPolicy === 0) {
        explicitPolicy = 0;
        explicitPolicyBy ??= cert.subject;
      }
    }
  }

  // §6.1.5 (g): intersect what the path is valid for with what the caller asked
  // for. Skipped when the caller accepts any policy, where the intersection is
  // the tree itself.
  if (!anyAcceptable && root) {
    // (iii)(1) and (2): a node under anyPolicy is only there because a CA
    // wildcarded it, so it survives only if the caller named it.
    const underWildcard = allNodes(levels).filter(
      (node) => node.parent !== undefined && node.parent.validPolicy === ANY_POLICY,
    );
    for (const node of underWildcard) {
      if (node.validPolicy !== ANY_POLICY && !acceptable.has(node.validPolicy)) removeNode(node);
    }

    // (iii)(3): anyPolicy surviving at the end stands in for each acceptable
    // policy not already present, and is then itself removed.
    const wildcardAtEnd = at(n).find((node) => node.validPolicy === ANY_POLICY);
    if (wildcardAtEnd) {
      const parent =
        at(n - 1).find((node) => node.validPolicy === ANY_POLICY) ?? wildcardAtEnd.parent;
      if (parent) {
        const present = new Set(
          underWildcard.filter((node) => !node.removed).map((node) => node.validPolicy),
        );
        for (const oid of acceptable) {
          if (!present.has(oid)) addChild(parent, oid, new Set([oid]));
        }
      }
      removeNode(wildcardAtEnd);
    }

    // (iii)(4)
    prune(n - 1);
  }

  // §6.1.5: the path succeeds if nothing insisted on an explicit policy, or if
  // something is left in the tree after the intersection.
  if (explicitPolicy > 0 || root) return undefined;

  const asserted = assertedByEndCertificate?.join(', ');
  return `No certificate policy is valid for the whole path: ${explicitPolicyBy ?? 'the caller'} requires one of ${[...acceptable].join(', ') || 'any policy'}, and the issuer certificate asserts ${asserted || 'none'}`;
}

function allNodes(levels: PolicyNode[][]): PolicyNode[] {
  return levels.flatMap((level) => [...level]);
}
