import { isIPv4, isIPv6 } from 'node:net';
import type {
  GeneralNameValue,
  NameConstraintSet,
  RelativeDistinguishedName,
} from './name-constraints.ts';

/**
 * Matching a name against a Name Constraint (RFC 5280 §4.2.1.10).
 *
 * Pure functions over the shapes `name-constraints.ts` produces: no
 * certificates, no I/O, no chain. Applying the result to a path is
 * `issuer-key.ts`.
 *
 * Every form has its own rule and they are not interchangeable — a dNSName
 * constraint grows labels to the left, a URI constraint applies only to the
 * host part, a directoryName constraint is a prefix of an RDN sequence. Getting
 * one of them subtly wrong produces a validator that accepts a chain it should
 * reject, which is why each rule is tested against its own boundary cases.
 *
 * SIMPLIFIED, deliberately: DN attribute values are compared case-insensitively
 * on trimmed, whitespace-collapsed text rather than under full RFC 4518 string
 * preparation. That is what practical implementations do, and full preparation
 * (Unicode normalisation, prohibited-character tables, bidirectional rules)
 * would be a project of its own. An attribute whose value is not a readable
 * string type matches nothing at all.
 */

/**
 * Why a certificate's names are not acceptable under a constraint set, or
 * undefined if they are. The string is for a human; callers switch on the
 * reason code they wrap it in.
 */
export function checkNames(
  names: GeneralNameValue[],
  constraints: NameConstraintSet,
): string | undefined {
  const subtrees = [...constraints.permitted, ...constraints.excluded];

  // RFC 5280 §4.2.1.10: "Within this profile, the minimum and maximum fields
  // are not used with any name forms, thus, the minimum MUST be zero, and
  // maximum MUST be absent." A subtree saying otherwise is one we would be
  // guessing at.
  for (const subtree of subtrees) {
    if (subtree.minimum !== 0 || subtree.maximum !== undefined) {
      return `name constraint uses minimum ${subtree.minimum}/maximum ${String(subtree.maximum)}, which RFC 5280 §4.2.1.10 forbids`;
    }
  }

  // A constraint in a form we cannot evaluate fails the chain rather than being
  // ignored. Ignoring it would leave the path looking validated when the one
  // statement the CA made about its own authority went unread.
  const unreadable = subtrees.find((subtree) => subtree.base.form === 'unsupported');
  if (unreadable && unreadable.base.form === 'unsupported') {
    return `name constraint uses the ${unreadable.base.label} name form, which is not implemented`;
  }

  for (const name of names) {
    // A name form no constraint can be expressed in — every constraint of an
    // unevaluable form has already failed above — is unconstrained.
    if (name.form === 'unsupported') continue;

    const excluded = constraints.excluded.find((subtree) => matches(name, subtree.base));
    if (excluded) {
      return `${describe(name)} is inside the excluded subtree ${describe(excluded.base)}`;
    }

    // Permitted subtrees constrain only the forms they mention: a certificate
    // with a dNSName is unaffected by a CA that permits only directoryNames.
    const sameForm = constraints.permitted.filter((subtree) => subtree.base.form === name.form);
    if (sameForm.length > 0 && !sameForm.some((subtree) => matches(name, subtree.base))) {
      return `${describe(name)} is outside every permitted subtree (${sameForm
        .map((subtree) => describe(subtree.base))
        .join(', ')})`;
    }
  }

  return undefined;
}

/** Whether one name falls inside one subtree base. Forms must agree. */
export function matches(name: GeneralNameValue, base: GeneralNameValue): boolean {
  if (name.form === 'dNSName' && base.form === 'dNSName') {
    return matchesDns(name.value, base.value);
  }
  if (name.form === 'rfc822Name' && base.form === 'rfc822Name') {
    return matchesEmail(name.value, base.value);
  }
  if (name.form === 'uniformResourceIdentifier' && base.form === 'uniformResourceIdentifier') {
    return matchesUri(name.value, base.value);
  }
  if (name.form === 'iPAddress' && base.form === 'iPAddress') {
    return matchesIp(name.value, base.value);
  }
  if (name.form === 'directoryName' && base.form === 'directoryName') {
    return matchesDirectoryName(name.rdns, base.rdns);
  }
  return false;
}

/**
 * RFC 5280: "any DNS name that can be constructed by simply adding zero or more
 * labels to the left-hand side of the name satisfies the name constraint" — so
 * `example.com` is satisfied by `foo.example.com` but not by `example1.com`,
 * which is exactly the trap a naive `endsWith` falls into.
 */
function matchesDns(name: string, constraint: string): boolean {
  const host = host_(name);
  const base = host_(constraint);
  // An empty constraint places no restriction on the form.
  if (base === '') return true;
  return host === base || host.endsWith(`.${base}`);
}

/**
 * RFC 5280: the constraint is a mailbox, a host, or a domain beginning with a
 * period. Only the host part is case-insensitive — the local part of a mailbox
 * belongs to the receiving host and is compared as given.
 */
function matchesEmail(name: string, constraint: string): boolean {
  const at = name.lastIndexOf('@');
  if (at < 0) return false;
  const local = name.slice(0, at);
  const host = host_(name.slice(at + 1));

  const constraintAt = constraint.lastIndexOf('@');
  if (constraintAt >= 0) {
    return local === constraint.slice(0, constraintAt) && host === host_(constraint.slice(constraintAt + 1));
  }
  // ".example.com" is satisfied by a.example.com but not by example.com.
  if (constraint.startsWith('.')) return host.endsWith(constraint.toLowerCase());
  return host === host_(constraint);
}

/**
 * RFC 5280: "the constraint applies to the host part of the name". A URI with
 * no host satisfies no constraint of this form.
 */
function matchesUri(name: string, constraint: string): boolean {
  let host: string;
  try {
    host = host_(new URL(name).hostname);
  } catch {
    return false;
  }
  if (host === '') return false;
  if (constraint.startsWith('.')) return host.endsWith(constraint.toLowerCase());
  return host === host_(constraint);
}

/**
 * The constraint is an address and a mask — the DER carries both in one
 * double-length octet string, which the parser renders as CIDR. The name is a
 * plain address. Both are compared as bytes, so families cannot cross.
 */
function matchesIp(name: string, constraint: string): boolean {
  const slash = constraint.lastIndexOf('/');
  // Without a mask it is an address, not a subtree, and constrains nothing.
  if (slash < 0) return false;

  const base = parseIp(constraint.slice(0, slash));
  const address = parseIp(name);
  const prefix = Number(constraint.slice(slash + 1));
  if (!base || !address || base.length !== address.length) return false;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > base.length * 8) return false;

  for (let i = 0; i < base.length; i += 1) {
    const bits = Math.min(8, Math.max(0, prefix - i * 8));
    const mask = bits === 0 ? 0 : (0xff << (8 - bits)) & 0xff;
    if ((address[i]! & mask) !== (base[i]! & mask)) return false;
  }
  return true;
}

/**
 * RFC 5280: a directoryName constraint matches when it is an initial
 * subsequence of the name's RDN sequence — `C=PT, O=Example` constrains
 * `C=PT, O=Example, CN=Leaf` and nothing shorter or divergent.
 */
function matchesDirectoryName(
  name: RelativeDistinguishedName[],
  constraint: RelativeDistinguishedName[],
): boolean {
  if (constraint.length > name.length) return false;
  return constraint.every((rdn, index) => rdnEquals(name[index]!, rdn));
}

/** An RDN is a SET, so order within it carries no meaning. */
function rdnEquals(a: RelativeDistinguishedName, b: RelativeDistinguishedName): boolean {
  if (a.length !== b.length) return false;
  return (
    a.every((left) => b.some((right) => attributeEquals(left, right))) &&
    b.every((right) => a.some((left) => attributeEquals(left, right)))
  );
}

function attributeEquals(
  a: { type: string; value: string | undefined },
  b: { type: string; value: string | undefined },
): boolean {
  if (a.type !== b.type) return false;
  // An attribute this code could not read as text matches nothing, including
  // another unreadable one: "we do not know" is not "they are equal".
  if (a.value === undefined || b.value === undefined) return false;
  return normalizeText(a.value) === normalizeText(b.value);
}

function normalizeText(value: string): string {
  return value.trim().replace(/\s+/g, ' ').toLowerCase();
}

/** Hostnames are case-insensitive, and a trailing root dot is not a label. */
function host_(value: string): string {
  return value.toLowerCase().replace(/\.$/, '');
}

function parseIp(text: string): Uint8Array | undefined {
  if (isIPv4(text)) return parseIpv4(text);
  if (isIPv6(text)) return parseIpv6(text);
  return undefined;
}

function parseIpv4(text: string): Uint8Array {
  return Uint8Array.from(text.split('.'), Number);
}

/** `node:net` has already validated the shape, so this only has to expand it. */
function parseIpv6(text: string): Uint8Array {
  const gap = text.indexOf('::');
  const head = gap < 0 ? text : text.slice(0, gap);
  const tail = gap < 0 ? '' : text.slice(gap + 2);

  const groups = (part: string): number[] => {
    if (part === '') return [];
    return part.split(':').flatMap((piece) => {
      // A trailing IPv4 literal, as in ::ffff:192.0.2.1, is two groups.
      if (!piece.includes('.')) return [Number.parseInt(piece, 16)];
      const v4 = parseIpv4(piece);
      return [(v4[0]! << 8) | v4[1]!, (v4[2]! << 8) | v4[3]!];
    });
  };

  const front = groups(head);
  const back = groups(tail);
  const all = [...front, ...Array<number>(8 - front.length - back.length).fill(0), ...back];

  const bytes = new Uint8Array(16);
  all.forEach((group, index) => {
    bytes[index * 2] = group >> 8;
    bytes[index * 2 + 1] = group & 0xff;
  });
  return bytes;
}

function describe(name: GeneralNameValue): string {
  switch (name.form) {
    case 'directoryName':
      return `directoryName ${name.rdns
        .map((rdn) => rdn.map((a) => `${a.type}=${a.value ?? '?'}`).join('+'))
        .join(', ')}`;
    case 'unsupported':
      return `${name.label} name`;
    default:
      return `${name.form} ${name.value}`;
  }
}
