/**
 * Certificates carrying Name Constraints, for the tests.
 *
 * `@peculiar/x509` is a devDependency and is used only here, to *build* test
 * material. The library itself parses with `@peculiar/asn1-x509` and does every
 * cryptographic operation with `node:crypto`; nothing in `src/` imports this.
 */
import 'reflect-metadata';
import { AsnConvert } from '@peculiar/asn1-schema';
import {
  CertificatePolicies,
  GeneralName,
  GeneralSubtree,
  GeneralSubtrees,
  InhibitAnyPolicy,
  Name as AsnName,
  NameConstraints,
  PolicyConstraints,
  PolicyInformation,
  PolicyMapping,
  PolicyMappings,
} from '@peculiar/asn1-x509';
import * as x509 from '@peculiar/x509';
import { X509Certificate, webcrypto } from 'node:crypto';

x509.cryptoProvider.set(webcrypto as never);

const ALG = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

/** A name form as the test writes it, before it becomes a GeneralName. */
export type NameSpec =
  | { dNSName: string }
  | { rfc822Name: string }
  | { uniformResourceIdentifier: string }
  /** An address (`10.0.0.1`) as a name, CIDR (`10.0.0.0/8`) as a constraint. */
  | { iPAddress: string }
  | { directoryName: string }
  | { registeredID: string };

/**
 * KeyUsage bits, by name (RFC 5280 §4.2.1.3).
 *
 * Omitting the option entirely leaves the extension absent, which is a
 * different statement from an empty list: absent is silence, empty is a
 * certificate refusing every use.
 */
export type KeyUsageName = keyof typeof x509.KeyUsageFlags;

function keyUsageExtension(usages: KeyUsageName[]): x509.KeyUsagesExtension {
  const flags = usages.reduce((mask, name) => mask | x509.KeyUsageFlags[name], 0);
  return new x509.KeyUsagesExtension(flags, true);
}

export type ConstraintSpec = {
  permitted?: NameSpec[];
  excluded?: NameSpec[];
  /** Both default to what RFC 5280 requires; set them to build a reject case. */
  minimum?: number;
  maximum?: number;
  critical?: boolean;
};

export function generalName(spec: NameSpec): GeneralName {
  if ('directoryName' in spec) {
    return new GeneralName({
      directoryName: AsnConvert.parse(new x509.Name(spec.directoryName).toArrayBuffer(), AsnName),
    });
  }
  return new GeneralName(spec as never);
}

/** The DER of a NameConstraints extension. */
export function nameConstraintsDer(spec: ConstraintSpec): ArrayBuffer {
  const subtree = (name: NameSpec) =>
    new GeneralSubtree({
      base: generalName(name),
      minimum: spec.minimum ?? 0,
      ...(spec.maximum === undefined ? {} : { maximum: spec.maximum }),
    });

  return AsnConvert.serialize(
    new NameConstraints({
      ...(spec.permitted ? { permittedSubtrees: new GeneralSubtrees(spec.permitted.map(subtree)) } : {}),
      ...(spec.excluded ? { excludedSubtrees: new GeneralSubtrees(spec.excluded.map(subtree)) } : {}),
    }),
  );
}

/**
 * The four certificate policy extensions (RFC 5280 §4.2.1.4, §4.2.1.5,
 * §4.2.1.11, §4.2.1.14), as a test writes them.
 *
 * `anyPolicy` is spelled out rather than special-cased: it is just the OID
 * `2.5.29.32.0` in the list, which is how a CA writes it too.
 */
export type PolicySpec = {
  policies?: string[];
  /** RFC 5280 leaves this to the CA; both live EUDI signers say false. */
  policiesCritical?: boolean;
  /** `[issuerDomainPolicy, subjectDomainPolicy]` pairs. */
  policyMappings?: [string, string][];
  requireExplicitPolicy?: number;
  inhibitPolicyMapping?: number;
  inhibitAnyPolicy?: number;
  /**
   * Extensions written as raw DER, for shapes a conforming CA never emits —
   * truncated values, a negative `SkipCerts`. Added after the ones above.
   */
  raw?: { oid: string; critical?: boolean; der: ArrayBuffer }[];
};

function policyExtensions(spec: PolicySpec): x509.Extension[] {
  const extensions: x509.Extension[] = [];

  if (spec.policies) {
    extensions.push(
      new x509.Extension(
        '2.5.29.32',
        spec.policiesCritical ?? false,
        AsnConvert.serialize(
          new CertificatePolicies(
            spec.policies.map((oid) => new PolicyInformation({ policyIdentifier: oid })),
          ),
        ),
      ),
    );
  }

  if (spec.policyMappings) {
    extensions.push(
      new x509.Extension(
        '2.5.29.33',
        true,
        AsnConvert.serialize(
          new PolicyMappings(
            spec.policyMappings.map(
              ([issuerDomainPolicy, subjectDomainPolicy]) =>
                new PolicyMapping({ issuerDomainPolicy, subjectDomainPolicy } as never),
            ),
          ),
        ),
      ),
    );
  }

  if (spec.requireExplicitPolicy !== undefined || spec.inhibitPolicyMapping !== undefined) {
    extensions.push(
      new x509.Extension(
        '2.5.29.36',
        true,
        AsnConvert.serialize(
          new PolicyConstraints({
            ...(spec.requireExplicitPolicy === undefined
              ? {}
              : { requireExplicitPolicy: skipCerts(spec.requireExplicitPolicy) }),
            ...(spec.inhibitPolicyMapping === undefined
              ? {}
              : { inhibitPolicyMapping: skipCerts(spec.inhibitPolicyMapping) }),
          }),
        ),
      ),
    );
  }

  if (spec.inhibitAnyPolicy !== undefined) {
    extensions.push(
      new x509.Extension(
        '2.5.29.54',
        true,
        AsnConvert.serialize(new InhibitAnyPolicy(skipCerts(spec.inhibitAnyPolicy))),
      ),
    );
  }

  for (const { oid, critical, der } of spec.raw ?? []) {
    extensions.push(new x509.Extension(oid, critical ?? false, der));
  }

  return extensions;
}

/** `SkipCerts ::= INTEGER (0..MAX)` as the content octets the converter wants. */
function skipCerts(count: number): ArrayBuffer {
  const bytes: number[] = [];
  let remaining = count;
  do {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  } while (remaining > 0);
  // A leading bit set would read back as a negative INTEGER.
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0);
  return new Uint8Array(bytes).buffer;
}

export type Issued = {
  cert: X509Certificate;
  /** For signing the next certificate down. */
  keys: CryptoKeyPair;
};

const YEAR = 365 * 24 * 60 * 60 * 1000;

/** A self-signed CA, optionally constrained. */
export async function createCa(
  subject: string,
  constraints?: ConstraintSpec,
  /** `pathLength: null` leaves the constraint absent, which means unlimited. */
  options: { pathLength?: number | null; keyUsage?: KeyUsageName[]; policies?: PolicySpec } = {},
): Promise<Issued> {
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: subject,
    notBefore: new Date(Date.now() - YEAR),
    notAfter: new Date(Date.now() + YEAR),
    signingAlgorithm: SIGN,
    keys: keys as never,
    extensions: [
      new x509.BasicConstraintsExtension(
        true,
        options.pathLength === undefined ? 3 : (options.pathLength ?? undefined),
        true,
      ),
      ...(options.keyUsage ? [keyUsageExtension(options.keyUsage)] : []),
      ...(options.policies ? policyExtensions(options.policies) : []),
      ...(constraints
        ? [new x509.Extension('2.5.29.30', constraints.critical ?? true, nameConstraintsDer(constraints))]
        : []),
    ],
  });
  return { cert: new X509Certificate(Buffer.from(cert.rawData)), keys };
}

/** A certificate issued by `parent`: a CA when constrained or asked for. */
export async function issue(
  parent: Issued,
  subject: string,
  options: {
    ca?: boolean;
    constraints?: ConstraintSpec;
    subjectAltNames?: NameSpec[];
    serial?: string;
    keyUsage?: KeyUsageName[];
    policies?: PolicySpec;
    /** Overrides the subject-derived issuer, for a self-issued certificate. */
    issuer?: string;
    /** `null` leaves the constraint absent, which means unlimited. */
    pathLength?: number | null;
  } = {},
): Promise<Issued> {
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const isCa = options.ca ?? options.constraints !== undefined;

  const pathLength =
    options.pathLength === undefined ? (isCa ? 2 : undefined) : (options.pathLength ?? undefined);
  const extensions: x509.Extension[] = [new x509.BasicConstraintsExtension(isCa, pathLength, true)];
  if (options.keyUsage) extensions.push(keyUsageExtension(options.keyUsage));
  if (options.policies) extensions.push(...policyExtensions(options.policies));
  if (options.constraints) {
    extensions.push(
      new x509.Extension('2.5.29.30', options.constraints.critical ?? true, nameConstraintsDer(options.constraints)),
    );
  }
  if (options.subjectAltNames) {
    // Built from raw GeneralNames so the tests can use forms x509.SubjectAlternativeNameExtension
    // does not model, such as directoryName.
    const { GeneralNames } = await import('@peculiar/asn1-x509');
    extensions.push(
      new x509.Extension(
        '2.5.29.17',
        false,
        AsnConvert.serialize(new GeneralNames(options.subjectAltNames.map(generalName))),
      ),
    );
  }

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: options.serial ?? '02',
    subject,
    issuer: options.issuer ?? new x509.X509Certificate(parent.cert.raw).subject,
    notBefore: new Date(Date.now() - YEAR),
    notAfter: new Date(Date.now() + YEAR),
    signingAlgorithm: SIGN,
    publicKey: keys.publicKey as never,
    signingKey: parent.keys.privateKey as never,
    extensions,
  });
  return { cert: new X509Certificate(Buffer.from(cert.rawData)), keys };
}
