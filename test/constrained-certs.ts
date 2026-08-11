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
  GeneralName,
  GeneralSubtree,
  GeneralSubtrees,
  Name as AsnName,
  NameConstraints,
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
  options: { pathLength?: number } = {},
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
      new x509.BasicConstraintsExtension(true, options.pathLength ?? 3, true),
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
  } = {},
): Promise<Issued> {
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const isCa = options.ca ?? options.constraints !== undefined;

  const extensions: x509.Extension[] = [new x509.BasicConstraintsExtension(isCa, isCa ? 2 : undefined, true)];
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
    issuer: new x509.X509Certificate(parent.cert.raw).subject,
    notBefore: new Date(Date.now() - YEAR),
    notAfter: new Date(Date.now() + YEAR),
    signingAlgorithm: SIGN,
    publicKey: keys.publicKey as never,
    signingKey: parent.keys.privateKey as never,
    extensions,
  });
  return { cert: new X509Certificate(Buffer.from(cert.rawData)), keys };
}
