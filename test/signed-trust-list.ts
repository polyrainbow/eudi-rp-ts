/**
 * A genuinely signed trust list, for the tests.
 *
 * The signature checks were network-only until the wrapping case needed one
 * offline: proving that content outside the signature is not read means having
 * a list where something *is* inside it. Nothing in `src/` imports this.
 *
 * Signing is RSA-SHA256, which xml-crypto ships. The ECDSA and RSASSA-PSS
 * implementations in `lotl.ts` are ours, and signing with them would make the
 * coverage tests below depend on the code they are meant to hold to account.
 */
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { webcrypto } from 'node:crypto';
import { SignedXml } from 'xml-crypto';

x509.cryptoProvider.set(webcrypto as never);

const RSA = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
} as const;

const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

export type TrustListSigner = {
  /** PEM, as `verifyTrustList`'s `expectedCerts` wants it. */
  certificatePem: string;
  /** Base64 DER, as a `<X509Certificate>` element carries it. */
  certificateBase64: string;
  /**
   * Sign `xml` with an enveloped signature over the whole document.
   *
   * `xpath` narrows what the signature covers, which is the only way to build
   * a list whose signature is valid over less than all of it.
   */
  sign(xml: string, options?: { xpath?: string }): string;
};

export async function trustListSigner(name = 'CN=Test TSL Signer'): Promise<TrustListSigner> {
  const keys = (await webcrypto.subtle.generateKey(RSA, true, ['sign', 'verify'])) as CryptoKeyPair;
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name,
    notBefore: new Date('2020-01-01T00:00:00Z'),
    notAfter: new Date('2035-01-01T00:00:00Z'),
    keys: keys as never,
    signingAlgorithm: RSA,
  });
  const certificatePem = certificate.toString('pem');
  const certificateBase64 = certificatePem.replace(/-----[^-]+-----|\s/g, '');
  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  const privateKeyPem = [
    '-----BEGIN PRIVATE KEY-----',
    ...(Buffer.from(pkcs8).toString('base64').match(/.{1,64}/g) ?? []),
    '-----END PRIVATE KEY-----',
  ].join('\n');

  return {
    certificatePem,
    certificateBase64,
    sign(xml, options = {}) {
      const xpath = options.xpath ?? '/*';
      const signedXml = new SignedXml({
        privateKey: privateKeyPem,
        publicCert: certificatePem,
        signatureAlgorithm: RSA_SHA256,
        canonicalizationAlgorithm: C14N,
      });
      signedXml.addReference({ xpath, transforms: [ENVELOPED, C14N], digestAlgorithm: SHA256 });
      // `verifyTrustList` takes the signing certificate from KeyInfo, as the
      // real lists publish it; xml-crypto writes no KeyInfo unless asked.
      signedXml.getKeyInfoContent = () =>
        `<X509Data><X509Certificate>${certificateBase64}</X509Certificate></X509Data>`;
      signedXml.computeSignature(xml, { location: { reference: xpath, action: 'append' } });
      return signedXml.getSignedXml();
    },
  };
}
