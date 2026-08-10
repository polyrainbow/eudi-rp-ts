/**
 * Generates a DEVELOPMENT Relying Party access certificate.
 *
 *   npm run access-cert -- verifier.example.org [outdir]
 *
 * This is NOT the access certificate the EUDI ecosystem means. A real Wallet
 * Relying Party Access Certificate is issued to you by a Relying Party Access
 * CA after you register with a national Registrar, and chains to a Member
 * State's Trusted List. You cannot mint one; a wallet validating the chain will
 * reject what this script produces unless you add the generated CA to that
 * wallet's trust store.
 *
 * What it IS good for: exercising the x509_san_dns code path — signed request
 * objects (JAR) with an x5c header, and encrypted responses — against your own
 * wallet or the test wallet in test/wallet.ts.
 *
 * Output:
 *   access-cert-key.pem     PKCS#8 EC P-256 private key  -> ACCESS_CERT_KEY_FILE
 *   access-cert-chain.pem   leaf + CA, leaf first        -> ACCESS_CERT_CHAIN_FILE
 *   access-ca.pem           the CA alone, to hand to a wallet as a trust anchor
 */
import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import { webcrypto } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

x509.cryptoProvider.set(webcrypto as never);

const ALG = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

export type AccessCertificate = {
  /** PKCS#8 EC P-256 private key. */
  keyPem: string;
  /** Leaf + CA, leaf first. */
  chainPem: string;
  /** The CA alone, to hand to a wallet as a trust anchor. */
  caPem: string;
};

export async function createAccessCertificate(
  dnsName: string,
  validForDays = 365,
): Promise<AccessCertificate> {
  const notBefore = new Date();
  const notAfter = new Date(Date.now() + validForDays * 24 * 60 * 60 * 1000);

  // A CA, so the chain has the same shape as a real one and a wallet has a
  // single certificate to trust rather than the leaf itself.
  const caKeys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=eudi-rp-ts Development RP Access CA',
    notBefore,
    notAfter,
    signingAlgorithm: SIGN,
    keys: caKeys as never,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });

  const leafKeys = await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: `CN=${dnsName}`,
    issuer: ca.subject,
    notBefore,
    notAfter,
    signingAlgorithm: SIGN,
    publicKey: leafKeys.publicKey as never,
    signingKey: caKeys.privateKey as never,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      // OID4VP 1.0 §5.10: with the x509_san_dns prefix the client_id after the
      // prefix MUST match a dNSName SAN in the leaf. Without this the wallet
      // has no way to tie the request to the host it came from.
      new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: dnsName }]),
    ],
  });

  const pkcs8 = await webcrypto.subtle.exportKey('pkcs8', leafKeys.privateKey);
  const keyPem = [
    '-----BEGIN PRIVATE KEY-----',
    ...(Buffer.from(pkcs8).toString('base64').match(/.{1,64}/g) ?? []),
    '-----END PRIVATE KEY-----',
  ].join('\n');

  return {
    keyPem: `${keyPem}\n`,
    chainPem: `${leaf.toString('pem')}\n${ca.toString('pem')}\n`,
    caPem: `${ca.toString('pem')}\n`,
  };
}

/** CLI entry point. */
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dnsName = process.argv[2];
  const outDir = resolve(process.argv[3] ?? 'config');

  if (!dnsName) {
    console.error('Usage: npm run access-cert -- <dns-name> [outdir]');
    console.error('The DNS name must match CLIENT_DNS_NAME and the host in BASE_URL.');
    process.exit(1);
  }

  const cert = await createAccessCertificate(dnsName);
  await mkdir(outDir, { recursive: true });
  await writeFile(`${outDir}/access-cert-key.pem`, cert.keyPem, { mode: 0o600 });
  await writeFile(`${outDir}/access-cert-chain.pem`, cert.chainPem);
  await writeFile(`${outDir}/access-ca.pem`, cert.caPem);

  console.log(`Wrote development access certificate for ${dnsName} to ${outDir}/\n`);
  console.log('  CLIENT_ID_PREFIX=x509_san_dns');
  console.log(`  CLIENT_DNS_NAME=${dnsName}`);
  console.log(`  ACCESS_CERT_CHAIN_FILE=${outDir}/access-cert-chain.pem`);
  console.log(`  ACCESS_CERT_KEY_FILE=${outDir}/access-cert-key.pem`);
  console.log('\nA real wallet will reject this unless it trusts access-ca.pem.');
}
