#!/usr/bin/env bash
# Check our OCSP CertID against OpenSSL's.
#
# The offline tests prove that src/trust/revocation.ts and scripts/make-fixtures.ts
# agree with each other about RFC 6960 §4.1.1. That is worth little on its own:
# both are ours, and a shared mistake would cancel out and pass. This compares
# the CertID our code puts on the wire against the one OpenSSL builds for the
# same certificate, which is an implementation nobody here wrote.
#
# Run after `npm run fixtures`; the fixture CA is regenerated each time, so the
# hashes differ between runs and only the match matters.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

node --input-type=module -e "
import { readFileSync, writeFileSync } from 'node:fs';
const f = JSON.parse(readFileSync('test/fixtures/credentials.json', 'utf8'));
const header = f.certificateRevocation.credential.split('.')[0];
const x5c = JSON.parse(Buffer.from(header, 'base64url').toString()).x5c;
const pem = (b) => '-----BEGIN CERTIFICATE-----\n' + b.match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
writeFileSync('$work/leaf.pem', pem(x5c[0]));
writeFileSync('$work/ca.pem', pem(x5c[1]));
"

openssl ocsp -issuer "$work/ca.pem" -cert "$work/leaf.pem" -reqout "$work/openssl.der" -no_nonce >/dev/null 2>&1

node --input-type=module -e "
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { AsnParser } from '@peculiar/asn1-schema';
import { OCSPRequest } from '@peculiar/asn1-ocsp';
import { checkChainRevocation } from './src/trust/revocation.ts';

const leaf = new X509Certificate(readFileSync('$work/leaf.pem', 'utf8'));
const ca = new X509Certificate(readFileSync('$work/ca.pem', 'utf8'));

// Drive the real code path and capture what it POSTs, rather than reaching
// into a helper: the bytes on the wire are what an actual responder sees.
let captured;
await checkChainRevocation([leaf, ca], {
  now: new Date(),
  fetchImpl: async (_url, init) => {
    if (init?.method === 'POST') captured = init.body;
    return new Response('unused', { status: 503 });
  },
});

const certId = (der) => AsnParser.parse(der, OCSPRequest).tbsRequest.requestList[0].reqCert;
const hex = (b) => Buffer.from(b).toString('hex').toUpperCase();
const mine = certId(captured);
const theirs = certId(new Uint8Array(readFileSync('$work/openssl.der')));

const fields = [
  ['hashAlgorithm', mine.hashAlgorithm.algorithm, theirs.hashAlgorithm.algorithm],
  ['issuerNameHash', hex(mine.issuerNameHash.buffer), hex(theirs.issuerNameHash.buffer)],
  ['issuerKeyHash', hex(mine.issuerKeyHash.buffer), hex(theirs.issuerKeyHash.buffer)],
  ['serialNumber', hex(mine.serialNumber), hex(theirs.serialNumber)],
];

let ok = true;
for (const [name, a, b] of fields) {
  const same = a === b;
  ok &&= same;
  console.log((same ? '  ok   ' : '  FAIL ') + name.padEnd(16) + a + (same ? '' : '  != ' + b));
}
console.log(ok ? '\nCertID matches OpenSSL.' : '\nCertID does NOT match OpenSSL.');
process.exit(ok ? 0 : 1);
"
