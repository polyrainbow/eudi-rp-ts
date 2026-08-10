/**
 * Network-gated probe against the EUDI reference issuer.
 *
 * Answers the open question from Phase 0: what does the live reference issuer
 * actually put in an `urn:eudi:pid:1` SD-JWT VC, and does it still carry
 * `age_equal_or_over` after PID Rulebook v1.1 removed the age attributes?
 *
 *   npm run probe                      # metadata only
 *   npm run probe -- <sd-jwt-string>   # also dissect a real credential
 *
 * Obtaining a real credential needs the OID4VCI authorization code flow with
 * the EU test IdP, which requires a browser and a wallet. This script does not
 * automate that; paste the resulting credential in as an argument.
 */
import { decodeProtectedHeader, decodeUnverifiedPayload } from '../src/crypto.ts';

const ISSUER = process.env['EUDI_ISSUER'] ?? 'https://issuer.eudiw.dev';

async function probeMetadata(): Promise<void> {
  const response = await fetch(`${ISSUER}/.well-known/openid-credential-issuer`);
  if (!response.ok) throw new Error(`Issuer metadata: HTTP ${response.status}`);
  const metadata = (await response.json()) as {
    credential_issuer?: string;
    credential_endpoint?: string;
    credential_configurations_supported?: Record<string, Record<string, unknown>>;
  };

  console.log(`issuer:              ${metadata.credential_issuer}`);
  console.log(`credential_endpoint: ${metadata.credential_endpoint}`);

  const configs = Object.entries(metadata.credential_configurations_supported ?? {}).filter(
    ([, config]) => typeof config['format'] === 'string' && /sd.?jwt/i.test(config['format']),
  );
  console.log(`\nSD-JWT VC configurations (${configs.length}):`);
  for (const [id, config] of configs) {
    const claims = Array.isArray(config['claims']) ? config['claims'] : [];
    console.log(`  ${id}`);
    console.log(`    format=${String(config['format'])} vct=${String(config['vct'])} claims=${claims.length}`);
  }

  // JWT VC Issuer Metadata is the spec's other key-resolution route. The
  // reference issuer answered "Not supported" when this was written, which is
  // why src/trust/issuer-key.ts only implements x5c.
  const jwtVcIssuer = await fetch(`${ISSUER}/.well-known/jwt-vc-issuer`);
  console.log(
    `\njwt-vc-issuer metadata: HTTP ${jwtVcIssuer.status} ${JSON.stringify((await jwtVcIssuer.text()).slice(0, 60))}`,
  );
}

function dissect(credential: string): void {
  const [issuerJwt, ...rest] = credential.trim().split('~');
  if (!issuerJwt) throw new Error('Not an SD-JWT');

  const header = decodeProtectedHeader(issuerJwt);
  const payload = decodeUnverifiedPayload(issuerJwt);

  console.log('\n--- credential (NOT verified, structure only) ---');
  console.log(`typ=${String(header['typ'])} alg=${String(header['alg'])} x5c=${Array.isArray(header['x5c']) ? `${header['x5c'].length} cert(s)` : 'absent'}`);
  console.log(`vct=${String(payload['vct'])} iss=${String(payload['iss'])}`);
  console.log(`always-disclosed claims: ${Object.keys(payload).join(', ')}`);

  const disclosed: string[] = [];
  for (const part of rest) {
    if (!part || part.includes('.')) continue; // trailing empty segment or KB-JWT
    try {
      const [, name] = JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as [string, string, unknown];
      disclosed.push(name);
    } catch {
      disclosed.push('<unparseable>');
    }
  }
  console.log(`selectively disclosable claims: ${disclosed.join(', ') || '(none)'}`);

  const hasAgeBucket = 'age_equal_or_over' in payload || disclosed.includes('age_equal_or_over');
  const hasAge18 = disclosed.includes('18');
  console.log(
    `\nage_equal_or_over present: ${hasAgeBucket} | per-age disclosure of "18": ${hasAge18}`,
  );
  console.log(`birthdate present: ${'birthdate' in payload || disclosed.includes('birthdate')}`);
}

await probeMetadata();
const credential = process.argv[2];
if (credential) dissect(credential);
else console.log('\n(pass a real SD-JWT VC as an argument to dissect it)');
