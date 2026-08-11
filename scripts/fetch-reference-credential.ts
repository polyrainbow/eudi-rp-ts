/**
 * Obtain a real credential from the EU reference issuer, without a wallet.
 *
 *   npm run fetch-credential -- sd-jwt   # eu.europa.ec.eudi.pid_vc_sd_jwt
 *   npm run fetch-credential -- mdoc     # eu.europa.ec.eudi.pid_mdoc
 *
 * This drives the OID4VCI authorization code flow that a wallet would normally
 * perform, using the issuer's FormEU test identity provider. It exists so the
 * claim "our verifier verifies a real EUDI credential" can be checked by
 * someone else rather than taken on trust — see REPRODUCE.md.
 *
 * It writes the credential and the holder key beside each other, so the result
 * can be dropped into test/fixtures/real/ and the existing tests re-run against
 * a freshly issued credential.
 *
 * This is not a wallet. It holds no keys beyond the run, implements no
 * consent, and should not be mistaken for one.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

const ISSUER = process.env['EUDI_ISSUER'] ?? 'https://issuer.eudiw.dev';
const BACKEND = process.env['EUDI_ISSUER_BACKEND'] ?? 'https://backend.issuer.eudiw.dev';

/** The issuer accepts any client id and redirect uri; a wallet would register. */
const CLIENT_ID = 'ID';
const REDIRECT_URI = 'eudi-openid4ci://authorize';

/**
 * FormEU: the issuer's test identity provider, where any data is accepted.
 * Country code `FC` selects it — the other codes route to real eID nodes.
 */
const COUNTRY = 'FC';

const SUBJECT_COMMON = {
  family_name: 'Tester',
  given_name: 'Test',
  'place_of_birth[0][country]': 'PT',
  'place_of_birth[0][locality]': 'Porto',
  // Contributed by the form's submit button. Without it the issuer returns 500
  // rather than 400 — reported upstream, see REPRODUCE.md.
  proceed: 'Submit',
};

/**
 * Fixed so a re-run produces a comparable credential. Over 18 deliberately.
 *
 * **The two configurations serve different forms.** The same data has
 * different field names in each — `birthdate` vs `birth_date`,
 * `nationalities[0][…]` vs `nationality[0][…]`, `picture` vs `portrait`.
 * Unknown fields are accepted and silently dropped, so posting the SD-JWT VC
 * names into the mdoc form yields a credential with no date of birth and no
 * error. That is exactly what this script used to do, and the missing
 * `birth_date` got recorded as an issuer behaviour for months before anyone
 * checked the form. Confirm against `POST /display_form` before changing these.
 */
const SUBJECT: Record<'sd-jwt' | 'mdoc', Record<string, string>> = {
  'sd-jwt': {
    ...SUBJECT_COMMON,
    birthdate: '1990-06-12',
    'nationalities[0][country_code]': 'PT',
    picture: 'Port1',
  },
  mdoc: {
    ...SUBJECT_COMMON,
    birth_date: '1990-06-12',
    'nationality[0][country_code]': 'PT',
    portrait: 'Port1',
  },
};

const CONFIGURATIONS = {
  'sd-jwt': 'eu.europa.ec.eudi.pid_vc_sd_jwt',
  mdoc: 'eu.europa.ec.eudi.pid_mdoc',
} as const;

const format = process.argv[2] as keyof typeof CONFIGURATIONS | undefined;
if (!format || !(format in CONFIGURATIONS)) {
  console.error('Usage: npm run fetch-credential -- <sd-jwt|mdoc>');
  process.exit(1);
}
const configurationId = CONFIGURATIONS[format];

const b64url = (bytes: Uint8Array | Buffer) => Buffer.from(bytes).toString('base64url');
const cookies = new Map<string, string>();

/** Minimal cookie jar: the issuer's form flow is session-bound. */
async function step(url: string, init: RequestInit = {}): Promise<Response> {
  const jar = [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  const response = await fetch(url, {
    ...init,
    redirect: 'manual',
    headers: { ...(init.headers ?? {}), ...(jar ? { cookie: jar } : {}) },
  });
  for (const value of response.headers.getSetCookie()) {
    const [pair] = value.split(';');
    const [k, v] = (pair ?? '').split('=');
    if (k && v) cookies.set(k.trim(), v);
  }
  if (process.env['DEBUG_FLOW']) {
    console.error(`  [${response.status}] ${init.method ?? 'GET'} ${url.slice(0, 78)}`);
  }
  return response;
}

/** Each interstitial posts a hidden `payload` field with JavaScript. */
function hiddenPayload(html: string): string {
  const match = /name="payload" value=.([\s\S]*?).>\s*\n/.exec(html);
  if (!match?.[1]) throw new Error('Could not find the hidden payload field');
  return match[1];
}

async function follow(response: Response): Promise<Response> {
  let current = response;
  for (let hop = 0; hop < 5 && current.status >= 300 && current.status < 400; hop++) {
    const location = current.headers.get('location');
    if (!location) break;
    current = await step(new URL(location, ISSUER).toString());
  }
  return current;
}

// ---------------------------------------------------------------- authorize
const codeVerifier = b64url(randomBytes(32));
const codeChallenge = b64url(createHash('sha256').update(codeVerifier).digest());

const authorize = new URLSearchParams({
  response_type: 'code',
  client_id: CLIENT_ID,
  redirect_uri: REDIRECT_URI,
  scope: configurationId,
  state: b64url(randomBytes(16)),
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
});

console.log(`Requesting ${configurationId} from ${ISSUER}`);
const authChoice = await follow(await step(`${ISSUER}/oidc/authorization?${authorize}`));
const countriesForm = new URLSearchParams({ payload: hiddenPayload(await authChoice.text()) });
await follow(await step(`${ISSUER}/display_countries`, { method: 'POST', body: countriesForm }));

// ------------------------------------------------------------ country + form
const countrySelected = await follow(
  await step(`${BACKEND}/dynamic/country_selected`, {
    method: 'POST',
    body: new URLSearchParams({ country: COUNTRY }),
  }),
);
const formPayload = new URLSearchParams({ payload: hiddenPayload(await countrySelected.text()) });
await follow(await step(`${ISSUER}/display_form`, { method: 'POST', body: formPayload }));

console.log(`Submitting the ${COUNTRY} (FormEU) test identity`);
const submitted = await follow(
  await step(`${BACKEND}/dynamic/form`, { method: 'POST', body: new URLSearchParams(SUBJECT[format]) }),
);
if (!submitted.ok) {
  throw new Error(`Form submission failed: HTTP ${submitted.status} ${await submitted.text()}`);
}

// ------------------------------------------------------------------- consent
const authorization = await follow(
  await step(`${ISSUER}/display_authorization`, {
    method: 'POST',
    body: new URLSearchParams({ payload: hiddenPayload(await submitted.text()) }),
  }),
);
const consentHtml = await authorization.text();
// Attribute order is not guaranteed, and this page happens to put `value`
// first — matching only one order silently breaks the whole flow.
const userId =
  /name="user_id"[^>]*value="([^"]*)"/.exec(consentHtml)?.[1] ??
  /value="([^"]*)"[^>]*name="user_id"/.exec(consentHtml)?.[1];
if (!userId) throw new Error('Could not find user_id on the consent page');

const redirected = await step(`${BACKEND}/dynamic/redirect_wallet`, {
  method: 'POST',
  body: new URLSearchParams({ user_id: userId, proceed: 'Submit' }),
});
const verifyUrl = redirected.headers.get('location');
if (!verifyUrl) throw new Error('No redirect after consent');

const callback = await step(verifyUrl);
const code = new URL(
  (callback.headers.get('location') ?? '').replace('eudi-openid4ci://', 'https://wallet.invalid/'),
).searchParams.get('code');
if (!code) throw new Error('No authorization code returned');

// --------------------------------------------------------- token + credential
const tokenResponse = await fetch(`${ISSUER}/oidc/token`, {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: codeVerifier,
  }),
});
const { access_token: accessToken } = (await tokenResponse.json()) as { access_token: string };
if (!accessToken) throw new Error('No access token');

// OID4VCI moved the nonce out of the token response into its own endpoint.
const { c_nonce: cNonce } = (await (await fetch(`${BACKEND}/nonce`, { method: 'POST' })).json()) as {
  c_nonce: string;
};

const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
const proof = await new SignJWT({ nonce: cNonce })
  .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: await exportJWK(publicKey) })
  .setIssuer(CLIENT_ID)
  .setAudience(ISSUER)
  .setIssuedAt()
  .sign(privateKey);

const credentialResponse = await fetch(`${BACKEND}/credential`, {
  method: 'POST',
  headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
  body: JSON.stringify({
    credential_configuration_id: configurationId,
    proof: { proof_type: 'jwt', jwt: proof },
  }),
});
const body = (await credentialResponse.json()) as { credentials?: { credential: string }[] };
const credential = body.credentials?.[0]?.credential;
if (!credential) {
  throw new Error(`No credential returned: ${JSON.stringify(body).slice(0, 300)}`);
}

// ------------------------------------------------------------------- output
const out = fileURLToPath(new URL('../out/', import.meta.url));
await mkdir(out, { recursive: true });
const stem = format === 'mdoc' ? 'eudiw-pid-mdoc' : 'eudiw-pid-sd-jwt-vc';
await writeFile(`${out}${stem}.txt`, credential);
await writeFile(
  `${out}${format === 'mdoc' ? 'mdoc-device' : 'holder'}-private-jwk.json`,
  JSON.stringify(await exportJWK(privateKey)),
);

console.log(`\nWrote out/${stem}.txt (${credential.length} chars) and its holder key.`);
console.log('The issuing CA is not in the credential; fetch it from the leaf\'s AIA extension —');
console.log('see REPRODUCE.md, "Verify what you fetched".');
