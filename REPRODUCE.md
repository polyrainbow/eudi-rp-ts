# Reproducing the results

Every claim in the README is meant to be checkable. This says exactly what was
done, when, against what, and how to repeat it — and, just as importantly, what
was **not** done.

## What is and is not claimed

| Claim | Status |
|---|---|
| Verifies a real credential issued by the EU reference issuer | **Reproducible**, see below |
| Verifies the live EU trust lists (LOTL and national lists) | **Reproducible**, `RUN_NETWORK_TESTS=1 npm test` |
| Full OID4VP round trip over a public deployment | **Reproducible**, against a simulated wallet |
| mdoc issuer signature, digests and device authentication | **Reproducible** |
| **Interoperates with the EUDI reference wallet app** | **Not done.** No wallet has ever talked to this verifier |

The wallet in every round trip is `test/wallet.ts` or `test/mdoc-wallet.ts` —
about eighty lines each, written for these tests. They exercise the protocol
correctly, and they are not evidence of interoperability with anyone else's
implementation. Getting a real wallet to present requires a Relying Party Access
Certificate; see "Access certificates" in the README.

## Environment of record

The results below were produced on:

| | |
|---|---|
| Date | **2026-08-09** (SD-JWT VC) and **2026-08-10** (mdoc, trust lists, deployment) |
| Commit | `8dad482` and later; x509_hash support added afterwards |
| Runtime | Node **v24.15.0**, npm 11.12.1 |
| Platform | macOS (Darwin 25.6.0), arm64 |
| Issuer | `https://issuer.eudiw.dev` / `https://backend.issuer.eudiw.dev` |
| Deployment | `https://eudi-rp-ts.fly.dev` (Fly.io, `fra`) |

Runtime dependencies as installed:

```
@openid4vc/openid4vp  0.5.4      cbor2       2.3.0      xml-crypto  6.1.2
@sd-jwt/sd-jwt-vc     0.20.0     jose        6.2.8      xpath       0.0.34
@xmldom/xmldom        0.9.10     qrcode      1.5.4
```

Specifications as of that date: SD-JWT is **RFC 9901**; SD-JWT VC is
**draft-ietf-oauth-sd-jwt-vc-18**; OpenID4VP is **1.0 Final** (10 July 2025).
The SD-JWT VC draft is not an RFC, so its details can still move.

## 1. Offline test suite

```bash
git clone https://github.com/polyrainbow/eudi-rp-ts && cd eudi-rp-ts
npm ci
npm test          # 94 tests, no network
npm run typecheck
```

This verifies committed credentials, including the real ones in
`test/fixtures/real/`. It proves the verifier's logic; it does not touch the
internet.

## 2. Fetch your own credential from the EU reference issuer

This is the claim most worth checking, and it is a single command:

```bash
npm run fetch-credential -- sd-jwt
npm run fetch-credential -- mdoc
```

`scripts/fetch-reference-credential.ts` drives the OID4VCI authorization code
flow that a wallet would normally perform. It is not a wallet — it holds no keys
beyond the run and implements no consent UI.

Exact parameters, so a different result is attributable:

| | |
|---|---|
| Credential configurations | `eu.europa.ec.eudi.pid_vc_sd_jwt`, `eu.europa.ec.eudi.pid_mdoc` |
| Identity provider | **FormEU**, selected by country code `FC`. Other codes route to real eID nodes. |
| Subject data | `given_name=Test`, `family_name=Tester`, `birthdate=1990-06-12`, `nationalities[0][country_code]=PT`, `place_of_birth[0][country]=PT`, `place_of_birth[0][locality]=Porto`, `picture=Port1` |
| `client_id` | `ID` — arbitrary. The issuer accepts any client id and any redirect uri. |
| `redirect_uri` | `eudi-openid4ci://authorize` |
| PKCE | S256 |
| Proof of possession | `openid4vci-proof+jwt`, ES256, freshly generated key |

Two details that will stop the flow if you rebuild it yourself. The form submit
button contributes a **`proceed`** field, and omitting it makes the issuer return
**500** rather than 400 — [reported
upstream](https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/issues) —
which looks like an outage and is not one. And the consent page emits
`value="…" name="user_id"`, with **`value` before `name`**, so a regex assuming
the other order finds nothing.

### Verify what you fetched

The credential's `x5c` (or COSE `x5chain`) carries **only the leaf**. The issuing
CA has to come from the leaf's Authority Information Access extension:

```bash
CA=$(openssl x509 -noout -text -in <(…leaf…) | sed -n 's/.*CA Issuers - URI://p')
curl -s "$CA" -o pid-issuer-ca.pem
```

At the time of writing that URL is
`https://preprod.pki.eudiw.dev/aia/PIDIssuerCA02-UT.cacert.pem`, and the CA is
`CN=PID Issuer CA - UT 02`.

Then verify with the library:

```ts
import { TrustAnchors, verifyAgeOver18, verifyMdoc } from 'eudi-rp-ts';

const anchors = TrustAnchors.fromPem(readFileSync('pid-issuer-ca.pem', 'utf8'));

await verifyAgeOver18({
  credential: readFileSync('out/eudiw-pid-sd-jwt-vc.txt', 'utf8').trim(),
  anchors, expectedVct: 'urn:eudi:pid:1',
  requireKeyBinding: false,   // issued, never presented, so no KB-JWT
  checkStatus: false,         // set true to also fetch the live status list
});

await verifyMdoc({
  issuerSigned: readFileSync('out/eudiw-pid-mdoc.txt', 'utf8').trim(),
  anchors, expectedDocType: 'eu.europa.ec.eudi.pid.1',
  tolerateMalformedValidityDates: true,   // see below
});
```

Expected on 2026-08-10: **SD-JWT VC verified via `birthdate`**, **mdoc
verified**. To reproduce that exactly, drop the fetched files into
`test/fixtures/real/` and re-run `npm test`.

### What those credentials actually contain

Recorded because it is surprising, and because it is the ecosystem's behaviour
rather than this library's:

- The **SD-JWT VC PID carries no `age_equal_or_over`.** Its disclosable claims
  are `family_name`, `given_name`, `birthdate`, `place_of_birth`,
  `nationalities`, `picture`, `date_of_issuance`, `date_of_expiry`,
  `issuing_authority`, `issuing_country`. PID Rulebook v1.1 removed the age
  attributes following CIR 2024/2977. Proving age therefore costs the holder
  their full date of birth.
- The **mdoc PID carries no age attribute *and no `birth_date`***, so the
  predicate cannot be satisfied from it at all — despite the same form
  submission producing a `birthdate` in the SD-JWT VC.
- The mdoc's **`validUntil` is not valid RFC 3339**: `2026-11-08T14:09:35+00:00Z`
  carries both an offset and a `Z`. `verifyMdoc` rejects it unless
  `tolerateMalformedValidityDates` is set. This matches upstream issue #177.

## 3. Verify the live EU trust lists

```bash
RUN_NETWORK_TESTS=1 npm test
```

Fetches `https://ec.europa.eu/tools/lotl/eu-lotl.xml`, verifies its XML
signature, follows a national list pointer and verifies that list against the
certificates the LOTL publishes for it.

Verified on 2026-08-10 for **AT, DE, ES, FR, IT** — 470 anchors with
`LOTL_SERVICE_TYPES=http://uri.etsi.org/TrstSvc/Svctype/CA/QC`. Germany's list
signs with RSASSA-PSS (`sha256-rsa-MGF1`), which `xml-crypto` does not ship;
`src/trust/lotl.ts` implements it. Every list is also pointed at as a PDF, so
pointers are filtered by MIME type.

Trust lists change. A different count later is expected; a *failure* is not.

## 4. Full OID4VP round trip

Against a local server:

```bash
npm test    # test/oid4vp.test.ts, signed-request.test.ts, oid4vp-mdoc.test.ts
```

Against the public deployment, with the simulated wallet:

```
POST https://eudi-rp-ts.fly.dev/presentations
GET  <request_uri>                        # application/oauth-authz-req+jwt
POST <response_uri>                       # vp_token + state
GET  https://eudi-rp-ts.fly.dev/presentations/<id>
  -> { "status": "verified",
       "result": { "verified": true, "evidence": "age_equal_or_over.18",
                   "vct": "urn:eudi:pid:1",
                   "issuer": "CN=eudi-rp-ts Test PID Issuer" } }
```

The deployment configuration that produced it:

```
BASE_URL=https://eudi-rp-ts.fly.dev
CLIENT_ID_PREFIX=x509_san_dns
CLIENT_DNS_NAME=eudi-rp-ts.fly.dev
WALLET_SCHEME=eudi-openid4vp://
REQUESTED_VCT=urn:eudi:pid:1
TRUST_MODE=pinned
TRUST_ANCHORS_FILE=/app/test/fixtures/trust-anchor.pem     # the demo CA
ACCESS_CERT_CHAIN_PEM / ACCESS_CERT_KEY_PEM                # fly secrets
```

with `fly scale count 1`. **One machine is required**: sessions live in memory,
so with two the browser's poll lands on the machine that never saw the create
about half the time and reports `SESSION_EXPIRED` for a session that exists.

The access certificate there is self-minted (`npm run access-cert`). It exercises
the signed-request path; no real wallet trusts it.

## Observed facts about the reference infrastructure

Recorded with dates because they will drift, and each was checked directly
rather than inferred:

| Observed | Value |
|---|---|
| Wallet invocation scheme | `eudi-openid4vp://` — not the `haip-vp://` the reference verifier's README documents |
| Reference verifier client id | `x509_hash:FTTP4DJV_P7icSZwBAo8cifSpYy8Sph0K1gZdbmaQh4` |
| Its signing certificate SAN | `URI:https://verifier-backend.eudiw.dev/` — a **URI**, not a dNSName |
| Its PID request format | `mso_mdoc`, doctype `eu.europa.ec.eudi.pid.1` |
| `/.well-known/jwt-vc-issuer` | HTTP 400, "Not supported" — so `x5c` is the only working key resolution |
| Response encryption metadata | `encrypted_response_enc_values_supported`; the pre-1.0 `authorization_encrypted_response_alg`/`_enc` appear **zero times** in OID4VP 1.0 |
| PID DS certificate EKUs | `1.0.18013.5.1.2`, `1.0.23220.4.1.2` |
| `x509_san_uri` in OID4VP 1.0 Final | **absent** — present in draft-21 and draft-24, replaced by `x509_hash` |

The `x509_hash` rule is implemented and pinned by a fixed test vector: hashing
`test/fixtures/real/eudiw-verifier-leaf.pem` reproduces
`x509_hash:FTTP4DJV_P7icSZwBAo8cifSpYy8Sph0K1gZdbmaQh4`, the identifier that
certificate was advertised with. To repeat the live check:

```bash
curl -s https://registry.serviceproviders.eudiw.dev/authentication   # QR_code_url
# fetch its request_uri, then:
#   sha256(DER of x5c[0]) base64url  ==  the client_id after "x509_hash:"
```

## Time-sensitive material

- The credentials in `test/fixtures/real/` **expire 2026-11-08**. Offline tests
  pin a fixed `now` and keep passing; the OID4VP round-trip test skips itself
  after that date with a message saying so. Re-run `npm run fetch-credential` for
  fresh ones.
- Upstream bugs referenced here may be fixed, which would change what you see.
- Trust list contents change continuously.
