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
| **Interoperates with the EUDI reference wallet app** | **Reproducible**, 2026-08-11, see section 6 |

Every round trip in sections 1–4 uses `test/wallet.ts` or `test/mdoc-wallet.ts`
— about eighty lines each, written for these tests. They exercise the protocol
correctly, and they are not evidence of interoperability with anyone else's
implementation. Section 6 is the one that is: a presentation from the EU
reference wallet, against a registered Relying Party Access Certificate.

Two defects that only a real wallet exposed are recorded there. Both were
invisible to the simulated wallets, which is the point of the distinction.

## Environment of record

The results below were produced on:

| | |
|---|---|
| Date | **2026-08-09** (SD-JWT VC), **2026-08-10** (mdoc, trust lists, deployment), **2026-08-11** (issuance proof types, wallet provider, LOTE) |
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
| Subject data | `given_name=Test`, `family_name=Tester`, `place_of_birth[0][country]=PT`, `place_of_birth[0][locality]=Porto`, plus **per-format** names: `birthdate` / `nationalities[0][country_code]` / `picture` for SD-JWT VC, `birth_date` / `nationality[0][country_code]` / `portrait` for mdoc. All `1990-06-12`, `PT`, `Port1`. See "Two forms, two sets of field names". |
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
import { TrustAnchors, verifyAgeOver18, verifyMdoc } from '@sauseschritt/eudi-rp-ts';

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
- The **mdoc PID carries no age attribute** either — no `age_over_18`. Neither
  form offers an age field, so `birth_date` is the only route to the predicate
  in either format.
- The mdoc **does** carry `birth_date`, contrary to what this file said until
  2026-08-11. See "Two forms, two sets of field names" below.
- The mdoc's **`validUntil` is not valid RFC 3339**: `2026-11-09T11:51:46+00:00Z`
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

Re-run on 2026-08-11 through `fetchTrustAnchors` itself rather than the raw
`fetch` the network test uses, to check the same five lists against the size,
redirect and https-only limits in `src/fetching.ts`: 860 anchors with no service
type filter, no failures, every list reached over https without a redirect.
Sizes that day, `curl -sL -o /dev/null -w '%{size_download}'`:

| | bytes |
|---|---|
| `tl.bundesnetzagentur.de/TL-DE.XML` | 5 355 449 |
| `tsl.digital.gob.es/TSL.xml` | 3 027 766 |
| `eidas.agid.gov.it/TL/TSL-IT.xml` | 2 855 744 |

Germany's is the largest of the set, which is where the 20 MB trust list ceiling
comes from — the 10 MB general default would leave it under a factor of two.

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

## 5. Issuance proof types and the wallet provider

Checked **2026-08-11**, prompted by the reference wallet failing to obtain a PID.
None of this is used by the library — a relying party never issues — but it
determines whether you can get a credential into a wallet at all, which is the
prerequisite for everything in "Access certificates" in the README.

The issuer advertises, for `eu.europa.ec.eudi.pid_vc_sd_jwt`:

```json
"proof_types_supported": {
  "attestation": { "key_attestations_required": { "key_storage": ["iso_18045_high"],
                   "user_authentication": ["iso_18045_high"] },
                   "proof_signing_alg_values_supported": ["ES256"] },
  "jwt":         { "key_attestations_required": { … same … } }
}
```

**It does not enforce any of it.** `npm run fetch-credential -- sd-jwt` sends a
plain `proof_type: jwt` over a freshly generated *software* key, with no key
attestation at all, and receives HTTP 200 and a credential. A
`proof_type: attestation` request also succeeds. Both were run on 2026-08-11.

Key attestations are obtainable by anyone regardless, from the wallet provider:

```bash
curl -s -X POST https://wallet-provider.eudiw.dev/key-attestation/jwk-set \
  -H 'Content-Type: application/json' \
  -d '{"nonce":"","jwkSet":{"keys":[{"kty":"EC","crv":"P-256","x":"…","y":"…"}]}}'
```

That returns a `key-attestation+jwt` (claims: `iat`, `exp`, `attested_keys`,
`key_storage`, `user_authentication`, `certification`, `nonce`,
`key_storage_status`) for an arbitrary software key — so the
`iso_18045_high` assertion is not evidence of anything about the key.
`/wallet-instance-attestation/jwk` behaves the same way. Both paths exist on
`wallet-provider.eudiw.dev` and `dev.wallet-provider.eudiw.dev`.

### Two forms, two sets of field names

A correction, recorded at length because this file asserted the opposite for
months and the mistake was ours.

The EU's Relying Party Registration service authenticates you with a PID
presentation. Its DCQL query — fetched live from `verifier-backend.eudiw.dev` —
asks for **`format: "mso_mdoc"`**, doctype `eu.europa.ec.eudi.pid.1`, and five
claims, none marked `optional` and with no `claim_sets`, so all five are
mandatory:

```
family_name, given_name, birth_date, issuing_authority, issuing_country
```

An SD-JWT VC PID cannot satisfy that, and `GET /authentication` takes no
parameters, so there is no format to negotiate — you need an mdoc PID. A wallet
holding one satisfied the request on 2026-08-11 and the service returned a
`hash_pid`, even though the mdoc this repo fetched had no `birth_date`.

The reason is that **the two credential configurations serve different forms,
with different names for the same field**:

| Data | `pid_vc_sd_jwt` form | `pid_mdoc` form |
|---|---|---|
| Date of birth | `birthdate` | **`birth_date`** |
| Nationality | `nationalities[0][country_code]` | **`nationality[0][country_code]`** |
| Photo | `picture` | **`portrait`** |

`scripts/fetch-reference-credential.ts` posted the SD-JWT VC names for both.
The issuer accepts unknown fields and drops them **without an error**, so the
mdoc came back missing exactly the attributes whose names differ. That absence
was then written up here, in the README and in `test/fixtures/real/README.md` as
a property of the reference issuer. It never was one.

Fixed 2026-08-11: `SUBJECT` is now per-configuration, and the same flow yields
`birth_date` (`1990-06-12T00:00:00.000Z`) and a real 10 kB `portrait`. To see
the field names for yourself, dump the form rather than trusting this table —
it is one POST:

```
POST /dynamic/country_selected  (country=FC)   -> hidden `payload`
POST /display_form              (payload=…)    -> the form HTML
```

The lesson generalises: a silently-dropped form field looks exactly like an
upstream omission, and only reading the form tells them apart.

### Why this breaks wallets

A wallet-core build configured with `ClientAuthenticationType.None` has no
`WalletKeyAttestationProvider`, so it cannot construct either proof type and
**refuses client-side, before sending a credential request**:

```
E  Offered document requires attestation proof, but client authentication type is None
D  Finished(issuedDocuments=[])
```

That is `eudi-lib-android-wallet-core`'s `SubmitRequest.kt` — the fall-through
after the `ATTESTATION` and `JWT` branches, both of which require the provider.
The token exchange succeeds first, so the failure looks like an issuer outage
and is not one. A build using `ClientAuthenticationType.AttestationBased`
(the upstream demo flavour uses `clientId = "eudiw-abca"` with
`walletProviderHost = https://wallet-provider.eudiw.dev`) has the provider and
gets past it.

### The full chain a wallet performs

Every step below returned HTTP 200 on 2026-08-11, driven directly rather than
through a wallet, using the upstream app's configuration:

| Step | Detail |
|---|---|
| PAR | `POST /oidc/pushed_authorization` → `request_uri`, `expires_in: 3600` |
| Token | DPoP proof + `OAuth-Client-Attestation` / `-PoP` headers → `token_type: DPoP`, token carries `cnf.jkt` |
| Nonce | `POST /nonce` → `c_nonce` |
| Key attestation | wallet provider, nonce embedded |
| Credential | `Authorization: DPoP …` plus a proof carrying `ath`, body `proof_type: attestation` → credential |

The authorization server accepts DPoP and attestation-based client
authentication even though it advertises only
`token_endpoint_auth_methods_supported: ["public"]`.

## 6. A presentation from the EU reference wallet

Done **2026-08-11**. This is the claim the README carried as unproven for
months: not a simulated wallet, but the EUDI reference wallet app presenting a
PID to this verifier over a public deployment.

The result, as the page rendered it:

```
Verified — 18 or over
Format           dc+sd-jwt
Evidence         birthdate
Credential type  urn:eudi:pid:1
Issuer           CN=PID DS - 002, organizationIdentifier=LEIEU-123456789,
                 O=EUDI Wallet Reference Implementation, C=UT
```

The deployment configuration that produced it:

```
BASE_URL=https://eudi-rp-ts.fly.dev
CLIENT_ID_PREFIX=x509_hash
WALLET_SCHEME=eudi-openid4vp://
REQUESTED_VCT=urn:eudi:pid:1
TRUST_MODE=pinned
TRUST_ANCHORS_FILE=/app/test/fixtures/real/eudiw-pid-issuer-ca.pem
MDOC_TOLERATE_MALFORMED_VALIDITY=true
ACCESS_CERT_CHAIN_PEM / ACCESS_CERT_KEY_PEM        # fly secrets, the RPAC below
```

with `fly scale count 1`, for the in-memory session reason in section 4.

### The access certificate

Obtained from the EU *Testing* Relying Party Registration service, by completing
the chain `npm run register-rp` stops at. The registered entity is fictional —
the PID that authenticates the registration is itself synthetic (`C=UT`,
Utopia), so there is no real identity to submit.

The issued leaf:

```
subject = CN=eudi-rp-ts, C=DE, O=eudi-rp-ts Test Verifier,
          organizationIdentifier=VATDE999999999
issuer  = CN=PID Issuer CA 02, O=EUDI Wallet Reference Implementation, C=EU
SAN     = URI:https://github.com/polyrainbow/eudi-rp-ts/issues
valid   = 2026-08-11 → 2028-08-10, EC P-256, KeyUsage digitalSignature
```

**The SAN is a URI, taken from the `supportURI` submitted at registration.** It
carries no dNSName, and OID4VP 1.0 Final has no `x509_san_uri` — so
`CLIENT_ID_PREFIX=x509_san_dns` is unusable and the identifier must be
`x509_hash`, here
`x509_hash:Kbo2tsX4JWQ0aLZ_S0zOXeKRSWH_qqXnvXaMsQZ0pvI`. The reference verifier
is in the same position; see "Observed facts" below. The PKCS#12 contained the
leaf only, no CA — which turned out not to matter, since the wallet accepted a
single-certificate `x5c`.

### Two defects only a real wallet exposed

**1. `vp_formats_supported` did not cover the DCQL query.** The query offers
`dc+sd-jwt` and `mso_mdoc` as alternatives, but `client_metadata` declared only
`dc+sd-jwt`. The wallet refused the entire request before considering any
credential:

```
invalid_request: InvalidClientMetaData(
  cause=Verifier does not support all Formats requested in the DCQL query)
```

A Verifier may only ask for formats it declares. Both simulated wallets skip
that check, so the whole suite passed. `signed-request.test.ts` now asserts
that every format in the DCQL query appears in `vp_formats_supported`.

**2. A wallet's refusal was reported as a malformed response.** Under
`direct_post.jwt` an OAuth error response is encrypted exactly like a success,
so it decrypts to `{error, error_description, state}` with no `vp_token`. The
protocol parser, looking for a `vp_token`, reported a DCQL schema violation —
and the wallet's stated reason never reached the user. Diagnosing defect 1 was
impossible until this was fixed. Encrypted error responses now surface as
`WALLET_ERROR` carrying the wallet's own code and description.

Both fixes are in `src/`, not the demo app: they are protocol handling, not
presentation.

### What the result shows, and what it does not

`Evidence: birthdate` means the **privacy-preserving path was not available**.
The wallet could not satisfy `age_equal_or_over.18` and fell back to disclosing
a full date of birth — more information than the question required. This is the
consequence of PID Rulebook v1.1 removing the age attributes per CIR 2024/2977,
observed rather than predicted. A verifier asking "is this person 18" against a
current reference PID learns exactly when they were born.

`Format: dc+sd-jwt` — the wallet chose SD-JWT VC although it also held the mdoc
PID that the registration service requires. Both were offered; the mdoc path
therefore remains proven only against `test/mdoc-wallet.ts`.

Unlike the credential in section 2, this presentation came through a wallet, so
it carries a Key Binding JWT and the holder-binding path was exercised for real.

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
| Issuer signed metadata | served **only** under `Accept: application/jwt`; the default JSON carries no `signed_metadata` claim. `typ: openidvci-issuer-metadata+jwt`, signed by `CN=PY Issuer PreProd` under `PID Issuer CA 02` (C=EU) |
| Credential request/response encryption | both advertised, both `encryption_required: false` |
| Token endpoint auth methods | advertises `["public"]`, yet accepts DPoP and attestation-based client authentication |
| Key attestation requirements | advertised as `iso_18045_high`, **not enforced** — a software key with no attestation is accepted |
| EUDI trust lists (LOTE) | `https://trustedlist.serviceproviders.eudiw.dev/LOTE/json/{PIDProviders,WRPACProviders,PubEAAProviders}.jwt` — JWS (`ES256`, `cty: octet-stream`) wrapping a `LoTE` JSON object, **not** the ETSI TS 119 612 XML of the eIDAS lists |
| `PIDProviders.jwt` contents | 14 CA certificates, issued **2026-07-09**, `NextUpdate` 2027-01-05; service types `…/19602/SvcType/PID/{Issuance,Revocation}`. Both the PID DS certificate and the signed-metadata signer verify against it |

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

- The credentials in `test/fixtures/real/` **expire 2026-11-08** (SD-JWT VC)
  and **2026-11-09** (mdoc). Offline tests
  pin a fixed `now` and keep passing; the OID4VP round-trip test skips itself
  after that date with a message saying so. Re-run `npm run fetch-credential` for
  fresh ones.
- Upstream bugs referenced here may be fixed, which would change what you see.
- Trust list contents change continuously.
