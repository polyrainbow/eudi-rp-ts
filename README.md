# eudi-rp-ts

A minimal EU Digital Identity relying party in Node/TypeScript. It proves one
predicate — **age over 18** — from an SD-JWT VC, over OpenID4VP.

The official EUDI implementations are Kotlin, Swift and Python. The one
TypeScript repo in the `eu-digital-identity-wallet` org is an Angular UI that
delegates all verification to the Kotlin backend, so there is no Node reference
for this. That gap is what this project fills.

## Quick start

Requires Node 22+ (developed on 24). There is no build step — Node runs the
TypeScript directly.

```bash
npm install
npm test                      # 27 tests, fully offline
RUN_NETWORK_TESTS=1 npm test  # also verifies the live EU trust lists
npm start                     # http://localhost:3000
```

Or `docker compose up`.

Open the page, click **Start age check**, and scan the QR code with a wallet.
To try the whole flow without a wallet, `test/oid4vp.test.ts` drives it
end to end against the simulated wallet in `test/wallet.ts`.

> **You must set `BASE_URL` before a real wallet can work.** OpenID4VP requires
> `response_uri` to be https, and a phone cannot reach your `localhost` anyway.
> Put a tunnel in front and set `BASE_URL` to its public https URL. The server
> itself still listens on plain HTTP behind it.

## How it flows

```
browser  ──POST /presentations──▶  build OID4VP request  ──▶  QR + deep link
wallet   ──POST /oid4vp/response──▶  ① protocol envelope   (@openid4vc/openid4vp)
                                     ② credential          (src/verify.ts)
browser  ──GET  /presentations/:id─▶  verified / rejected + reason code
```

Keeping ① and ② apart matters. Layer ① says *the wallet answered the question we
asked*. Only layer ② says *and the answer is backed by a credential we trust*.

Every rejection ends at exactly one `ReasonCode` (`src/result.ts`), so callers
switch on a code and never parse an error string.

## Layout

```
src/config.ts             all env-driven configuration; nothing else reads process.env
src/result.ts             ReasonCode and the Outcome type
src/crypto.ts             ES256 allowlist, JWS verification, hashing
src/verify.ts             credential verification, orchestration
src/predicate/age.ts      age_equal_or_over["18"], birthdate fallback
src/trust/anchors.ts      the trust anchor set
src/trust/issuer-key.ts   x5c resolution + chain validation   <- the part no library does
src/trust/lotl.ts         ETSI TS 119 612 trust list client   <- no Node implementation existed
src/oid4vp/query.ts       the DCQL query
src/oid4vp/request.ts     authorization request (+ JAR)
src/oid4vp/response.ts    response validation, hand-off to src/verify.ts
src/oid4vp/callbacks.ts   the crypto callbacks @openid4vc/openid4vp requires
src/http/                 server, session store
```

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `3000` | Listen port (plain HTTP). |
| `BASE_URL` | `https://localhost:3000` | Public https URL wallets reach. **Set this.** |
| `WALLET_SCHEME` | `haip-vp://` | Deep-link scheme. The EUDI reference verifier calls this `VERIFIER_AUTHORIZATIONREQUESTURI`. |
| `CLIENT_ID_PREFIX` | `redirect_uri` | Or `x509_san_dns`. |
| `CLIENT_DNS_NAME` | — | Required for `x509_san_dns`; must match a dNSName SAN in the leaf. |
| `ACCESS_CERT_CHAIN_FILE` / `ACCESS_CERT_KEY_FILE` | — | Required for `x509_san_dns`; signs the request object. |
| `REQUESTED_VCT` | `urn:eudi:pid:1` | Credential type to ask for. |
| `TRUST_MODE` | `pinned` | Or `lotl`. |
| `TRUST_ANCHORS_FILE` | — | PEM anchors, required for `pinned`. |
| `LOTL_URL` | EU LOTL | Trust list to fetch for `lotl`. |
| `LOTL_TERRITORIES` | all | e.g. `DE,AT`. All 42 lists is ~20 MB and slow. |
| `LOTL_SERVICE_TYPES` | all | e.g. `http://uri.etsi.org/TrstSvc/Svctype/CA/QC`. |

**Pointing at a different wallet**: change `WALLET_SCHEME`. **A different trust
list**: `LOTL_URL` plus `LOTL_SERVICE_TYPES`.

### Two client identifier modes

`redirect_uri` (default) — the Client Identifier *is* the response URI, and the
request MUST NOT be signed, because the wallet has no way to obtain a trusted
key for it. Needs no PKI, so the demo starts with one command.

`x509_san_dns` — the request MUST be signed, with the access certificate chain
in the JAR `x5c` header. This is what the EUDI reference verifier uses and what
a real wallet will accept. Response encryption (`direct_post.jwt`) turns on with
it, using a per-session ephemeral key.

## Claim encoding

Per the EUDI PID Rulebook (ARF 2.4, chapter 4), the SD-JWT VC encoding differs
from the mdoc one:

| Data identifier | SD-JWT VC claim | Encoding |
|---|---|---|
| `age_over_18` | `age_equal_or_over.18` | boolean |
| `birth_date` | `birthdate` | string, `YYYY-MM-DD` (OIDC registered claim) |

`age_equal_or_over` is one object keyed by age, e.g. `{"16": true, "18": true}`
— not flat `age_over_NN` claims. So the DCQL query asks for the path
`["age_equal_or_over", "18"]`, and a wallet that discloses that property alone
reveals nothing else. A test asserts the verifier learns nothing more.

## Spec-compliant vs simplified

**Compliant.** SD-JWT digests and disclosures (RFC 9901); SD-JWT VC media types
`dc+sd-jwt` and transitional `vc+sd-jwt` (draft-18); OID4VP 1.0 request and
response shapes, DCQL, `direct_post` and `direct_post.jwt`; Key Binding JWT with
`sd_hash`, `nonce`, and `aud` equal to the full prefixed Client Identifier
(§14.8); x5c chain signature linkage and certificate validity windows; ETSI TS
119 612 trust list signature verification, including RSASSA-PSS.

**Simplified, deliberately.**

- **No revocation.** No CRL, no OCSP, and SD-JWT VC status list checking is off
  (`disableStatusVerification`). This is the biggest gap.
- **Certificate path validation is partial.** Signature linkage and validity
  windows are checked; name constraints, path length, key usage, EKU and
  certificate policies are not.
- **Trust lists are not fully TS 119 615.** We check the signature and that a
  service is `granted`. No service status history, no validity-time evaluation
  against the credential date, no qualifier processing, no `Sie` extensions.
- **Sessions are in memory.** Restarting drops in-flight sessions.
- **ES256 only**, matching what the reference issuer advertises.

## Three things the libraries do not do

All handled in `src/`; all easy to get wrong by assuming otherwise.

1. **`@sd-jwt` never resolves issuer keys.** Its verifier callback is
   `(data, sig) => boolean`, so key discovery and trust are entirely the relying
   party's problem. `src/trust/issuer-key.ts` is that missing half.
2. **`@sd-jwt` does not check the KB-JWT audience.** It requires `aud` to be
   present and matches `nonce`, but never compares `aud` to the verifier's own
   identifier — so a presentation minted for a different verifier would pass. We
   check it explicitly. Relatedly, key binding is verified *only* when a nonce is
   supplied; passing none silently skips it even when a KB-JWT is present, which
   is why `verifyCredential` throws rather than defaulting.
3. **`xml-crypto` does not ship RSASSA-PSS.** Several member states sign their
   trust lists with it (Germany's is `sha256-rsa-MGF1`), so without the
   implementation in `src/trust/lotl.ts` those lists simply fail to verify.

## Open questions

- **Does the live reference issuer still emit `age_equal_or_over`?** PID
  Rulebook v1.1 (4 Sep 2025) removed the age attributes following CIR 2024/2977,
  and `issuer.eudiw.dev` advertises an empty `claims` array for
  `eu.europa.ec.eudi.pid_vc_sd_jwt`, so its metadata does not answer this. Run
  `npm run probe -- <credential>` with a real credential to settle it. The
  `birthdate` fallback covers the case where the answer is no — at the cost of
  the holder disclosing their full date of birth.
- **SD-JWT VC and current EU age verification are diverging.** The dedicated EU
  Age Verification profile (`av-doc-technical-specification`, Annex A) is
  **mdoc-only**: doctype `eu.europa.ec.av.1`, flat `age_over_18`, `redirect_uri`
  client id, `direct_post`. This project deliberately stays on the SD-JWT VC path.
- **`/.well-known/jwt-vc-issuer` is unsupported** by the reference issuer (HTTP
  400, "Not supported"), so `x5c` is the only key-resolution route that works
  against real EU infrastructure today. Only `x5c` is implemented.
- **The eIDAS LOTL is not a registry of PID Providers.** It lists qualified
  trust service providers. EUDI provider lists are published separately, per
  deployment — which is why the EU's own trust validator makes the list location
  a per-provider setting. `LOTL_URL` exists for exactly that reason.

## Testing against a real wallet

Not yet done. `npm test` proves the logic against a simulated wallet and
fixtures signed by a throwaway CA; the trust-list code is proven against the
live EU lists. **Neither proves interoperability with the EUDI reference
wallet** — that needs a public https deployment, an access certificate the
wallet trusts, and a credential from `issuer.eudiw.dev`.

To attempt it: set `CLIENT_ID_PREFIX=x509_san_dns`, supply the access
certificate, set `BASE_URL` to your tunnel, and point `WALLET_SCHEME` at the
wallet's scheme.

## Fixtures

`test/fixtures/` is generated by `npm run fixtures` and committed. The
credentials are signed by a throwaway CA created by that script. They prove our
verification logic is correct; they say nothing about EUDI interoperability.
