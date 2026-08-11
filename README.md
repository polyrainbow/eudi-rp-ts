# eudi-rp-ts

A minimal EU Digital Identity relying party in Node/TypeScript. It proves one
predicate — **age over 18** — from an SD-JWT VC, over OpenID4VP.

The official EUDI implementations are Kotlin, Swift and Python. The one
TypeScript repo in the `eu-digital-identity-wallet` org is an Angular UI that
delegates all verification to the Kotlin backend, so there is no Node reference
for this. That gap is what this project fills.

## Quick start

Requires **Node 22.18+ or 24+** — that is when running `.ts` files directly
became unflagged. On Node 22.0–22.17 type stripping is behind
`--experimental-strip-types` and `npm start` will fail. There is no build step;
Node runs the TypeScript as-is.

```bash
npm install
npm test                      # 94 tests, fully offline
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

New to the vocabulary? [GLOSSARY.md](GLOSSARY.md) defines EUDIW, PID, mDoc,
SD-JWT VC, OID4VCI vs OID4VP, DCQL, RPAC and the rest — including the ones that
are easy to confuse.

## How it flows

```
browser  ──POST /presentations─────▶  build OID4VP request  ──▶  QR + deep link
wallet   ──GET  /oid4vp/request/:id─▶  signed request object (x509_san_dns only)
wallet   ──POST /oid4vp/response/:id▶  ① protocol envelope   (@openid4vc/openid4vp)
                                     ② credential          (src/verify.ts)
browser  ──GET  /presentations/:id─▶  verified / rejected + reason code
```

Keeping ① and ② apart matters. Layer ① says *the wallet answered the question we
asked*. Only layer ② says *and the answer is backed by a credential we trust*.

Every rejection ends at exactly one `ReasonCode` (`src/result.ts`), so callers
switch on a code and never parse an error string.

## Layout

`src/` is the library and `app/` is a demo that consumes it. The library reads
no configuration, opens no ports and logs nothing; `app/config.ts` is the only
file that touches `process.env`.

```
src/index.ts              the public API — anything else is a deep import
src/result.ts             ReasonCode and the Outcome type
src/crypto.ts             ES256 allowlist, JWS verification, hashing
src/verify.ts             credential verification, orchestration
src/predicate/age.ts      age_equal_or_over["18"], birthdate
src/trust/anchors.ts      the trust anchor set
src/trust/issuer-key.ts   x5c resolution + chain validation   <- the part no library does
src/trust/lotl.ts         ETSI TS 119 612 trust list client   <- no Node implementation existed
src/trust/status.ts       Token Status List revocation
src/mdoc/verify.ts        ISO 18013-5 mdoc, through the same trust layer
src/mdoc/device-response.ts     DeviceResponse + device authentication
src/mdoc/cose.ts          COSE_Sign1 verification
src/mdoc/session-transcript.ts  the OID4VP handover a device signature commits to
src/oid4vp/identity.ts    who this verifier is on the wire
src/oid4vp/query.ts       the DCQL query
src/oid4vp/request.ts     authorization request (+ JAR)
src/oid4vp/response.ts    response validation, hand-off to src/verify.ts
src/oid4vp/callbacks.ts   the crypto callbacks @openid4vc/openid4vp requires

app/config.ts             environment -> library options
app/http/                 server, in-memory session store
app/main.ts               entry point
app/public/index.html     the single page
```

### Using it as a library

```bash
npm install @sauseschritt/eudi-rp-ts
```

Or from a checkout:

```bash
npm run build     # tsc -> dist/, with declarations
```

```ts
import { TrustAnchors, verifyAgeOver18 } from '@sauseschritt/eudi-rp-ts';

const result = await verifyAgeOver18({
  credential,
  anchors: TrustAnchors.fromPem(issuerCaPem),
  expectedVct: 'urn:eudi:pid:1',
  keyBinding: { nonce, audience: clientId },
});
```

**The demo in `app/` is a demo.** In-memory sessions, no auth, one page. Do not
deploy it as-is; use the library inside your own service.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `3000` | Listen port (plain HTTP). |
| `BASE_URL` | `https://localhost:3000` | Public https URL wallets reach. **Set this.** Must be https, checked at startup — it is where the wallet posts the VP Token. |
| `WALLET_SCHEME` | `eudi-openid4vp://` | Deep-link scheme. What the live EUDI reference infrastructure emits; its verifier README documents `haip-vp://`. |
| `CLIENT_ID_PREFIX` | `redirect_uri` | Or `x509_san_dns`, or `x509_hash`. |
| `CLIENT_DNS_NAME` | — | Required for `x509_san_dns` only; must match a dNSName SAN in the leaf. `x509_hash` needs no name. |
| `ACCESS_CERT_CHAIN_FILE` / `ACCESS_CERT_KEY_FILE` | — | Required for `x509_san_dns`; signs the request object. |
| `ACCESS_CERT_CHAIN_PEM` / `ACCESS_CERT_KEY_PEM` | — | Same, inline. For hosts with no filesystem for secrets. |
| `REQUESTED_VCT` | `urn:eudi:pid:1` | Credential type to ask for. |
| `STATUS_CHECK` | `true` | Verify each credential's status list. Set `false` only for an offline demo. |
| `MDOC_TOLERATE_MALFORMED_VALIDITY` | `false` | Accept an mdoc whose `validUntil` is not valid RFC 3339. Needed for the EU reference issuer today; see upstream issue #177. |
| `TRUST_MODE` | `pinned` | Or `lotl`. |
| `TRUST_ANCHORS_FILE` / `TRUST_ANCHORS_PEM` | — | PEM anchors, required for `pinned`. Path or inline. |
| `LOTL_URL` | EU LOTL | Trust list to fetch for `lotl`. |
| `LOTL_TERRITORIES` | all | e.g. `DE,AT`. All 42 lists is ~20 MB and slow. |
| `LOTL_SERVICE_TYPES` | all | e.g. `http://uri.etsi.org/TrstSvc/Svctype/CA/QC`. |

**Pointing at a different wallet**: change `WALLET_SCHEME`. **A different trust
list**: `LOTL_URL` plus `LOTL_SERVICE_TYPES`.

### Three client identifier modes

`redirect_uri` (default) — the Client Identifier *is* the response URI, and the
request MUST NOT be signed, because the wallet has no way to obtain a trusted
key for it. Needs no PKI, so the demo starts with one command.

`x509_san_dns` — the request MUST be signed, with the access certificate chain
in the JAR `x5c` header, and the DNS name must match a dNSName SAN in the leaf.

`x509_hash` — the same signed request, but the identifier is the base64url
SHA-256 of the DER leaf certificate rather than a name inside it. **This is how
the EU reference verifier identifies itself**, and it is what to reach for when
the certificate you are issued carries a URI SAN, or none, instead of a dNSName
— which is exactly what the reference verifier's certificate does. A test pins
our implementation against that certificate and the identifier it published.

Both x509 modes turn on response encryption (`direct_post.jwt`) with a
per-session ephemeral key.

## Claim encoding

Per the EUDI PID Rulebook (ARF 2.4, chapter 4), the SD-JWT VC encoding differs
from the mdoc one:

| Data identifier | SD-JWT VC claim | Encoding |
|---|---|---|
| `age_over_18` | `age_equal_or_over.18` | boolean |
| `birth_date` | `birthdate` | string, `YYYY-MM-DD` (OIDC registered claim) |

In **mdoc** the same information is spelled differently again: a flat
`age_over_18` boolean and `birth_date`, inside the namespace
`eu.europa.ec.eudi.pid.1`. `evaluateAgeOver18Mdoc` handles that form.

The live reference issuer emits **only `birthdate`** — see "Open questions".
Both are implemented, `age_equal_or_over.18` preferred when present.

`age_equal_or_over` is one object keyed by age, e.g. `{"16": true, "18": true}`
— not flat `age_over_NN` claims. So the DCQL query asks for the path
`["age_equal_or_over", "18"]`, and a wallet that discloses that property alone
reveals nothing else. A test asserts the verifier learns nothing more.

## Spec-compliant vs simplified

**Compliant.** Token Status List revocation, including verifying the status
list token's own signature against the same trust anchors; SD-JWT digests and
disclosures (RFC 9901); SD-JWT VC media types
`dc+sd-jwt` and transitional `vc+sd-jwt` (draft-18); OID4VP 1.0 request and
response shapes, DCQL, `direct_post` and `direct_post.jwt`; Key Binding JWT with
`sd_hash`, `nonce`, and `aud` equal to the full prefixed Client Identifier
(§14.8); x5c chain signature linkage and certificate validity windows; ETSI TS
119 612 trust list signature verification, including RSASSA-PSS.

**Simplified, deliberately.**

- **No CRL or OCSP** for the issuer's certificate chain. Credential revocation
  via Token Status List **is** checked (see below); certificate revocation is
  not.
- **Certificate path validation is partial.** Checked: validity windows,
  signature linkage, that every issuing certificate is a CA, path length, an
  optional Extended Key Usage allowlist, and Name Constraints (see below). Not
  checked: KeyUsage bits and certificate policies — Node's `X509Certificate`
  exposes *extended* key usage but not the KeyUsage bit string, so enforcing
  those means parsing DER by hand.
- **No CRL or OCSP for issuer certificates.** Credential revocation is checked
  via Token Status List; certificate revocation relies on the issuer leaving the
  trusted list, which the refresh picks up. That is weaker, and worth knowing.
- **Trust lists are not fully TS 119 615.** We check the signature and that a
  service is `granted`. No service status history, no validity-time evaluation
  against the credential date, no qualifier processing, no `Sie` extensions.
- **Sessions are in memory** in the demo app. Restarting drops them, and more
  than one instance breaks them. The library holds no state.
- **ES256 only**, matching what the reference issuer advertises.

### Name Constraints

A CA carrying this extension (RFC 5280 §4.2.1.10) is stating which names it is
entitled to certify. Without the check, any CA on any Member State's trusted
list can vouch for any subject — so a chain that links correctly and terminates
at a trusted anchor can still be one no CA on it was authorised to produce. That
rejection is `ISSUER_NAME_NOT_PERMITTED`, kept distinct from `ISSUER_UNTRUSTED`
for exactly that reason.

Constraints are applied across the whole path, anchor included, and bind every
certificate below the one carrying them rather than only the one it signed.
All five name forms the EUDI ecosystem could plausibly use are implemented —
`dNSName`, `rfc822Name`, `uniformResourceIdentifier`, `iPAddress`,
`directoryName` — each with its own matching rule, because they are not
interchangeable.

Two deliberate positions:

- **A constraint we cannot evaluate fails the chain.** An unimplemented name
  form, a malformed extension, or the `minimum`/`maximum` fields RFC 5280
  forbids all reject rather than being skipped. A path validated by ignoring the
  one statement a CA made about its own authority is not validated.
- **DN comparison is simplified.** Attribute values are compared
  case-insensitively on trimmed, whitespace-collapsed text, not under RFC 4518
  string preparation. An attribute that is not a readable string type matches
  nothing at all.

Measured against the live eIDAS trust lists on 2026-08-11: 2 of 1897 anchors
carry the extension, using only `dNSName` and `iPAddress`. So failing closed on
an unimplemented form costs nothing today — see REPRODUCE.md.

## mdoc

The verifier accepts **either format**. The DCQL query lists both and uses
`credential_sets` to say either will do — without that the wallet is asked for
*all* listed credentials (OID4VP 1.0 §6.4.2), which no holder has, so it returns
nothing. The response handler dispatches on whichever entry comes back, and the
result carries a `format` field.

For mdoc the holder binding works differently: instead of a Key Binding JWT over
a nonce, the wallet signs a SessionTranscript. The handler rebuilds that
transcript from the request it sent, so a response produced for another verifier
cannot verify — a test asserts exactly that through the full handler.

`verifyMdoc` checks an issued `IssuerSigned`; `verifyDeviceResponse` checks what
a wallet actually sends. Both run issuer identity through the same
`TrustAnchors` and path validation as SD-JWT VC — mdoc carries its chain in a
COSE `x5chain` header rather than a JOSE `x5c`, and that is the only difference
that reaches the trust code.

A DeviceResponse carries two independent signatures. **issuerAuth** proves the
issuer attested the claims; **deviceSignature** proves the wallet holds the key
the issuer bound them to, and produced this response for *this* request. The
second is why a stolen credential is not enough: it signs a
`DeviceAuthentication` structure containing the OID4VP session transcript, which
commits to our client identifier, nonce and response URI. Tests assert that a
response replayed at another verifier, bound to a nonce we never issued, or
signed by a different key, is rejected.

Two things the real reference credential taught us, both pinned by tests:

- **Its mdoc PID carries no age predicate** — no `age_over_18`, matching the
  SD-JWT VC's missing `age_equal_or_over`. It *does* carry `birth_date`; the
  committed fixture lacks one only because the script that fetched it posted the
  SD-JWT VC form's field names, and the mdoc form calls that field `birth_date`
  rather than `birthdate`. Unknown fields are dropped without an error. Fixed in
  `scripts/fetch-reference-credential.ts`; see REPRODUCE.md, "Two forms, two
  sets of field names".
- **Its `validUntil` is not valid RFC 3339** (`...+00:00Z`, carrying both an
  offset and a `Z`; upstream issue #177). Rejected by default, with an explicit
  opt-out, because a validity window that cannot be read is not one.

Device MAC authentication is not implemented: it needs an ECDH session key that
OID4VP over redirects never establishes, so its presence is a rejection rather
than a gap.

## Revocation

A credential's `status.status_list` names a URI and an index; the URI serves a
signed token holding a bitstring, and the bit at that index says whether the
credential is still valid. The EU reference issuer publishes one for every PID.

`@sd-jwt/sd-jwt-vc` drives this but leaves fetching **and verifying the list's
own signature** to the relying party — it refuses to proceed without a
`statusVerifier`, which is the right call: an unauthenticated status list would
let anyone who can answer an HTTP request declare a revoked credential valid.
`src/trust/status.ts` chains the list's `x5c` to the same trust anchors as the
credential, and checks its `typ` is `statuslist+jwt` so a credential cannot be
replayed as its own status list.

**It fails closed.** An unreachable or unverifiable status list is
`STATUS_UNAVAILABLE`, not a pass — a verifier that accepts what it could not
check has no revocation at all.

Status lists cover many credentials, so pass a shared `statusCache`
(`createStatusListCache()`) in anything serving traffic; without one every
verification refetches the same document. Concurrent misses on the same URL
collapse into a single fetch, and a *failed* fetch is remembered for 30 seconds
— verification still fails closed either way, but without that the issuer's
outage becomes one here, at one full timeout per credential.

### What an outbound request is allowed to do

Every URL this library fetches was read out of a document that arrived over the
network — a status list URI from a credential, a national list location from the
LOTL — so the limits are policy rather than plumbing. All of them are options on
`fetchText`, and the defaults are exported.

| | Default | Why |
|---|---|---|
| `timeoutMs` | 10 s | One deadline for the whole exchange, redirects included. |
| `maxBytes` | 10 MB | A deadline bounds nothing alone: a body arriving steadily for ten seconds is still unbounded memory. Enforced while reading, not just against `Content-Length`. Trust lists ask for 20 MB — Germany's list is 5.4 MB. |
| `maxRedirects` | 3 | The fetch specification allows twenty, which is far more indirection than any of these endpoints needs. |
| `allowedProtocols` | `https:` only | Checked on every hop, so a redirect cannot walk off TLS. A trust list served over http cannot be forged — it is signature-checked — but it can be replayed, and a stale list still grants a CA that has since been withdrawn. |

## Using it in a service

The library is deliberately inert: it reads no configuration, opens no ports and
logs nothing. Four things are worth passing in anything serving traffic.

```ts
const result = await verifyCredential({
  credential, anchors, expectedVct: 'urn:eudi:pid:1', keyBinding,

  statusCache,                          // shared; see Revocation above
  allowedAlgs: ['ES256'],               // policy, checked against the token's alg
  pathValidation: { requiredExtendedKeyUsage: ['1.0.18013.5.1.2'] },
  onEvent: (event) => audit(event),     // structured, no personal data
});
```

**Reason codes are derived from recorded state, never from error text.** An
earlier version matched on library error messages; adding a fetch helper changed
one string and silently turned `STATUS_UNAVAILABLE` into `CREDENTIAL_MALFORMED`.
Every distinction that matters is now either checked explicitly or recorded by a
callback, and a test pins that a structural defect is not reported as a bad
signature.

**Events carry no personal data by construction** — no claim values, no subject
identifiers, no credential bytes. A test asserts it. An audit trail that quietly
accumulates dates of birth is worse than none.

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

- ~~Does the live reference issuer still emit `age_equal_or_over`?~~
  **Answered: no.** A real `urn:eudi:pid:1` obtained from the reference issuer
  on 2026-08-09 discloses `family_name`, `given_name`, `birthdate`,
  `place_of_birth`, `nationalities`, `picture`, `date_of_issuance`,
  `date_of_expiry`, `issuing_authority`, `issuing_country` — and no age
  attribute at all, matching PID Rulebook v1.1 / CIR 2024/2977. **So the
  `birthdate` path is the real one today, not a fallback**, and proving age
  against the reference issuer means the holder discloses their full date of
  birth. The credential is committed at `test/fixtures/real/`.
- **SD-JWT VC and current EU age verification are diverging.** The dedicated EU
  Age Verification profile (`av-doc-technical-specification`, Annex A) is
  **mdoc-only**: doctype `eu.europa.ec.av.1`, flat `age_over_18`, `redirect_uri`
  client id, `direct_post`. This project deliberately stays on the SD-JWT VC path.
- **`/.well-known/jwt-vc-issuer` is unsupported** by the reference issuer (HTTP
  400, "Not supported"), so `x5c` is the only key-resolution route that works
  against real EU infrastructure today. Only `x5c` is implemented.
- ~~`x509_san_uri` is not implemented.~~ **Corrected: it does not exist in
  OID4VP 1.0.** It appears in draft-21 and draft-24 and is absent from the final
  specification, which introduced `x509_hash` in its place — zero occurrences of
  `x509_san_uri` in 1.0 Final against fourteen of `x509_hash`. The EUDI
  reference verifier documents `pre-registered`, `x509_san_dns` and `x509_hash`
  only. So the three prefixes implemented here cover the current specification;
  a wallet still on a pre-1.0 draft would be the only reason to want it.
- **The eIDAS LOTL is not a registry of PID Providers.** It lists qualified
  trust service providers. EUDI provider lists are published separately, per
  deployment — which is why the EU's own trust validator makes the list location
  a per-provider setting. `LOTL_URL` exists for exactly that reason.

## Deploying

A wallet on a phone needs to reach `response_uri` over public https, so a real
test needs a deployment. `fly.toml` is included and uses the `Dockerfile`
unchanged:

```bash
fly launch --no-deploy --copy-config --name <your-app>
fly secrets set BASE_URL=https://<your-app>.fly.dev
fly deploy
```

Any Docker host works the same way — Render, Railway, a VPS. The only two things
that matter are that `BASE_URL` is the public https URL and that the container
can reach the internet if you use `TRUST_MODE=lotl`.

Serverless platforms (Netlify, Vercel, Lambda) need code changes first: sessions
live in an in-memory `Map`, so an ephemeral function would answer every
presentation with `SESSION_UNKNOWN`. `SessionStore` is behind a small interface
specifically so it can be swapped for a KV store, but that work isn't done.

Two things to expect on a fresh deployment:

- **`TRUST_MODE=pinned` with the demo anchor rejects every real credential** with
  `ISSUER_UNTRUSTED`. That is correct behaviour — the fixture CA is a throwaway.
  Point `TRUST_ANCHORS_FILE` at the issuer's real anchor, or switch to `lotl`.
- **Fly's trial plan stops machines after 5 minutes**, regardless of
  `auto_stop_machines = 'off'`. They restart on the next request, but in-memory
  sessions do not survive. Add a card, or expect to restart a check that sat
  idle.
- **Run exactly one machine.** Sessions live in an in-memory `Map`, so with two
  machines the wallet's POST and the browser's poll land on different instances
  about half the time and the page shows `SESSION_EXPIRED` for a session that
  exists. `min_machines_running = 1` is a floor, not a cap — `fly launch`
  provisions two by default, so run `fly scale count 1`. Scaling out needs a
  shared session store first.

## What is proven against real infrastructure

Every claim below is reproducible, and [REPRODUCE.md](REPRODUCE.md) says exactly
how — with the dates, versions, endpoints and configuration that produced it,
and an explicit list of what was *not* done.


- **A genuine EUDI credential verifies.** `test/real-credential.test.ts` runs
  the full credential path — `x5c` resolution, chain to the real
  `PID Issuer CA - UT 02`, issuer signature, disclosure resolution, predicate —
  against a `urn:eudi:pid:1` issued by `backend.issuer.eudiw.dev`.
- **The EU trust lists parse and verify.** `RUN_NETWORK_TESTS=1 npm test`.
- **The EUDI reference wallet presents to this verifier.** 2026-08-11, over a
  public deployment with a registered access certificate. Verified 18-or-over
  from a `urn:eudi:pid:1` issued by `CN=PID DS - 002`. Unlike the credential
  above — fetched by driving OID4VCI directly — this one came through a wallet,
  so it carries a Key Binding JWT. See [REPRODUCE.md](REPRODUCE.md) section 6
  for the configuration and the two defects it exposed.

**Fetch your own credential and check it**: `npm run fetch-credential -- sd-jwt`
drives the OID4VCI flow against `issuer.eudiw.dev` and writes a real credential
you can verify with this library.

Two caveats on the wallet result. The evidence was `birthdate`, not
`age_equal_or_over.18`: PID Rulebook v1.1 removed the age attributes, so the
wallet disclosed a full date of birth rather than the boolean — the
privacy-preserving path is not available against a current reference PID. And
the wallet answered in `dc+sd-jwt`; the `mso_mdoc` path is still proven only
against the simulated wallet.

To repeat it: run `npm run register-rp`, complete the registration chain it
stops at, and configure `CLIENT_ID_PREFIX=x509_hash` — the issued certificate
carries a URI SAN rather than a dNSName, so `x509_san_dns` will not work. Point
`TRUST_ANCHORS_FILE` at `anchors/eudiw-pid-issuer-ca.pem`, set
`BASE_URL` to your public URL, and `WALLET_SCHEME` to `eudi-openid4vp://`.

### Access certificates

Two different things go by this name, and only one of them is something you can
generate.

**A real Wallet Relying Party Access Certificate (RPAC)** is *issued to you*.
You register with your Member State's Relying Party Registrar, and a Relying
Party Access CA issues the certificate, chaining to that Member State's Trusted
List. It carries your relying party identifier and the set of attributes you are
authorised to request. There is no way to mint one yourself — that is the point
of it.

There are three routes, in descending order of how quickly you can get going.

**1. A test certificate under the reference implementation's trust list.** Run
`npm run register-rp` — it starts the flow, prints a QR code in your terminal
and waits while you present a PID from the reference wallet, then hands you the
`hash_pid` every other endpoint needs. It stops there on purpose: the remaining
steps submit your real legal identity and intended use.

The
EU runs a *Testing* Relying Party Registration service at
<https://registry.serviceproviders.eudiw.dev/> which issues access and
registration certificates "under the trusted list of the EUDI Wallet Reference
Implementation, enabling you to test with the EUDI Wallet". It needs an EU Login
account, and authentication happens via a PID/OID4VP flow — so you need the
reference wallet holding a PID from `issuer.eudiw.dev` first. The API is
documented at `/apidocs/`; the certificate comes from `/wallet_rp/certificate`
as PKCS#12. This is the route that gets a real wallet to accept this verifier.

Convert the P12 into what the config wants (add `-legacy` if OpenSSL 3 rejects
the file's older ciphers):

```bash
openssl pkcs12 -in wrp.p12 -clcerts -nokeys       -out access-cert-chain.pem
openssl pkcs12 -in wrp.p12 -cacerts -nokeys       >>  access-cert-chain.pem
openssl pkcs12 -in wrp.p12 -nocerts -nodes | \
  openssl pkcs8 -topk8 -nocrypt                   -out access-cert-key.pem
```

Set `CLIENT_DNS_NAME` to a dNSName SAN actually present in the issued leaf —
check with `openssl x509 -in access-cert-chain.pem -noout -text | grep -A1 'Subject Alternative Name'`.

**2. Production: register with your national Registrar.** Under
[CIR (EU) 2025/848](https://eur-lex.europa.eu/eli/reg_impl/2025/848/oj), each
Member State runs one or more registers of wallet-relying parties. You register
in the Member State where you are established, declaring your legal identity,
the attributes you intend to request and the intended use for each. An Access CA
designated by that Member State then issues the RPAC; some Member States also
issue a Registration Certificate (RPRC) that lets a wallet show the user what
you registered for. **The regulation applies from 24 December 2026**, so national
registrars are still coming online — check with your Member State's supervisory
body for its timeline.

Registration is not a formality: a wallet checks requested attributes against
your registered intended use, and warns the user when a verifier asks for more
than it registered for. Asking only for `age_equal_or_over.18`, as this project
does, is the kind of narrow registration that gets approved easily.

**3. A development certificate** is enough to exercise the code path locally:

```bash
npm run access-cert -- verifier.example.org
```

That writes `config/access-cert-{key,chain}.pem` plus `config/access-ca.pem`.
It is an EC P-256 leaf with a `dNSName` SAN matching the name you pass —
which is what OID4VP 1.0 §5.10 requires — under a throwaway CA.

```bash
CLIENT_ID_PREFIX=x509_san_dns \
CLIENT_DNS_NAME=verifier.example.org \
BASE_URL=https://verifier.example.org \
ACCESS_CERT_CHAIN_FILE=config/access-cert-chain.pem \
ACCESS_CERT_KEY_FILE=config/access-cert-key.pem \
npm start
```

A real wallet validates the chain, so it will reject this unless you add
`config/access-ca.pem` to that wallet's trust store. Use it to test your own
wallet build, or the simulated wallet in `test/wallet.ts` — not to get past a
production one.

**With a signed request the QR code holds only a reference.** A JAR carries the
whole `x5c` chain, which is well past what a QR code can encode — embedding it
by value fails outright. So the request object is served from
`GET /oid4vp/request/:id` as `application/oauth-authz-req+jwt` and the QR holds
just `client_id` and `request_uri`.

**Signed requests use encrypted responses** (`direct_post.jwt`), sealed to a
per-session ephemeral key. That is why `response_uri` carries a per-session id:
under `direct_post.jwt` the `state` is inside the ciphertext, so the URL is the
only thing that says which session — and therefore which decryption key — a
response belongs to, before it can be decrypted.

## Fixtures

`test/fixtures/` is generated by `npm run fixtures` and committed. The
credentials are signed by a throwaway CA created by that script. They prove our
verification logic is correct; they say nothing about EUDI interoperability.

## Security

Test key material is committed on purpose and protects nothing; the known gaps
are listed in [SECURITY.md](SECURITY.md) and under "Spec-compliant vs
simplified" above. This is a reference implementation, not production software.

## Licence

Copyright 2026 Sebastian Wiese-Wagner.

Apache License 2.0 — see [LICENSE](LICENSE). All dependencies are permissive
(Apache-2.0 or MIT) and compatible; they are listed in [NOTICE](NOTICE).
