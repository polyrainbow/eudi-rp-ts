# eudi-rp-ts

An EU Digital Identity relying party in Node/TypeScript. It verifies SD-JWT VC
and ISO 18013-5 mdoc credentials over OpenID4VP: you supply the DCQL query, it
checks the answer against that query and hands back the credentials. Both
formats have verified a PID presented by the EUDI reference wallet.

The demo asks one question — **age over 18** — and that question lives in
`src/presets/`, not in the verification path. It is a query plus a predicate,
which is what any other question is too.

The official EUDI implementations are Kotlin, Swift and Python. The one
TypeScript repo in the `eu-digital-identity-wallet` org is an Angular UI that
delegates all verification to the Kotlin backend, so there is no Node reference
for this. That gap is what this project fills.

## Quick start

Requires **Node 22.18 or newer** — that is when running `.ts` files directly
became unflagged. On Node 22.0–22.17 type stripping is behind
`--experimental-strip-types` and `npm start` will fail. There is no build step;
Node runs the TypeScript as-is. CI runs the suite on 22.18.0, 24.x and 26.x —
the floor, the release line the Docker image runs, and the current one.

```bash
npm install
npm test                      # the whole suite, fully offline
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
wallet   ──GET  /oid4vp/request/:id─▶  signed request object (both x509 modes)
wallet   ──POST /oid4vp/response/:id▶  ① protocol envelope   (@openid4vc/openid4vp)
                                     ② credential          (src/verify.ts | src/mdoc/)
browser  ──GET  /presentations/:id─▶  verified / rejected + reason code
```

Keeping ① and ② apart matters. Layer ① says *the wallet answered the question we
asked*. Only layer ② says *and the answer is backed by a credential we trust*.

Every rejection ends at exactly one `ReasonCode` (`src/result.ts`), so callers
switch on a code and never parse an error string.

## Layout

`src/` is the library and `app/` is a demo that consumes it. The library reads
no configuration, opens no ports and logs nothing; `app/config.ts` is the only
file outside `scripts/` that touches `process.env`.

```
src/index.ts              the public API — anything else is a deep import
src/result.ts             ReasonCode and the Outcome type
src/crypto.ts             algorithm policy, JWS verification, hashing
src/events.ts             typed audit events; carries no personal data
src/fetching.ts           outbound HTTP policy: deadline, size cap, TTL cache
src/verify.ts             credential verification, orchestration
src/predicate/age.ts      age_equal_or_over["18"], birthdate
src/presets/age-over-18.ts      one question: the DCQL query and the predicate over its answer
src/presets/eudi-pid.ts         the PID's vct, doc type and namespace
src/trust/anchors.ts      the trust anchor set
src/trust/issuer-key.ts   x5c resolution + chain validation   <- the part no library does
src/trust/policy-tree.ts  RFC 5280 §6.1 certificate policy processing
src/trust/critical-extensions.ts  §6.1.4 (o) — what we refuse to ignore
src/trust/{key-usage,name-constraints,policies,basic-constraints}.ts
                          DER readers for what node:crypto does not expose
src/trust/lotl.ts         ETSI TS 119 612 trust list client   <- no Node implementation existed
src/trust/status.ts       Token Status List revocation (the credential)
src/trust/revocation.ts   CRL and OCSP                 (the issuer's certificates)
src/mdoc/verify.ts        ISO 18013-5 mdoc, through the same trust layer
src/mdoc/device-response.ts     DeviceResponse + device authentication
src/mdoc/cose.ts          COSE_Sign1 verification
src/mdoc/session-transcript.ts  the OID4VP handover a device signature commits to
src/oid4vp/identity.ts    who this verifier is on the wire
src/oid4vp/query.ts       DCQL query types, and the readers that check a response against one
src/oid4vp/request.ts     authorization request (+ JAR)
src/oid4vp/response.ts    response validation, query-driven hand-off to the verifiers
src/oid4vp/callbacks.ts   the crypto callbacks @openid4vc/openid4vp requires

app/config.ts             environment -> library options
app/audit.ts              verification events -> JSON lines on stdout
app/http/                 server, session store, rate limit, shutdown
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
import { TrustAnchors, verifyAgeOver18SdJwtVc } from '@sauseschritt/eudi-rp-ts';

const result = await verifyAgeOver18SdJwtVc({
  credential,
  anchors: TrustAnchors.fromPem(issuerCaPem),
  expectedVct: 'urn:eudi:pid:1',
  keyBinding: { nonce, audience: clientId },
});
```

The mdoc counterpart is `verifyAgeOver18Mdoc`, taking a `DeviceResponse` and the
session transcript it was signed over instead of a credential and a nonce:

```ts
import { TrustAnchors, verifyAgeOver18Mdoc } from '@sauseschritt/eudi-rp-ts';

const result = await verifyAgeOver18Mdoc({
  deviceResponse,
  anchors: TrustAnchors.fromPem(issuerCaPem),
  sessionTranscript,
  expectedDocType: 'eu.europa.ec.eudi.pid.1',
});
```

Both return `credentialType` rather than `vct` or `docType`. The two formats
name the same idea differently — see the glossary — and the result type is what
both produce, so it names neither: the mdoc path used to fill a field called
`vct` with a doc type. `namespace` on the mdoc call defaults to the doc type,
which is right for the EUDI PID, where they coincide, and wrong for an ISO mDL,
where the doc type is `org.iso.18013.5.1.mDL` and the namespace is
`org.iso.18013.5.1`.

### Reading the answer

A DCQL claims path is a pointer over both formats (OID4VP 1.0 §7): a string
selects an object member, a number an array index, `null` every element of an
array, and §7.2 maps it onto mdoc as `[namespace, element]`. `selectClaims` and
`readClaim` walk it, so the pointer that asked for a claim is the one that reads
it:

```ts
import { readClaim, selectClaims } from '@sauseschritt/eudi-rp-ts';

readClaim(credential.claims, ['age_equal_or_over', '18']);        // SD-JWT VC
readClaim(credential.claims, ['eu.europa.ec.eudi.pid.1', 'birth_date']);  // mdoc
selectClaims(credential.claims, ['nationalities', null]);         // every element
```

`readClaim` returns undefined when a path selects nothing *or* several; use
`selectClaims` where several is the point.

**A verified credential is checked against the claims its query asked for** —
`REQUESTED_CLAIMS_MISSING` if a required claim was not disclosed, or if one
carries a value the query's `values` excluded. That is distinct from
`PREDICATE_*` and the distinction is who fell short: this is the wallet
answering something other than what was asked, before any rule of yours has run.
Without it, a caller with no predicate is handed `verified: true` beside
`claims.given_name === undefined`, with nothing to separate a wallet that
withheld the claim from a holder who never had it.

### Asking your own question

The two calls above verify one credential you already hold. Over OpenID4VP you
also have to ask for it, and **the DCQL query is the argument that decides
everything downstream**: which formats may answer, which `vct` or doc type each
must carry, which combinations are enough, and what
`client_metadata.vp_formats_supported` advertises. `verifyPresentationResponse`
reads the query back off the request that was sent, so the answer is checked
against exactly what was asked.

```ts
import { buildAuthorizationRequest, verifyPresentationResponse } from '@sauseschritt/eudi-rp-ts';

const query = {
  credentials: [
    {
      id: 'holder_name',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['urn:eudi:pid:1'] },
      require_cryptographic_holder_binding: true,
      claims: [{ path: ['given_name'] }, { path: ['family_name'] }],
    },
  ],
} as const;

const request = await buildAuthorizationRequest(identity, query);
// ... hand request.walletUri to the holder, store request.requestPayload ...

const outcome = await verifyPresentationResponse(
  { config: identity, anchors, nonce: request.nonce, requestPayload, decryptionJwk },
  authorizationResponse,
);
if (outcome.verified) {
  for (const credential of outcome.value.credentials) {
    console.log(credential.queryId, credential.format, credential.claims);
  }
}
```

A verified presentation is a *set*: `credentials` in the order the `vp_token`
listed them, and `byQueryId` keyed by Credential Query id. `claims` is the
format's own structure — a plain object for SD-JWT VC, `{ namespace: { element:
value } }` for mdoc — which is what a DCQL claims path addresses (OID4VP 1.0
§7.2), so a path taken from the query reads either.

Verifying every credential the query asked for is the default test. A question
about what the credentials *say* is a predicate, supplied by the caller and
evaluated before the verdict, so that one `verification.accepted` covers both:

```ts
import { ageOver18Predicate, ageOver18Query } from '@sauseschritt/eudi-rp-ts';

const request = await buildAuthorizationRequest(identity, ageOver18Query());
const outcome = await verifyPresentationResponse(
  { ...context, predicate: ageOver18Predicate },
  authorizationResponse,
);
if (outcome.verified) console.log(outcome.value.predicate.evidence); // 'birthdate'
```

`ageOver18Query` and `ageOver18Predicate` are a preset — the pair the demo uses,
and the model for your own. Nothing in the verification path imports them.

The response is also checked for answering *no more* than the query needed. A
wallet answering both alternatives of a query that offered a choice is rejected
before either credential is verified: the holder disclosed a credential the
verifier had no basis to ask for, and verifying it is the act of collecting it.

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
| `ACCESS_CERT_CHAIN_FILE` / `ACCESS_CERT_KEY_FILE` | — | Required for **both** x509 modes; signs the request object. Startup fails without them. |
| `ACCESS_CERT_CHAIN_PEM` / `ACCESS_CERT_KEY_PEM` | — | Same, inline. For hosts with no filesystem for secrets. |
| `REQUESTED_VCT` | `urn:eudi:pid:1` | Credential type to ask for. |
| `STATUS_CHECK` | `true` | Verify each credential's status list. Set `false` only for an offline demo. |
| `CERT_REVOCATION_CHECK` | `true` | Check the issuer's certificate chain by CRL or OCSP. Fails closed, so set `false` if the CA's endpoints are unreachable from your deployment. |
| `MDOC_TOLERATE_MALFORMED_VALIDITY` | `false` | Accept an mdoc whose `validUntil` is not valid RFC 3339. Needed for the EU reference issuer today; see upstream issue #177. |
| `VERIFICATION_TIMEOUT_MS` | `30000` | A bound on one whole presentation check, which the per-request timeouts are not: a verification can fetch a status list and then a CRL per certificate. Exceeding it is `VERIFICATION_ABORTED`. |
| `TRUST_MODE` | `pinned` | Or `lotl`. |
| `TRUST_ANCHORS_FILE` / `TRUST_ANCHORS_PEM` | — | PEM anchors, required for `pinned`. Path or inline. |
| `LOTL_URL` | EU LOTL | Trust list to fetch for `lotl`. |
| `LOTL_TERRITORIES` | all | e.g. `DE,AT`. All 42 lists is ~20 MB and slow. |
| `LOTL_SERVICE_TYPES` | all | e.g. `http://uri.etsi.org/TrstSvc/Svctype/CA/QC`. |
| `ALLOWED_ALGS` | `ES256` | Credential signature algorithms accepted, e.g. `ES256,PS256`. Advertised to the wallet and enforced on the response. |
| `LOTL_INSECURE_SKIP_FRESHNESS_CHECK` | `false` | Accept a trust list past its own `NextUpdate`, or declaring none. A stale list still grants services withdrawn since. Only for development, or when a missed republication upstream would otherwise be your outage. |
| `SESSION_LIMIT` | `10000` | Most presentation sessions held at once. Beyond it, `/presentations` answers 503 `at_capacity` rather than evicting someone else's pending check. |
| `RATE_LIMIT` / `RATE_LIMIT_WINDOW_MS` | `30` / `60000` | `POST /presentations` per client per window; 429 with `Retry-After` beyond it. `0` disables. Polling is not limited. |
| `TRUSTED_PROXY_HOPS` | `0` | Proxies of *yours* in front of this server. `0` keys the rate limit on the socket address; behind a load balancer that is one key for everyone, so set the hop count. See below. |
| `TRUST_REFRESH_MS` / `TRUST_REFRESH_RETRY_MS` | `43200000` / `300000` | Between successful trust list refreshes, and after a failed one — doubling per consecutive failure, capped at the interval. |
| `SHUTDOWN_DRAIN_MS` / `SHUTDOWN_GRACE_MS` | `0` / `35000` | Keep serving this long after readiness starts failing, and the hard deadline for the whole shutdown. |

Every numeric variable is parsed at startup and a value that is not a
non-negative number is a startup failure. That is deliberate: `Number('1O000')`
is `NaN`, every comparison against `NaN` is false, and a limit that silently
enforces nothing is worse than no limit at all.

**Pointing at a different wallet**: change `WALLET_SCHEME`. **A different trust
list**: `LOTL_URL` plus `LOTL_SERVICE_TYPES`.

### Serving it: limits, probes, shutdown

Four things the demo server does that are about running rather than verifying.

**Two limits, and they are different questions.** The rate limit is per client
and refuses with 429: you are asking too often. The session cap is shared and
refuses with 503 `at_capacity`: this instance is holding as many presentations
as it will. Neither substitutes for the other — a per-client limit cannot bound
what a large enough number of clients does, and a shared cap cannot tell one
abusive caller from a crowd. Both guard `POST /presentations`, which is the
endpoint where asking is cheaper than answering: each call mints a session,
signs a request object and renders a QR code, and the caller has to hold none of
it. Refusing a new session rather than evicting the oldest is the deliberate
half of the cap, because evicting would let whoever is flooding cancel the
checks of people who actually scanned a code.

Behind a proxy, set `TRUSTED_PROXY_HOPS` to the number of hops **you** operate.
`X-Forwarded-For` is a header, so trusting it by default would hand every caller
a way to be a new client on every request; trusting nothing is safer but not
safe, because then every request shares one socket address and the per-client
limit becomes a global one. With `n` hops the client is the nth entry from the
right, since appending is what a conforming proxy does — entries to the left of
that are the client's own to write. Too few entries and the socket address is
used instead of a value nothing vouched for.

**`GET /healthz` and `GET /readyz` are different questions too.** Liveness is
"is this process running" and answers 200 through both a lapsed trust list and a
shutdown in progress — on purpose, because restarting the container fixes
neither. Readiness answers 503 while draining, and 503 with
`trust_anchors_stale` once the loaded lists are past their own `NextUpdate` and
every refresh since has failed. That second state already existed and had no way
to say so: the server would decline each presentation individually while
reporting itself healthy.

**Trust list refresh backs off.** A flat twelve-hour interval means a failure at
hour zero is not retried until hour twelve, which is long enough to run past
`NextUpdate` and take the verifier out of service over a blip that lasted a
minute. Failures retry from `TRUST_REFRESH_RETRY_MS`, doubling per consecutive
failure up to the interval, each delay jittered ±10% so instances started
together do not synchronise on one Member State's endpoint.

**SIGTERM drains rather than exits.** Node's default handler exits immediately,
which severs every verification in flight — and by then the wallet has already
posted and its `nonce` is spent, so the presentation cannot be retried and the
person holding the phone sees a check that never answers. Instead: readiness
fails, `SHUTDOWN_DRAIN_MS` passes (set it to at least your balancer's readiness
interval; `0` is right with nothing in front), the listener closes, in-flight
requests finish, and `SHUTDOWN_GRACE_MS` bounds the lot. A second signal exits
immediately — an operator saying they are done waiting should get that rather
than a SIGKILL from the platform.

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

**Dates keep their type.** ISO 18013-5 encodes `birth_date` as an RFC 8943
`full-date` (CBOR tag 1004) and `validityInfo` as `tdate` (tag 0), and `cbor2`
decodes both to a JS `Date` — turning a birth date into an instant at midnight
UTC. `decodeCbor` decodes tag 1004 to the `YYYY-MM-DD` string it wraps, so
`birth_date` reads as a date and the MSO's validity still reads as a timestamp.
Without that every reader downstream has to know to cut the time back off, and
the one that forgets is wrong by a day near midnight.

## Spec-compliant vs simplified

**Compliant.** Certificate revocation by CRL (RFC 5280 §5) and OCSP (RFC 6960),
including verifying the CRL's or response's own signature and bounding its
freshness; Token Status List revocation **for both credential formats**,
including verifying the status list token's own signature against the same trust
anchors, that its `sub` is the URI the credential named, and that it has not
expired; SD-JWT digests and
disclosures (RFC 9901); trust list freshness, in that a list past its own
`NextUpdate` — or declaring none — is refused rather than replayed (see below);
trust list signature *coverage*, so that the services parsed are the ones the
signature protected rather than whatever the fetched document contained (see
below);
SD-JWT VC media types
`dc+sd-jwt` and transitional `vc+sd-jwt` (draft-18); OID4VP 1.0 request and
response shapes, DCQL, `direct_post` and `direct_post.jwt`; Key Binding JWT with
`sd_hash`, `nonce`, and `aud` equal to the full prefixed Client Identifier
(§14.8); x5c chain signature linkage and certificate validity windows; ETSI TS
119 612 trust list signature verification, including RSASSA-PSS and ECDSA.

**Certificate path validation is RFC 5280 §6.1 in full**: validity windows,
signature linkage, that every issuing
certificate is a CA and asserts `keyCertSign` (§6.1.4 (n)), that the leaf
asserts `digitalSignature` (see below), path length — the caller's limit *and*
each CA's own `pathLenConstraint` (§6.1.4 (l), (m), see below) — Name
Constraints (§6.1.3, see below), certificate policies as the full §6.1 state
machine (see below), rejection of critical extensions this project does not
process (§6.1.4 (o), see below), and revocation by CRL or OCSP (see below).
Three readings within that are this project's own and are argued where they are
made: the trust anchor is treated per RFC 5937 rather than §6.1, Extended Key
Usage is enforced only against a `requiredExtendedKeyUsage` the caller sets, and
policy qualifiers are read but not acted on — which §6.1.5 (f) leaves local.

**Simplified, deliberately.**

- **Trust lists are not fully TS 119 615.** Service status history,
  validity-time evaluation, the list's own issue date and next-update, and
  §5.5.9 service information extensions including `Qualifications` *are*
  implemented (see below). Not implemented: the parts of TS 119 615 that turn a
  qualifier into a verdict — this project derives the qualifiers and reports
  them, and leaves what they oblige to the caller.
- **Sessions are in memory** in the demo app, though no longer irreversibly:
  `SessionStore` is an interface and `MemorySessionStore` is one implementation
  of it, so a shared store is a class rather than a rewrite (see below).
  Restarting still drops them, and more than one instance still breaks them,
  until something implements it. The library holds no state either way.
- **ES256 by default** — the whole of the EUDI reference deployment. ECDSA on
  three curves and RSA in six algorithms are implemented; widening the policy is
  a deliberate act (see below).

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

### Certificate policies

A certificate policy (RFC 5280 §4.2.1.4) is a CA stating *under which rules* it
issued: the identity proofing, the key protection, the audit regime. In eIDAS
that is the load-bearing statement — an ETSI policy OID is what separates a
qualified certificate from one a CA issued to anyone who asked, and both can sit
under the same trusted list entry. 2336 of the 2439 service certificates on the
live lists assert one, across 512 distinct OIDs (REPRODUCE.md).

The check is not "does the leaf assert OID X". That would be a one-line test and
it would be wrong, because a policy is only worth anything if every CA on the
path authorised it. RFC 5280 §6.1 answers the real question with a
`valid_policy_tree` and three counters, and all of it is implemented: policy
mapping (`policyMappings`), the anyPolicy wildcard and its withdrawal
(`inhibitAnyPolicy`), and a CA's demand that its successors be explicit
(`policyConstraints`). The rejection is `ISSUER_POLICY_NOT_PERMITTED`, kept
distinct from `ISSUER_UNTRUSTED` for the same reason as
`ISSUER_NAME_NOT_PERMITTED`: the chain links and reaches an anchor, but not
under any policy agreed the whole way down.

```ts
pathValidation: {
  certificatePolicies: { acceptable: ['0.4.0.194112.1.2'] },
}
```

Four positions worth stating:

- **Naming policies means requiring them.** RFC 5280 §6.1.5 (g) succeeds on
  `explicit_policy > 0` whatever the caller's policy set said, so under the
  letter of the RFC a caller can name the policies it accepts and still be
  handed a path that asserts none. Here `acceptable` implies
  `requireExplicit`; pass `requireExplicit: false` for the RFC's own reading.
- **Naming nothing is not the same as skipping the step.** With no options the
  caller accepts any policy — but every certificate's own `policyConstraints`,
  `inhibitAnyPolicy` and mappings are still processed, because those are the
  CAs' demands and not the caller's. Eight CA certificates on the live lists
  make one.
- **The anchor's constraints bind; its assertions do not.** `policyConstraints`
  and `inhibitAnyPolicy` on a trust anchor are folded into the initial state
  (RFC 5937 §3.2), on the same reading as Name Constraints: a trust anchor that
  constrains the paths beneath it means it. Its own `certificatePolicies` are
  *not* read as the path's policy — §6.1 gives the anchor's position to a
  root node of anyPolicy, and treating the anchor as the first certificate
  would end the tree at every anchor that asserts nothing, which is 67 of the
  1165 CAs on the live lists and the EU PID Issuer CA among them.
- **A policy extension that cannot be read fails the chain**, like a Name
  Constraint that cannot be read. All 2439 certificates on the live lists parse,
  so this costs nothing today.

There is no default `acceptable`, and that is deliberate: the EU reference PID
signer asserts the placeholder `1.2.3.4` and the reference verifier signer
`0.4.0.194118.1.2`, so the OID a deployment should demand is a property of the
deployment rather than of this library.

Because a state machine that agrees with its own tests proves little, the same
chains are put to `openssl verify`, which implements §6.1 and exposes each
initial input as a flag. `scripts/check-policy-tree.ts` compares the verdicts;
all ten cases agree (REPRODUCE.md).

### Path length

`basicConstraints` carries two statements, and Node exposes one. `.ca` says a
certificate may sign certificates; `pathLenConstraint` says how many further CAs
may sit between it and an end entity, and reaching it means parsing the DER.

It is not a theoretical gap: 692 of the 1165 CA certificates on the live trusted
lists set it to **zero** — "I sign end-entity certificates only" — and the EU PID
Issuer CA is one of them. Unread, a chain claiming any of those issued a sub-CA,
which then vouches for any subject at all, validated on every other check.

RFC 5280 §6.1.4 (l) and (m) as written: the anchor's own constraint applies to
the path below it (RFC 5937 §3.2 again), a self-issued certificate does not spend
a step because a CA re-keying itself is not a delegation, and the end
certificate's own constraint is not read — it says what *it* may issue, which is
a different question. `pathValidation.maxChainLength` is unrelated and still
enforced: that one is the caller's limit, this one is each CA's.

### Signature algorithms

Two separate questions, kept apart: what this **can** verify, and what a
deployment **will** accept.

Capability is `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`, `PS256`,
`PS384` and `PS512`. Policy — `allowedAlgs`, or `ALLOWED_ALGS` in the demo — is
`ES256` alone by default, because that is what the entire EUDI reference
deployment uses: the PID document signer, the status list token and the wallet's
key binding. The token's own `alg` is checked against the policy and never used
to select the verification algorithm, which is how algorithm substitution
attacks work.

RSA is here because a chain does not terminate in that deployment; it terminates
in eIDAS. Measured on 2026-08-12: **2013 of the 2305 certificates on the live
trusted lists carry RSA keys, against 274 EC** (REPRODUCE.md). Verifying ECDSA
alone meant an issuer could chain to a trusted qualified CA and still be
unverifiable for signing the way most of eIDAS signs — and the refusal came from
path validation, which rejected any non-EC leaf before an algorithm had even
been named.

Three details worth stating:

- **The key must match the algorithm**, and a mismatch is `UNSUPPORTED_ALGORITHM`
  rather than a bad signature. An RSA key offered for `ES256`, a P-256 key for
  `ES384`, a 1024-bit RSA key (RFC 7518 §3.3 requires 2048; four such
  certificates are published today), a brainpool curve JOSE has no algorithm for
  (24 published): each is an unusable key, not a failed verification.
- **`RS*` and `PS*` are not interchangeable.** Both are "RSA with SHA-256"; the
  padding is the whole difference, and reading the wrong one turns a good
  signature into an invalid one. An `rsa-pss` key may not produce PKCS#1 at all
  (RFC 4055), which is why an RSA access certificate signs with `PS256`.
- **mdoc stays ECDSA-only.** ISO/IEC 18013-5 §9.1.3.4 permits only ECDSA and
  EdDSA for issuer and device authentication, so the COSE identifiers for RSA
  are deliberately left unmapped: an RSA-signed `issuerAuth` is outside the
  standard rather than an interoperability case being refused.

The policy is advertised to the wallet in `client_metadata.vp_formats_supported`
and enforced when the presentation comes back, from one value — a verifier that
advertises more than it accepts rejects wallets for answering what it asked for.

### Key usage

`basicConstraints` says a certificate *is* a CA; `keyUsage` (RFC 5280 §4.2.1.3)
says what its key is allowed to do. They are separate assertions, and §6.1.4 (n)
requires the second to be honoured.

The interesting part is which half was actually missing.

**`keyCertSign` was already enforced, by accident of the platform.** Node's
`X509Certificate.ca` is OpenSSL's `X509_check_ca`, which clears the CA flag when
a KeyUsage extension is present without `keyCertSign`; `checkIssued` refuses
such an issuer as well. So the existing "is it a CA" test had been carrying a
requirement nobody had written down. The explicit check now in `issuer-key.ts`
changes no outcome — it is there because Node documents `.ca` as "is this a CA
certificate" and nothing more, so relying on the rest is relying on an
undocumented property of the TLS backend. A test pins Node's behaviour beside
it, so a divergence is a red build rather than a silent loss.

**The leaf's KeyUsage was checked by nobody**, and that is the real gap. No
library in the tree knows this key is about to verify a credential signature
rather than a TLS handshake, so nothing looked. A leaf that asserts KeyUsage
must now include `digitalSignature`. `nonRepudiation` alone does not qualify: it
covers a non-repudiation service rather than the data-origin signature an issuer
makes over a credential, and ISO 18013-5 Annex B requires `digitalSignature` on
a document signer certificate.

An **absent** extension is silence, not refusal, and stays unrestricted — 60 of
the end-entity certificates on the live trusted lists carry no KeyUsage at all,
and rejecting them for saying nothing would be wrong.

Measured on 2026-08-12 (REPRODUCE.md): all 1055 CA certificates published across
the live lists carry KeyUsage and all 1055 assert `keyCertSign`; the EU reference
PID document signer asserts exactly `digitalSignature`, for the SD-JWT VC and
the mdoc alike, and its CA asserts `keyCertSign|cRLSign`. So the rules cost
nothing today — the same measured argument as Name Constraints, and it goes
stale the same way, so `ecosystem-drift.test.ts` watches it.

### Critical extensions

Marking an extension **critical** is a CA saying *this changes what the
certificate means, and you may not use it without understanding me*. RFC 5280
§6.1.4 (o) is the other half of that bargain: a validator meeting one it does
not process must reject the certificate.

The rule is inverted from every other check here. Those ask whether a
certificate satisfies something; this asks whether anything on it was left
unread. A validator that skips a critical extension has not validated a weaker
path — it has validated a *different certificate* from the one the CA issued,
because the extension it ignored could be narrowing that certificate to a
purpose this is not, and silence reads exactly like permission.

Which makes the recognised set the security-relevant part, and it is exported as
`RECOGNISED_CRITICAL_EXTENSIONS` to be read rather than taken on faith. The
membership rule is **this library reads the extension and lets it change an
outcome** — nothing is on it for being common or expected, which is how this
rule turns into decoration. Eleven OIDs: `basicConstraints`, `keyUsage`,
`nameConstraints`, `subjectAltName`, `certificatePolicies`, `policyMappings`,
`policyConstraints`, `inhibitAnyPolicy`, `extKeyUsage`,
`cRLDistributionPoints` and `authorityInfoAccess`.

Two of those are processed *conditionally*, and saying so is the point of
listing them: `extKeyUsage` is enforced against the caller's
`requiredExtendedKeyUsage`, unset by default — §4.2.1.12 leaves the purpose
check to the application in exactly that way, and 1002 certificates on the live
lists mark it critical, so a verifier rejecting them would be enforcing the rule
by refusing eIDAS. `cRLDistributionPoints` and `authorityInfoAccess` are read to
find a CRL or a responder, which fails closed, but only while
`checkCertificateRevocation` is on. The set is deliberately **not** computed
from the caller's options: a certificate that is valid under one configuration
and malformed under another makes this rejection unreproducible.

`subjectKeyIdentifier`, `authorityKeyIdentifier`, `issuerAltName`,
`subjectDirectoryAttributes` and `freshestCRL` are absent on purpose. RFC 5280
requires all five to be non-critical, so a critical one is a non-conforming
certificate and rejecting it is the rule working rather than a gap in it.

**The trust anchor is exempt.** §6.1 never processes it as a certificate — it
supplies the initial state, and the loop (o) belongs to runs over the
certificates below it. RFC 5937 does extend an anchor's influence downward, but
only its *constraints*, which this library obeys; a critical extension is not a
constraint on the path but an instruction about the certificate carrying it.
Same rule as everywhere else here: constraints bind, assertions do not. An
anchor is trusted because an operator pinned it or a Member State published it,
not because every field on it was understood.

Measured on 2026-08-12 (REPRODUCE.md): six extensions are ever marked critical
across the live trusted lists, and exactly one is outside the set —
`privateKeyUsagePeriod` (RFC 3280 §4.2.1.4, dropped from RFC 5280), on four
certificates. So turning this rule on costs four certificates today, none of
them in the reference deployment: the EU PID document signer and its CA mark
only `basicConstraints` and `keyUsage` critical, and a test pins that against
the committed real credential. Before certificate policies were implemented the
same measurement was 78, which is most of why they came first.

The rejection is `ISSUER_EXTENSION_UNRECOGNISED`, kept distinct from
`ISSUER_UNTRUSTED` because the distinction is the useful part: nothing is known
to be wrong with the issuer, the chain or the credential. This verifier is the
thing that fell short, and the operator's next step is to go and read the
extension rather than to go looking at the issuer.

### Trust list validity time

A service on a trusted list is `granted` **from a stated instant**, not forever,
and usually has a `ServiceHistory` recording what it was before. So "is this
certificate a trust anchor" is a question about a time, and `TrustAnchors`
answers it that way: each anchor from a trust list carries the half-open
intervals it was granted for, and path validation looks it up against an instant.

That instant defaults to the validation time. For a credential being presented
live this is the safer reading — a service withdrawn since issuance stops
vouching for anything, including what it signed while granted. Pass
`pathValidation.trustListEvaluationTime` for the other reading, the one eIDAS
uses for long-term signatures, where withdrawal is not retroactive and what
matters is that the service was granted *when it signed*. That reading also
rejects the case the default accepts: a service granted only **after** the
credential was signed. Pinned anchors from a PEM file are unaffected — an
operator's decision has no published status to evaluate.

Measured against the live lists on 2026-08-12, and this is the honest summary:
at the default evaluation time the anchor set is **unchanged** — 2301 unique
certificates before and after. The previous flat parse reported 2434 because it
counted a certificate once per service that names it; 133 of those were
duplicates. What changes is that the question can now be asked at another time:
223 of the services on eight member states' lists became granted during 2026
alone, and none of them vouches for anything signed earlier.

Two details the real lists forced:

- **`StatusStartingTime` is required.** It is the only thing saying when a
  status began, so an entry without one is dropped rather than assumed to have
  applied forever. All 2797 services and 3330 history instances sampled carry
  it, so nothing real is lost — the same measured argument as Name Constraints.
- **`ServiceInformation` is current by definition, not by timestamp.** Poland
  republishes the current entry as a history instance with the *same*
  `StatusStartingTime`; ordering the two by time gives the live entry a
  zero-length interval and drops the service. That cost 14 real anchors before
  it was pinned by a test.

### Qualifiers and service extensions

A trusted list says more about a service than *granted*. ETSI TS 119 612 §5.5.9
gives each entry a set of extensions, and two of them carry statements a
verifier can act on: `AdditionalServiceInformation`, which says what the service
is provided *for* — `ForeSignatures`, `ForeSeals`, `ForWebSiteAuthentication`,
`RootCA-QC` — and `Qualifications`, usually called *the Sie* after the namespace
it lives in, which is a **rule set over the certificates the service issues**.
Not a property of the CA: a rule matches on policy OIDs, KeyUsage bits, Extended
Key Usage or subject DN attributes, and awards qualifiers such as `QCStatement`,
`QCForESig`, `QCWithQSCD` or `NotQualified` to the certificates that match. Two
leaves under one CA can qualify differently, which is why nothing here can be
reduced to a flag on the anchor.

`verifyTrustList` reads all of it; `TrustAnchors.qualify` evaluates the rules
against a certificate; and the answer reaches the caller as `issuerQualification`
on `VerifiedCredential` and `VerifiedMdoc`, and as `qualification` on
`ResolvedIssuer`:

```ts
const result = await verifySdJwtVc({ credential, anchors, keyBinding });
if (result.verified) {
  result.issuerQualification?.qualifiers; // ['…/QCForESeal', '…/QCWithQSCD']
  result.issuerQualification?.serviceInformation; // ['…/ForeSeals']
}
```

**Derived, never enforced.** Whether an issuer must hold a qualified certificate
for electronic seals is a policy, and policies belong to the caller — the same
relation `requiredExtendedKeyUsage` has to Extended Key Usage. `NotQualified` in
particular is *not* a rejection here: an EUDI PID Provider need not be a QTSP and
most are not, so reading eIDAS qualification as a precondition for issuing a PID
would refuse most of the ecosystem this library exists to verify. Note the two
kinds of silence, which a caller must keep apart: `undefined` means no list was
consulted — a pinned anchor, or a service publishing no extensions — while an
empty `qualifiers` array means the rules were evaluated and none matched.

**A critical extension this project cannot process costs the service its place
as an anchor.** §5.5.9 makes `Critical="true"` the member state saying the entry
may not be used without understanding the extension, which is the same statement
RFC 5280 §6.1.4 (o) makes about a certificate, so it gets the same answer:
`RECOGNISED_SERVICE_EXTENSIONS` is the set this project claims to read, and a
critical extension outside it drops the entry. So does an extension inside it
that cannot be read, and so does a `CriteriaList` carrying no criteria — vacuous
truth is the trap there, since `assert="all"` over nothing is satisfied by every
certificate in existence, and there is no safe direction to guess in when
qualifiers both grant and take away.

Measured on 2026-08-14 across all 30 reachable lists and 10010 service entries:
**half of everything published is critical** — 3810 `AdditionalServiceInformation`
and 1195 `Qualifications` — and turning the rule on **costs no anchors at all**,
because every critical extension published is one of the four now processed. The
one unrecognised extension on any list, Slovakia's own, is published
non-critical, which is its author saying it may be ignored. All three `assert`
values, nested criteria lists, and all four criterion kinds occur in live rules;
see REPRODUCE.md, and `ecosystem-drift.test.ts` re-measures both numbers against
the library's own set each run.

### What the trust list signature covers

An XML signature covers a *reference*, not a file, and every parser here reads
the list by XPath from the root. Those are two different documents whenever a
reference covers less than the whole, and the gap between them is **XML
Signature Wrapping**: leave a genuinely signed subtree untouched so the
signature still verifies, nest it inside a new root, and add a `TSPService` of
your own outside it. `//tsl:TSPService` finds both. The attacker's service
certificate becomes a trust anchor without anyone signing it.

`xml-crypto`'s `checkSignature` does not close this, and does not claim to: it
proves the references are intact and that `SignedInfo` is signed, never which
element they covered. Nor is the attack remote here — a national list may be
fetched over plain http (see below), so rewriting the envelope around a
signature that cannot be forged is precisely the move an on-path attacker has.

So `verifyTrustList` **returns the octets the signature covered** — xml-crypto's
`getSignedReferences()`, populated only on the success path — and everything
downstream parses that rather than what was fetched. Freshness, pointers and
services are all read from the signed content, so material outside the signature
is not merely distrusted, it is absent. A signature that covers no
`TrustServiceStatusList` at all — over the header alone, say — is refused rather
than treated as covering the list it sits in.

Callers using `parsePointers`, `parseTrustServices` or `parseServiceCertificates`
directly must pass that return value for the same reason; `fetchTrustAnchors`
already does.

### What a trust list may not make the parser do

The same reasoning one layer down. Wrapping is about which part of a document is
read; this is about what merely *parsing* one is allowed to cost, and it has the
same premise — a national list may arrive over plain http, so an on-path
attacker chooses the bytes.

XML's three classical answers all begin in a document type declaration: an
internal entity that expands until memory runs out (`&l4;` referring to ten
`&l3;` and so on down), an external entity that reads `file:///etc/passwd` into
the element a `TSLLocation` was about to be read from, and an external DTD that
turns a parse into an outbound request to whoever wrote the list.

`@xmldom/xmldom` 0.9 does none of it — it expands no entity at all and
dereferences no identifier, leaving `&x;` as three characters of text — so none
of these is reachable through it today. That is a property of a dependency, of
the kind a minor release changes without saying so. `parseXml` in
`src/trust/lotl.ts` is therefore the only way a trust list becomes a document
here, and it **refuses a declaration that carries an internal subset or an
external identifier** before anything else looks at the document — including
before the signature is checked, since `xml-crypto` parses the string again with
a parser this project does not configure. An entity cannot be declared without
one or the other, so refusing both is the whole of it, and a trust list needs
neither: no live list carries a declaration, which `test/ecosystem-drift.test.ts`
measures rather than assumes. A bare `<!DOCTYPE TrustServiceStatusList>`
declares nothing and is left alone; the five entities XML defines itself
(`&amp;` and its siblings) need no declaration and are unaffected.

The declaration is read off the parsed tree, not matched in the string — a
`<!DOCTYPE` inside a comment or a CDATA section is character data, and a regex
cannot tell the difference.

`parseXml` also passes its own error handler, because xmldom's default writes
non-fatal parse errors to `console.error` and **the library logs nothing** — an
undeclared entity reference is enough to put a string the attacker composed into
an operator's log from a code path with no business logging at all.
`test/xml-entities.test.ts` pins each of these separately: what this library
refuses, and what the parser underneath happens not to do.

### Trust list freshness

A signature says *who* wrote a list, never *when*. Every list here is fetched
from a location named by another document, and a national list may arrive over
plain http (Slovakia publishes one), so a signed copy from last year verifies
exactly as well as today's — while still granting every service withdrawn since,
which is the point of withdrawing them. Nothing about a valid XML signature
distinguishes the two.

TS 119 612 §5.3.13 gives each list a `ListIssueDateTime` and a `NextUpdate`, and
`checkTrustListFreshness` treats them exactly as `revocation.ts` treats a CRL's
`thisUpdate` and `nextUpdate`:

- **Past `NextUpdate`** — refused. The replay window becomes the publisher's own
  republication interval instead of forever. Measured on 2026-08-12: every live
  list republishes on a six-month cadence (median 183 days from issue to next
  update), and none was overdue.
- **No `NextUpdate` at all** — refused, because there is then nothing to bound
  freshness with. Measured cost: **one list**, the United Kingdom's, which
  declares an empty `<NextUpdate/>`, was issued `2020-12-31T22:59:59Z` and has
  not moved since withdrawal from the EU. A list nobody maintains is the case
  this rule is for.
- **Issued in the future** — refused.

A lapsed *national* list costs that territory its anchors and nothing else; it
is reported in `failures`, never dropped silently. A lapsed **LOTL** fails the
whole fetch before its pointers are read, because a stale root names both where
the national lists live and which certificates authenticate them.

`TrustListResult.validUntil` carries the earliest `NextUpdate` across every list
used, because a service holding an anchor set between refreshes needs the same
answer: past that instant, what is in memory is precisely the stale copy this
check refuses on the way in. The demo app uses it to answer `503` at
`POST /presentations` rather than let verification fail — anchors we can no
longer confirm produce a rejection that reads as "your credential is not
trusted", which blames the holder for our own housekeeping.

Not covered: replay of an older but *still fresh* list. Catching that means
remembering the highest `TSLSequenceNumber` per list across restarts, which is
persistent state the library deliberately does not hold.

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
that reaches the trust code — and both check the MSO's status reference against
the same Token Status List code, on by default and failing closed. See
[Revocation](#revocation).

A DeviceResponse carries two independent signatures. **issuerAuth** proves the
issuer attested the claims; **deviceSignature** proves the wallet holds the key
the issuer bound them to, and produced this response for *this* request. The
second is why a stolen credential is not enough: it signs a
`DeviceAuthentication` structure containing the OID4VP session transcript, which
commits to our client identifier, nonce and response URI. Tests assert that a
response replayed at another verifier, bound to a nonce we never issued, or
signed by a different key, is rejected.

Three things the real reference credential taught us, all pinned by tests:

- **Its MSO carries a status reference**, `status.status_list`, pointing at
  `issuer.eudiw.dev/token_status_list/...` — and an `identifier_list` beside it.
  So an mdoc verifier that skips revocation is not making a theoretical
  omission; it is ignoring something this issuer actually publishes.

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

A credential's status reference names a URI and an index; the URI serves a
signed token holding a bitstring, and the bit at that index says whether the
credential is still valid. The EU reference issuer publishes one for every PID,
**in both formats** — `status.status_list` in the SD-JWT VC's claims, the same
structure in the mdoc's MobileSecurityObject. Both are checked, by the same code
in `src/trust/status.ts`, on the same terms. The format a wallet happens to
answer in does not decide whether revocation is checked.

`@sd-jwt/sd-jwt-vc` drives the SD-JWT VC flow but leaves fetching **and
verifying the list's own signature** to the relying party — it refuses to
proceed without a `statusVerifier`, which is the right call: an unauthenticated
status list would let anyone who can answer an HTTP request declare a revoked
credential valid. On the mdoc side nothing drives anything, so `checkStatusList`
is the whole check in one call. Four things are established before a bit is read:

- **The signature**, with the list's `x5c` chained to the same trust anchors as
  the credential.
- **`typ` is `statuslist+jwt`**, so a credential cannot be replayed as its own
  status list.
- **`sub` is the URI the credential named.** The signature alone only proves
  that *a* trusted issuer produced *a* status list. Without this, anyone able to
  answer at that URI — a redirect, a hijacked name, a stale cache — can
  substitute another list that the same anchors validate, and we index into it.
- **It has not expired.** Checked against the same clock and skew as the
  credential, and re-checked on a cache hit, because a token cached while fresh
  can expire before its cache entry does.

**It fails closed.** An unreachable or unverifiable status list is
`STATUS_UNAVAILABLE`, not a pass — a verifier that accepts what it could not
check has no revocation at all. So is an index past the end of the published
list, and so is a `status` element offering only a mechanism we do not implement:
the EU reference issuer's mdoc also carries an `identifier_list`, which is not
implemented, and an issuer who told us how to revoke in terms we cannot read has
not told us the credential is valid.

Status lists cover many credentials, so pass a shared `statusCache`
(`createStatusListCache()`) in anything serving traffic; without one every
verification refetches the same document. Concurrent misses on the same URL
collapse into a single fetch, and a *failed* fetch is remembered for 30 seconds
— verification still fails closed either way, but without that the issuer's
outage becomes one here, at one full timeout per credential.

### Certificate revocation: CRL and OCSP

The status list above revokes a **credential**. This revokes the **certificates
that signed it** — a different question, and neither substitutes for the other.
A credential can be withdrawn while its issuer is impeccable, and an issuer's
key can be compromised without any individual credential being withdrawn.

`src/trust/revocation.ts` checks every certificate in the resolved path except
the anchor, each against the certificate above it. A self-signed anchor cannot
meaningfully revoke itself; its withdrawal is expressed by leaving the trusted
list, which the refresh picks up.

**It is a separate step from path validation, and has to be.** Path validation
is synchronous — `@sd-jwt`'s `statusVerifier` is a `(data, signature) => boolean`
callback with nowhere to await — while revocation needs the network. So
`resolveIssuerCertificateChain` establishes the chain and the check runs against
the chain it returned, which is also what guarantees it checks what was actually
trusted rather than re-deriving it.

**OCSP is preferred, CRL is the fallback.** An OCSP response is one
certificate's status now; a CRL is every revocation the CA has ever issued, and
is correspondingly staler and larger. If the responder cannot be reached the CRL
is still tried — two mechanisms being down is a different situation from one.

Both documents are authenticated before anything is read out of them:

- **The signature**, against the issuing CA. For OCSP that may instead be a
  delegated responder, which must be signed by the same CA *and* carry the
  `id-kp-OCSPSigning` extended key usage — without that check, any certificate
  the CA ever issued could answer for every certificate the CA ever issued.
- **Freshness.** A CRL past its `nextUpdate` is refused, and so is one that
  states no `nextUpdate` at all: a document whose freshness cannot be bounded is
  indistinguishable from a replayed copy from any point in the past. Same for an
  OCSP response past its `nextUpdate`. This is what makes it safe for a CRL
  distribution point to be plain `http:`, as most are — the CA's signature makes
  forgery impossible and `nextUpdate` bounds the replay window.

**It fails closed** (`ISSUER_REVOCATION_UNAVAILABLE`), like the status list. An
OCSP `unknown` is *not* a clean bill of health and counts as unavailable. The
one case that is not fail-closed is a certificate publishing neither a CRL
distribution point nor a responder: a CA that published nothing has not told us
something we are ignoring, so there is nothing to check and the path passes.

Measured against the EU reference infrastructure on 2026-08-12: both the PID
document signer and its CA publish a CRL over https — 457 bytes, ECDSA-signed,
`nextUpdate` two days out — and **neither runs an OCSP responder**; the leaf's
AIA carries `caIssuers` only. So CRL is the mechanism that is exercised against
real infrastructure, and OCSP is exercised only against fixtures. Its `CertID`
construction (RFC 6960 §4.1.1) is pinned byte-for-byte against OpenSSL by
`scripts/check-ocsp-certid.sh`, because a fixture written by the same hand as the
verifier would otherwise agree with it about a mistake. See REPRODUCE.md.

Pass a shared `revocationCache` (`createRevocationCache()`) in anything serving
traffic: a CRL covers every certificate its CA ever issued, so refetching it per
credential is the difference between one request and one per holder.

### Bounding a whole verification

Every outbound request below has its own deadline. That bounds a *request*, and
a verification is not one: it can fetch a status list, then a CRL or an OCSP
round trip for each certificate in the chain, in sequence. Ten seconds each is
not ten seconds, and under load the number that matters is the total.

So `verifySdJwtVc`, `verifyMdoc`, `verifyDeviceResponse` and
`verifyPresentationResponse` all take a `signal`. `AbortSignal.timeout(ms)` is
the deadline; anything else that aborts is cancellation — a client that hung up,
a shutdown, work nobody is waiting for. It is combined with each request's own
timeout rather than replacing it, so neither bound is lost.

An abort is `VERIFICATION_ABORTED`: a rejection like any other, not a thrown
`AbortError`, so it fails closed and cannot be caught somewhere that treats a
throw as "carry on". It is kept distinct from `STATUS_UNAVAILABLE` and
`ISSUER_REVOCATION_UNAVAILABLE` because those say an endpoint did not answer,
and reporting our own deadline as one of them sends an operator to look at an
issuer that was answering fine. Which of the two it is comes from the signal's
state, never from the shape of the error.

**A cancellation is never remembered as an outage.** The status and revocation
caches remember failures — deliberately, so an endpoint that is down does not
cost a full timeout per credential — and an abort recorded there would be
served to *other* callers for the error TTL, turning one client's timeout into
everybody's. Aborts are evicted rather than cached, and a test pins both halves:
that the abort is not remembered, and that a real failure still is.

The demo sets `VERIFICATION_TIMEOUT_MS` (30 s) per presentation. It deliberately
does not abort when the wallet's connection drops, which looks like the obvious
thing to do: under `direct_post` the browser is polling for the same outcome, so
discarding the work would leave the session unanswered until it expired.

One thing this does not cover: `fetchTrustAnchors` takes no signal, so a trust
list refresh cannot be cancelled. It is a startup and background operation
rather than part of a verification, and it reports per-list failures rather than
an outcome, so a signal there would need a different shape than the one this
section describes.

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
| `allowedProtocols` | `https:` only | Checked on every hop, so a redirect cannot walk off TLS. **Exception:** national trust lists also accept `http:`, because Slovakia publishes over it and the list's authenticity comes from an XML signature made with a certificate the (https, signed) LOTL published for it. The residual risk is replay of an older signed copy, which may still grant a since-withdrawn service. The LOTL itself stays https-only: it is where both the locations and the signing certificates come from. |

## Using it in a service

The library is deliberately inert: it reads no configuration, opens no ports and
logs nothing. Four things are worth passing in anything serving traffic.

```ts
const result = await verifySdJwtVc({
  credential, anchors, expectedVct: 'urn:eudi:pid:1', keyBinding,

  statusCache,                          // shared; see Revocation above
  allowedAlgs: ['ES256', 'PS256'],      // policy, checked against the token's alg
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

The same pressure shows up in *where* a check runs, not just how it reports.
`@sd-jwt/core` validates the status list token's `exp` itself and throws before
it calls our `statusVerifier`, so an expiry check made in that callback would
never run — and a stale list would be reported as a malformed credential,
blaming the holder for the issuer's housekeeping. Everything that binds a status
list to the credential and to now is therefore checked in the *fetcher*, which
the library calls first. A test pins the resulting code.

**Events carry no personal data by construction** — no claim values, no subject
identifiers, no credential bytes. A test asserts it. An audit trail that quietly
accumulates dates of birth is worse than none.

Two further rules make the trail worth keeping.

**Both credential formats emit the same stream.** `verification.started`,
`issuer.resolved`, `status.checked`, `issuer.revocation.checked` and a verdict,
whether the wallet answered in `dc+sd-jwt` or `mso_mdoc` — the same reasoning
that stops the format deciding whether the credential's status is checked. Each
event names its `format`, because the two prove holder binding by different
means and a mixed stream would otherwise be ambiguous. The one asymmetry is that
`verification.started` cannot name the credential type for mdoc: the doc type
lives inside the signed Mobile Security Object and is unreadable until the
issuer signature has verified. It appears on `verification.accepted` instead.

**Exactly one `verification.accepted` or `verification.rejected` per
verification, and the outermost verifier owns it.** A credential can verify
perfectly and still be rejected afterwards — by a predicate, or by mdoc device
authentication, neither of which the inner verifier knows about. So
`verifyAgeOver18SdJwtVc`, `verifyDeviceResponse` and `verifyPresentationResponse`
withhold the verdict until it is one, letting every intermediate event through
in the meantime. Without that the trail records an acceptance for a presentation
the caller was told to reject, which is the single claim it exists to make.

`verifyPresentationResponse` is the case that makes the rule load-bearing rather
than tidy: it can verify several credentials for one query, so one verdict per
credential would report acceptances nobody was given. `credentialTypes` is a
list for that reason, and `format` is undefined only when the set spans both
formats. `verification.accepted` also carries `evidence` when a predicate
supplied one — for the age predicate, which of the two ways it was satisfied,
and therefore whether the holder disclosed a boolean or a full date of birth. An
envelope rejection, where the wallet declined before any credential was seen,
has no `format` at all rather than a guessed one.

`app/audit.ts` is a worked example: the demo turns the events into one JSON
object per line, binding each to the presentation id — the library has no notion
of a session, so correlation is the application's to add, and without it two
holders presenting at once produce a trail nothing can be read out of. It also
logs what the library never sees: that a presentation was requested, and the
`SESSION_UNKNOWN` rejections the server makes before any verifier runs. A real
round trip against the reference issuer's credential looks like this:

```json
{"at":"…","presentation":"04cb0a12-…","type":"presentation.requested","vct":"urn:eudi:pid:1","clientIdPrefix":"redirect_uri"}
{"at":"…","presentation":"04cb0a12-…","type":"verification.started","format":"dc+sd-jwt","credentialType":"urn:eudi:pid:1"}
{"at":"…","presentation":"04cb0a12-…","type":"issuer.resolved","format":"dc+sd-jwt","subject":"CN=PID DS - 002…","chainLength":2}
{"at":"…","presentation":"04cb0a12-…","type":"verification.accepted","format":"dc+sd-jwt","credentialTypes":["urn:eudi:pid:1"],"evidence":"birthdate","durationMs":14}
```

`evidence: "birthdate"` is the privacy fact worth having in a record: the
current reference PID carries no age attribute, so proving 18-or-over meant the
holder disclosing a full date of birth. Note that every field of every event is
logged verbatim — the application does not filter, because "carries no personal
data" is the library's guarantee and is tested there, and re-deciding it in the
consumer is how a tested guarantee turns into an assumed one.

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
   is why `verifySdJwtVc` throws rather than defaulting.
3. **`xml-crypto` ships neither RSASSA-PSS nor ECDSA.** Several member states
   sign their trust lists with one or the other — Germany's is
   `sha256-rsa-MGF1`, Greece and Slovenia use `ecdsa-sha512`, Hungary
   `ecdsa-sha256` — so without the implementations in `src/trust/lotl.ts` those
   lists fail to verify and their anchors are silently absent. The ECDSA half
   turns on one detail: XMLDSig carries the signature as the raw r‖s pair
   (RFC 4051 §2.3.6), while Node produces and expects DER unless told otherwise.

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
  client id, `direct_post`. This project implements the **PID** in both formats;
  that profile's doctype is not implemented. Note that the PID mdoc carries no
  `age_over_18` either (REPRODUCE.md section 7), so the flat boolean the AV
  profile defines is not reachable through the PID in *either* encoding.
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

Serverless platforms (Netlify, Vercel, Lambda), and any deployment running more
than one instance, need a shared session store: the default keeps sessions in a
`Map`, so an ephemeral function would answer every presentation with
`SESSION_UNKNOWN`. `SessionStore` in `app/http/session.ts` is the interface to
implement, and `createVerifierServer` takes one — the in-memory implementation
is a default, not a hard-coded dependency.

Three properties of that interface are the contract, not incidental to it:

- **Every operation is asynchronous**, reads included. A synchronous interface
  would be implementable over a `Map` and over nothing else.
- **`Session` is JSON-serialisable**, which is why `decryptionJwk` is a JWK
  rather than a `KeyObject`. Note what that implies: a store outside the process
  holds ephemeral response-decryption keys, so it is secret material at rest.
- **`claimByResponseId` is atomic.** An OID4VP `nonce` is single use, and the
  response URI is retired in the same step that hands over the session — so two
  wallet posts arriving while the first verification is still fetching a status
  list cannot both be verified. Over Redis that is one `GETDEL`, not a get and a
  later delete. The interface deliberately offers no plain `getByResponseId`,
  because an implementation that did would let a caller reintroduce the gap.

Three things to expect on a fresh deployment:

- **`TRUST_MODE=pinned` with the demo anchor rejects every real credential** with
  `ISSUER_UNTRUSTED`. That is correct behaviour — the fixture CA is a throwaway.
  Point `TRUST_ANCHORS_FILE` at the issuer's real anchor, or switch to `lotl`.
- **Fly's trial plan stops machines after 5 minutes**, regardless of
  `auto_stop_machines = 'off'`. They restart on the next request, but in-memory
  sessions do not survive. Add a card, or expect to restart a check that sat
  idle.
- **Run exactly one machine.** With the default in-memory store and two
  machines, the wallet's POST and the browser's poll land on different instances
  about half the time and the page shows `SESSION_EXPIRED` for a session that
  exists. `min_machines_running = 1` is a floor, not a cap — `fly launch`
  provisions two by default, so run `fly scale count 1`. Scaling out needs an
  implementation of `SessionStore` that both machines share.

## What is proven against real infrastructure

Every claim below is reproducible, and [REPRODUCE.md](REPRODUCE.md) says exactly
how — with the dates, versions, endpoints and configuration that produced it,
and an explicit list of what was *not* done.

Several of those claims are *measurements* rather than reasoning — "failing
closed on an unimplemented Name Constraint form costs nothing", "requiring
`StatusStartingTime` loses nothing" — and a measurement goes stale silently.
`test/ecosystem-drift.test.ts` re-checks them against the live deployment every
week, and fails with what changed and what to update. A failure there means
nothing in `src/` is broken and the EU has moved: a rotated CA, a stale CRL, an
OCSP responder appearing. Some of those would be good news, and a red build is
still the only way to hear it.


- **A genuine EUDI credential verifies.** `test/real-credential.test.ts` runs
  the full credential path — `x5c` resolution, chain to the real
  `PID Issuer CA - UT 02`, issuer signature, disclosure resolution, predicate —
  against a `urn:eudi:pid:1` issued by `backend.issuer.eudiw.dev`.
- **The EU trust lists parse and verify.** `RUN_NETWORK_TESTS=1 npm test`.
- **The EUDI reference wallet presents to this verifier, in both formats.**
  2026-08-11 as `dc+sd-jwt` and 2026-08-13 as `mso_mdoc`, over a public
  deployment with a registered access certificate, both verified 18-or-over from
  a PID issued by `CN=PID DS - 002`. Unlike the credential above — fetched by
  driving OID4VCI directly — these came through a wallet, so the SD-JWT one
  carries a Key Binding JWT and the mdoc one a device signature over the
  SessionTranscript. The same query offered both alternatives each time; which
  arrived was the holder's choice in the wallet's credential picker, not a
  configuration change. The mdoc run also checked the live status list and the
  CA's CRL, both on by default, and was the first live exercise of the RFC 5280
  §6.1.4 (o) critical-extension rule. See [REPRODUCE.md](REPRODUCE.md) sections 6
  and 7 for the configuration, the audit trail, and the three defects the two
  runs exposed.

**Fetch your own credential and check it**: `npm run fetch-credential -- sd-jwt`
drives the OID4VCI flow against `issuer.eudiw.dev` and writes a real credential
you can verify with this library.

One caveat on both results, and it is the substantive finding. The evidence was
`birthdate`, not an age boolean: PID Rulebook v1.1 removed the age attributes
per CIR 2024/2977, so the holder disclosed a full date of birth. That is true in
**both** encodings — the reference PID carries no age attribute as SD-JWT VC and
none as mdoc either, so choosing the mdoc credential does not avoid it. Easy to
assume otherwise, because the EU's dedicated Age Verification profile is
mdoc-only and does define a flat `age_over_18` (see "Open questions"); the PID
is not that profile. Asking "is this person 18" against a current reference PID
costs you their date of birth whichever format answers.

To repeat it: run `npm run register-rp`, complete the registration chain it
stops at, and configure `CLIENT_ID_PREFIX=x509_hash` — the issued certificate
carries a URI SAN rather than a dNSName, so `x509_san_dns` will not work. Point
`TRUST_ANCHORS_FILE` at `anchors/eudiw-pid-issuer-ca.pem`, set
`BASE_URL` to your public URL, and `WALLET_SCHEME` to `eudi-openid4vp://`.
Which format you get is then chosen in the wallet: it offers both credentials it
holds and you pick one. Nothing in the request needs changing to exercise either
path.

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

That is also why the script issues a synthetic **mdoc**, alongside the real one
in `test/fixtures/real/`. Proving that a revoked mdoc is rejected needs a status
list the credential's own issuer signed — and the real credential's issuer is
the EU reference CA, whose key we obviously do not have. The synthetic pair is
the only way to test both answers offline.

## Security

Test key material is committed on purpose and protects nothing; the known gaps
are listed in [SECURITY.md](SECURITY.md) and under "Spec-compliant vs
simplified" above. This is a reference implementation, not production software.

## Licence

Copyright 2026 Sebastian Wiese-Wagner.

Apache License 2.0 — see [LICENSE](LICENSE). All dependencies are permissive
(Apache-2.0 or MIT) and compatible; they are listed in [NOTICE](NOTICE).
