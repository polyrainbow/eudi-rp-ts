# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

There is **no build step for development** — Node 22.18 or newer runs the `.ts` files directly via
unflagged type stripping. `npm run build` exists only to produce `dist/` for npm publication.

```bash
npm test                                  # node --test over test/**/*.test.ts, fully offline
node --test test/verify.test.ts           # a single file
node --test --test-name-pattern='nonce' test/verify.test.ts   # a single test
RUN_NETWORK_TESTS=1 npm test              # also hits the live EU trust lists and status lists
npm run typecheck                         # tsc --noEmit over src, test, scripts
npm run build                             # tsc -p tsconfig.build.json -> dist/ with declarations
npm run check:package                     # assert the publish tarball ships dist/ and no key material
npm start                                 # the demo app on :3000 (see README for env vars)
npm run fixtures                          # regenerate test/fixtures/ (output is committed)
npm run access-cert -- verifier.example.org   # dev access certificate into config/
npm run fetch-credential -- sd-jwt        # drive OID4VCI against the EU reference issuer
```

`config/`, `out/` and `dist/` are gitignored; `test/fixtures/` is committed on purpose.

`anchors/` holds committed **public** certificates that deployments point
`TRUST_ANCHORS_FILE` at, and is the only non-code directory the Dockerfile copies
into the runtime image. Nothing under `test/` may be referenced by a deployment
config or by the image — that is how throwaway private keys ended up shipping
once already. Private key material belongs in `config/`, which is gitignored.

## Architecture

`src/` is the library, `app/` is a demo that consumes it. The boundary is load-bearing:
**the library reads no configuration, opens no ports and logs nothing.** `app/config.ts` is the
only file outside `scripts/` that touches `process.env`. Do not introduce env reads, `console.*` or
ambient state into `src/`.

`src/index.ts` is the public API surface. Anything not exported there is a deep import and not
covered by the version contract.

**The library asks no question of its own.** `buildAuthorizationRequest` takes a DCQL query and
`verifyPresentationResponse` reads that query back off the request payload to decide what the
answer must satisfy — the formats that may answer, each one's `vct` or doc type, which
combinations of credentials are enough, and what `vp_formats_supported` advertises. `src/presets/`
holds one question asked one way (`ageOver18Query` + `ageOver18Predicate`, and the PID's
identifiers) and nothing in the verification path imports it. This was not always true:
`request.ts` used to build the age query itself and `response.ts` dispatched on two constants
naming its credential query ids, so a second query could be sent but never verified. A new
question is a query and a predicate in `src/presets/`, never an edit to `oid4vp/`.

`src/oid4vp/transaction-data.ts` applies the same rule to what a request *authorises* (OID4VP 1.0
§5.1, §8.4). A transaction data **type** is defined outside the specification, so the library
defines none and holds only what is not type-specific: encoding the entries onto the request,
reading them back off it, and the §B.3.3 hash profile. Three things there are load-bearing. The
hash covers the base64url string **as sent**, so `verifyPresentationResponse` reads the strings
back off `requestPayload` rather than re-encoding the objects — the same reason it reads the query
back, and re-encoding would compare against something the wallet never saw. `sha-256` is the
default on each side independently, so a request naming an algorithm and a response naming none
disagree. And mdoc has no fixed location for the hashes: §B.2.1 leaves the data element to the
type, so the caller passes `mdocTransactionData` and a type missing from it **fails closed** —
being unable to look is not evidence that the holder agreed.

### Two verification layers, kept apart

`src/oid4vp/response.ts` is where they meet:

1. **Protocol envelope** — `@openid4vc/openid4vp` handles JARM decryption, response shape, and
   DCQL matching. It says *the wallet answered the question we asked*.
2. **Credential** — `src/verify.ts` (SD-JWT VC) or `src/mdoc/device-response.ts` (mdoc) handles
   issuer trust, signature, disclosures, holder binding. Only this says *the answer is backed by a
   credential we trust*.

Both formats funnel into the same `TrustAnchors` and the same path validation. The only difference
that reaches the trust code is that mdoc carries its chain in a COSE `x5chain` header rather than a
JOSE `x5c`.

A third layer sits on top and belongs to the caller: `PresentationPredicate`, a rule over the
verified set, evaluated before the verdict. Layer 1 says *the wallet answered the question we
asked*, layer 2 *the answer is backed by credentials we trust*, the predicate *the answer means
what we needed*. It takes the whole set rather than one credential, because a query offering two
formats is answered by either and a query asking for two credentials is answered only by both.

`verifyPresentationResponse` also decides whether the response answers the query at all
(`unsatisfiedRequirement`, OID4VP 1.0 §6.4.2) and whether it answers *more* than the query needed
(`redundantCredential`) — both before any credential is verified, since both are properties of
which `vp_token` keys arrived. The second is the general form of a check that used to read
"answers both credential queries; expected one": a credential the query offered an alternative to
is one the verifier had no basis to receive, and verifying it is the act of collecting it.

Per credential, and only after it verifies, `unsatisfiedClaims` (`oid4vp/claims.ts`) checks that
what was disclosed is what the Credential Query asked for — §6.4.1 for `claims` and `claim_sets`,
§6.3 for `values` — and rejects with `REQUESTED_CLAIMS_MISSING`. The age predicate used to cover
this by accident, being the only thing that noticed a missing claim; a caller with no predicate got
`verified: true` beside an `undefined` claim. `REQUESTED_CLAIMS_MISSING` is deliberately not a
`PREDICATE_*` code: one says the wallet answered something else, the other that the answer arrived
and the caller's rule said no.

`selectClaims`/`readClaim` in the same file walk a DCQL claims path (§7) over either format, which
is what `PresentedCredential.claims` keeping each format's own structure is for: §7.2 makes an mdoc
path `[namespace, element]`, so a two-step walk over the namespace map is the whole mapping.

### Reason codes are derived from state, never from error text

Every rejection path ends at exactly one `ReasonCode` (`src/result.ts`), returned as
`Outcome<T> = Verified<T> | Rejected`. Nothing may infer a reason by matching a dependency's error
message — that broke once already, silently turning `STATUS_UNAVAILABLE` into
`CREDENTIAL_MALFORMED`. Distinctions are either checked explicitly before the library runs, or
recorded by a callback: see the three-state `SignatureState` (`untested` / `ok` / `bad`) and
`mapLibraryError` in `src/verify.ts`, and `status.outcome` in `src/trust/status.ts`. Adding a new
failure mode means adding or reusing a code, not a new error string.

### What the dependencies do not do (and why `src/trust/` exists)

- `@sd-jwt/*` never resolves issuer keys — its verifier callback is `(data, sig) => boolean`.
  `src/trust/issuer-key.ts` is that missing half: x5c resolution plus path validation.
- Node's `X509Certificate` reaches four of the extensions RFC 5280 §6.1 turns on and no more —
  `.ca`, `.keyUsage` (which is the *extended* one), the names. The KeyUsage bit string, Name
  Constraints, the certificate policy extensions and `pathLenConstraint` are all read out of the
  DER by `key-usage.ts`, `name-constraints.ts`, `policies.ts` and `basic-constraints.ts`. The
  §6.1 policy state machine on top of them is `policy-tree.ts` — a tree and three counters,
  because "is this policy asserted" is not the question a policy answers.
  `critical-extensions.ts` is the inverse of all of them: not "does the certificate satisfy this"
  but "was anything on it left unread" (§6.1.4 (o)). Its `RECOGNISED_CRITICAL_EXTENSIONS` set is
  the security-relevant part — every OID on it asserts that code elsewhere acts on that extension,
  so adding one without the processing silently reopens the hole. A test pins the set for exactly
  that reason. `service-extensions.ts` is the same inversion one level up, over a trust list's
  own §5.5.9 extensions rather than a certificate's: `RECOGNISED_SERVICE_EXTENSIONS` carries the
  identical promise, and a service publishing a critical extension outside it is dropped rather
  than loaded as an anchor.
- A trusted list's `Qualifications` (the "Sie") is a **rule set over the certificates a service
  issues**, not a property of the service — so it is evaluated per end-entity certificate and
  cannot be reduced to a flag on the anchor. `TrustAnchors.qualify` derives it; the answer reaches
  the caller as `issuerQualification` on both formats' results and `qualification` on
  `ResolvedIssuer`. **Derived, never enforced**: `NotQualified` is not a rejection, because an
  EUDI PID Provider need not be a QTSP. Two kinds of silence, and they must stay apart —
  `undefined` is "no list was consulted", an empty `qualifiers` array is "the rules were evaluated
  and none matched".
- `@sd-jwt/*` requires the KB-JWT `aud` to exist but never compares it to the verifier's own
  identifier. `src/verify.ts` checks it explicitly, twice (before and after library verification).
  Key binding is verified only when a nonce is supplied, which is why `verifySdJwtVc` throws
  rather than defaulting `requireKeyBinding`. It also surfaces the KB-JWT's transaction data
  claims on `VerifiedKeyBinding`, read from the payload the library *verified* rather than from
  the unverified decode above it — a hash nobody's key signed authorises nothing.
- `@openid4vc/openid4vp` parses `transaction_data` and ships a `verifyTransactionData`, but does
  not call it during response validation and cannot: its `credentials` argument is the hashes
  already extracted from each presentation, which is the half only a credential verifier can do.
  Same shape as the two gaps above it.
- `xml-crypto` ships no RSASSA-PSS, which several member states' trust lists use.
  `src/trust/lotl.ts` implements it. Its `checkSignature` also never says *which*
  element the signature covered — only that the references are intact — so
  verifying a document and then parsing that document are two different
  statements, and the gap between them is XML Signature Wrapping.
  `verifyTrustList` therefore returns the octets the signature covered
  (`getSignedReferences()`), and `fetchTrustAnchors` parses that rather than what
  it fetched. Anything reading a trust list must read the returned content: a
  new parse of the fetched XML reopens the hole silently, because the wrapped
  document verifies.
- `@xmldom/xmldom` expands no entity and dereferences no external identifier —
  today. That is the dependency's property, not ours, and `parseXml` is where it
  becomes ours: it is the only way a trust list becomes a document in
  `lotl.ts`, and it refuses a DOCTYPE carrying an internal subset or an external
  identifier, which is the only place an entity can be declared. It runs before
  the signature check, because `xml-crypto` parses the string again with a
  parser this project does not configure. It also supplies an `onError`, since
  xmldom's default writes non-fatal parse errors to `console.error` and the
  library logs nothing. A new `new DOMParser()` anywhere in `src/` gives both
  properties back.
- Status list fetching *and* verifying the list's own signature are the relying party's job.
  `src/trust/status.ts` chains it to the same anchors and **fails closed**.
- Nothing in the tree does CRL or OCSP. `src/trust/revocation.ts` implements both on
  `@peculiar/asn1-x509` and `@peculiar/asn1-ocsp` for the structures, `node:crypto` for the
  signatures. Note X.509 carries ECDSA as a **DER** sequence, the opposite of the raw r‖s that JWS
  and COSE use — the same trap as XMLDSig in `lotl.ts`, in the other direction.

### Deliberate simplifications

The gaps listed under "Spec-compliant vs simplified" in the README and in `SECURITY.md` are
decisions, not oversights: trust lists not fully TS 119 615 (service status history,
validity-time evaluation and §5.5.9 extensions *are* implemented, qualifiers included; what is
left to the caller is turning a qualifier into a verdict), the demo's default in-memory session
store, ES256 only. Path validation is no longer among them — it implements RFC 5280
§6.1 in full, Name Constraints, certificate policies, `pathLenConstraint` and §6.1.4 (o) included,
via `@peculiar/asn1-x509` for the DER while crypto stays on `node:crypto`.

Where RFC 5280 and RFC 5937 disagree about the trust anchor, this codebase follows 5937 and says
so: an anchor's Name Constraints, `policyConstraints`, `inhibitAnyPolicy` and `pathLenConstraint`
bind the path beneath it, while its own `certificatePolicies` are not read as the path's policy.
Constraints bind, assertions do not.

Don't quietly close one; if a change touches these, update the README section too.

Revocation is checked at two independent levels, and conflating them is a mistake worth naming:
`src/trust/status.ts` is Token Status List over the *credential*; `src/trust/revocation.ts` is CRL
and OCSP over the *issuer's certificates*. Both are on by default and fail closed. Certificate
revocation is a separate async step rather than part of path validation because
`resolveIssuerCertificateChain` must stay synchronous — `@sd-jwt`'s `statusVerifier` callback has
nowhere to await, so the check runs against the chain that call returned.

CBOR dates carry a type and it has to survive decoding. `cbor2` renders RFC 8943 tag 1004
(`full-date`, what ISO 18013-5 uses for `birth_date`) and tag 0 (`tdate`, `validityInfo`) alike as a
JS `Date`, which silently promotes a birth date to an instant at midnight UTC. `decodeCbor` in
`mdoc/cbor.ts` is the only decode entry point in the mdoc path for that reason, and passes its tag
decoders per call — `Tag.registerDecoder` is a global registry, and this library must not change
how CBOR decodes for everything else in the process.

Interop workarounds are named as workarounds and default to strict —
`tolerateMalformedMdocValidity` exists because the EU reference issuer emits a `validUntil` that is
not valid RFC 3339 (upstream issue #177).

### The demo's operational layer

`app/http/` carries what running the verifier needs and verifying a credential does not, and
each piece exists because its absence was a specific failure rather than a missing feature:

- **`SessionStore` is an interface; `MemorySessionStore` is one implementation.** Three
  properties make a remote implementation possible and are the contract: every operation is
  async (a sync interface is implementable over a `Map` and nothing else), `Session` is
  JSON-serialisable (which is why `decryptionJwk` is a JWK, and which means a shared store holds
  secret material at rest), and `claimByResponseId` is atomic. That last one is the single-use
  `nonce`: the response URI is retired in the same step that hands over the session, so two posts
  arriving during one verification cannot both be verified. Do not add a plain `getByResponseId`
  — it lets a caller reintroduce the gap.
- **Two limits that are different questions.** Per-client rate limiting (429) cannot bound what
  enough clients do; the shared session cap (503) cannot tell an abuser from a crowd. The cap
  refuses rather than evicting, because evicting lets a flood cancel the checks of people who
  scanned a code.
- **Liveness and readiness say different things.** `/healthz` stays 200 through stale trust
  anchors and shutdown, since restarting fixes neither; `/readyz` is where those show.
- **Trust list refresh backs off**, because the gap after a failure is time spent walking toward
  refusing all traffic once the lists pass `NextUpdate`.
- **SIGTERM drains**, because a severed verification cannot be retried — the wallet's nonce is
  already spent.

### Cancellation

`signal` on the verify options is the only bound on a *whole* verification — each fetch's
`timeoutMs` bounds one request, and a verification makes several in sequence (status list, then a
CRL or OCSP round trip per certificate). It is combined with the per-request deadline in
`fetching.ts` via `AbortSignal.any`, never substituted for it.

An abort is `VERIFICATION_ABORTED`, decided from `signal.aborted` and never from the error — the
same state-not-text rule as every other reason code — and kept distinct from `STATUS_UNAVAILABLE`
and `ISSUER_REVOCATION_UNAVAILABLE` because our deadline is not the issuer's outage. `StatusOutcome`
and `RevocationOutcome` each carry an `aborted` kind so the caller reads a recorded fact rather than
inferring one.

The trap worth knowing: both caches remember failures, so an abort stored there is served to every
*other* caller until the error TTL expires — one client's cancellation becomes everyone's outage.
`loadThroughCache` in `status.ts` and `load` in `revocation.ts` evict on abort for that reason, and
`test/cancellation.test.ts` pins both that the abort is not remembered and that a real failure still
is.

### Events

`src/events.ts` emits typed events and **carries no personal data by construction** — no claim
values, no subject identifiers, no credential bytes. `test/hardening.test.ts` asserts it. Keep new
event fields non-identifying. `transaction.authorised` is the case that shows where the line is:
it carries the transaction data `type` values, which this verifier chose before the wallet was
involved, and never the hashes or the data itself, which are a record of what somebody did.

Two invariants there, both pinned by tests in the same file:

- **The stream does not depend on the credential format.** SD-JWT VC and mdoc emit the same
  sequence, each event naming its `format`. Same rule as the status check in `response.ts`: what a
  wallet happens to answer in must not decide what the verifier can audit. A new emit point on one
  path needs its counterpart on the other.
- **The demo consumes them in `app/audit.ts`** — JSON lines on stdout, correlated by presentation
  id, which is the application's to add because the library has no notion of a session. It logs
  every event field verbatim on purpose: the no-personal-data guarantee is the library's and is
  tested there, so re-deciding it in the consumer would turn a tested property into an assumed one.
- **Exactly one verdict per verification, owned by the outermost verifier.** `verifySdJwtVc` and
  `verifyMdoc` are entry points *and* steps inside `verifyAgeOver18SdJwtVc`, `verifyDeviceResponse` and
  `verifyPresentationResponse`, each of which can still reject what the inner one accepted. The
  outer ones therefore wrap the sink in `withoutVerdict` and emit the terminal event themselves. Any
  new wrapper around a verifier has to do the same, or the trail records an acceptance the caller
  never got. `verifyPresentationResponse` is where the rule stops being tidiness: it verifies every
  credential a query asked for, so one verdict per credential would report acceptances the caller
  was never given. Hence `credentialTypes` is a list on `verification.accepted`, and `format` is
  undefined there only when the set spans both formats.

## Conventions

- Imports use explicit `.ts` extensions (`allowImportingTsExtensions`; the build rewrites them).
- `tsconfig.json` sets `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` and
  `verbatimModuleSyntax`. Optional properties are therefore passed with conditional spreads —
  `...(options.statusCache ? { statusCache: options.statusCache } : {})` — rather than
  `key: maybeUndefined`. Use `import type` for type-only imports.
- Comments in this codebase explain *why* — a spec section, a dependency's behaviour, a decision
  that looks wrong without context. Match that; don't add comments restating the code.
- Spec citations are precise (e.g. "OID4VP 1.0 §14.8", "RFC 9901"). Keep them accurate rather than
  approximate.
- **"Credential" is format-neutral, and no identifier may claim it for one format.** An mdoc is a
  credential; so is an SD-JWT VC. Anything handling exactly one of them says which —
  `verifySdJwtVc` / `verifyMdoc`, `evaluateAgeOver18SdJwt` / `evaluateAgeOver18Mdoc` — and the bare
  word is reserved for what genuinely spans both: the `CREDENTIAL_*` reason codes, `VerifiedCredential`,
  the glossary. This was not always true. `verifyCredential` took the general name when SD-JWT VC was
  the only format implemented and kept it after mdoc arrived, which left the same word meaning "either
  format" in the reason codes and "SD-JWT VC only" in the entry point beside them. A new format must
  not have to be told it is the exception.

## Tests

`node:test` with `describe`/`it` and `node:assert/strict`. Tests assert on `ReasonCode`, not on
message text. `test/wallet.ts` and `test/mdoc-wallet.ts` are simulated wallets that drive the full
round trip offline.

- Network tests are opt-in via a skip predicate:
  `describe('…', { skip: online ? false : 'set RUN_NETWORK_TESTS=1' }, …)`. They come in two
  kinds, and the distinction is load-bearing: most ask *does our code still work against live
  infrastructure*, where a failure is a bug; `test/ecosystem-drift.test.ts` asks *is REPRODUCE.md
  still true*, where a failure means nothing in `src/` is broken and the EU deployment has moved.
  Decisions justified by a measurement — Name Constraints "costs nothing today", requiring
  `StatusStartingTime` — belong there, or the measurement goes stale silently.
- Nothing in the default suite may touch the network. This has broken twice, both times passing
  for the wrong reason because the endpoint happened to answer; to check, run the suite with a
  `globalThis.fetch` that throws and confirm only `127.0.0.1` appears.
- `test/generic-query.test.ts` is the genericity test: every query in it is one no preset builds,
  driven end to end through `buildAuthorizationRequest` and `verifyPresentationResponse`. If a new
  question ever needs a change in `src/` to work, that file is where it should have been provable
  without one. `test/transaction-data.test.ts` is the same test for what a request *authorises* —
  every type in it is one nothing in `src/` has heard of — and it computes its hashes with
  `node:crypto` directly rather than with the library's own helper, so it cannot agree with the
  implementation about the detail §B.3.3 is easiest to get wrong.
- `test/serving.test.ts` covers the demo server's operational surface — limits, probes, the
  single-use response URI, shutdown — none of which is credential verification, which is why it
  needs tests of its own. It is also the only place that drives `installShutdownHandlers`, so it
  injects `exit` and `log` and removes its signal handlers afterwards; a test that let those
  defaults run would take the runner down with it.
- `test/fixtures/` is generated by `npm run fixtures` and signed by a throwaway CA — it proves the
  verification logic, nothing about EUDI interop.
- `test/fixtures/real/` holds genuine credentials from the EU reference issuer, **expiring
  2026-11-08** (SD-JWT VC) and **2026-11-09** (mdoc). Most assertions against them pin a fixed
  `now`, so they keep working past those dates; only the full round trip in
  `test/real-credential.test.ts`, which runs through the app server on the real clock, skips itself
  once the credential expires. `test/fixture-freshness.test.ts` exists so that skip is never
  silent: it reads both expiry dates out of the fixtures, warns within 30 days, and **fails** after
  them with instructions. When it goes red, nothing in `src/` is broken — the evidence has lapsed
  and the fixtures need refetching. Committed private keys there are throwaway and documented in
  `test/fixtures/real/README.md`.

## Documentation

`README.md` is the substantive document and is kept current with the code — behaviour changes
generally need a README edit in the same commit. `REPRODUCE.md` records exactly how every claim
about real EU infrastructure was produced (dates, endpoints, versions); any new such claim belongs
there. `GLOSSARY.md` defines the domain vocabulary.
