# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

There is **no build step for development** — Node 22.18+/24+ runs the `.ts` files directly via
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
only file in the repo that touches `process.env`. Do not introduce env reads, `console.*` or
ambient state into `src/`.

`src/index.ts` is the public API surface. Anything not exported there is a deep import and not
covered by the version contract.

### Two verification layers, kept apart

`src/oid4vp/response.ts` is where they meet:

1. **Protocol envelope** — `@openid4vc/openid4vp` handles JARM decryption, response shape, and
   DCQL matching. It says *the wallet answered the question we asked*.
2. **Credential** — `src/verify.ts` (SD-JWT VC) or `src/mdoc/device-response.ts` (mdoc) handles
   issuer trust, signature, disclosures, holder binding, predicate. Only this says *the answer is
   backed by a credential we trust*.

Both formats funnel into the same `TrustAnchors` and the same path validation. The only difference
that reaches the trust code is that mdoc carries its chain in a COSE `x5chain` header rather than a
JOSE `x5c`.

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
  that reason.
- `@sd-jwt/*` requires the KB-JWT `aud` to exist but never compares it to the verifier's own
  identifier. `src/verify.ts` checks it explicitly, twice (before and after library verification).
  Key binding is verified only when a nonce is supplied, which is why `verifyCredential` throws
  rather than defaulting `requireKeyBinding`.
- `xml-crypto` ships no RSASSA-PSS, which several member states' trust lists use.
  `src/trust/lotl.ts` implements it.
- Status list fetching *and* verifying the list's own signature are the relying party's job.
  `src/trust/status.ts` chains it to the same anchors and **fails closed**.
- Nothing in the tree does CRL or OCSP. `src/trust/revocation.ts` implements both on
  `@peculiar/asn1-x509` and `@peculiar/asn1-ocsp` for the structures, `node:crypto` for the
  signatures. Note X.509 carries ECDSA as a **DER** sequence, the opposite of the raw r‖s that JWS
  and COSE use — the same trap as XMLDSig in `lotl.ts`, in the other direction.

### Deliberate simplifications

The gaps listed under "Spec-compliant vs simplified" in the README and in `SECURITY.md` are
decisions, not oversights: trust lists not fully TS 119 615 (service status history and
validity-time evaluation *are* implemented; qualifiers and `Sie` extensions are not), in-memory
sessions in the demo, ES256 only. Path validation is no longer among them — it implements RFC 5280
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

Interop workarounds are named as workarounds and default to strict —
`tolerateMalformedMdocValidity` exists because the EU reference issuer emits a `validUntil` that is
not valid RFC 3339 (upstream issue #177).

### Events

`src/events.ts` emits typed events and **carries no personal data by construction** — no claim
values, no subject identifiers, no credential bytes. `test/hardening.test.ts` asserts it. Keep new
event fields non-identifying.

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
