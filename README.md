# eudi-rp-ts

A minimal EU Digital Identity relying party in Node/TypeScript. It proves one
predicate — **age over 18** — from an SD-JWT VC.

The official EUDI implementations are Kotlin, Swift and Python. The one
TypeScript repo in the `eu-digital-identity-wallet` org is an Angular UI that
delegates all verification to the Kotlin backend, so there is no Node reference
for this. That gap is what this project fills.

**Phase 1 (current): offline verification of a single SD-JWT VC.** No HTTP, no
wallet, no QR code. Phase 2 adds the OID4VP round trip.

## Quick start

Requires Node 22+ (developed on 24). There is no build step — Node runs the
TypeScript directly.

```bash
npm install
npm test          # 15 tests, fully offline
npm run typecheck
```

## What it does

```ts
const result = await verifyAgeOver18({
  credential,                                   // compact SD-JWT VC + KB-JWT
  anchors: TrustAnchors.fromPem(rootCaPem),
  expectedVct: 'urn:eudi:pid:1',
  keyBinding: { nonce, audience: 'https://verifier.example/oid4vp' },
});

if (result.verified) result.value.ageOver18;    // true
else result.reason;                             // e.g. 'KEY_BINDING_AUDIENCE_MISMATCH'
```

Every rejection path ends at exactly one `ReasonCode` (see `src/result.ts`), so
callers switch on a code and never parse an error string.

The verification steps, in order: reject any `alg` other than ES256 → check the
`typ` is an SD-JWT VC media type → resolve the issuer key from `x5c` and chain
it to a trust anchor → verify the issuer signature → resolve disclosures →
verify the Key Binding JWT (signature, `sd_hash`, `nonce`, **and audience**) →
check `vct` → evaluate the predicate.

## Dependencies

One runtime dependency: **`@sd-jwt/sd-jwt-vc`** (OpenWallet Foundation,
Apache-2.0) for SD-JWT parsing, disclosure resolution and KB-JWT mechanics.
Everything else — certificate parsing, chain validation, ECDSA verification — is
`node:crypto`. `@peculiar/x509` is a dev dependency, used only to mint test
certificates in `scripts/make-fixtures.ts`.

## Layout

```
src/crypto.ts             ES256 allowlist, JWS verification, hashing
src/result.ts             ReasonCode and the Outcome type
src/trust/anchors.ts      trust anchor set (Phase 2 will populate this from the LOTL)
src/trust/issuer-key.ts   x5c resolution + chain validation   <- the part no library does
src/predicate/age.ts      age_equal_or_over["18"], birthdate fallback
src/verify.ts             orchestration
scripts/make-fixtures.ts  regenerates test/fixtures (committed)
scripts/probe-reference-issuer.ts   network-gated probe of issuer.eudiw.dev
```

## Claim encoding

Per the EUDI PID Rulebook (ARF 2.4, chapter 4), the SD-JWT VC encoding of the
PID differs from the mdoc one:

| Data identifier | SD-JWT VC claim | Encoding |
|---|---|---|
| `age_over_18` | `age_equal_or_over.18` | boolean |
| `birth_date` | `birthdate` | string, `YYYY-MM-DD` (OIDC registered claim) |

`age_equal_or_over` is a single object keyed by age, e.g.
`{"16": true, "18": true, "65": false}` — not a set of flat `age_over_NN` claims.
This matters for disclosure: making each *property* selectively disclosable lets
a holder reveal `"18": true` alone, which is what the fixtures do and what the
privacy test asserts.

## Spec-compliant vs simplified

**Compliant.** SD-JWT digest and disclosure handling (RFC 9901, via
`@sd-jwt`); SD-JWT VC media types `dc+sd-jwt` and the transitional `vc+sd-jwt`
(draft-ietf-oauth-sd-jwt-vc-18); the PID claim encoding above; key binding with
`sd_hash`, `nonce` and audience checks; x5c chain signature linkage and
certificate validity windows.

**Simplified, deliberately.**

- **No revocation.** No CRL, no OCSP, and SD-JWT VC status list checking is
  switched off (`disableStatusVerification`) because Phase 1 is offline. Phase 2
  turns it on.
- **Certificate path validation is partial.** Signature linkage and validity
  windows are checked; name constraints, path length, key usage, EKU and
  certificate policies are not.
- **Trust anchors come from a PEM file**, not the EU List of Trusted Lists. The
  `TrustAnchors` class is the seam where Phase 2 swaps in the LOTL.
- **ES256 only**, matching what the reference issuer advertises.

## Two things the library does not do

Both are handled in `src/verify.ts`; both are easy to get wrong if you assume
the library covers them.

1. **`@sd-jwt` never resolves issuer keys.** Its verifier callback is
   `(data, sig) => boolean`, so key discovery and trust are entirely the relying
   party's problem. `src/trust/issuer-key.ts` is that missing half.
2. **`@sd-jwt` does not check the KB-JWT audience.** It requires `aud` to be
   present and matches `nonce`, but never compares `aud` to the verifier's own
   identifier — so a presentation minted for a different verifier would pass. We
   check it explicitly. Relatedly, key binding is verified *only* when a nonce is
   supplied; passing no nonce silently skips it even when a KB-JWT is present,
   which is why `verifyCredential` throws rather than defaulting.

## Open questions

- **Does the live reference issuer still emit `age_equal_or_over`?** PID
  Rulebook v1.1 (4 Sep 2025) removed the age attributes following CIR 2024/2977,
  and `issuer.eudiw.dev` advertises an empty `claims` array for
  `eu.europa.ec.eudi.pid_vc_sd_jwt`, so its metadata does not answer this. Run
  `npm run probe -- <credential>` with a real credential to settle it. The
  `birthdate` fallback exists for the case where the answer is no — at the cost
  of the holder disclosing their full date of birth, which is more than the
  verifier asked for.
- **SD-JWT VC and current EU age verification are diverging.** The dedicated EU
  Age Verification profile (`av-doc-technical-specification`, Annex A) is
  **mdoc-only**: doctype `eu.europa.ec.av.1`, flat `age_over_18` boolean,
  `redirect_uri` client id, `direct_post`. This project deliberately stays on the
  SD-JWT VC path.
- **`/.well-known/jwt-vc-issuer` is unsupported** by the reference issuer (HTTP
  400, "Not supported"), so `x5c` is the only key-resolution route that works
  against real EU infrastructure today. Only `x5c` is implemented.

## Fixtures

`test/fixtures/` is generated by `npm run fixtures` and committed. The
credentials are signed by a throwaway CA created by that script.

**They prove our verification logic is correct. They prove nothing about EUDI
interoperability** — that requires the reference wallet, which is Phase 2.
