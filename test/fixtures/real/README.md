# Real EUDI credential

Unlike everything in `test/fixtures/`, this is **not** ours. It is a genuine
`urn:eudi:pid:1` SD-JWT VC issued by the EU reference issuer
(`https://backend.issuer.eudiw.dev`) on 2026-08-09, obtained by driving the
OID4VCI authorization code flow against `issuer.eudiw.dev` with the FormEU test
identity provider.

| File | What it is |
|---|---|
| `eudiw-pid-sd-jwt-vc.txt` | The issued credential, no Key Binding JWT (it was never presented) |
| `holder-private-jwk.json` | The throwaway P-256 key the credential is bound to (`cnf.jwk`) |
| `eudiw-pid-mdoc.txt` | The same subject in ISO 18013-5 mdoc form, `IssuerSigned` as base64url CBOR. A **separate issuance, 2026-08-11**, expiring **2026-11-09** |
| `mdoc-device-private-jwk.json` | The throwaway device key that mdoc is bound to |

The issuing CA — `CN=PID Issuer CA - UT 02`, fetched from the leaf's AIA
extension — used to sit in this directory too, and is now in **`anchors/`**. It
is a public certificate that deployments point `TRUST_ANCHORS_FILE` at, and
reaching it should not mean shipping a directory of private keys into a runtime
image, which is exactly what the Dockerfile used to do.

The private key is committed deliberately. It was generated solely to request
this credential and exists nowhere else; publishing it lets the test suite mint
Key Binding JWTs and run a genuine credential through the full presentation
path. It protects nothing.

`eudiw-verifier-leaf.pem` and `eudiw-verifier-client-id.txt` are a different
kind of artefact: the certificate `verifier-backend.eudiw.dev` signed an
authorization request with on 2026-08-10, and the `x509_hash` client identifier
it advertised alongside it. They are a fixed test vector for
`src/oid4vp/identity.ts` — hashing fixed bytes gives a fixed answer, so the test
neither depends on the live service nor rots when that certificate rotates.

The subject data is synthetic — "Test Tester", born 1990-06-12, PT — entered
into the issuer's own test form. The issuer is a testing issuer and says so on
its front page. Nothing here identifies a real person.

**The SD-JWT VC expires 2026-11-08 and the mdoc 2026-11-09** — they are separate
issuances — so `test/real-credential.test.ts` and `test/mdoc.test.ts` each pin a
fixed `now`. After those dates the credentials are still useful for structural
assertions but will fail validity checks against the real clock.

You will not have to remember that. `test/fixture-freshness.test.ts` reads both
dates out of these files, prints a warning within 30 days of expiry and fails
the build afterwards, with the commands for refetching. It is the one test in
the suite that says nothing about `src/`.

## Why it is worth having

It is the only artefact in this repo that proves interoperability rather than
self-consistency. Everything else is signed by a CA the fixture script invents,
which can only demonstrate that our verifier agrees with our own issuer.

It also settles what the reference issuer actually emits:

- **No `age_equal_or_over`.** The selectively disclosable claims are
  `family_name`, `given_name`, `birthdate`, `place_of_birth` (with `country`,
  `locality`), `nationalities`, `picture`, `date_of_issuance`,
  `date_of_expiry`, `issuing_authority`, `issuing_country`. This matches PID
  Rulebook v1.1 removing the age attributes per CIR 2024/2977, and means the
  `birthdate` path in `src/predicate/age.ts` is the real one today, not a
  fallback.
- **A `status` claim is present**, pointing at a token status list. Real
  credentials carry revocation information that we currently skip.
- **The mdoc carries `birth_date`** — `given_name`, `family_name`,
  `nationality`, `place_of_birth`, `portrait`, `birth_date`,
  `issuing_authority`, `issuing_country`, `issuance_date`, `expiry_date`.

  This file used to say the opposite, and that was our bug rather than the
  issuer's. The mdoc form names the field **`birth_date`** while the SD-JWT VC
  form names it **`birthdate`** (likewise `nationality[…]` vs
  `nationalities[…]`, `portrait` vs `picture`), and
  `scripts/fetch-reference-credential.ts` posted the SD-JWT VC names into both.
  Unknown fields are accepted and dropped without an error, so the credential
  came back missing exactly those attributes and the absence was written up as
  an issuer behaviour. Fixed and the fixture regenerated on 2026-08-11; see
  REPRODUCE.md, "Two forms, two sets of field names".
- **It carries no `age_over_18`**, and that part stands: neither form offers an
  age field, so `birth_date` is the only route to the predicate — mirroring
  `birthdate` in the SD-JWT VC. `test/mdoc.test.ts` and
  `test/oid4vp-mdoc.test.ts` now prove that end to end against this credential.
- **Its `validUntil` is malformed**: `2026-11-09T11:51:46+00:00Z` carries both
  an offset and a `Z`, which is not valid RFC 3339. Reported upstream as issue
  #177. `verifyMdoc` rejects it by default and has an explicit opt-out.
- **`x5c` carries only the leaf.** The CA has to come from somewhere else — the
  AIA extension here, a trust list in production.
