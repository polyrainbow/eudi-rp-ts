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
import { TrustAnchors, verifyAgeOver18SdJwtVc, verifyMdoc } from '@sauseschritt/eudi-rp-ts';

const anchors = TrustAnchors.fromPem(readFileSync('pid-issuer-ca.pem', 'utf8'));

await verifyAgeOver18SdJwtVc({
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

### Name Constraints across the whole trust list, 2026-08-11

Enforcing RFC 5280 Name Constraints means deciding what to do with a name form
the implementation does not cover. Rejecting is the safe answer and the one
taken, but it is only free if no real CA uses such a form — so this was measured
rather than assumed, by running `fetchTrustAnchors` over every territory and
reading extension 2.5.29.30 off each anchor:

```
lists ok: 25, failed: 6, anchors: 1897
anchors carrying Name Constraints: 2 of 1897
subtree forms seen: dNSName=2  iPAddress=4
  e.g. C=EE, O=AS Sertifitseerimiskeskus, CN=ESTEID-SK 2015
       critical=false  permitted=0  excluded=3
```

Both are Estonian, both use only forms this code implements, and both carry
*excluded* subtrees only. Note `critical=false`: RFC 5280 says conforming CAs
MUST mark this extension critical, so these do not conform. The check is applied
regardless of criticality, which is the stricter reading.

The same run recorded six lists that did not load, none of them related to name
constraints and all worth knowing:

| Territory | Why | Since |
|---|---|---|
| EL, SI | XMLDSig `ecdsa-sha512` unsupported by `xml-crypto` | **fixed** |
| HU | XMLDSig `ecdsa-sha256`, likewise | **fixed** |
| SK | Its `TSLLocation` is **http**, which `src/fetching.ts` refused | **fixed** |
| IE, PT | TLS chain incomplete — see below | open |

### After ECDSA and the http exception, same day

```
lists ok: 29, failed: 2, anchors: 2434
  EL: OK 112 services    HU: OK 164 services
  SI: OK  41 services    SK: OK 220 services
```

537 more anchors than the run above, from four member states that were silently
absent.

Ireland and Portugal remain, and it is worth being precise about why, because
the symptom is misleading. `fetch failed` is not an outage:

```
$ curl -sS -o /dev/null -w '%{http_code}' https://eidas.gov.ie/Irelandtslsignedv6.xml
200
$ node -e "fetch('https://eidas.gov.ie/Irelandtslsignedv6.xml')" # cause:
UNABLE_TO_VERIFY_LEAF_SIGNATURE
```

Both endpoints serve an incomplete TLS certificate chain — the intermediate is
missing. curl and browsers paper over it by fetching the missing certificate
from the AIA extension; Node does not, and should not be made to. Nothing in
this repository can fix it without weakening TLS verification, and the servers
are the thing that is wrong.

There is an argument for reaching them anyway, not taken here: a national list's
authenticity comes from its XML signature and not from the transport, which is
exactly why http is now allowed for one. By that reasoning an unverifiable TLS
chain is no worse than plain http. It is left open because "ignore TLS errors"
is a much larger hammer than "allow a scheme", and worth deciding deliberately.

### Service status history and validity time, 2026-08-12

Whether evaluating status against an instant costs anchors, and what the
published lists actually contain. Both were measured before the parser changed,
so the comparison is against the flat parse it replaced.

```
old parser: 2434 certs, 2301 unique
new parser: 2433 granted-now entries, 2301 unique
unique certs the old parser had and the new one does not: 0
services granted-now with no StatusStartingTime: 0
history-only certificates under a granted service: 0
earliest granted starting times: 2016-06-30 (×5)
```

Three things follow, and the first is the one worth stating plainly.

**The anchor set is unchanged.** 2301 unique certificates before and after. The
familiar figure of 2434 was never a count of distinct anchors — it counted a
certificate once per service naming it, and 133 of those were repeats. Nothing
was lost by moving to intervals, and nothing was gained at the default
evaluation time either. What was gained is that another time can be asked about:

```
granted right now:  2287        # of 2305 certificates across all periods
granted 2020-01-01:  748
granted 2015-01-01:    0        # the lists begin 2016-06-30
```

**`StatusStartingTime` is universal.** Across 2797 services and 3330 history
instances on eight member states' lists, every entry carries one — so requiring
it, and dropping entries without one rather than inventing a start, costs
nothing today. Same measured argument as Name Constraints above.

**Sixteen services carry a starting time in the future**, all of them
`withdrawn` (FR: Certinomis and the Ministère de l'Intérieur timestamping
services, dated 2027–2029). None is `granted`, so excluding not-yet-effective
grants changes nothing today either — but the case is live in the data.

The one real trap was Poland, and it does not appear in any count above because
it was found by reconciling the 14 certificates that went missing on the first
attempt:

```
$ node -e "…parse https://www.nccert.pl/tsl/PL_TSL.xml…"
ServiceInformation: granted 2017-02-13T10:38:44Z
   history instance: granted 2017-02-13T10:38:44Z
```

The current entry is republished as a history instance with an identical
`StatusStartingTime`. Ordering entries by time alone gives the live one a
zero-length interval and drops the service. `ServiceInformation` is the status
in effect by definition rather than by timestamp, and a test pins it.

### What the ecosystem signs with, 2026-08-12

Whether verifying ECDSA alone was a limitation or a policy, measured by reading
the public key off every anchor the LOTL leads to:

```
$ node -e "…parse each anchor's key type with node:crypto…"

unique anchors: 2305
    983  rsa 2048        123  ec secp384r1
    751  rsa 4096        103  ec prime256v1
    270  rsa 3072         28  ec secp521r1
      7  rsa-pss 2048     20  ec brainpoolP256r1
      6  rsa-pss 4096      4  ec brainpoolP384r1
      6  rsa 8192
      4  rsa 1024

CA anchors only (1055):  861 RSA, 184 EC, of which 602 are rsa 4096
```

**2013 of 2305 are RSA against 274 EC.** So refusing anything but ECDSA — which
`resolveIssuerCertificateChain` did, before any algorithm had been named — made
a chain terminating at a trusted qualified CA unverifiable whenever the issuer
signed the way most of eIDAS signs.

Two long tails matter, and both are refused with a stated reason rather than a
failed signature:

- **4 certificates carry 1024-bit RSA keys.** RFC 7518 §3.3 requires 2048 for
  RS* and PS*, so the floor refuses something real.
- **24 carry brainpool curves** (`brainpoolP256r1`, `brainpoolP384r1`). They are
  valid X.509 and chain normally; JOSE simply has no algorithm to verify them
  under, so they are reported as an unusable key.

Against that, the EUDI reference deployment is uniformly ES256, which is why the
default policy stayed narrow:

```
issuer.eudiw.dev advertised credential signing algs:  ES256, -7   (COSE ES256)
proof signing alg values (jwt, attestation):          ES256
committed SD-JWT VC header alg:                       ES256, DS key ec prime256v1
its status list token:                                alg ES256, typ statuslist+jwt
```

`ecosystem-drift.test.ts` asserts that last block still holds: if the reference
issuer starts advertising an algorithm the default policy does not include, the
default has become too narrow for the deployment it was chosen for.

### Key usage across the trust lists and the reference PKI, 2026-08-12

Whether requiring `keyCertSign` of every issuing certificate and
`digitalSignature` of every leaf costs anything, measured by reading the
extension off every anchor the LOTL leads to and off the committed credentials:

```
$ node -e "…parse each anchor's KeyUsage with @peculiar/asn1-x509…"

unique anchors: 2305
  basicConstraints CA=true : 1055   KeyUsage absent:  0
  basicConstraints CA=false: 1250   KeyUsage absent: 60
CA anchors asserting KeyUsage but NOT keyCertSign: 0

CA bit combinations:
    849  keyCertSign|cRLSign
    189  digitalSignature|keyCertSign|cRLSign
      7  digitalSignature|nonRepudiation|keyCertSign|cRLSign
      4  digitalSignature|keyCertSign
      2  keyAgreement|keyCertSign|cRLSign
      1  keyCertSign
      1  digitalSignature|keyAgreement|keyCertSign
      1  digitalSignature|keyAgreement|keyCertSign|cRLSign
      1  digitalSignature|nonRepudiation|keyEncipherment|dataEncipherment|
         keyAgreement|keyCertSign|cRLSign

anchors/eudiw-pid-issuer-ca.pem   ca=true   KU=keyCertSign|cRLSign
PID DS - 002 (SD-JWT VC x5c[0])   ca=false  KU=digitalSignature  EKU=1.0.18013.5.1.2, 1.0.23220.4.1.2
PID DS - 002 (mdoc x5chain[0])    ca=false  KU=digitalSignature
```

Three things follow.

**Both rules are free today.** Every one of the 1055 CA certificates asserts
`keyCertSign`, and the EU reference document signer asserts `digitalSignature`
in both credential formats. Same measured argument as Name Constraints.

**Most anchors are not CAs.** 1250 of 2305 are end-entity certificates published
as service digital identities — timestamping units, responders — and 60 of them
carry no KeyUsage at all. They are legitimately on a trusted list and
legitimately unable to sign certificates, which is why the `keyCertSign`
requirement is applied only to certificates actually used as issuers, and why an
absent extension is read as silence rather than refusal.

**Node was already enforcing half of it.** `X509Certificate.ca` is OpenSSL's
`X509_check_ca`, which clears the CA flag when KeyUsage is present without
`keyCertSign`; `checkIssued` refuses such an issuer too. Measured directly:

```
CA:TRUE + no KeyUsage extension   node .ca = true
CA:TRUE + [keyCertSign]           node .ca = true
CA:TRUE + [keyCertSign|cRLSign]   node .ca = true
CA:TRUE + []                      node .ca = false
CA:TRUE + [cRLSign]               node .ca = false
CA:TRUE + [digitalSignature]      node .ca = false
```

So the issuing-side rule changed no outcome; it is written out because Node
documents `.ca` only as "is this a CA certificate", and a path validation
resting on the undocumented remainder would break silently. `key-usage.test.ts`
pins the table above beside the explicit check. What was genuinely unchecked is
the **leaf**: nothing in the tree knew that key was about to verify a credential
signature rather than a TLS handshake.

### Certificate policies across the trust lists and the reference PKI, 2026-08-12

Certificate policy processing (RFC 5280 §6.1) was written against what the live
lists actually carry, measured by reading all four policy extensions off every
service certificate the LOTL leads to:

```
$ node -e "…fetch the LOTL, parsePointers, parseTrustServices on each list,
           then readCertificatePolicies / readPolicyMappings /
           readPolicyConstraints / readInhibitAnyPolicy on every certificate…"

lists: 29/31  unreachable: IE, PT
certificates: 2439 (1165 CAs)
  certificatePolicies: 2336 (1098 of the CAs)
  distinct policy OIDs: 512      anyPolicy asserted: 625
  unreadable: 0

policyConstraints  IT  req=0  CN=Postecert per Camera dei Deputati, O=Postecom S.p.A.
policyConstraints  IT  req=0  CN=Postecom CA1, O=Postecom s.p.a.
policyConstraints  IT  req=0  CN=Postecom CA2, O=Postecom S.p.A.
policyConstraints  IT  req=0  CN=Postecert per Regione Emilia-Romagna, O=Postecom s.p.a.
policyConstraints  SK  req=0  CN=CAMOSR2, O=Ministry of Defence, C=SK
policyConstraints  SK  req=0  CN=CAMOSR3, O=Ministry of Defence, C=SK
policyConstraints  SK  req=0  CN=I.CA - Qualified Certification Authority, 09/2009, C=CZ
policyConstraints  SK  req=0  CN=I.CA Qualified CA/RSA 07/2015, C=CZ

policyMappings     SK  1.3.158.36061701.0.0.0.1.2.2 -> 0.4.0.1456.1.1
                       1.3.158.36061701.0.0.0.1.2.2 -> 1.3.158.36061701.0.0.0.1.2.2
                       (the same four CAs the Slovak list publishes, above)

inhibitAnyPolicy   none on any list
```

The count is service *entries* that yielded a certificate, not unique
certificates — 2439 against the 2305 unique anchors in the KeyUsage measurement
above, the difference being the same certificate published by more than one
service.

Four things follow.

**Policies are the norm, not the exception.** 2336 of 2439 certificates assert
at least one, across 512 distinct OIDs. Ignoring the extension means ignoring
what almost every CA in the ecosystem is saying about how it issued.

**Every `policyConstraints` on the lists is `requireExplicitPolicy: 0`**, on
eight CA certificates from two Member States, and none sets
`inhibitPolicyMapping`. No certificate anywhere carries `inhibitAnyPolicy`. So
the counters are exercised against fixtures rather than against live material —
worth knowing when reading `test/certificate-policies.test.ts`.

**Policy mapping is live infrastructure.** The four CAs on the Slovak list map a
national policy arc onto `0.4.0.1456.1.1`. A verifier that asked for the EU OID
and refused to follow the mapping would reject certificates those CAs say are
equivalent — which is the case `inhibitMapping` exists to make deliberate.

**Nothing on the lists is unreadable.** All 2439 parsed, so failing closed on a
policy extension that cannot be read costs nothing today — the same measured
argument as Name Constraints and KeyUsage.

The reference PKI, read the same way:

```
anchors/eudiw-pid-issuer-ca.pem   no policy extension of any kind
PID DS - 002 (SD-JWT VC x5c[0])   certificatePolicies: 1.2.3.4  (non-critical,
                                    with a CPS qualifier, 1.3.6.1.5.5.7.2.1)
PID DS - 002 (mdoc x5chain[0])    certificatePolicies: 1.2.3.4  (the same)
Verifier Signer (access cert)     certificatePolicies: 0.4.0.194118.1.2
```

`1.2.3.4` is a placeholder OID, which is what a test deployment is entitled to
publish. It is the reason `acceptable` has no default: the OID a deployment
should demand is a property of the deployment, and hardcoding the reference
issuer's would be pinning a placeholder. The anchor asserting nothing at all is
why the trust anchor's own policies are not read as the path's — see README
"Certificate policies".

### Policy processing against OpenSSL

The tests for §6.1 prove the implementation does what this project believes the
RFC says, which is worth less than it looks: tests and implementation were
written by the same hand. And the live ecosystem does not settle it either —
nothing on the trusted lists inhibits mapping or anyPolicy, so the interesting
branches meet no real material.

`scripts/check-policy-tree.ts` puts the same chains to an implementation nobody
here wrote. `openssl verify` implements §6.1 in full and takes each initial
input as a flag: `-policy` is the user-initial-policy-set, `-explicit_policy`,
`-inhibit_map` and `-inhibit_any` the three initial settings. Only the verdicts
are compared:

```
$ node scripts/check-policy-tree.ts
  ok    ours=accept  openssl=accept  the leaf asserts the accepted policy
  ok    ours=reject  openssl=reject  the leaf asserts a policy that was not accepted
  ok    ours=reject  openssl=reject  no CA above the leaf authorised its policy
  ok    ours=accept  openssl=accept  a CA asserts anyPolicy
  ok    ours=reject  openssl=reject  a CA asserts anyPolicy, and the caller inhibits it
  ok    ours=reject  openssl=reject  the leaf wildcards after a CA withdrew anyPolicy
  ok    ours=accept  openssl=accept  a CA maps the accepted policy onto its own
  ok    ours=reject  openssl=reject  the same mapping, inhibited by the caller
  ok    ours=reject  openssl=reject  a CA requires an explicit policy and the leaf is silent
  ok    ours=reject  openssl=reject  a sub-CA under an anchor whose pathLenConstraint is zero

Every case agrees with OpenSSL.
```

Run against OpenSSL 3.6.2 on 2026-08-12. The certificates are generated fresh
each run, so only the agreement means anything.

Two limits worth stating. OpenSSL is being asked about a **path**, this project
about a **presented chain plus a trust anchor**, so the anchor is supplied as
`-CAfile` and the intermediates as `-untrusted`; the RFC 5937 reading of an
anchor's own constraints is therefore this project's alone and is not what
agreement above confirms. And ten cases are ten cases: they cover each branch
that has ever been wrong here, not the space.

### Path length, and which extensions are marked critical, 2026-08-12

The same pass, reading `basicConstraints` and the critical flag off every
certificate:

```
$ node -e "…AsnConvert.parse each certificate, read BasicConstraints and
           every extension's critical flag…"

CA certificates: 1165        carrying a pathLenConstraint: 734
  pathLen 0: 692    1: 31    2: 2    3: 3    4: 4    7: 2

extensions ever marked critical, with how many certificates mark them:
  2.5.29.15  keyUsage               2216
  2.5.29.19  basicConstraints       1662
  2.5.29.37  extendedKeyUsage       1002
  2.5.29.32  certificatePolicies      72
  2.5.29.36  policyConstraints         6
  2.5.29.16  privateKeyUsagePeriod     4

anchors/eudiw-pid-issuer-ca.pem   ca=true  pathLenConstraint=0
```

**Path length is not free to ignore.** 692 of the 1165 CA certificates say they
sign end-entity certificates only, the EU PID Issuer CA among them. Before this
was enforced, a chain claiming any of them issued a sub-CA — which then vouches
for any subject at all — validated. Node exposes `.ca` and not the constraint
beside it, which is why it went unread; nothing in the reference deployment is
affected, because its chains are one document signer under the anchor directly.

**Six extensions are ever marked critical, and one is outside the recognised
set.** `privateKeyUsagePeriod` (RFC 3280 §4.2.1.4, dropped from RFC 5280), on
four certificates. RFC 5280 §6.1.4 (o) says a certificate with a critical
extension the verifier does not process must be rejected, and this measurement
is what decided that the rule could be turned on: it bounded the cost at four
certificates, none of them in the reference deployment. It is now implemented —
see README "Critical extensions" — so this number is no longer a gap being
bounded but the set of certificates a deployment **rejects**, which is why
`ecosystem-drift.test.ts` re-measures it against the library's own
`RECOGNISED_CRITICAL_EXTENSIONS` rather than a copy. Note that 78 certificates
were outside the set before certificate policies were implemented, which is most
of why those came first.

The same pass over the two committed real credentials confirms the reference
deployment is unaffected — `PID DS - 002` and `PID Issuer CA - UT 02` mark only
`basicConstraints` and `keyUsage` critical, for the SD-JWT VC and the mdoc
alike:

```
$ node -e "…read every extension and its critical flag off the x5c in
           test/fixtures/real/eudiw-pid-sd-jwt-vc.txt…"

PID DS - 002   2.5.29.19* 2.5.29.35 1.3.6.1.5.5.7.1.1 2.5.29.32 2.5.29.37
               2.5.29.31 2.5.29.14 2.5.29.15* 1.3.6.1.5.5.7.1.3
               (* = critical)
```

`test/critical-extensions.test.ts` pins that against the committed fixtures, so
it is checked offline on every run rather than only when the drift test does.

### Trust list freshness: what the lists declare about themselves, 2026-08-12

Refusing a list past its own `NextUpdate` is only defensible if the live lists
publish one and keep it current, and refusing a list that declares *none* is
only defensible if the set that costs is the abandoned ones. Both were measured
before the check was written, by reading `SchemeInformation` off every list the
LOTL points at as XML:

```
$ node -e "…fetch the LOTL, parsePointers, fetch each list, read
           SchemeInformation/{ListIssueDateTime,NextUpdate/dateTime,TSLSequenceNumber}…"

LOTL   issued 2026-08-03T13:16:38Z  nextUpdate 2027-01-27T13:16:38Z  seq 390
national lists pointed at as XML: 31   fetched: 29   (IE, PT did not answer)

missing ListIssueDateTime:            0
NextUpdate element absent:            0
NextUpdate present but empty:         1   <- UK
already past their NextUpdate:        0
issue age (days):        min 1.1 (SK)   median 57.7   max 2049.4 (UK)
issue -> nextUpdate:     min 92.0 (PL)  median 183.0  max 184.0
```

Three things follow.

**The cadence is six months.** Every list but Poland's declares a window of
roughly 183 days, Poland's 92. So refusing a lapsed list turns an unbounded
replay window into one bounded by the publisher's own schedule, and does not
require anyone to republish more often than they already do.

**Nothing is currently overdue.** Not one of the 29 lists was past its
`NextUpdate`, so the strict rule costs no territory today. The freshest was
Slovakia's, republished 1.1 days earlier; the median list was 58 days old and
comfortably inside its window.

**The empty `NextUpdate` is the United Kingdom's, and only theirs.**

```
UK  issued=2020-12-31T22:59:59Z  age=2049.4d  nextUpdate=EMPTY  seq=25
```

`2020-12-31T22:59:59Z` is the moment of withdrawal from the EU. The list has
been frozen for five years and declares no next update because there will not be
one. Refusing a list whose freshness cannot be bounded therefore costs exactly
one list, and it is the one that most needs refusing — the argument is the same
shape as Name Constraints above, and it goes stale the same way, so
`ecosystem-drift.test.ts` asserts that the set of unbounded lists is still
exactly `['UK']` and fails loudly when it is not.

### Certificate revocation: what the reference PKI publishes, 2026-08-12

Which of CRL and OCSP the EU reference infrastructure actually offers, checked
by reading the extensions off the committed credential's own chain:

```
$ node -e "…read x5chain from test/fixtures/real/eudiw-pid-mdoc.txt…"
--- CN=PID DS - 002
   AIA: 1.3.6.1.5.5.7.48.2 https://preprod.pki.eudiw.dev/aia/PIDIssuerCA02-UT.cacert.pem
   CRL: ["https://preprod.pki.eudiw.dev/crl/pid_CA_UT_02.crl"]
--- CN=PID Issuer CA - UT 02
   CRL: ["https://preprod.pki.eudiw.dev/crl/pid_CA_UT_02.crl"]
```

**Both certificates publish a CRL. Neither publishes an OCSP responder** — the
only AIA access method present is `1.3.6.1.5.5.7.48.2`, which is `caIssuers`;
`…48.1` (`ocsp`) is absent. So CRL is the only mechanism the real EU
infrastructure offers today, and the only one that can be exercised against it.

The CRL itself:

```
$ curl -sS -o pid.crl https://preprod.pki.eudiw.dev/crl/pid_CA_UT_02.crl
HTTP 200  457 bytes  application/octet-stream

$ openssl crl -inform DER -in pid.crl -noout -text
    Signature Algorithm: ecdsa-with-SHA256
    Issuer: CN=PID Issuer CA - UT 02, O=EUDI Wallet Reference Implementation, C=UT
    Last Update: Aug 11 15:49:04 2026 GMT
    Next Update: Aug 13 15:49:03 2026 GMT
    X509v3 CRL Number: 484
Revoked Certificates:
    Serial Number: 44E8FD79564DA111A882289DC699E579BB6B1BEB
        Revocation Date: Jun 26 12:08:17 2025 GMT
```

Small, ECDSA-signed, and genuinely maintained: CRL number 484, a two-day
`nextUpdate`, and a real revocation in it. The end-to-end check against it —
fetch, verify the signature against the CA, bound the freshness, look the serial
up — returns `{"kind":"good","via":"crl"}` for the committed credential, and is
run by `RUN_NETWORK_TESTS=1 npm test`.

Note the two-day `nextUpdate`. Because this project refuses a CRL past it, a
deployment pointed at this CA is dependent on the EU continuing to republish;
that is the correct behaviour and worth knowing before turning the check on.

### OCSP CertID against OpenSSL

Since no reference responder exists, the OCSP path is exercised only against
fixtures — and the fixtures are written by the same hand as the verifier, so on
their own they prove the two agree rather than that either is right. The part
where that matters most is the `CertID` (RFC 6960 §4.1.1), which identifies the
certificate by SHA-1 hashes of the issuer's name and key rather than by value.

`scripts/check-ocsp-certid.sh` builds a request with OpenSSL for the same
certificate and compares, field by field, against the bytes our code puts on the
wire:

```
$ npm run fixtures && ./scripts/check-ocsp-certid.sh
  ok   hashAlgorithm   1.3.14.3.2.26
  ok   issuerNameHash  80C9DD75F29B513D7FE6173F1BDB87D55DB8F71F
  ok   issuerKeyHash   7D50546D787B3590949A059F7E55F86E6679BA14
  ok   serialNumber    0A

CertID matches OpenSSL.
```

The hashes differ on every run — the fixture CA is regenerated each time — so
only the match means anything.

One trap worth recording, because it cost a debugging round: **X.509 and OCSP
carry an ECDSA signature as a DER `SEQUENCE`, while WebCrypto produces the raw
r‖s pair.** This is the same encoding trap as XMLDSig in `lotl.ts`, pointing the
other way. A fixture signed with WebCrypto's output directly is not what a real
responder emits, and a verifier tuned to accept it would fail against every
genuine one.

### Keeping this document honest

Everything above is a measurement, and a measurement goes stale silently. Two
decisions in this project rest on one — "failing closed on an unimplemented name
form costs nothing" and "requiring `StatusStartingTime` loses nothing" — and
both are true today rather than true by construction.

`test/ecosystem-drift.test.ts` asserts the claims here against the live
deployment, weekly, in `.github/workflows/network.yml`. It is deliberately
separate from the other network tests: those ask *does our code still work*, and
a failure is a bug; this asks *is REPRODUCE.md still true*, and a failure means
nothing in `src/` is broken and the EU has moved. Each assertion fails with what
changed and what to update, because a scheduled job that merely warns is a job
nobody reads. Some of the failures would be good news — an OCSP responder
appearing, `/.well-known/jwt-vc-issuer` starting to answer — and a red build is
still the only way to find out.

It watches: the PID Issuer CA still being the certificate committed in
`anchors/`; the CRL still published and still inside its `nextUpdate`; no OCSP
responder appearing; `/.well-known/jwt-vc-issuer` still refusing; and, across
every national list, that no Name Constraint uses a form we do not implement,
that no granted service omits `StatusStartingTime`, that the anchor count has
not collapsed, and — for the freshness rule above — that every list still
declares a `ListIssueDateTime`, that none has lapsed past its own `NextUpdate`,
and that the lists declaring no `NextUpdate` at all are still exactly `['UK']`.

Run on 2026-08-12:

```
$ RUN_NETWORK_TESTS=1 node --test test/ecosystem-drift.test.ts
✔ still uses the CA certificate committed in anchors/
✔ still publishes a CRL, and it is still fresh
✔ still runs no OCSP responder
✔ still does not support /.well-known/jwt-vc-issuer
✔ still support every assumption the trust code makes
  ℹ 2361 granted services across 29 lists; 52 identify themselves without a
    certificate; 2439 service entries yielded a certificate; unreachable: IE, PT
```

**52 granted services publish no certificate at all.** Their
`ServiceDigitalIdentity` carries `X509SubjectName` and `X509SKI` instead —
Liechtenstein and the United Kingdom are the two lists that do this. TS 119 612
permits it, and it means those services can never be trust anchors here: this
implementation holds anchor certificates and matches them by fingerprint, so a
service that names a subject and a key identifier without supplying the key
gives it nothing to hold. A fuller implementation would match a *presented*
chain against the name and SKI rather than needing the certificate up front.
That is a real gap, reported by the drift test as a diagnostic rather than a
failure because it is a property of the lists rather than a change in them.

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

That anchor path is what the run used and is left as recorded. It no longer
exists in the image: the runtime no longer carries `test/fixtures/`, and the
anchor moved to `/app/anchors/eudiw-pid-issuer-ca.pem`. Repeating this today
means pointing at that instead — which anchors the reference issuer rather than
the fixture CA, so the wallet must present a credential from the reference
issuer, as the 2026-08-10 run below did.

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
TRUST_ANCHORS_FILE=/app/anchors/eudiw-pid-issuer-ca.pem
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
