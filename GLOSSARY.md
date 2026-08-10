# Glossary

The EUDI ecosystem has an unusually dense vocabulary, and a lot of it is
near-homophones for different things (`mdoc` vs SD-JWT VC, OID4VCI vs OID4VP,
access certificate vs registration certificate). This is the set of terms you
need to read this repo and the specs it implements.

Terms this project actually uses in code are marked **(used here)**. The rest is
context you will meet in the ARF and in the reference implementations.

---

## Ecosystem and regulation

**eIDAS** — Regulation (EU) 910/2014 on electronic identification and trust
services. **eIDAS 2.0** is the 2024 amendment, Regulation (EU) 2024/1183, which
introduced the EUDI Wallet.

**EUDIW / EUDI Wallet** — EU Digital Identity Wallet. The app a citizen holds
credentials in. Every Member State must offer at least one.

**ARF** — Architecture and Reference Framework. The EU's technical
specification of the wallet ecosystem, versioned separately from the
regulations. Published at
[eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework).

**CIR** — Commission Implementing Regulation. The binding technical rules under
eIDAS 2.0. Two matter here:

- **CIR 2024/2977** — cited by PID Rulebook v1.1 as the reason the age
  verification attributes were removed from the PID.
- **CIR 2025/848** — registration of wallet-relying parties. Applies from
  **24 December 2026**.

**Rulebook** — the document defining one attestation type: its attributes, their
encoding in each format, and the rules for issuing it. The **PID Rulebook** is
the one this project cares about; it now lives in
[eudi-doc-attestation-rulebooks-catalog](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog).

**Member State** — an EU country, and in this ecosystem the entity that
designates registrars, access CAs and trusted lists. Much of the trust
infrastructure is per-Member-State rather than EU-wide.

**LSP** — Large Scale Pilot. Consortia (POTENTIAL, EWC, NOBID, DC4EU) piloting
wallet use cases ahead of the regulation applying.

---

## Roles

**Issuer** / **Attestation Provider** — signs and issues credentials. A **PID
Provider** issues the PID specifically.

**Holder** — the person. Their **Wallet Unit** (or Wallet Instance) holds
credentials and the private keys bound to them.

**Verifier** / **Relying Party (RP)** — asks the holder for a presentation and
checks it. **This project is a Relying Party.** **(used here)**

**Intermediary** — a party that acts for relying parties, registering once on
their behalf.

**Registrar** — Member State body that maintains the national register of
relying parties. **Access CA** issues their certificates. See *RPAC* / *RPRC*.

---

## Credential types

**PID** — Person Identification Data. The core government-issued identity
credential: name, birth date, nationality. `vct` is `urn:eudi:pid:1`.
**(used here)**

**mDL** — mobile Driving Licence, per ISO/IEC 18013-5.

**EAA / QEAA / PubEAA** — Electronic Attestation of Attributes, and its
Qualified and Public-body variants. Any non-PID credential: a diploma, an IBAN,
a health card. Qualification is a legal status, not a technical one.

---

## Credential formats

**SD-JWT** — Selective Disclosure JWT, **RFC 9901** (November 2025). A JWT whose
claims are replaced by salted hashes, plus separate *disclosures* the holder
chooses to reveal. **(used here)**

**SD-JWT VC** — SD-JWT for Verifiable Credentials,
`draft-ietf-oauth-sd-jwt-vc` (draft 18 at time of writing, not yet an RFC).
Adds `vct`, issuer identification and type metadata on top of SD-JWT.
**(used here)**

**`dc+sd-jwt`** — the media type and OID4VP format identifier for SD-JWT VC.
Formerly **`vc+sd-jwt`**; renamed to avoid clashing with W3C VC. The draft says
both should be accepted during a transition, and the EU reference issuer emits
`dc+sd-jwt`. **(used here — both accepted)**

**mdoc / mDoc / MSO mdoc** — the ISO/IEC 18013-5 credential format. CBOR and
COSE rather than JSON and JOSE. Identified by a **doctype** (e.g.
`eu.europa.ec.eudi.pid.1`) with claims grouped into **namespaces**.
**(used here)**

**MSO** — Mobile Security Object. The signed object inside an mdoc carrying the
digests of its data elements. The mdoc analogue of an SD-JWT's `_sd` array.
**(used here)**

**DeviceResponse** — what an mdoc wallet actually sends: the issuer-signed
credential plus a **device signature** over a `SessionTranscript`. The device
signature is mdoc's equivalent of a Key Binding JWT. **(used here)**

**SessionTranscript / OpenID4VPHandover** — the structure an mdoc device
signature commits to, binding the response to one request's client identifier,
nonce and response URI. **(used here)**

**`vct` vs `doctype`** — the same idea in the two formats. `vct` is a URI-ish
string in SD-JWT VC (`urn:eudi:pid:1`); `doctype` is a reverse-DNS string in
mdoc (`eu.europa.ec.eudi.pid.1`). They are *not* interchangeable and the same
credential has different values for each.

---

## SD-JWT mechanics

**Disclosure** — a base64url-encoded `[salt, claim_name, value]` triple,
appended to the JWT after a `~`. The holder sends only the ones they choose.
**(used here)**

**`_sd`** — array of digests in the signed payload. A disclosure is valid only
if its hash appears here, which is what stops a holder forging claims.
**`_sd_alg`** names the hash function. **(used here)**

**Selective disclosure** — revealing some claims and not others, without
invalidating the issuer's signature.

**Key binding / KB-JWT** — a JWT the *holder* signs over the presentation,
proving they hold the private key the credential is bound to. Contains `nonce`,
`aud`, `iat` and `sd_hash`. **(used here)**

**`cnf`** — confirmation claim in the credential, carrying the holder's public
key. What the KB-JWT is verified against. **(used here)**

**`sd_hash`** — digest of the presented SD-JWT, inside the KB-JWT. Binds the key
proof to this exact set of disclosures, so a KB-JWT cannot be replayed against a
different selection. **(used here)**

**Status list / Token Status List** — a compressed bitstring published by the
issuer; a credential's `status` claim points at an index in it. How revocation
works for SD-JWT VC. Real reference credentials carry one. **(used here —
checked by default, and failing closed)**

---

## Protocols

**OID4VCI** — OpenID for Verifiable Credential **Issuance**. How a credential
gets *into* a wallet. Wallet ← issuer.

**OID4VP** — OpenID for Verifiable **Presentations**, **1.0 Final** since 10
July 2025. How a credential gets *out of* a wallet to a verifier.
Wallet → verifier. **(used here)**

The two are constantly confused. Mnemonic: **I**ssuance fills the wallet,
**P**resentation empties it.

**Credential Offer** — the OID4VCI object (usually a QR code or deep link) that
tells a wallet what an issuer is offering and how to start.

**DCQL** — Digital Credentials Query Language. OID4VP 1.0's way of describing
what a verifier wants: credential format, type, and specific claim paths. It
replaced Presentation Exchange. **(used here)**

**Presentation Exchange (PEX)** — the older `presentation_definition` query
language. Superseded by DCQL but still widely supported.

**VP Token / `vp_token`** — the response payload. In OID4VP 1.0 it is a JSON
object keyed by DCQL credential query id, each value an array of presentations.
**(used here)**

**`response_mode`** — how the wallet returns the response.
**`direct_post`** posts it to the verifier's `response_uri` in the clear;
**`direct_post.jwt`** posts it encrypted to a key the verifier published.
**(used here — both)**

**JAR** — JWT-Secured Authorization Request, RFC 9101. The request signed as a
JWT rather than sent as query parameters. Required with `x509_san_dns` and
`x509_hash`. **(used here)**

**JARM** — JWT Secured Authorization Response Mode. The response equivalent;
what `direct_post.jwt` wraps. **(used here)**

**Client Identifier Prefix** — how a verifier identifies itself, as
`<prefix>:<id>`. The ones you meet: **`redirect_uri`** (the id *is* the response
URI; request must not be signed), **`x509_san_dns`** (a DNS name matching a
dNSName SAN in the signing certificate), **`x509_hash`** (base64url SHA-256 of
the DER leaf — what the EU reference verifier uses), plus `pre-registered`,
`verifier_attestation`, `openid_federation` and `origin` for the DC API.
**(used here — `redirect_uri`, `x509_san_dns`, `x509_hash`)**

**`x509_san_uri`** — a prefix from OID4VP drafts 21 and 24, **removed before
1.0 Final** and superseded by `x509_hash`. You will still see it in libraries
that support pre-1.0 drafts.

**HAIP** — High Assurance Interoperability Profile. An OpenID profile
constraining OID4VCI/OID4VP for high-assurance use. Source of the `haip-vp://`
and `haip-vci://` URI schemes you see in EU reference deployments.

**DC API** — the browser Digital Credentials API, an alternative to custom URI
schemes for invoking a wallet from a web page.

**Proof of possession** — in OID4VCI, a JWT (`typ: openid4vci-proof+jwt`) the
wallet signs to prove it holds the key the credential will be bound to.

**Key attestation** — evidence about *where* a key lives (secure element,
etc.). The reference issuer advertises requiring it; it did not enforce it in
testing.

---

## Trust and PKI

**Trust anchor** — a certificate you have decided to trust a priori. Chains
terminate here. **(used here)**

**Trusted List** — **ETSI TS 119 612**. A signed XML list of trust service
providers and their certificates, one per Member State. **(used here)**

**LOTL** — List of Trusted Lists. The signed index pointing at every national
trusted list. The EU one is at
`https://ec.europa.eu/tools/lotl/eu-lotl.xml`. **(used here)**

**ETSI TS 119 615** — the procedures for *interpreting* a trusted list: service
status history, qualifiers, validity at a point in time. This project implements
a deliberately simplified subset.

**QTSP / TSP** — (Qualified) Trust Service Provider. The entities a trusted list
lists. Note the eIDAS trusted lists cover qualified trust services, **not** EUDI
PID providers, which are published on separate lists per deployment.

**RPAC** — Wallet Relying Party Access Certificate. Issued to a registered
relying party by an Access CA; used to authenticate to a wallet. Cannot be
self-minted. **(used here — via `ACCESS_CERT_*`)**

**RPRC** — Wallet Relying Party Registration Certificate. Optional per Member
State; states which attributes the RP registered to request, so a wallet can
warn the user when a verifier asks for more.

**`x5c`** — JOSE header carrying the certificate chain, base64 DER, leaf first.
How both issuers and verifiers ship their certificates inline. Note the EU
reference issuer puts *only the leaf* there. **(used here)**

**AIA** — Authority Information Access, an X.509 extension. Its *CA Issuers*
URI is where you fetch an issuing CA that was not included in `x5c`.

---

## Terms specific to this repo

**`age_equal_or_over`** — the PID Rulebook's SD-JWT VC encoding of age
predicates: one object keyed by age, e.g. `{"16": true, "18": true}`. The mdoc
form is a flat `age_over_18`. Note the live reference issuer emits **neither** —
see the README's open questions.

**Trust anchor set** — `TrustAnchors`, the certificates a chain may terminate
at. Loaded from PEM or from a trusted list.

**ReasonCode** — this project's machine-readable rejection reasons. Every
failure path ends at exactly one, so callers never parse error strings.

---

## Frequently confused

| These | Are not these |
|---|---|
| **OID4VCI** — issuance, into the wallet | **OID4VP** — presentation, out of the wallet |
| **SD-JWT VC** — JSON/JOSE, `vct` | **mdoc** — CBOR/COSE, `doctype` |
| **RPAC** — access certificate, authenticates you to a wallet | **RPRC** — registration certificate, tells the user what you may ask for |
| **eIDAS Trusted List** — qualified trust services | **EUDI provider lists** — PID providers, published separately |
| **`vct`** — SD-JWT VC type | **`doctype`** — mdoc type |
| **JAR** — signed *request* | **JARM** — encrypted/signed *response* |
| **Registrar** — approves and registers you | **Access CA** — issues your certificate |
