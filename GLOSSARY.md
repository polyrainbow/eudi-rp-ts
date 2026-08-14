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

**TS1–TS14** — the ARF's numbered **Technical Specifications**, published
separately from the ARF itself in
[eudi-doc-standards-and-technical-specifications](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications).
They are versioned independently of both the ARF and the regulations, so "TS3
v1.5" is a meaningful citation and "TS3" alone often is not.

**TS3** — *Specification of Wallet Unit Attestations (WUA) used in issuance of
PID and Attestations*. The one this project keeps meeting, because it governs
what an issuer may demand of a wallet before issuing. The EU reference issuer's
changelog records aligning with **TS3 v1.5**, and the deployed issuer advertises
`key_attestations_required` on every PID proof type — which is what stops a
wallet with no attestation provider from obtaining a PID at all. See
`REPRODUCE.md` section 5. Clause numbers cited in the reference issuer's own
source: **2.2.2.1** (cap proof keys at the issuer's `batch_size`) and **2.4.3**
(a credential's technical validity must end before the WIA's
`client_status.exp`).

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

**EAASP** / **QEAASP** — (Qualified) Electronic Attestation of Attributes
Service Provider: an Attestation Provider in its eIDAS guise, issuing **EAA**
and, when qualified, **QEAA**. The prefix is the whole distinction and it is
legal rather than technical: a QEAASP is a **QTSP**, audited against its own
practice statement and attestation policies and listed on a trusted list, while
a plain EAASP is any commercial party issuing attestations and is audited by
nobody. Both sign credentials a verifier reads identically, so the difference
shows up only in whether the issuer's certificate chains to an anchor you trust
and what an audit stands behind the claims — never in the credential format.

Worth keeping in view: nothing in law requires an EAASP to issue into a Wallet
Unit. An EAA can go to another kind of wallet — the European Business Wallet is
the intended case — or be emailed or downloaded, using the same formats and
protocols. See the Wallet Unit entry below for why that matters to a verifier.

**Holder** — the person. Their **Wallet Unit** holds credentials and the private
keys bound to them.

**Wallet Unit** / **Wallet Instance** / **WSCA** / **WSCD** — the wallet, in the
four parts ARF Annex 1 splits it into. The **Wallet Unit** is the whole
configuration a Wallet Provider issues to one user; the **Wallet Instance** is
only the installed app; the **Wallet Secure Cryptographic Application (WSCA)**
manages the critical assets; and the **Wallet Secure Cryptographic Device
(WSCD)** is the tamper-resistant device the WSCA is linked to — a secure
element, eUICC, external smartcard or remote HSM — which protects those assets
and performs the cryptography. The keys live in the WSCD, not in the Instance,
which is why "Wallet Unit" and "Wallet Instance" are not interchangeable.

None of this reaches a verifier. Holder binding proves possession of the key in
`cnf` (SD-JWT VC) or `DeviceKey` (mdoc) — that whatever signed is what the
issuer bound — and says nothing about where that key lives. ARF §6.6.3.11 is
explicit that the Relying Party has no way to verify the Wallet Unit or the
Wallet Provider and instead trusts the issuer to have done so at issuance; see
[ARF issue #664](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/issues/664)
for the argument that this delegation is unsound, and `REPRODUCE.md` section 5
for the reference deployment not enforcing the key attestation it advertises.

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
a health card. Qualification is a legal status, not a technical one — it
describes the issuer, the **EAASP**, and not the bytes.

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
credential has different values for each. Because the idea is shared and the
two names are not, this codebase calls the union `credentialType` wherever a
value could be either — on `VerifiedCredential`, on the events, and in the
`UNEXPECTED_CREDENTIAL_TYPE` reason code. Format-specific spellings survive
where they are genuinely format-specific: `expectedVct`, `expectedDocType`,
`VerifiedMdoc.docType`. **(used here)**

---

## Encodings and signature containers

The two credential formats do the same cryptography in two encodings, and most
of the vocabulary above is really one of these two stacks. JSON and JOSE for
SD-JWT VC; CBOR and COSE for mdoc.

**JOSE** — JSON Object Signing and Encryption. The RFC family the JSON side is
built from: **JWS** (7515), **JWE** (7516), **JWK** (7517), **JWA** (7518, the
algorithm names) and **JWT** (7519). **(used here)**

**JWT** — JSON Web Token. A set of claims carried as a JWS (or JWE). Signed
JWTs are what an SD-JWT VC, a Key Binding JWT, a status list token and a signed
request object all are. **(used here)**

**JWS** — JSON Web Signature. In *compact serialization*, three base64url
segments joined by dots: `header.payload.signature`. The signature covers the
first two segments joined by the dot, which is why they must be verified as
received rather than re-serialised. **(used here)**

**JWE** — JSON Web Encryption. What `direct_post.jwt` wraps a response in.
**(used here)**

**JWK** — JSON Web Key. A public (or private) key as JSON. The holder's key in
an SD-JWT VC `cnf.jwk` is one, and so is the ephemeral encryption key a verifier
publishes in `client_metadata`. **(used here)**

**CBOR** — Concise Binary Object Representation, RFC 8949. A binary encoding
with a JSON-like data model. What mdoc is written in. **(used here)**

**COSE** — CBOR Object Signing and Encryption, RFC 9052 (structures) and RFC
9053 (algorithms). The CBOR counterpart to JOSE. **(used here)**

**COSE_Sign1** — a COSE single-signer signed object: protected header,
unprotected header, payload, signature. An mdoc's `issuerAuth` and its device
signature are both COSE_Sign1. **(used here)**

**`Sig_structure`** — what a COSE signature actually covers, and a common
source of bugs: not the payload alone but an array committing to the protected
header, any external data, and the payload (RFC 9052 §4.4). Verifying the
payload by itself would let a signature be moved to another algorithm or
context. **(used here)**

**Detached payload** — a COSE_Sign1 carrying `null` where the payload would be,
because the verifier reconstructs it. mdoc device authentication works this way:
the signed bytes are the `DeviceAuthentication` structure, which never travels.
**(used here)**

**`x5chain`** — the COSE counterpart of JOSE's `x5c` (see *Trust and PKI*):
header label 33, RFC 9360, carrying the certificate chain as raw DER rather than
base64. The same chain in a different encoding, and the only format difference
that reaches this project's trust code. **(used here)**

**`alg`** — the algorithm a signature claims to use. JOSE names it as a string
(`ES256`), COSE as a number from the IANA registry (`-7` is ES256, `-35` ES384,
`-36` ES512). A verifier must check it against a policy, never use it to *select*
the algorithm: that is how algorithm substitution attacks work. **(used here)**

**ES256 / ES384 / ES512** — ECDSA with SHA-256/384/512 over P-256/P-384/P-521.
The curve is implied by the algorithm, so a P-256 key cannot perform ES384.
`ES256` is what the entire EUDI reference deployment signs with, and this
project's default policy. **(used here)**

**RS256 / PS256** — RSA with SHA-256, twice over, differing only in padding:
**RS\*** is RSASSA-PKCS1-v1_5, **PS\*** is RSASSA-PSS. Not interchangeable —
reading one as the other reports a valid signature as invalid. Most of eIDAS
signs with RSA even though the EUDI pilot does not. **(used here — not in the
default policy)**

**EdDSA** — signatures over Edwards curves (Ed25519, Ed448). Permitted by ISO
18013-5 for mdoc alongside ECDSA; not implemented here, because nothing in the
EUDI deployment uses it.

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

**Transaction data** — what the End-User is agreeing *to*, signed with the same
key that proves possession of the credential (OID4VP 1.0 §5.1, §8.4). The DCQL
query asks who someone is; transaction data asks what they authorise — this
amount to this payee, this document hash — and binding the two into one
signature is what turns a login into a mandate. The **type** is defined outside
OID4VP, so it is the verifier's to write; the library defines none.
**(used here)**

**`transaction_data_hashes`** — how the answer comes back: base64url hashes of
the transaction data, over the string as sent rather than the JSON it decodes
to. In the **Key Binding JWT** for SD-JWT VC (§B.3.3), and in a device-signed
**data element the type names** for mdoc (§B.2.1) — a difference worth knowing,
because only the first has a fixed location. **(used here)**

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

**PAR** — Pushed Authorization Requests, **RFC 9126**. The client POSTs the
authorization request parameters to the AS's
`pushed_authorization_request_endpoint` and receives a short-lived `request_uri`,
which is then the only parameter in the front-channel authorization request. Not
to be confused with JAR: PAR moves the parameters to a back channel, JAR signs
them. The reference wallet uses PAR whenever the AS advertises the endpoint.

**DPoP** — Demonstrating Proof of Possession at the Application Layer,
**RFC 9449**. Sender-constrains an access token to a key, so a stolen token is
useless on its own. The client sends a `DPoP` header holding a proof JWT
(`typ: dpop+jwt`, with `htm`, `htu`, `jti`, `iat`, plus `ath` — a digest of the
access token — once it has one), and the AS returns `token_type: DPoP` with the
key's thumbprint in `cnf.jkt`. Thereafter the token travels as
`Authorization: DPoP …` rather than `Bearer`. The EU reference issuer issues
DPoP-bound tokens when the wallet asks for them.

**Proof of possession** — in OID4VCI, a JWT (`typ: openid4vci-proof+jwt`) the
wallet signs to prove it holds the key the credential will be bound to.

**Key attestation** — evidence about *where* a key lives (secure element,
etc.), governed by **TS3**. The reference issuer advertises requiring it
(`key_attestations_required`, at assurance level `iso_18045_high`); it did not
enforce it in testing — a bare software key was accepted.

**WUA** — Wallet Unit Attestation. What TS3 specifies: the wallet provider's
signed statement about the wallet unit and the keys it holds, presented at the
**credential** endpoint as the key attestation backing a proof of possession.

**WIA** — Wallet Instance Attestation. The provider's statement that this app
instance is genuine, presented at the **token** endpoint as client
authentication (`OAuth-Client-Attestation` / `-PoP` headers). Distinct from the
WUA despite both coming from the wallet provider, and issued from a different
endpoint. A wallet configured without one has neither, which is the practical
reason a build can fail to obtain a PID.

---

## Trust and PKI

**Trust anchor** — a certificate you have decided to trust a priori. Chains
terminate here. **(used here)**

**Trusted List** — **ETSI TS 119 612**. A signed XML list of trust service
providers and their certificates, one per Member State. **(used here)**

**LOTL** — List of Trusted Lists. The signed index pointing at every national
trusted list. The EU one is at
`https://ec.europa.eu/tools/lotl/eu-lotl.xml`. **(used here)**

**LOTE** — List of Trusted Entities. The EUDI ecosystem's own trust list format,
signed as a JWS with a JSON payload (`LoTE.ListAndSchemeInformation` plus
`LoTE.TrustedEntitiesList`) rather than the signed XML of an eIDAS trusted list.
Its list-type and service-type identifiers live under the
`http://uri.etsi.org/19602/` namespace — e.g.
`…/LoTEType/EUPIDProvidersList` and `…/SvcType/PID/Issuance`. This is where PID
providers are published, because the eIDAS trusted lists do not cover them; the
reference deployment publishes separate lists for PID providers, RP access CAs
and public-body EAA providers under
`https://trustedlist.serviceproviders.eudiw.dev/LOTE/json/`. Not the same thing
as the **LOTL**, despite the near-identical name.

**ETSI TS 119 615** — the procedures for *interpreting* a trusted list: service
status history, qualifiers, validity at a point in time. This project implements
service status history, validity-time evaluation and the qualifier derivation of
§4.4. What it does not implement is the step after: turning a qualifier into a
verdict, which it leaves to the caller. **(partly used here)**

**Sie** — a Service Information Extension, ETSI TS 119 612 §5.5.9, after the
`SvcInfoExt` namespace. Usually means `Qualifications` specifically: a rule set a
service publishes over the certificates *it issues*, matching on policy OIDs,
KeyUsage bits, Extended Key Usage or subject DN attributes, and awarding
qualifiers to those that match. Marked critical by half the live lists, which
means an entry carrying one a verifier cannot process may not be used at all.
**(used here)**

**Qualifier** — a URI a `Qualifications` rule awards to a matching certificate:
`QCStatement`, `QCForESig`, `QCForESeal`, `QCForWSA`, `QCWithQSCD`, `NotQualified`
and the rest of TS 119 612 Annex D. It describes a *certificate*, not a service —
two certificates from one CA can qualify differently. This project derives them
and reports them; whether one is required is the relying party's policy, and
`NotQualified` is not a rejection here, since a PID Provider need not be a QTSP.
**(used here)**

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

**Certificate policy** — an OID in a certificate (**RFC 5280 §4.2.1.4**) naming
the rules a CA issued it under: identity proofing, key protection, audit. In
eIDAS this is what separates a qualified certificate from an ordinary one —
ETSI's qualified certificate policies live under the `0.4.0.194112.1` arc, the
most common of the 512 distinct OIDs on the live trusted lists — and both can
sit under the same trusted list entry, so the policy is the only thing
distinguishing them. **anyPolicy** (`2.5.29.32.0`) is the wildcard. Validating
one is not a lookup but a walk down the path: each CA may narrow the set, rename
it into its own arc (**policy mapping**, §4.2.1.5), or require its successors to
be explicit (**policy constraints**, §4.2.1.11). **(used here — the full RFC
5280 §6.1 processing; which OIDs are acceptable is the caller's to name)**

**Path length constraint** — the second field of `basicConstraints` (**RFC 5280
§4.2.1.9**), saying how many further CA certificates may sit between this CA and
an end entity. Zero means "I sign end-entity certificates only", which is what
the EU PID Issuer CA and 692 of the 1165 CAs on the live trusted lists say.
Distinct from a verifier's own cap on how long a chain it will look at.
**(used here — both)**

**Critical extension** — the boolean every X.509 extension carries (**RFC 5280
§4.2**), by which a CA says *this changes what the certificate means, and you
may not use it without understanding me*. §6.1.4 (o) is the other half: a
validator meeting a critical extension it does not process must reject the
certificate rather than proceed without it. Skipping one does not validate a
weaker path, it validates a *different certificate* from the one the CA issued —
the ignored extension may have been narrowing it to a purpose this is not.
Non-critical is the opposite statement: use this if you understand it. Six
extensions are ever marked critical across the live trusted lists. **(used here
— enforced below the trust anchor, against an explicit recognised set; see the
README)**

**AIA** — Authority Information Access, an X.509 extension (**RFC 5280
§4.2.2.1**). Its *CA Issuers* URI is where you fetch an issuing CA that was not
included in `x5c`; its *OCSP* URI names the responder to ask about the
certificate's revocation. The EU reference PID signer publishes the first and
**not** the second. **(used here — the OCSP URI, when a certificate has one)**

**CRL** — Certificate Revocation List, **RFC 5280 §5**. A list, signed by a CA,
of the serial numbers of certificates it has revoked, with a `thisUpdate` and a
`nextUpdate` bounding how long it may be relied on. A certificate says where its
CA publishes one in the **CRL Distribution Points** extension (§4.2.1.13).
Answers "has this certificate been withdrawn", which is a different question
from a **status list**, which answers "has this *credential* been withdrawn".
Both the EU reference PID signer and its CA publish one. **(used here — checked
by default, and failing closed; a CRL past its `nextUpdate` is refused rather
than relied on)**

**CRL Distribution Point / CRLDP** — the X.509 extension naming the URL where a
certificate's CRL is published. Commonly plain `http:`, which is safe because
the CRL is signed by the CA and verified after fetching; the residual risk is
replay of an older CRL, which `nextUpdate` bounds. **(used here)**

**OCSP** — Online Certificate Status Protocol, **RFC 6960**. Instead of
downloading every revocation a CA has ever issued, ask the CA's responder about
one certificate and get a signed answer: `good`, `revoked`, or `unknown`. The
request identifies the certificate by a **CertID** — the SHA-1 hashes of the
issuer's name and public key, plus the serial number (§4.1.1) — rather than by
sending the certificate itself. Fresher and smaller than a CRL, at the cost of
an online dependency at verification time. `unknown` is not a clean bill of
health. **(used here — preferred over CRL when a certificate publishes both;
no EU reference issuer runs a responder today)**

**OCSP stapling** — the server presenting a recent OCSP response itself rather
than the client asking the responder. A TLS mechanism; it has no equivalent in
OID4VP, where the credential arrives from a wallet rather than from the issuer.
**(not applicable here)**

**Delegated OCSP responder** — a certificate, issued by the CA, that answers
OCSP on the CA's behalf. It must carry the `id-kp-OCSPSigning` extended key
usage (`1.3.6.1.5.5.7.3.9`); without checking that, any certificate the CA ever
issued could answer for every certificate the CA ever issued. **(used here —
accepted only with the EKU)**

**Soft-fail / hard-fail** — what a verifier does when revocation information
cannot be fetched. Soft-fail accepts anyway (common in browsers, because
responders are unreliable); hard-fail rejects. This project hard-fails, on the
same reasoning as the status list: a check you could not perform is not a check.
A certificate that publishes *no* revocation information at all is a separate
case and is accepted — the CA has not told us anything we are ignoring.
**(used here — hard-fail)**

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
| **LOTL** — index of the national eIDAS trusted lists, signed XML | **LOTE** — EUDI list of trusted entities, signed JSON |
| **`vct`** — SD-JWT VC type | **`doctype`** — mdoc type |
| **JOSE** — JSON stack: JWS, JWE, JWK, `x5c` | **COSE** — CBOR stack: COSE_Sign1, COSE_Key, `x5chain` |
| **JWS and COSE** — ECDSA signature as raw `r‖s` | **X.509, CRL, OCSP** — the same signature as a DER sequence |
| **`RS256`** — RSA with PKCS#1 v1.5 padding | **`PS256`** — RSA with PSS padding, same hash |
| **`alg`** — what the token *claims* | **`allowedAlgs`** — what the verifier *accepts*; never the other way round |
| **JAR** — signed *request* | **JARM** — encrypted/signed *response* |
| **JAR** — signs the request parameters | **PAR** — moves them to a back channel |
| **WUA** — about the wallet unit and its keys, sent to the *credential* endpoint | **WIA** — about the app instance, sent to the *token* endpoint |
| **WSCD** — the tamper-resistant device holding the keys | **WSCA** — the application managing them, linked to the WSCD |
| **Wallet Unit** — Instance plus WSCA plus WSCD, what a provider issues | **Wallet Instance** — the installed app alone, which holds no keys |
| **Registrar** — approves and registers you | **Access CA** — issues your certificate |
