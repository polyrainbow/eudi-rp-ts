# Security

## This is not production software

It verifies credentials correctly as far as it goes, and the README is explicit
about where it stops. Before relying on it for anything real, read
"Spec-compliant vs simplified" there. The gaps that matter most:

- **Certificate path validation is RFC 5280 §6.1 in full.** Signature linkage,
  validity windows, path length — both the caller's limit and each CA's own
  `pathLenConstraint` — an optional EKU allowlist, RFC 5280 Name Constraints,
  the KeyUsage bits that matter (`keyCertSign` on every issuer,
  `digitalSignature` on the leaf), certificate policies as the full §6.1 state
  machine (the policy tree, `policyMappings`, `policyConstraints`,
  `inhibitAnyPolicy`), rejection of critical extensions this project does not
  process (§6.1.4 (o)) and revocation by CRL or OCSP are all checked. Three
  readings within that are this project's own, and each is argued in the README
  rather than left implicit: the trust anchor follows RFC 5937 rather than §6.1
  — including its exemption from §6.1.4 (o) — Extended Key Usage is enforced
  only against a `requiredExtendedKeyUsage` the caller sets, and policy
  qualifiers are read but not acted on, which §6.1.5 (f) leaves local.
- **Trust list processing is not full ETSI TS 119 615.** Service status history,
  validity-time evaluation and the list's own issue date and next-update are
  implemented — a list past its `NextUpdate`, or declaring none, is refused
  rather than replayed. So is signature *coverage*: `verifyTrustList` returns
  the octets the signature covered and everything downstream parses those, so a
  service added outside the signed reference is absent rather than trusted (XML
  Signature Wrapping). So are §5.5.9 service information extensions, including
  `Qualifications` — a service publishing a critical extension this project
  cannot process is dropped rather than trusted, and the qualifiers derived for
  an issuer's certificate are **reported to the caller and never enforced**.
  What is not implemented is the rest of TS 119 615: turning a qualifier into a
  verdict is left to the caller's policy, deliberately, because an EUDI PID
  Provider need not be a QTSP.
- **Sessions are in memory** by default, so a restart drops them and more than
  one instance breaks them. `SessionStore` is an interface and a shared
  implementation can be passed in; note that a store outside this process holds
  the ephemeral response-decryption keys, which is secret material at rest.
- **The algorithm policy defaults to ES256**, which is what the EUDI reference
  deployment uses and narrower than eIDAS at large. ECDSA on three curves and
  RSA in six algorithms can be verified; accepting them is a deliberate
  `allowedAlgs` decision, and the token's `alg` is never used to select the
  verification algorithm.

Revocation **is** checked, at both levels and failing closed at both: the
credential, via Token Status List for SD-JWT VC and mdoc alike; and the issuer's
certificate chain, via CRL or OCSP. A certificate that publishes neither a CRL
distribution point nor a responder is accepted — that is the one case where
there is genuinely nothing to check.

The one revocation mechanism not implemented is the `identifier_list` the EU
reference issuer publishes alongside its status list; a credential offering
*only* that is rejected rather than accepted unchecked.

## Test key material is committed on purpose

`test/fixtures/` contains private keys. All of it is throwaway material
generated for tests, and none of it protects anything:

- `credentials.json` holds a holder private JWK for fixtures signed by a CA the
  fixture script invents on each run.
- `test/fixtures/real/holder-private-jwk.json` is the key bound to a real
  credential from the EU *testing* issuer, carrying synthetic subject data, and
  was generated solely to obtain that credential.

Do not copy these patterns into anything real, and do not reuse these keys.

`config/` is gitignored — that is where a real access certificate and its
private key land if you generate or install one. Check it stays untracked.

None of it reaches a deployment. The runtime image carries `anchors/`, which is
public certificates only; it used to carry the whole of `test/fixtures/`,
private keys included, because the default trust anchor happened to live there.
`npm run check:package` makes the same assertion about the published tarball.

## Reporting a vulnerability

Open an issue for anything already public — a wrong check, a missing
validation, a spec deviation. For something that should not be public first,
contact the repository owner directly rather than filing publicly.

Findings about the EUDI reference implementations themselves belong upstream,
in the relevant repository under
[eu-digital-identity-wallet](https://github.com/eu-digital-identity-wallet).
