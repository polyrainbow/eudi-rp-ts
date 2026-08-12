# Security

## This is not production software

It verifies credentials correctly as far as it goes, and the README is explicit
about where it stops. Before relying on it for anything real, read
"Spec-compliant vs simplified" there. The gaps that matter most:

- **Certificate path validation is partial.** Signature linkage, validity
  windows, path length, an optional EKU allowlist and RFC 5280 Name Constraints
  are checked; KeyUsage bits and certificate policies are not. No CRL or OCSP
  for the issuer chain.
- **Trust list processing is not full ETSI TS 119 615.** No service status
  history, no validity-time evaluation, no qualifier processing.
- **Sessions are in memory**, so a restart drops them and more than one
  instance breaks them.

Credential revocation via Token Status List **is** checked, for SD-JWT VC and
mdoc alike, and fails closed. The one revocation mechanism not implemented is
the `identifier_list` the EU reference issuer publishes alongside its status
list; a credential offering *only* that is rejected rather than accepted
unchecked.

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
