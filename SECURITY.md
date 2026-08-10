# Security

## This is not production software

It verifies credentials correctly as far as it goes, and the README is explicit
about where it stops. Before relying on it for anything real, read
"Spec-compliant vs simplified" there. The gaps that matter most:

- **Certificate path validation is partial.** Signature linkage and validity
  windows are checked; name constraints, path length, key usage, EKU and
  certificate policies are not. No CRL or OCSP for the issuer chain.
- **Trust list processing is not full ETSI TS 119 615.** No service status
  history, no validity-time evaluation, no qualifier processing.
- **Sessions are in memory**, so a restart drops them and more than one
  instance breaks them.

Credential revocation via Token Status List **is** checked, and fails closed.

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

## Reporting a vulnerability

Open an issue for anything already public — a wrong check, a missing
validation, a spec deviation. For something that should not be public first,
contact the repository owner directly rather than filing publicly.

Findings about the EUDI reference implementations themselves belong upstream,
in the relevant repository under
[eu-digital-identity-wallet](https://github.com/eu-digital-identity-wallet).
