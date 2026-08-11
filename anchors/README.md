# Trust anchors

Certificates a chain may terminate at, for `TRUST_MODE=pinned`. Public
certificates only — nothing here is secret, and nothing here should ever be a
private key.

This directory exists so that a deployment never has to point
`TRUST_ANCHORS_FILE` inside `test/`. It used to: `fly.toml` named a path under
`test/fixtures/real/`, and the `Dockerfile` copied the whole fixture tree into
the runtime image to satisfy it — including the throwaway private keys
documented in `test/fixtures/real/README.md`. Those keys protect nothing, so
nothing was compromised, but "the production trust anchor lives under `test/`"
is one refactor away from being a real problem.

| File | What it is |
|---|---|
| `eudiw-pid-issuer-ca.pem` | `CN=PID Issuer CA - UT 02`, the CA behind the EU **reference** PID issuer at `https://backend.issuer.eudiw.dev`. Fetched from the issuing certificate's AIA extension; see REPRODUCE.md. |

## This is a testing anchor

The EU reference issuer is a testing issuer and says so on its own front page.
Pinning its CA is what lets this repository verify a genuine credential end to
end, and it is what `docker compose up` and `fly.toml` default to — but it
anchors test credentials carrying synthetic subject data, not identities anyone
should make a decision about.

A real deployment either pins the CA of the PID Provider it actually accepts, or
runs `TRUST_MODE=lotl` against the trust list for its ecosystem. Note that the
eIDAS LOTL is not a registry of PID Providers, which is why `LOTL_URL` is a
setting rather than a constant — see the README.

The credentials this anchor verifies **expire 2026-11-08** (SD-JWT VC) and
**2026-11-09** (mdoc). The certificate outlives them, but once they expire it
anchors nothing this repository still exercises.
