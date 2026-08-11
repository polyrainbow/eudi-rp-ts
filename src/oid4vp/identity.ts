import { X509Certificate, createHash } from 'node:crypto';

/**
 * Who this verifier is, on the wire.
 *
 * The library takes this explicitly rather than reading configuration: an
 * application decides where these values come from (environment, database,
 * per-tenant lookup), and the library only needs the answers.
 */
export type ClientIdPrefix = 'redirect_uri' | 'x509_san_dns' | 'x509_hash';

export type VerifierIdentity = {
  /** Public https base URL the wallet reaches. */
  baseUrl: string;
  /** Scheme used to invoke the wallet, e.g. `eudi-openid4vp://`. */
  walletScheme: string;
  clientIdPrefix: ClientIdPrefix;
  /**
   * DNS name in the access certificate's SAN. Required for `x509_san_dns`.
   *
   * Not used by `x509_hash`, which derives the identifier from the certificate
   * itself — useful when the certificate you are issued carries a URI SAN, or
   * none, rather than a dNSName. The EU reference verifier identifies this way.
   */
  clientDnsName: string | undefined;
  /** Access certificate chain and key, PEM. Required for `x509_san_dns`. */
  accessCertificateChainPem: string | undefined;
  accessCertificatePrivateKeyPem: string | undefined;
  /** Credential type to request. */
  requestedVct: string;
  /** How long a request stays valid. */
  requestTtlSeconds: number;
  /** Verify credential status lists. Leave true unless deliberately offline. */
  checkStatus: boolean;
};

/**
 * The full Client Identifier, prefix included.
 *
 * OID4VP 1.0 §14.8 ("Always Use the Full Client Identifier") requires the
 * prefixed form, and the Key Binding JWT `aud` must equal exactly this string.
 *
 * With the `redirect_uri` prefix the Client Identifier IS the response URI,
 * which is per-session — so verification reads the value back off the request
 * that was actually sent rather than recomputing it.
 */
export function clientId(identity: VerifierIdentity, responseUri: string): string {
  switch (identity.clientIdPrefix) {
    case 'x509_san_dns':
      return `x509_san_dns:${identity.clientDnsName}`;
    case 'x509_hash':
      if (!identity.accessCertificateChainPem) {
        throw new Error('x509_hash requires the access certificate chain');
      }
      return `x509_hash:${x509Hash(identity.accessCertificateChainPem)}`;
    default:
      return `redirect_uri:${responseUri}`;
  }
}

/**
 * The `x509_hash` identifier for a certificate chain.
 *
 * OID4VP 1.0 §5.10: "the base64url-encoded value of the SHA-256 hash of the
 * DER-encoded X.509 certificate" — the leaf, which is the first entry.
 *
 * Verified against the live EU reference verifier: hashing its published leaf
 * reproduces the `client_id` it advertises. See REPRODUCE.md.
 */
export function x509Hash(chainPem: string): string {
  const leaf = /-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/.exec(chainPem)?.[0];
  if (!leaf) throw new Error('No certificate found in the access certificate chain');

  const der = new X509Certificate(leaf).raw;
  return createHash('sha256').update(der).digest('base64url');
}

/**
 * The verifier's base URL, checked before anything is built on it.
 *
 * OID4VP 1.0 §14.6 requires TLS, and for `response_uri` the reason is not
 * ceremony: that is where the wallet posts the VP Token, so an http base
 * publishes a credential presentation in clear to anyone on the path. The same
 * base serves `request_uri`, whose whole job under a signed request is to be
 * fetched intact.
 *
 * No exemption for loopback. It would only help a wallet running on this
 * machine, and a wallet on a phone cannot reach loopback anyway — which is what
 * the demo warns about at startup when `BASE_URL` is left at localhost.
 */
export function verifierBaseUrl(identity: VerifierIdentity): string {
  let parsed: URL;
  try {
    parsed = new URL(identity.baseUrl);
  } catch {
    throw new Error(`baseUrl is not a valid URL: ${identity.baseUrl}`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(`baseUrl must be https (OID4VP 1.0 §14.6), got ${identity.baseUrl}`);
  }
  return identity.baseUrl;
}

/** Where the wallet posts the response for a given session. */
export function responseUri(identity: VerifierIdentity, responseId: string): string {
  return `${verifierBaseUrl(identity)}/oid4vp/response/${responseId}`;
}
