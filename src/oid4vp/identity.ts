/**
 * Who this verifier is, on the wire.
 *
 * The library takes this explicitly rather than reading configuration: an
 * application decides where these values come from (environment, database,
 * per-tenant lookup), and the library only needs the answers.
 */
export type ClientIdPrefix = 'redirect_uri' | 'x509_san_dns';

export type VerifierIdentity = {
  /** Public https base URL the wallet reaches. */
  baseUrl: string;
  /** Scheme used to invoke the wallet, e.g. `eudi-openid4vp://`. */
  walletScheme: string;
  clientIdPrefix: ClientIdPrefix;
  /** DNS name in the access certificate's SAN. Required for `x509_san_dns`. */
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
  return identity.clientIdPrefix === 'x509_san_dns'
    ? `x509_san_dns:${identity.clientDnsName}`
    : `redirect_uri:${responseUri}`;
}

/** Where the wallet posts the response for a given session. */
export function responseUri(identity: VerifierIdentity, responseId: string): string {
  return `${identity.baseUrl}/oid4vp/response/${responseId}`;
}
