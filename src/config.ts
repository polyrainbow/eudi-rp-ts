import { readFileSync } from 'node:fs';

/**
 * All deployment-specific settings, from the environment.
 *
 * Everything a different wallet or a different trust list would need is here;
 * nothing else in the codebase reads `process.env`. See README "Configuration".
 */
export type ClientIdPrefix = 'redirect_uri' | 'x509_san_dns';

export type Config = {
  port: number;
  /** Public base URL of this verifier. The wallet must be able to reach it. */
  baseUrl: string;
  /**
   * Scheme used to invoke the wallet. The EUDI reference verifier calls this
   * VERIFIER_AUTHORIZATIONREQUESTURI and defaults it to `haip-vp://`.
   */
  walletScheme: string;
  clientIdPrefix: ClientIdPrefix;
  /** DNS name in the access certificate's SAN. Only used with x509_san_dns. */
  clientDnsName: string | undefined;
  /** PEM chain + key used to sign the request object (JAR). x509_san_dns only. */
  accessCertificateChainPem: string | undefined;
  accessCertificatePrivateKeyPem: string | undefined;
  requestedVct: string;
  /** Seconds a presentation request stays valid. */
  requestTtlSeconds: number;
  trust: TrustConfig;
};

export type TrustConfig = {
  /**
   * How issuer certificates are anchored.
   *   pinned — a PEM file of trust anchors (offline, the default)
   *   lotl   — an ETSI TS 119 612 trust list, fetched and signature-verified
   */
  mode: 'pinned' | 'lotl';
  pinnedAnchorsPem: string | undefined;
  /**
   * Trust list location. Defaults to the eIDAS EU List of Trusted Lists.
   *
   * NOTE: the eIDAS LOTL lists qualified trust service providers. EUDI PID
   * Providers are published on separate lists, one per deployment — which is
   * why the EU's own trust validator makes this a per-provider setting rather
   * than hardcoding a URL. Point this at your ecosystem's list.
   */
  lotlUrl: string;
  /** Service type URIs to accept. Empty means "any service type". */
  serviceTypes: string[];
  /**
   * Two-letter scheme territories to follow. Empty means all of them, which is
   * 42 national lists and roughly 20 MB of XML — slow, but it works.
   */
  territories: string[];
  /** Certificates the LOTL signature itself must chain to. */
  lotlSigningAnchorsPem: string | undefined;
  /** Skip verifying the trust list signature. Never enable outside development. */
  insecureSkipSignatureCheck: boolean;
};

const EU_LOTL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

function env(name: string): string | undefined {
  const value = process.env[name];
  return value === undefined || value === '' ? undefined : value;
}

function envFile(name: string): string | undefined {
  const path = env(name);
  return path === undefined ? undefined : readFileSync(path, 'utf8');
}

/**
 * PEM from either a file path or the value itself.
 *
 * Hosts like Fly have no filesystem to put secrets on, so `<NAME>_PEM` carries
 * the material inline (`fly secrets set X_PEM="$(cat file.pem)"`). The `_FILE`
 * form wins when both are set.
 */
function envPem(name: string): string | undefined {
  return envFile(`${name}_FILE`) ?? env(`${name}_PEM`);
}

export function loadConfig(): Config {
  const port = Number(env('PORT') ?? 3000);
  // OID4VP 1.0 §14.6 requires TLS, and the library enforces https on
  // `response_uri`. The server itself still listens on plain HTTP — put a
  // tunnel or reverse proxy in front and set BASE_URL to its public URL.
  const baseUrl = (env('BASE_URL') ?? `https://localhost:${port}`).replace(/\/$/, '');
  const clientIdPrefix = (env('CLIENT_ID_PREFIX') ?? 'redirect_uri') as ClientIdPrefix;

  if (clientIdPrefix !== 'redirect_uri' && clientIdPrefix !== 'x509_san_dns') {
    throw new Error(`CLIENT_ID_PREFIX must be redirect_uri or x509_san_dns, got ${clientIdPrefix}`);
  }

  const config: Config = {
    port,
    baseUrl,
    walletScheme: env('WALLET_SCHEME') ?? 'haip-vp://',
    clientIdPrefix,
    clientDnsName: env('CLIENT_DNS_NAME'),
    accessCertificateChainPem: envPem('ACCESS_CERT_CHAIN'),
    accessCertificatePrivateKeyPem: envPem('ACCESS_CERT_KEY'),
    requestedVct: env('REQUESTED_VCT') ?? 'urn:eudi:pid:1',
    requestTtlSeconds: Number(env('REQUEST_TTL_SECONDS') ?? 300),
    trust: {
      mode: (env('TRUST_MODE') ?? 'pinned') as TrustConfig['mode'],
      pinnedAnchorsPem: envPem('TRUST_ANCHORS'),
      lotlUrl: env('LOTL_URL') ?? EU_LOTL,
      serviceTypes: (env('LOTL_SERVICE_TYPES') ?? '').split(',').filter(Boolean),
      territories: (env('LOTL_TERRITORIES') ?? '').split(',').filter(Boolean),
      lotlSigningAnchorsPem: envPem('LOTL_SIGNING_ANCHORS'),
      insecureSkipSignatureCheck: env('LOTL_INSECURE_SKIP_SIGNATURE_CHECK') === 'true',
    },
  };

  if (clientIdPrefix === 'x509_san_dns') {
    // A signed request object is mandatory for this prefix, so the key material
    // is not optional. Fail at startup rather than at the first wallet scan.
    if (!config.clientDnsName) throw new Error('CLIENT_DNS_NAME is required when CLIENT_ID_PREFIX=x509_san_dns');
    if (!config.accessCertificateChainPem || !config.accessCertificatePrivateKeyPem) {
      throw new Error(
        'ACCESS_CERT_CHAIN_{FILE,PEM} and ACCESS_CERT_KEY_{FILE,PEM} are required when CLIENT_ID_PREFIX=x509_san_dns',
      );
    }
  }
  if (config.trust.mode === 'pinned' && !config.trust.pinnedAnchorsPem) {
    throw new Error('TRUST_ANCHORS_FILE or TRUST_ANCHORS_PEM is required when TRUST_MODE=pinned');
  }

  return config;
}

/**
 * The full Client Identifier, prefix included.
 *
 * OID4VP 1.0 §14.8 ("Always Use the Full Client Identifier") requires the
 * prefixed form, and the Key Binding JWT `aud` must equal exactly this string.
 *
 * With the `redirect_uri` prefix the Client Identifier IS the response URI,
 * which is per-session — so verification reads the value back off the request
 * we actually sent rather than recomputing it. See `verifyPresentationResponse`.
 */
export function clientId(config: Config, responseUri: string): string {
  return config.clientIdPrefix === 'x509_san_dns'
    ? `x509_san_dns:${config.clientDnsName}`
    : `redirect_uri:${responseUri}`;
}

/** Where the wallet posts the response for a given session. */
export function responseUri(config: Config, responseId: string): string {
  return `${config.baseUrl}/oid4vp/response/${responseId}`;
}
