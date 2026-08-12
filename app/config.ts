import { readFileSync } from 'node:fs';
import { DEFAULT_ALLOWED_ALGS, type JwsAlg, isSupportedAlg } from '../src/crypto.ts';
import { type ClientIdPrefix, type VerifierIdentity, verifierBaseUrl } from '../src/oid4vp/identity.ts';
import type { TrustListOptions } from '../src/trust/lotl.ts';

/**
 * Configuration for the demo application.
 *
 * Nothing in `src/` reads the environment — the library takes explicit options.
 * This file is the only place that turns environment variables into them, which
 * is what lets the same library run inside an application with entirely
 * different configuration.
 */
export type Config = VerifierIdentity & {
  port: number;
  trust: TrustConfig;
  /**
   * Accept an mdoc whose `validUntil` is not valid RFC 3339. The EU reference
   * issuer emits one; see upstream issue #177.
   */
  tolerateMalformedMdocValidity: boolean;
};

export type TrustConfig = TrustListOptions & {
  /**
   * How issuer certificates are anchored.
   *   pinned — a PEM file of trust anchors (offline, the default)
   *   lotl   — an ETSI TS 119 612 trust list, fetched and signature-verified
   */
  mode: 'pinned' | 'lotl';
  pinnedAnchorsPem: string | undefined;
  /**
   * Two-letter scheme territories to follow. Empty means all of them, which is
   * 42 national lists and roughly 20 MB of XML — slow, but it works.
   */
  territories: string[];
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
 * the material inline. The `_FILE` form wins when both are set.
 */
function envPem(name: string): string | undefined {
  return envFile(`${name}_FILE`) ?? env(`${name}_PEM`);
}

export function loadConfig(): Config {
  const port = Number(env('PORT') ?? 3000);
  // OID4VP 1.0 §14.6 requires TLS. The server itself still listens on plain
  // HTTP — put a tunnel or reverse proxy in front and set BASE_URL to its
  // public URL, which is the address the wallet actually uses.
  const baseUrl = (env('BASE_URL') ?? `https://localhost:${port}`).replace(/\/$/, '');
  const clientIdPrefix = (env('CLIENT_ID_PREFIX') ?? 'redirect_uri') as ClientIdPrefix;

  const prefixes: ClientIdPrefix[] = ['redirect_uri', 'x509_san_dns', 'x509_hash'];
  if (!prefixes.includes(clientIdPrefix)) {
    throw new Error(`CLIENT_ID_PREFIX must be one of ${prefixes.join(', ')}, got ${clientIdPrefix}`);
  }

  // Advertised to the wallet and enforced on the way back, from one value.
  // ES256 alone is what the EUDI reference deployment uses; most of eIDAS signs
  // with RSA, so a verifier accepting issuers outside the pilot has to say so.
  const allowedAlgs: readonly JwsAlg[] = (env('ALLOWED_ALGS') ?? '')
    .split(',')
    .map((alg) => alg.trim())
    .filter(Boolean)
    .map((alg) => {
      if (!isSupportedAlg(alg)) {
        throw new Error(`ALLOWED_ALGS contains ${alg}, which is not a supported JWS algorithm`);
      }
      return alg;
    });

  const config: Config = {
    port,
    baseUrl,
    // `eudi-openid4vp://` is what the live EUDI reference infrastructure emits.
    walletScheme: env('WALLET_SCHEME') ?? 'eudi-openid4vp://',
    clientIdPrefix,
    clientDnsName: env('CLIENT_DNS_NAME'),
    accessCertificateChainPem: envPem('ACCESS_CERT_CHAIN'),
    accessCertificatePrivateKeyPem: envPem('ACCESS_CERT_KEY'),
    requestedVct: env('REQUESTED_VCT') ?? 'urn:eudi:pid:1',
    requestTtlSeconds: Number(env('REQUEST_TTL_SECONDS') ?? 300),
    // Accepting a credential whose revocation status you did not check is
    // accepting a revoked one. Off only for an offline demo.
    checkStatus: env('STATUS_CHECK') !== 'false',
    // Accepting a credential signed by a certificate the CA has revoked is
    // accepting an issuer that is no longer trusted to have issued it. Off only
    // for an offline demo, or where the CA's CRL endpoint is unreachable.
    checkCertificateRevocation: env('CERT_REVOCATION_CHECK') !== 'false',
    tolerateMalformedMdocValidity: env('MDOC_TOLERATE_MALFORMED_VALIDITY') === 'true',
    allowedAlgs: allowedAlgs.length > 0 ? allowedAlgs : DEFAULT_ALLOWED_ALGS,
    trust: {
      mode: (env('TRUST_MODE') ?? 'pinned') as TrustConfig['mode'],
      pinnedAnchorsPem: envPem('TRUST_ANCHORS'),
      lotlUrl: env('LOTL_URL') ?? EU_LOTL,
      serviceTypes: (env('LOTL_SERVICE_TYPES') ?? '').split(',').filter(Boolean),
      territories: (env('LOTL_TERRITORIES') ?? '').split(',').filter(Boolean),
      lotlSigningAnchorsPem: envPem('LOTL_SIGNING_ANCHORS'),
      insecureSkipSignatureCheck: env('LOTL_INSECURE_SKIP_SIGNATURE_CHECK') === 'true',
      // A list past its own NextUpdate is a replayable list. Off only where a
      // missed republication upstream would otherwise be a local outage.
      insecureSkipFreshnessCheck: env('LOTL_INSECURE_SKIP_FRESHNESS_CHECK') === 'true',
    },
  };

  if (clientIdPrefix === 'x509_san_dns' || clientIdPrefix === 'x509_hash') {
    // Both prefixes require a signed request object, so the key material is not
    // optional. Fail at startup rather than at the first wallet scan.
    if (!config.accessCertificateChainPem || !config.accessCertificatePrivateKeyPem) {
      throw new Error(
        `ACCESS_CERT_CHAIN_{FILE,PEM} and ACCESS_CERT_KEY_{FILE,PEM} are required when CLIENT_ID_PREFIX=${clientIdPrefix}`,
      );
    }
    // Only x509_san_dns needs a name; x509_hash derives its identifier from
    // the certificate, which is why it works with a URI SAN or none at all.
    if (clientIdPrefix === 'x509_san_dns' && !config.clientDnsName) {
      throw new Error('CLIENT_DNS_NAME is required when CLIENT_ID_PREFIX=x509_san_dns');
    }
  }
  if (config.trust.mode === 'pinned' && !config.trust.pinnedAnchorsPem) {
    throw new Error('TRUST_ANCHORS_FILE or TRUST_ANCHORS_PEM is required when TRUST_MODE=pinned');
  }
  // The library refuses a non-https base too, but it does so when the first
  // request is built. Calling it here turns that into a startup failure, which
  // is where a deployment mistake should surface.
  verifierBaseUrl(config);

  return config;
}
