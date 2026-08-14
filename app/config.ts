import { readFileSync } from 'node:fs';
import { DEFAULT_ALLOWED_ALGS, type JwsAlg, isSupportedAlg } from '../src/crypto.ts';
import { type ClientIdPrefix, type VerifierIdentity, verifierBaseUrl } from '../src/oid4vp/identity.ts';
import type { TrustListOptions } from '../src/trust/lotl.ts';
import type { DcqlQuery } from '../src/oid4vp/query.ts';
import { ageOver18Query } from '../src/presets/age-over-18.ts';
import { PID_VCT } from '../src/presets/eudi-pid.ts';

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
  /**
   * The question this deployment asks, as DCQL.
   *
   * Configuration, not a library constant: `buildAuthorizationRequest` takes a
   * query and `verifyPresentationResponse` checks the answer against the one
   * that was sent, so the demo picking age-over-18 here is the demo's choice.
   * Asking something else is this value plus a matching predicate in
   * `server.ts`, and nothing in `src/`.
   */
  query: DcqlQuery;
  /** The SD-JWT VC type the query asks for. Kept for the audit trail and the startup banner. */
  requestedVct: string;
  trust: TrustConfig;
  /**
   * Accept an mdoc whose `validUntil` is not valid RFC 3339. The EU reference
   * issuer emits one; see upstream issue #177.
   */
  tolerateMalformedMdocValidity: boolean;
  /**
   * How long one presentation check may take, in total.
   *
   * Distinct from the per-request timeouts inside the library: a verification
   * can fetch a status list and then a CRL per certificate, so ten seconds each
   * is not ten seconds. Without a bound here a handful of wallets arriving
   * while an issuer's endpoint hangs will hold every request open until each
   * inner deadline expires in turn.
   */
  verificationTimeoutMs: number;
  limits: ServerLimits;
  shutdown: ShutdownConfig;
  trustRefresh: TrustRefreshConfig;
};

/** What one instance will hold and how fast it will let itself be asked. */
export type ServerLimits = {
  /** Most presentation sessions held at once; see `MemorySessionStore`. */
  sessions: number;
  /** `POST /presentations` allowed per client per window. Zero disables it. */
  requestsPerWindow: number;
  windowMs: number;
  /**
   * How many proxies of your own sit in front of this server.
   *
   * Zero — the default — means the socket address identifies the client, which
   * is right when nothing is in front and wrong behind a load balancer, where
   * every request then shares one key and the per-client limit becomes a global
   * one. Set it to the number of hops you operate; `clientKey` explains why a
   * count rather than a boolean.
   */
  trustedProxyHops: number;
};

export type ShutdownConfig = {
  /** Serve on for this long after readiness starts failing. */
  drainMs: number;
  /** Hard deadline for the whole shutdown. */
  graceMs: number;
};

export type TrustRefreshConfig = {
  /** Between successful trust list refreshes. */
  intervalMs: number;
  /**
   * After a failed one, doubling per consecutive failure up to `intervalMs`.
   *
   * A flat interval is the trap here: refreshing every twelve hours means a
   * failure at hour zero is not retried until hour twelve, which is long enough
   * to run past the lists' own `NextUpdate` and take the verifier out of
   * service for a blip that lasted a minute.
   */
  retryMs: number;
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

/**
 * A number from the environment, or the default, and never `NaN`.
 *
 * `Number(env(...) ?? fallback)` is the obvious spelling and it fails quietly
 * in the worst place: a typo in `SESSION_LIMIT` yields `NaN`, every comparison
 * against it is false, and the cap that was configured is simply not there. A
 * misconfigured limit has to be a startup failure, because the alternative is a
 * limit that reports itself as set and enforces nothing.
 */
function envNumber(name: string, fallback: number): number {
  const raw = env(name);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be a non-negative number, got ${raw}`);
  }
  return value;
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
  const port = envNumber('PORT', 3000);
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

  const requestedVct = env('REQUESTED_VCT') ?? PID_VCT;

  const config: Config = {
    port,
    requestedVct,
    query: ageOver18Query({ vct: requestedVct }),
    clientName: env('CLIENT_NAME') ?? 'eudi-rp-ts age check',
    baseUrl,
    // `eudi-openid4vp://` is what the live EUDI reference infrastructure emits.
    walletScheme: env('WALLET_SCHEME') ?? 'eudi-openid4vp://',
    clientIdPrefix,
    clientDnsName: env('CLIENT_DNS_NAME'),
    accessCertificateChainPem: envPem('ACCESS_CERT_CHAIN'),
    accessCertificatePrivateKeyPem: envPem('ACCESS_CERT_KEY'),
    requestTtlSeconds: envNumber('REQUEST_TTL_SECONDS', 300),
    // Accepting a credential whose revocation status you did not check is
    // accepting a revoked one. Off only for an offline demo.
    checkStatus: env('STATUS_CHECK') !== 'false',
    // Accepting a credential signed by a certificate the CA has revoked is
    // accepting an issuer that is no longer trusted to have issued it. Off only
    // for an offline demo, or where the CA's CRL endpoint is unreachable.
    checkCertificateRevocation: env('CERT_REVOCATION_CHECK') !== 'false',
    tolerateMalformedMdocValidity: env('MDOC_TOLERATE_MALFORMED_VALIDITY') === 'true',
    // Comfortably above a healthy round trip — the reference issuer's status
    // list and CRL answer in well under a second — and far below the sum of
    // every inner timeout, which is the number this exists to replace.
    verificationTimeoutMs: envNumber('VERIFICATION_TIMEOUT_MS', 30_000),
    allowedAlgs: allowedAlgs.length > 0 ? allowedAlgs : DEFAULT_ALLOWED_ALGS,
    limits: {
      // Five minutes of requests at the default TTL, which is the ceiling
      // expiry alone would leave. Generous for a demo and finite, which is the
      // property that matters.
      sessions: envNumber('SESSION_LIMIT', 10_000),
      // A person scanning a QR code needs one of these, and needs it again only
      // if they abandon the first. Thirty a minute leaves that far behind while
      // staying a long way below what makes signing and QR rendering hurt.
      requestsPerWindow: envNumber('RATE_LIMIT', 30),
      windowMs: envNumber('RATE_LIMIT_WINDOW_MS', 60_000),
      trustedProxyHops: envNumber('TRUSTED_PROXY_HOPS', 0),
    },
    shutdown: {
      // Zero because the default deployment has nothing in front of this that
      // polls readiness. Behind a load balancer, set it to at least that
      // balancer's readiness interval.
      drainMs: envNumber('SHUTDOWN_DRAIN_MS', 0),
      // Above verificationTimeoutMs on purpose: a presentation that arrived
      // just before the signal has already spent its nonce, so it is owed the
      // deadline it was given rather than the time that happens to be left.
      graceMs: envNumber('SHUTDOWN_GRACE_MS', 35_000),
    },
    trustRefresh: {
      // A service withdrawn from a trusted list should not stay trusted until
      // the next restart.
      intervalMs: envNumber('TRUST_REFRESH_MS', 12 * 60 * 60 * 1000),
      retryMs: envNumber('TRUST_REFRESH_RETRY_MS', 5 * 60 * 1000),
    },
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
