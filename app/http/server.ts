import { type IncomingMessage, type ServerResponse, createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import QRCode from 'qrcode';
import { auditPresentation, auditSink } from '../audit.ts';
import type { Config } from '../config.ts';
import { buildAuthorizationRequest } from '../../src/oid4vp/request.ts';
import { verifyPresentationResponse } from '../../src/oid4vp/response.ts';
import { ageOver18Predicate } from '../../src/presets/age-over-18.ts';
import type { TrustAnchors } from '../../src/trust/anchors.ts';
import { createStatusListCache } from '../../src/trust/status.ts';
import { createRevocationCache } from '../../src/trust/revocation.ts';
import { RateLimiter, clientKey } from './rate-limit.ts';
import { MemorySessionStore, SessionCapacityError, type SessionStore } from './session.ts';

const PAGE = readFileSync(fileURLToPath(new URL('../public/index.html', import.meta.url)), 'utf8');

/**
 * The verifier's HTTP surface. Four endpoints, plus two probes:
 *
 *   GET  /                      the single demo page
 *   POST /presentations         start a session -> QR code + deep link
 *   GET  /presentations/:id     poll the outcome
 *   POST /oid4vp/response/:id   the wallet posts the VP Token here
 *   GET  /healthz               liveness
 *   GET  /readyz                readiness
 */
/**
 * @param getAnchors called per request, so a refreshed trust list takes effect
 *   without a restart.
 * @param options.trustUnusable asked before each new presentation, and by
 *   `/readyz`; a string means the anchor set can no longer be relied on, and why.
 * @param options.draining true once shutdown has begun, so `/readyz` fails
 *   before the listener closes.
 * @param options.sessions where sessions live. Constructed here only as a
 *   default: an in-memory store is what a demo wants and the reason this server
 *   cannot yet run as more than one process, so a deployment that needs to
 *   scale passes its own.
 */
export function createVerifierServer(
  config: Config,
  getAnchors: TrustAnchors | (() => TrustAnchors),
  options: {
    trustUnusable?: () => string | undefined;
    draining?: () => boolean;
    sessions?: SessionStore;
  } = {},
) {
  const sessions = options.sessions ?? new MemorySessionStore({ maxSessions: config.limits.sessions });
  const anchorsNow = typeof getAnchors === 'function' ? getAnchors : () => getAnchors;
  // One cache each for the process: a status list covers many credentials, and
  // a CRL covers every certificate its CA ever issued.
  const statusCache = createStatusListCache();
  const revocationCache = createRevocationCache();
  const rateLimiter = new RateLimiter({
    limit: config.limits.requestsPerWindow,
    windowMs: config.limits.windowMs,
  });

  return createServer((req, res) => {
    handle(req, res).catch((error) => {
      console.error('unhandled error', error);
      json(res, 500, { error: 'internal_error' });
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', config.baseUrl);
    const path = url.pathname;

    if (req.method === 'GET' && path === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(PAGE);
      return;
    }

    // Liveness: is this process running. Deliberately says nothing about trust
    // anchors or shutdown — a liveness probe that fails for those reasons gets
    // the container restarted, and restarting fixes neither a Member State's
    // unreachable trust list nor a shutdown already under way.
    if (req.method === 'GET' && path === '/healthz') {
      json(res, 200, { status: 'ok' });
      return;
    }

    // Readiness: should traffic be sent here. Both reasons it can be no are
    // states this server already knew about and had no way to say.
    if (req.method === 'GET' && path === '/readyz') {
      const draining = options.draining?.() ?? false;
      const unusable = options.trustUnusable?.();
      const anchors = anchorsNow().certificates.length;
      if (draining) {
        json(res, 503, { status: 'draining', anchors });
      } else if (unusable) {
        json(res, 503, { status: 'trust_anchors_stale', detail: unusable, anchors });
      } else {
        json(res, 200, { status: 'ready', anchors });
      }
      return;
    }

    if (req.method === 'POST' && path === '/presentations') {
      await startPresentation(req, res);
      return;
    }

    // The wallet dereferences `request_uri` to fetch the signed request object.
    // It is served by reference rather than embedded in the QR because the x5c
    // chain makes the request far too large to encode.
    const requestObject = /^\/oid4vp\/request\/([\w-]+)$/.exec(path);
    if (req.method === 'GET' && requestObject) {
      const session = await sessions.getByRequestObjectId(requestObject[1]!);
      if (!session?.requestObject) {
        json(res, 404, { error: 'invalid_request_uri' });
        return;
      }
      // RFC 9101 media type for a JWT-Secured Authorization Request.
      res.writeHead(200, { 'content-type': 'application/oauth-authz-req+jwt' });
      res.end(session.requestObject.jwt);
      return;
    }

    const poll = /^\/presentations\/([\w-]+)$/.exec(path);
    if (req.method === 'GET' && poll) {
      const session = await sessions.get(poll[1]!);
      if (!session) {
        json(res, 404, { status: 'rejected', reason: 'SESSION_EXPIRED' });
        return;
      }
      json(res, 200, { status: session.status, result: session.result ?? null });
      return;
    }

    const walletResponse = /^\/oid4vp\/response\/([\w-]+)$/.exec(path);
    if (req.method === 'POST' && walletResponse) {
      await handleWalletResponse(req, res, walletResponse[1]!);
      return;
    }

    json(res, 404, { error: 'not_found' });
  }

  /**
   * Start a session and hand back the QR code.
   *
   * Three ways to decline, and they are different things rather than three
   * spellings of "no": the caller is asking too often, this instance is holding
   * as many sessions as it will, or the anchors are stale and so the question
   * cannot honestly be asked at all.
   */
  async function startPresentation(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Before anything is built: everything below this line costs a signature or
    // a QR render, and the point of a limit is to refuse ahead of the cost.
    const limit = rateLimiter.take(clientKey(req, config.limits.trustedProxyHops));
    if (!limit.allowed) {
      json(res, 429, { error: 'rate_limited' }, { 'retry-after': String(limit.retryAfterSeconds) });
      return;
    }

    // Refuse here rather than let the verification fail later. Anchors we can
    // no longer confirm produce a rejection that reads as "your credential is
    // not trusted", which blames the holder for our own stale trust list;
    // declining to ask the question says the true thing instead.
    const unusable = options.trustUnusable?.();
    if (unusable) {
      json(res, 503, { error: 'trust_anchors_stale', detail: unusable });
      return;
    }

    // Built before the capacity check rather than after, because `create` needs
    // the nonce, state and response id this produces. So a refusal at capacity
    // still costs one signature — which is why the rate limiter above it is the
    // thing that bounds how often anyone can ask, and this is a memory bound.
    const request = await buildAuthorizationRequest(config, config.query);
    let session;
    try {
      session = await sessions.create({
        nonce: request.nonce,
        state: request.state,
        requestPayload: request.requestPayload,
        decryptionJwk: request.decryptionJwk,
        requestObject: request.requestObject,
        responseId: request.responseId,
        expiresAt: Date.now() + config.requestTtlSeconds * 1000,
      });
    } catch (error) {
      if (!(error instanceof SessionCapacityError)) throw error;
      // 503 with Retry-After rather than 429: the caller has not done anything
      // wrong and slowing that one caller down would not help, because what is
      // full is shared. The wait is until sessions expire, so the request TTL
      // is the honest estimate.
      console.warn(`refusing a presentation: ${error.message}`);
      json(res, 503, { error: 'at_capacity' }, { 'retry-after': String(config.requestTtlSeconds) });
      return;
    }

    // The first line of this presentation's trail, and the one that
    // introduces the correlation id every later line carries.
    auditPresentation(session.id, 'presentation.requested', {
      vct: config.requestedVct,
      clientIdPrefix: config.clientIdPrefix,
    });
    json(res, 201, {
      id: session.id,
      walletUri: request.walletUri,
      qrCodeDataUri: await QRCode.toDataURL(request.walletUri, { errorCorrectionLevel: 'M', margin: 1 }),
      expiresAt: new Date(session.expiresAt).toISOString(),
    });
  }

  /**
   * The wallet's `direct_post`. Body is form-encoded with `vp_token` and
   * `state` (OID4VP 1.0 §8.1), or a single `response` JWT for `direct_post.jwt`.
   *
   * The session comes from the URL, not the body: under `direct_post.jwt` the
   * `state` is sealed inside the encrypted response, and the session is what
   * holds the key needed to open it.
   */
  async function handleWalletResponse(
    req: IncomingMessage,
    res: ServerResponse,
    responseId: string,
  ): Promise<void> {
    const body = await readBody(req);
    const form = Object.fromEntries(new URLSearchParams(body));

    // Claimed, not looked up: this retires the response URI in the same step,
    // so a second post arriving while this one is still fetching a status list
    // finds nothing. A nonce is single use, and "single" has to hold against
    // two posts at once, not only against two in sequence.
    const session = await sessions.claimByResponseId(responseId);
    if (!session) {
      // Without a session there is no nonce to check the presentation against,
      // so there is nothing safe to do here.
      //
      // Audited under the response id rather than a session id, because there
      // is no session — an expired one, a replayed nonce, or a wallet posting
      // somewhere it invented. That is worth a line precisely because no
      // verifier will run and so the library will emit nothing.
      auditPresentation(responseId, 'presentation.rejected', { reason: 'SESSION_UNKNOWN' });
      json(res, 400, { error: 'invalid_request', reason: 'SESSION_UNKNOWN' });
      return;
    }

    const parsedResponse: Record<string, unknown> = form['response']
      ? { response: form['response'] }
      : { ...form, vp_token: safeJsonParse(form['vp_token']) };

    const outcome = await verifyPresentationResponse(
      {
        config,
        anchors: anchorsNow(),
        statusCache,
        revocationCache,
        tolerateMalformedMdocValidity: config.tolerateMalformedMdocValidity,
        nonce: session.nonce,
        requestPayload: session.requestPayload,
        decryptionJwk: session.decryptionJwk,
        onEvent: auditSink(session.id),
        // The demo's question, applied to whatever the query brought back. The
        // library verifies credentials; deciding that they mean "18 or over" is
        // the relying party's, and this is where that is said.
        predicate: ageOver18Predicate,
        // A bound on the whole check, which the per-request timeouts inside the
        // library are not: one verification can fetch a status list and then a
        // CRL per certificate.
        //
        // Deliberately *not* tied to the wallet's connection. Aborting when the
        // wallet hangs up would be the obvious move and is wrong here: under
        // `direct_post` the browser is polling for the same outcome, so
        // discarding the work leaves the session pending until it expires and
        // the person who scanned the code never hears an answer.
        signal: AbortSignal.timeout(config.verificationTimeoutMs),
      },
      parsedResponse,
    );

    await sessions.complete(
      session,
      outcome.verified
        ? {
            verified: true,
            evidence: outcome.value.predicate.evidence,
            credentials: outcome.value.credentials.map((credential) => ({
              format: credential.format,
              credentialType: credential.credentialType,
              issuer: credential.issuerCertificateSubject,
            })),
          }
        : { verified: false, reason: outcome.reason, detail: outcome.detail },
    );

    // The wallet gets a bare acknowledgement either way: whether the check
    // passed is the relying party's business, not the wallet's.
    json(res, 200, {});
  }
}

function safeJsonParse(value: string | undefined): unknown {
  if (value === undefined) return undefined;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 1_000_000) throw new Error('Request body too large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    ...headers,
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}
