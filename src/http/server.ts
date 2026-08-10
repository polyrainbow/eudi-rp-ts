import { type IncomingMessage, type ServerResponse, createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import QRCode from 'qrcode';
import type { Config } from '../config.ts';
import { buildAuthorizationRequest } from '../oid4vp/request.ts';
import { verifyPresentationResponse } from '../oid4vp/response.ts';
import type { TrustAnchors } from '../trust/anchors.ts';
import { SessionStore } from './session.ts';

const PAGE = readFileSync(fileURLToPath(new URL('../../public/index.html', import.meta.url)), 'utf8');

/**
 * The verifier's HTTP surface. Four endpoints:
 *
 *   GET  /                      the single demo page
 *   POST /presentations         start a session -> QR code + deep link
 *   GET  /presentations/:id     poll the outcome
 *   POST /oid4vp/response       the wallet posts the VP Token here
 */
export function createVerifierServer(config: Config, anchors: TrustAnchors) {
  const sessions = new SessionStore();

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

    if (req.method === 'POST' && path === '/presentations') {
      const request = await buildAuthorizationRequest(config);
      const session = sessions.create({
        nonce: request.nonce,
        state: request.state,
        requestPayload: request.requestPayload,
        decryptionJwk: request.decryptionJwk,
        requestObject: request.requestObject,
        expiresAt: Date.now() + config.requestTtlSeconds * 1000,
      });
      json(res, 201, {
        id: session.id,
        walletUri: request.walletUri,
        qrCodeDataUri: await QRCode.toDataURL(request.walletUri, { errorCorrectionLevel: 'M', margin: 1 }),
        expiresAt: new Date(session.expiresAt).toISOString(),
      });
      return;
    }

    // The wallet dereferences `request_uri` to fetch the signed request object.
    // It is served by reference rather than embedded in the QR because the x5c
    // chain makes the request far too large to encode.
    const requestObject = /^\/oid4vp\/request\/([\w-]+)$/.exec(path);
    if (req.method === 'GET' && requestObject) {
      const session = sessions.getByRequestObjectId(requestObject[1]!);
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
      const session = sessions.get(poll[1]!);
      if (!session) {
        json(res, 404, { status: 'rejected', reason: 'SESSION_EXPIRED' });
        return;
      }
      json(res, 200, { status: session.status, result: session.result ?? null });
      return;
    }

    if (req.method === 'POST' && path === '/oid4vp/response') {
      await handleWalletResponse(req, res);
      return;
    }

    json(res, 404, { error: 'not_found' });
  }

  /**
   * The wallet's `direct_post`. Body is form-encoded with `vp_token` and
   * `state` (OID4VP 1.0 §8.1), or a single `response` JWT for `direct_post.jwt`.
   */
  async function handleWalletResponse(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    const form = Object.fromEntries(new URLSearchParams(body));

    // For direct_post.jwt the state is inside the encrypted JWT, so it can only
    // be read after decryption. Try the cleartext form first.
    const session = form['state'] ? sessions.getByState(form['state']) : undefined;
    if (!session) {
      // Without a session there is no nonce to check the presentation against,
      // so there is nothing safe to do here.
      json(res, 400, { error: 'invalid_request', reason: 'SESSION_UNKNOWN' });
      return;
    }

    const parsedResponse: Record<string, unknown> = form['response']
      ? { response: form['response'] }
      : { ...form, vp_token: safeJsonParse(form['vp_token']) };

    const outcome = await verifyPresentationResponse(
      {
        config,
        anchors,
        nonce: session.nonce,
        requestPayload: session.requestPayload,
        decryptionJwk: session.decryptionJwk,
      },
      parsedResponse,
    );

    sessions.complete(
      session,
      outcome.verified
        ? {
            verified: true,
            evidence: outcome.value.evidence,
            vct: outcome.value.vct,
            issuer: outcome.value.issuerCertificateSubject,
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

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
  res.end(payload);
}
