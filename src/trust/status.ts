import { inflateSync } from 'node:zlib';
import type { KeyObject } from 'node:crypto';
import { decodeProtectedHeader, decodeUnverifiedPayload, verifyEs256 } from '../crypto.ts';
import { DEFAULT_TIMEOUT_MS, TtlCache, fetchText } from '../fetching.ts';
import type { TrustAnchors } from './anchors.ts';
import { resolveIssuerKeyFromX5c } from './issuer-key.ts';

/**
 * Token Status List checking, for both credential formats.
 *
 * A credential's status reference names a URI and an index — `status.status_list`
 * in an SD-JWT VC's claims, the same structure in an mdoc's MobileSecurityObject.
 * The URI serves a signed JWT holding a compressed bitstring; the bit at that
 * index says whether the credential is still valid. The EU reference issuer
 * publishes one for every PID it issues, in *both* formats — see
 * `test/fixtures/real/`.
 *
 * Two entry points, because the two formats arrive here differently:
 *
 *  - `createStatusChecker` supplies the three callbacks `@sd-jwt/sd-jwt-vc`
 *    demands. It drives the flow but leaves fetching and *verifying the list's
 *    own signature* to us, refusing to proceed without a `statusVerifier`.
 *  - `checkStatusList` is the whole check in one call, for mdoc, where no
 *    library drives anything.
 *
 * Both run the same validation, which is the point: a status list is only worth
 * fetching if it is authenticated. An unauthenticated one would let anyone who
 * can answer an HTTP request declare any credential valid. The list is signed by
 * the same document signer as the credential and carries its own `x5c`, so it is
 * chained to the same trust anchors.
 */
export type StatusCheckOptions = {
  anchors: TrustAnchors;
  now: Date;
  /** Injectable for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Abort a status list request after this long. */
  timeoutMs?: number;
  /**
   * Shared cache. Status lists cover many credentials, so without one every
   * verification refetches the same document. Omit to disable caching.
   */
  cache?: TtlCache<string>;
  /** Tolerance for clock differences with the issuer, in seconds. */
  clockSkewSeconds?: number;
};

/** Where a credential says its status bit lives. */
export type StatusListReference = {
  /** `status.status_list.uri` — where the list is published. */
  uri: string;
  /** `status.status_list.idx` — this credential's index into the bitstring. */
  index: number;
};

/**
 * A cache suitable for status lists.
 *
 * The TTL is the window in which a revocation is not yet visible, so it trades
 * freshness against load on the issuer. Five minutes is a starting point, not
 * a recommendation for every deployment.
 *
 * Failures are cached too, briefly. Status checking fails closed, so an issuer
 * whose endpoint is down rejects every credential it issued either way — but
 * without a negative TTL each of those rejections first waits out the full
 * request timeout and holds a socket, which turns the issuer's outage into an
 * outage here. Thirty seconds bounds the retry rate while still recovering
 * promptly once the endpoint returns.
 */
export function createStatusListCache(ttlMs = 5 * 60_000, errorTtlMs = 30_000): TtlCache<string> {
  return new TtlCache<string>({ ttlMs, errorTtlMs });
}

/**
 * What the status check concluded, recorded rather than inferred.
 *
 * `@sd-jwt` reports failures by throwing, and the only thing distinguishing a
 * revoked credential from an unreachable status endpoint is the wording of the
 * message. Matching on that wording breaks silently when the library rephrases
 * it — which is exactly what happened when a fetch helper changed one string.
 * So the checker records its own outcome and the caller reads it.
 */
export type StatusOutcome =
  | { kind: 'not-checked' }
  | { kind: 'valid' }
  | { kind: 'revoked'; status: number }
  | { kind: 'unavailable'; detail: string };

export type StatusChecker = {
  statusListFetcher: (uri: string) => Promise<string>;
  statusVerifier: (data: string, signature: string) => boolean;
  statusValidator: (status: number) => Promise<void>;
  /** Read after verification to see what the status check decided. */
  readonly outcome: StatusOutcome;
};

/** Media type for a status list token (IETF Token Status List). */
const STATUS_LIST_JWT = 'application/statuslist+jwt';

async function loadStatusListToken(uri: string, options: StatusCheckOptions): Promise<string> {
  const { body, contentType } = await fetchText(uri, {
    headers: { Accept: STATUS_LIST_JWT },
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
  });
  if (!contentType.includes('application/statuslist+jwt')) {
    throw new Error(`Status list ${uri}: unexpected content type ${contentType}`);
  }
  return body.trim();
}

/**
 * The checks that bind a fetched token to *this* credential's status reference
 * and to now. Returns a detail string when one fails, `undefined` when they pass.
 *
 * Deliberately separate from the signature check, and run before it, because of
 * where each one has to happen on the SD-JWT path: `@sd-jwt/core`'s `Jwt.verify`
 * validates `exp` itself and throws *before* it calls `statusVerifier`, so
 * anything checked in that callback arrives too late to record an outcome — and
 * the rejection then surfaces as a malformed credential rather than an
 * unusable status list. Everything here therefore runs in the fetcher, which
 * `@sd-jwt` calls first. Both must pass; neither is sufficient alone.
 */
function inspectStatusListToken(
  token: string,
  uri: string,
  options: StatusCheckOptions,
): string | undefined {
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(token);
    payload = decodeUnverifiedPayload(token);
  } catch {
    return 'Status list is not a decodable JWT';
  }

  // `typ` is what distinguishes a status list token from any other JWT the same
  // issuer signs. Without checking it, a credential could be replayed as its
  // own status list.
  if (header['typ'] !== 'statuslist+jwt') {
    return `Status list typ is ${String(header['typ'])}`;
  }

  // The Status List Token's `sub` MUST equal the `uri` the credential pointed
  // at. The signature proves a trusted issuer produced *some* status list; only
  // this proves it is the one this credential's index refers to. Without it,
  // anyone able to answer at that URI — a redirect, a stale cache, a hijacked
  // name — can substitute a different list that the same trust anchors happily
  // validate, and index into it instead.
  if (payload['sub'] !== uri) {
    return `Status list sub is ${String(payload['sub'])}, expected ${uri}`;
  }

  const skew = options.clockSkewSeconds ?? 0;
  const nowSeconds = Math.floor(options.now.getTime() / 1000);
  const exp = payload['exp'];
  if (typeof exp === 'number' && exp + skew < nowSeconds) {
    return `Status list expired at ${new Date(exp * 1000).toISOString()}`;
  }
  const iat = payload['iat'];
  if (typeof iat === 'number' && iat - skew > nowSeconds) {
    return `Status list is not yet valid (iat ${new Date(iat * 1000).toISOString()})`;
  }

  return undefined;
}

/** The signer's key, if its `x5c` chains to the anchors. */
function resolveStatusListSigner(
  token: string,
  options: StatusCheckOptions,
): { ok: true; publicKey: KeyObject } | { ok: false; detail: string } {
  const issuer = resolveIssuerKeyFromX5c(token, options.anchors, options.now);
  return issuer.verified
    ? { ok: true, publicKey: issuer.value.publicKey }
    : { ok: false, detail: `Status list signer untrusted: ${issuer.detail}` };
}

/**
 * Read one status out of the token's bitstring.
 *
 * `lst` is base64url over a zlib-compressed byte array in which statuses are
 * packed `bits` at a time, first status in the *least* significant bits of the
 * first byte (draft-ietf-oauth-status-list §4.1).
 */
function readStatusAt(
  token: string,
  index: number,
): { ok: true; status: number } | { ok: false; detail: string } {
  let statusList: unknown;
  try {
    statusList = decodeUnverifiedPayload(token)['status_list'];
  } catch {
    return { ok: false, detail: 'Status list is not a decodable JWT' };
  }
  if (typeof statusList !== 'object' || statusList === null) {
    return { ok: false, detail: 'Status list token has no status_list claim' };
  }

  const { bits, lst } = statusList as { bits?: unknown; lst?: unknown };
  if (bits !== 1 && bits !== 2 && bits !== 4 && bits !== 8) {
    return { ok: false, detail: `Status list bits is ${String(bits)}, must be 1, 2, 4 or 8` };
  }
  if (typeof lst !== 'string') {
    return { ok: false, detail: 'Status list lst is not a string' };
  }

  let bytes: Buffer;
  try {
    bytes = inflateSync(Buffer.from(lst, 'base64url'));
  } catch (error) {
    return { ok: false, detail: `Status list lst does not decompress: ${String(error)}` };
  }

  const perByte = 8 / bits;
  if (!Number.isInteger(index) || index < 0 || index >= bytes.length * perByte) {
    // An index past the end is the issuer and the credential disagreeing about
    // the list. Treating it as "not revoked" would be reading a bit that was
    // never published.
    return { ok: false, detail: `Status index ${index} is outside a list of ${bytes.length * perByte}` };
  }

  const byte = bytes[Math.floor(index / perByte)]!;
  const status = (byte >> ((index % perByte) * bits)) & ((1 << bits) - 1);
  return { ok: true, status };
}

/**
 * Check a status reference end to end: fetch, authenticate, read the bit.
 *
 * Used by the mdoc path, where nothing else drives the flow. Never throws —
 * everything it can conclude is a `StatusOutcome`, and the caller maps that to
 * a reason code. `unavailable` is a rejection, not a pass: see `verifyMdoc`.
 */
export async function checkStatusList(
  reference: StatusListReference,
  options: StatusCheckOptions,
): Promise<StatusOutcome> {
  let token: string;
  try {
    token = options.cache
      ? await options.cache.get(reference.uri, () => loadStatusListToken(reference.uri, options))
      : await loadStatusListToken(reference.uri, options);
  } catch (error) {
    return { kind: 'unavailable', detail: error instanceof Error ? error.message : String(error) };
  }

  const problem = inspectStatusListToken(token, reference.uri, options);
  if (problem) return { kind: 'unavailable', detail: problem };

  const signer = resolveStatusListSigner(token, options);
  if (!signer.ok) return { kind: 'unavailable', detail: signer.detail };

  const [header, payload, signature] = token.split('.');
  if (!header || !payload || !signature) {
    return { kind: 'unavailable', detail: 'Status list is not a compact JWS' };
  }
  if (!verifyEs256(signer.publicKey, `${header}.${payload}`, signature)) {
    return { kind: 'unavailable', detail: 'Status list signature is not valid' };
  }

  const status = readStatusAt(token, reference.index);
  if (!status.ok) return { kind: 'unavailable', detail: status.detail };

  return status.status === 0 ? { kind: 'valid' } : { kind: 'revoked', status: status.status };
}

export function createStatusChecker(options: StatusCheckOptions): StatusChecker {
  // The verifier callback gets only (data, signature) — no header, no token. So
  // the fetched list is kept here for the verifier to resolve a key from.
  let fetched: string | undefined;

  let outcome: StatusOutcome = { kind: 'not-checked' };

  return {
    get outcome() {
      return outcome;
    },

    async statusListFetcher(uri: string): Promise<string> {
      let token: string;
      try {
        token = options.cache
          ? await options.cache.get(uri, () => loadStatusListToken(uri, options))
          : await loadStatusListToken(uri, options);
      } catch (error) {
        outcome = {
          kind: 'unavailable',
          detail: error instanceof Error ? error.message : String(error),
        };
        throw error;
      }

      // Runs on a cache hit too, and must: a token cached while fresh can
      // expire before its entry does.
      const problem = inspectStatusListToken(token, uri, options);
      if (problem) {
        outcome = { kind: 'unavailable', detail: problem };
        throw new Error(problem);
      }

      fetched = token;
      return token;
    },

    async statusValidator(status: number): Promise<void> {
      if (status !== 0) {
        outcome = { kind: 'revoked', status };
        throw new Error(`Credential status is ${status}`);
      }
      outcome = { kind: 'valid' };
    },

    statusVerifier(data: string, signature: string): boolean {
      if (!fetched) return false;

      const signer = resolveStatusListSigner(fetched, options);
      if (!signer.ok) {
        outcome = { kind: 'unavailable', detail: signer.detail };
        return false;
      }

      const ok = verifyEs256(signer.publicKey, data, signature);
      if (!ok) outcome = { kind: 'unavailable', detail: 'Status list signature is not valid' };
      return ok;
    },
  };
}
