import { decodeProtectedHeader, verifyEs256 } from '../crypto.ts';
import { DEFAULT_TIMEOUT_MS, TtlCache, fetchText } from '../fetching.ts';
import type { TrustAnchors } from './anchors.ts';
import { resolveIssuerKeyFromX5c } from './issuer-key.ts';

/**
 * Token Status List checking for SD-JWT VC.
 *
 * A credential's `status.status_list` names a URI and an index. The URI serves
 * a signed JWT holding a compressed bitstring; the bit at that index says
 * whether the credential is still valid. The EU reference issuer publishes one
 * for every PID it issues — see `test/fixtures/real/`.
 *
 * `@sd-jwt/sd-jwt-vc` drives the flow but leaves two things to the relying
 * party, both of which matter:
 *
 *  - fetching the list, and
 *  - *verifying the list's own signature*, which it refuses to do without a
 *    `statusVerifier`.
 *
 * The second is the point. An unauthenticated status list would let anyone who
 * can answer an HTTP request declare any credential valid. The list is signed
 * by the same document signer as the credential and carries its own `x5c`, so
 * it is chained to the same trust anchors.
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
};

/**
 * A cache suitable for status lists.
 *
 * The TTL is the window in which a revocation is not yet visible, so it trades
 * freshness against load on the issuer. Five minutes is a starting point, not
 * a recommendation for every deployment.
 */
export function createStatusListCache(ttlMs = 5 * 60_000): TtlCache<string> {
  return new TtlCache<string>({ ttlMs });
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

export function createStatusChecker(options: StatusCheckOptions): StatusChecker {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  // The verifier callback gets only (data, signature) — no header, no token. So
  // the fetched list is kept here for the verifier to resolve a key from.
  let fetched: string | undefined;

  let outcome: StatusOutcome = { kind: 'not-checked' };

  const load = async (uri: string): Promise<string> => {
    const { body, contentType } = await fetchText(uri, {
      headers: { Accept: STATUS_LIST_JWT },
      timeoutMs,
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    });
    if (!contentType.includes('application/statuslist+jwt')) {
      throw new Error(`Status list ${uri}: unexpected content type ${contentType}`);
    }
    return body.trim();
  };

  return {
    get outcome() {
      return outcome;
    },

    async statusListFetcher(uri: string): Promise<string> {
      try {
        fetched = options.cache ? await options.cache.get(uri, () => load(uri)) : await load(uri);
        return fetched;
      } catch (error) {
        outcome = {
          kind: 'unavailable',
          detail: error instanceof Error ? error.message : String(error),
        };
        throw error;
      }
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

      // `typ` is what distinguishes a status list token from any other JWT the
      // same issuer signs. Without checking it, a credential could be replayed
      // as its own status list.
      let header: Record<string, unknown>;
      try {
        header = decodeProtectedHeader(fetched);
      } catch {
        outcome = { kind: 'unavailable', detail: 'Status list is not a decodable JWT' };
        return false;
      }
      if (header['typ'] !== 'statuslist+jwt') {
        outcome = { kind: 'unavailable', detail: `Status list typ is ${String(header['typ'])}` };
        return false;
      }

      const issuer = resolveIssuerKeyFromX5c(fetched, options.anchors, options.now);
      if (!issuer.verified) {
        outcome = { kind: 'unavailable', detail: `Status list signer untrusted: ${issuer.detail}` };
        return false;
      }

      const ok = verifyEs256(issuer.value.publicKey, data, signature);
      if (!ok) outcome = { kind: 'unavailable', detail: 'Status list signature is not valid' };
      return ok;
    },
  };
}
