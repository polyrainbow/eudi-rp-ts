import { decodeProtectedHeader, verifyEs256 } from '../crypto.ts';
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
};

export type StatusChecker = {
  statusListFetcher: (uri: string) => Promise<string>;
  statusVerifier: (data: string, signature: string) => boolean;
};

/** Media type for a status list token (IETF Token Status List). */
const STATUS_LIST_JWT = 'application/statuslist+jwt';

export function createStatusChecker(options: StatusCheckOptions): StatusChecker {
  const doFetch = options.fetchImpl ?? fetch;

  // The verifier callback gets only (data, signature) — no header, no token. So
  // the fetched list is kept here for the verifier to resolve a key from.
  let fetched: string | undefined;

  return {
    async statusListFetcher(uri: string): Promise<string> {
      const response = await doFetch(uri, { headers: { Accept: STATUS_LIST_JWT } });
      if (!response.ok) {
        throw new Error(`Status list ${uri}: HTTP ${response.status}`);
      }
      const contentType = response.headers.get('content-type') ?? '';
      if (!contentType.includes('application/statuslist+jwt')) {
        throw new Error(`Status list ${uri}: unexpected content type ${contentType}`);
      }
      fetched = (await response.text()).trim();
      return fetched;
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
        return false;
      }
      if (header['typ'] !== 'statuslist+jwt') return false;

      const issuer = resolveIssuerKeyFromX5c(fetched, options.anchors, options.now);
      if (!issuer.verified) return false;

      return verifyEs256(issuer.value.publicKey, data, signature);
    },
  };
}
