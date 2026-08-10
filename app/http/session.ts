import { randomUUID } from 'node:crypto';
import type { JWK } from 'jose';
import type { ReasonCode } from '../../src/result.ts';

/**
 * In-memory presentation sessions.
 *
 * No persistence layer by design (see README non-goals). Restarting the server
 * drops in-flight sessions, which is fine for a demo and not fine for anything
 * else.
 */
export type SessionStatus = 'pending' | 'verified' | 'rejected';

export type Session = {
  id: string;
  /** OID4VP `nonce`, replayed by the wallet inside the Key Binding JWT. */
  nonce: string;
  /** OID4VP `state`, echoed by the wallet and checked by the OID4VP layer. */
  state: string;
  /** Identifies this session in the `response_uri` path. */
  responseId: string;
  /** The exact request payload we sent, needed to validate the response. */
  requestPayload: Record<string, unknown>;
  /** Ephemeral private key for `direct_post.jwt` response decryption. */
  decryptionJwk: JWK | undefined;
  /** Signed request object, fetched by the wallet from `request_uri`. */
  requestObject: { id: string; jwt: string } | undefined;
  expiresAt: number;
  status: SessionStatus;
  result:
    | { verified: true; format: string; evidence: string; vct: string; issuer: string }
    | { verified: false; reason: ReasonCode; detail: string }
    | undefined;
};

export class SessionStore {
  readonly #sessions = new Map<string, Session>();
  readonly #byResponseId = new Map<string, string>();
  readonly #byRequestObjectId = new Map<string, string>();

  create(input: Omit<Session, 'id' | 'status' | 'result'>): Session {
    this.#evictExpired();
    const session: Session = { ...input, id: randomUUID(), status: 'pending', result: undefined };
    this.#sessions.set(session.id, session);
    this.#byResponseId.set(session.responseId, session.id);
    if (session.requestObject) this.#byRequestObjectId.set(session.requestObject.id, session.id);
    return session;
  }

  get(id: string): Session | undefined {
    const session = this.#sessions.get(id);
    return session && session.expiresAt > Date.now() ? session : undefined;
  }

  /** Look a session up by the id in the `response_uri` the wallet posted to. */
  getByResponseId(responseId: string): Session | undefined {
    const id = this.#byResponseId.get(responseId);
    return id === undefined ? undefined : this.get(id);
  }

  /** Look a session up by the id in its `request_uri`. */
  getByRequestObjectId(requestObjectId: string): Session | undefined {
    const id = this.#byRequestObjectId.get(requestObjectId);
    return id === undefined ? undefined : this.get(id);
  }

  complete(session: Session, result: NonNullable<Session['result']>): void {
    session.status = result.verified ? 'verified' : 'rejected';
    session.result = result;
    // A nonce is single use: once answered, the response URI stops resolving.
    this.#byResponseId.delete(session.responseId);
  }

  #evictExpired(): void {
    const now = Date.now();
    for (const [id, session] of this.#sessions) {
      if (session.expiresAt <= now) {
        this.#sessions.delete(id);
        this.#byResponseId.delete(session.responseId);
        if (session.requestObject) this.#byRequestObjectId.delete(session.requestObject.id);
      }
    }
  }
}
