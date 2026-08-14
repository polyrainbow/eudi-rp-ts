import { randomUUID } from 'node:crypto';
import type { JWK } from 'jose';
import type { ReasonCode } from '../../src/result.ts';

/**
 * Presentation sessions: the interface, and the in-memory implementation the
 * demo runs on.
 *
 * The interface exists because the implementation is the thing that stops this
 * server running as more than one process. A `Map` is right for a demo and
 * wrong for anything else: restarting drops in-flight presentations, and with
 * two instances the wallet's POST and the browser's poll land on different ones
 * about half the time. Swapping in a shared store is now implementing
 * `SessionStore`, not editing `server.ts`.
 *
 * Two properties of this interface are what make a remote implementation
 * possible rather than merely typeable, and neither is obvious from the
 * signatures alone:
 *
 *  - **Every operation is asynchronous**, including the reads. A synchronous
 *    interface would be implementable over a `Map` and over nothing else.
 *  - **`Session` is JSON-serialisable, deliberately.** The private key in
 *    `decryptionJwk` is a JWK rather than a `KeyObject` for exactly this
 *    reason. Anything added to it that is not JSON makes the interface a
 *    promise this codebase cannot keep — and note what that key is: a store
 *    outside this process holds ephemeral response-decryption keys, so it is
 *    secret material at rest, not session bookkeeping.
 */
export type SessionStatus = 'pending' | 'verified' | 'rejected';

export type SessionResult =
  /**
   * A list, because one presentation can answer a query that asked for several
   * credentials. The age query offers two formats as alternatives, so this demo
   * always sees exactly one — which is a property of the query it sends, not of
   * the verifier.
   */
  | {
      verified: true;
      evidence: string | undefined;
      credentials: { format: string; credentialType: string; issuer: string }[];
    }
  | { verified: false; reason: ReasonCode; detail: string };

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
  result: SessionResult | undefined;
};

/** What the server supplies; the store assigns the rest. */
export type NewSession = Omit<Session, 'id' | 'status' | 'result'>;

export interface SessionStore {
  /**
   * Start a session.
   *
   * Throws `SessionCapacityError` when the store is full. Refusing rather than
   * making room is the deliberate half: evicting the oldest pending session to
   * admit a new one lets whoever is flooding `/presentations` push out the
   * sessions of people who actually scanned a code, which turns a bounded queue
   * into a way of cancelling other people's checks.
   */
  create(input: NewSession): Promise<Session>;

  /** By presentation id — what the browser polls with. Expired is absent. */
  get(id: string): Promise<Session | undefined>;

  /** By the id in the session's `request_uri`, which the wallet dereferences. */
  getByRequestObjectId(requestObjectId: string): Promise<Session | undefined>;

  /**
   * Take the session a `response_uri` belongs to, and make that URI stop
   * resolving in the same step.
   *
   * **The atomicity is the contract**, not an implementation detail: an OID4VP
   * `nonce` is single use, and a store that answers two concurrent posts to the
   * same response URI with the same session has agreed to verify a replay. The
   * URI is retired before verification rather than after it, so a second post
   * arriving while the first is still fetching a status list gets nothing —
   * which is also why an implementation must not offer a plain
   * `getByResponseId` and let the caller delete afterwards. Over a KV store
   * this is one atomic take (Redis `GETDEL`), not a get and a delete.
   */
  claimByResponseId(responseId: string): Promise<Session | undefined>;

  /** Record the verdict. The session stays readable until it expires. */
  complete(session: Session, result: SessionResult): Promise<void>;
}

/** The store is full. Distinct from any verification outcome: nothing was asked. */
export class SessionCapacityError extends Error {
  constructor(limit: number) {
    super(`session store is at its limit of ${limit}`);
    this.name = 'SessionCapacityError';
  }
}

export type MemorySessionStoreOptions = {
  /**
   * Most sessions held at once.
   *
   * Expiry alone does not bound this: `requestTtlSeconds` is five minutes by
   * default, so the ceiling without a cap is however many requests reach
   * `/presentations` in five minutes. The rate limiter in `rate-limit.ts` is
   * the first line and this is the backstop, because a limiter keyed on the
   * client cannot bound what a large enough number of clients does.
   */
  maxSessions: number;
  /** Injectable clock, for tests. */
  now?: () => number;
};

export class MemorySessionStore implements SessionStore {
  readonly #sessions = new Map<string, Session>();
  readonly #byResponseId = new Map<string, string>();
  readonly #byRequestObjectId = new Map<string, string>();
  readonly #maxSessions: number;
  readonly #now: () => number;

  constructor(options: MemorySessionStoreOptions) {
    this.#maxSessions = options.maxSessions;
    this.#now = options.now ?? Date.now;
  }

  create(input: NewSession): Promise<Session> {
    // Sweeping first means the cap is reached only by sessions that are still
    // live, so a burst that has since expired costs nothing.
    this.#evictExpired();
    if (this.#sessions.size >= this.#maxSessions) {
      return Promise.reject(new SessionCapacityError(this.#maxSessions));
    }
    const session: Session = { ...input, id: randomUUID(), status: 'pending', result: undefined };
    this.#sessions.set(session.id, session);
    this.#byResponseId.set(session.responseId, session.id);
    if (session.requestObject) this.#byRequestObjectId.set(session.requestObject.id, session.id);
    return Promise.resolve(session);
  }

  get(id: string): Promise<Session | undefined> {
    return Promise.resolve(this.#live(id));
  }

  getByRequestObjectId(requestObjectId: string): Promise<Session | undefined> {
    const id = this.#byRequestObjectId.get(requestObjectId);
    return Promise.resolve(id === undefined ? undefined : this.#live(id));
  }

  claimByResponseId(responseId: string): Promise<Session | undefined> {
    const id = this.#byResponseId.get(responseId);
    if (id === undefined) return Promise.resolve(undefined);
    // Atomic here by construction: nothing awaits between the read and the
    // delete, so no second caller can observe the index still populated.
    this.#byResponseId.delete(responseId);
    return Promise.resolve(this.#live(id));
  }

  complete(session: Session, result: SessionResult): Promise<void> {
    session.status = result.verified ? 'verified' : 'rejected';
    session.result = result;
    return Promise.resolve();
  }

  /** Sessions currently held, expired ones included. For tests and readiness. */
  get size(): number {
    return this.#sessions.size;
  }

  #live(id: string): Session | undefined {
    const session = this.#sessions.get(id);
    return session && session.expiresAt > this.#now() ? session : undefined;
  }

  #evictExpired(): void {
    const now = this.#now();
    for (const [id, session] of this.#sessions) {
      if (session.expiresAt <= now) {
        this.#sessions.delete(id);
        this.#byResponseId.delete(session.responseId);
        if (session.requestObject) this.#byRequestObjectId.delete(session.requestObject.id);
      }
    }
  }
}
