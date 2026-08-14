import type { IncomingMessage } from 'node:http';

/**
 * A fixed-window request counter, keyed on the client.
 *
 * `POST /presentations` is the endpoint worth bounding: each call mints a
 * session, builds and signs a request object, and renders a QR code. None of
 * that requires the caller to hold anything, so without a limit the cost of
 * asking is a fraction of the cost of answering — which is the shape of every
 * amplification problem.
 *
 * The polling endpoint is deliberately not limited. A browser polls it about
 * once a second for the life of a presentation, so a limit low enough to matter
 * would break the demo and one high enough not to would bound nothing; the work
 * behind a poll is a map lookup either way.
 *
 * Fixed window rather than a token bucket: its one flaw is that a client can
 * spend a full window's allowance either side of a boundary, and twice a small
 * number is still a small number. What it buys is a limit an operator can
 * predict from the two numbers they set.
 */
export type RateLimitOptions = {
  /** Requests allowed per key per window. Zero disables the limiter. */
  limit: number;
  windowMs: number;
  /**
   * Distinct keys tracked at once.
   *
   * A limiter that remembers every client it has ever seen is itself the memory
   * exhaustion it was added to prevent, so this is not a tuning knob. When the
   * table is full the oldest window is dropped to make room, which means a
   * client rotating through enough addresses can keep evicting its own record
   * and escape the limit. That is the honest trade — the alternative, refusing
   * unknown keys once full, lets the same attacker lock out everyone else — and
   * it is why the session cap in `session.ts` exists behind this rather than
   * instead of it.
   */
  maxKeys?: number;
  /** Injectable clock, for tests. */
  now?: () => number;
};

export type RateLimitDecision = { allowed: true } | { allowed: false; retryAfterSeconds: number };

const DEFAULT_MAX_KEYS = 10_000;

export class RateLimiter {
  readonly #windows = new Map<string, { count: number; resetAt: number }>();
  readonly #limit: number;
  readonly #windowMs: number;
  readonly #maxKeys: number;
  readonly #now: () => number;

  constructor(options: RateLimitOptions) {
    this.#limit = options.limit;
    this.#windowMs = options.windowMs;
    this.#maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
    this.#now = options.now ?? Date.now;
  }

  take(key: string): RateLimitDecision {
    if (this.#limit <= 0) return { allowed: true };

    const now = this.#now();
    const current = this.#windows.get(key);
    if (!current || current.resetAt <= now) {
      this.#windows.delete(key);
      this.#evict(now);
      this.#windows.set(key, { count: 1, resetAt: now + this.#windowMs });
      return { allowed: true };
    }

    if (current.count >= this.#limit) {
      // Rounded up, so the advice is never "retry now" for a window that has
      // not actually turned over.
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((current.resetAt - now) / 1000)) };
    }

    current.count += 1;
    return { allowed: true };
  }

  /** Windows currently tracked. For tests. */
  get size(): number {
    return this.#windows.size;
  }

  #evict(now: number): void {
    if (this.#windows.size < this.#maxKeys) return;
    for (const [key, window] of this.#windows) {
      if (window.resetAt <= now) this.#windows.delete(key);
    }
    // Insertion order is window-start order, so the first entry is the one
    // closest to expiring anyway.
    while (this.#windows.size >= this.#maxKeys) {
      const oldest = this.#windows.keys().next();
      if (oldest.done) return;
      this.#windows.delete(oldest.value);
    }
  }
}

/**
 * Which client a request is from, for rate limiting.
 *
 * `X-Forwarded-For` is a header, which means it is whatever the client typed
 * unless something in front of this server overwrites it — so trusting it by
 * default would hand every caller a way to be a new client on every request,
 * and the limiter would bound nothing at all. Trusting nothing by default is
 * the opposite failure and is the safer one, but it is still a failure: behind
 * a proxy every request carries the same socket address, so an untrusted-header
 * limiter degrades into a single global limit where one abuser blocks everyone.
 *
 * `hops` is how many proxies of your own the request passes through, so an
 * operator states their topology rather than a boolean. With `hops = n` the
 * client is the nth entry from the right, because appending is what a
 * conforming proxy does (RFC 7239 §5.2 makes the same point about `Forwarded`):
 * entries to the left of that are the client's to write and are ignored. Too
 * few entries means the header did not come from those proxies, so the socket
 * address is used instead of a value that was never vouched for.
 */
export function clientKey(req: IncomingMessage, hops: number): string {
  const socketAddress = req.socket.remoteAddress ?? 'unknown';
  if (hops <= 0) return socketAddress;

  const header = req.headers['x-forwarded-for'];
  const raw = Array.isArray(header) ? header.join(',') : header;
  if (!raw) return socketAddress;

  const entries = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  return entries[entries.length - hops] ?? socketAddress;
}
