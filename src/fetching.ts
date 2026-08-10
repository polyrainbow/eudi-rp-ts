/**
 * Outbound HTTP with a deadline, and a small cache.
 *
 * Verification depends on resources hosted by other people: status lists at the
 * issuer, trust lists at a Member State. Without a timeout, one slow endpoint
 * stalls a verification indefinitely and, under load, exhausts the caller. And
 * without a cache, every single verification refetches a status list that can
 * run to megabytes — slow for the verifier and abusive toward the issuer.
 *
 * Deliberately small: no retries, no backoff, no connection pooling. A caller
 * that needs those can pass its own `fetch`.
 */
export type FetchOptions = {
  /** Abort and fail after this many milliseconds. */
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
};

export const DEFAULT_TIMEOUT_MS = 10_000;

/** Fetch text, failing rather than hanging. */
export async function fetchText(
  url: string,
  init: RequestInit & FetchOptions = {},
): Promise<{ body: string; contentType: string }> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = fetch, ...rest } = init;

  // AbortSignal.timeout covers the whole request including the body, which
  // setTimeout around the fetch call alone would not.
  const response = await fetchImpl(url, { ...rest, signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) {
    throw new Error(`${url}: HTTP ${response.status}`);
  }
  return { body: await response.text(), contentType: response.headers.get('content-type') ?? '' };
}

export type CacheOptions = {
  /** How long an entry stays fresh. */
  ttlMs: number;
  /** Maximum entries retained; the oldest is evicted first. */
  maxEntries?: number;
  /** Injectable clock, for tests. */
  now?: () => number;
};

/**
 * A time-to-live cache that collapses concurrent misses.
 *
 * The in-flight map matters more than the cache: without it, a burst of
 * verifications against the same status list issues one request each. With it,
 * they share a single response.
 */
export class TtlCache<T> {
  readonly #entries = new Map<string, { value: T; expiresAt: number }>();
  readonly #inFlight = new Map<string, Promise<T>>();
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;

  constructor(options: CacheOptions) {
    this.#ttlMs = options.ttlMs;
    this.#maxEntries = options.maxEntries ?? 64;
    this.#now = options.now ?? Date.now;
  }

  async get(key: string, load: () => Promise<T>): Promise<T> {
    const cached = this.#entries.get(key);
    if (cached && cached.expiresAt > this.#now()) return cached.value;

    const existing = this.#inFlight.get(key);
    if (existing) return existing;

    const pending = load()
      .then((value) => {
        this.#entries.set(key, { value, expiresAt: this.#now() + this.#ttlMs });
        this.#evict();
        return value;
      })
      .finally(() => {
        this.#inFlight.delete(key);
      });

    this.#inFlight.set(key, pending);
    return pending;
  }

  /** Drop an entry, e.g. after a verification failure that it may have caused. */
  delete(key: string): void {
    this.#entries.delete(key);
  }

  get size(): number {
    return this.#entries.size;
  }

  #evict(): void {
    while (this.#entries.size > this.#maxEntries) {
      const oldest = this.#entries.keys().next();
      if (oldest.done) return;
      this.#entries.delete(oldest.value);
    }
  }
}
