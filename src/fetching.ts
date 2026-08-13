/**
 * Outbound HTTP with a deadline, a size limit, and a small cache.
 *
 * Verification depends on resources hosted by other people: status lists at the
 * issuer, trust lists at a Member State. Every one of those URLs is read out of
 * a document that arrived over the network, so what this module allows is a
 * policy decision rather than plumbing:
 *
 *  - **A deadline.** Without one, a slow endpoint stalls a verification
 *    indefinitely and, under load, exhausts the caller.
 *  - **A byte limit.** A deadline alone bounds nothing: a body that arrives
 *    steadily for ten seconds can still be gigabytes, and `response.text()`
 *    buffers all of it.
 *  - **A redirect limit, and https on every hop.** The fetch specification
 *    already caps redirects at twenty, which is far more indirection than any
 *    of these endpoints needs, and it will happily follow one down to http.
 *    A trust list served over http cannot be forged — it is signature-checked —
 *    but it can be replayed, and an old list still grants a CA that has since
 *    been withdrawn.
 *  - **A cache, optionally remembering failures.** Without it every
 *    verification refetches a status list that can run to megabytes.
 *
 * Deliberately small: no retries, no backoff, no connection pooling. A caller
 * that needs those can pass its own `fetch`.
 */
export type FetchOptions = {
  /** Abort and fail after this many milliseconds, redirects included. */
  timeoutMs?: number;
  /** Refuse a response body larger than this. */
  maxBytes?: number;
  /** Redirect hops to follow. Every hop is re-checked against the policy. */
  maxRedirects?: number;
  /** URL schemes this fetch is willing to speak, as `URL.protocol` values. */
  allowedProtocols?: readonly string[];
  fetchImpl?: typeof fetch;
  /**
   * The caller's cancellation, combined with `timeoutMs` rather than replacing
   * it: the deadline is this module's policy and the signal is the caller's
   * reason, and whichever fires first wins.
   *
   * `RequestInit` already declares a `signal`, and until this existed one
   * passed there was destructured into the fetch call and then silently
   * overwritten by the internal timeout — accepted, ignored, no error.
   */
  signal?: AbortSignal;
};

export const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * A ceiling for the general case: comfortably above any status list, far below
 * what would hurt. Trust lists are the one caller that needs more, and asks for
 * it explicitly — see `src/trust/lotl.ts`.
 */
export const DEFAULT_MAX_BYTES = 10_000_000;

export const DEFAULT_MAX_REDIRECTS = 3;

export const DEFAULT_ALLOWED_PROTOCOLS: readonly string[] = ['https:'];

/** Fetch text, failing rather than hanging, and rather than growing forever. */
export async function fetchText(
  url: string,
  init: RequestInit & FetchOptions = {},
): Promise<{ body: string; contentType: string }> {
  const { body, contentType } = await fetchBytes(url, init);
  return { body: Buffer.from(body).toString('utf8'), contentType };
}

/**
 * The same, for content that is not text.
 *
 * CRLs and OCSP responses are DER, and decoding them as UTF-8 first would
 * corrupt them — every policy above applies unchanged.
 */
export async function fetchBytes(
  url: string,
  init: RequestInit & FetchOptions = {},
): Promise<{ body: Uint8Array; contentType: string }> {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = DEFAULT_MAX_BYTES,
    maxRedirects = DEFAULT_MAX_REDIRECTS,
    allowedProtocols = DEFAULT_ALLOWED_PROTOCOLS,
    fetchImpl = fetch,
    signal: callerSignal,
    ...rest
  } = init;

  // One deadline for the whole exchange rather than one per hop: a redirect
  // chain whose hops each answer just inside the timeout is the same stall as a
  // single endpoint that never answers.
  //
  // AbortSignal.timeout covers the request including the body, which a
  // setTimeout around the fetch call alone would not.
  //
  // The caller's signal is combined with it, not chosen between: this module's
  // deadline bounds one request, the caller's signal bounds whatever it is
  // doing, and neither subsumes the other.
  const deadline = AbortSignal.timeout(timeoutMs);
  const signal = callerSignal ? AbortSignal.any([callerSignal, deadline]) : deadline;

  let target = url;
  for (let hop = 0; ; hop += 1) {
    requireAllowedProtocol(target, allowedProtocols, url);

    // Redirects are followed here rather than by fetch, so that every hop goes
    // through the protocol check above and the count below.
    const response = await fetchImpl(target, { ...rest, redirect: 'manual', signal });

    if (!isRedirect(response.status)) {
      if (!response.ok) {
        await discard(response);
        throw new Error(`${url}: HTTP ${response.status}`);
      }
      return {
        body: await readCapped(response, url, maxBytes),
        contentType: response.headers.get('content-type') ?? '',
      };
    }

    const location = response.headers.get('location');
    await discard(response);
    if (!location) {
      throw new Error(`${url}: HTTP ${response.status} without a Location header`);
    }
    if (hop >= maxRedirects) {
      throw new Error(`${url}: more than ${maxRedirects} redirects`);
    }
    target = new URL(location, target).toString();
  }
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function requireAllowedProtocol(target: string, allowed: readonly string[], original: string): void {
  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    throw new Error(`${original}: ${target} is not a valid URL`);
  }
  if (!allowed.includes(parsed.protocol)) {
    throw new Error(`${original}: ${parsed.protocol}// is not allowed (${allowed.join(' ')})`);
  }
}

/**
 * Read a body, stopping at the limit rather than after it.
 *
 * `Content-Length` is checked first because it is free, but it is a claim by
 * the sender and chunked responses omit it. The count while reading is the
 * enforcement; the header only saves a transfer we know will fail.
 */
async function readCapped(response: Response, url: string, maxBytes: number): Promise<Uint8Array> {
  const declared = response.headers.get('content-length');
  if (declared !== null && Number(declared) > maxBytes) {
    await discard(response);
    throw new Error(`${url}: declared ${declared} bytes, limit is ${maxBytes}`);
  }

  if (!response.body) return new Uint8Array(0);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      // Cancel rather than break: the point is to stop the transfer, not to
      // let it finish into a buffer we then throw away.
      await reader.cancel();
      throw new Error(`${url}: body exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

/** Release a body we are not going to read, so the socket is not held open. */
async function discard(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // A body already consumed or errored is exactly what we wanted.
  }
}

export type CacheOptions = {
  /** How long a value stays fresh. */
  ttlMs: number;
  /**
   * How long a *failure* is remembered. Zero — the default — retries on the
   * next call, which is the right behaviour for a cache holding values and the
   * wrong one for a service: see `createStatusListCache`.
   */
  errorTtlMs?: number;
  /** Maximum entries retained; the oldest is evicted first. */
  maxEntries?: number;
  /** Injectable clock, for tests. */
  now?: () => number;
};

type Entry<T> = { expiresAt: number } & ({ ok: true; value: T } | { ok: false; error: unknown });

/**
 * A time-to-live cache that collapses concurrent misses.
 *
 * The in-flight map matters more than the cache: without it, a burst of
 * verifications against the same status list issues one request each. With it,
 * they share a single response.
 */
export class TtlCache<T> {
  readonly #entries = new Map<string, Entry<T>>();
  readonly #inFlight = new Map<string, Promise<T>>();
  readonly #ttlMs: number;
  readonly #errorTtlMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;

  constructor(options: CacheOptions) {
    this.#ttlMs = options.ttlMs;
    this.#errorTtlMs = options.errorTtlMs ?? 0;
    this.#maxEntries = options.maxEntries ?? 64;
    this.#now = options.now ?? Date.now;
  }

  async get(key: string, load: () => Promise<T>): Promise<T> {
    const cached = this.#entries.get(key);
    if (cached) {
      if (cached.expiresAt > this.#now()) {
        // A remembered failure is rethrown as it was recorded, so the caller
        // still reads the original reason — for a status list that is the
        // difference between STATUS_UNAVAILABLE and a shrug.
        if (!cached.ok) throw cached.error;
        return cached.value;
      }
      this.#entries.delete(key);
    }

    const existing = this.#inFlight.get(key);
    if (existing) return existing;

    const pending = load()
      .then(
        (value) => {
          this.#store(key, { ok: true, value, expiresAt: this.#now() + this.#ttlMs });
          return value;
        },
        (error: unknown) => {
          if (this.#errorTtlMs > 0) {
            this.#store(key, { ok: false, error, expiresAt: this.#now() + this.#errorTtlMs });
          }
          throw error;
        },
      )
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

  #store(key: string, entry: Entry<T>): void {
    this.#entries.set(key, entry);
    this.#evict();
  }

  #evict(): void {
    while (this.#entries.size > this.#maxEntries) {
      const oldest = this.#entries.keys().next();
      if (oldest.done) return;
      this.#entries.delete(oldest.value);
    }
  }
}
