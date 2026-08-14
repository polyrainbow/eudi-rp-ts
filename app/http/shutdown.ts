import type { Server } from 'node:http';

/**
 * Stop serving without dropping work that is already in flight.
 *
 * A container runtime redeploys by sending SIGTERM and killing what is left
 * after its own grace period. Node's default handler for SIGTERM exits
 * immediately, so without this every redeploy severs whatever verifications
 * were mid-flight — and a verification here can be several seconds of fetching
 * a status list and then a CRL per certificate. The wallet has already posted
 * by then, and its `nonce` is spent, so the presentation cannot be retried:
 * the person holding the phone sees a check that never answers.
 *
 * Three steps, in this order, because each one only works if the previous one
 * has happened:
 *
 *  1. **Fail readiness.** A load balancer stops sending new requests here.
 *  2. **Wait `drainMs`.** Readiness is polled, not pushed, so between the probe
 *     failing and the balancer acting there is a window in which requests are
 *     still being routed to this instance. Closing the listener inside that
 *     window turns a graceful shutdown into refused connections. Zero is the
 *     right value with no balancer in front, which is why it is the default.
 *  3. **Close the listener, then wait for in-flight requests.** `close` stops
 *     accepting and calls back once the last response is finished;
 *     `closeIdleConnections` retires keep-alive sockets that are holding it open
 *     with no request on them, which otherwise delays that callback until the
 *     client times out.
 *
 * `graceMs` bounds the whole thing. It wants to be longer than
 * `verificationTimeoutMs` — a request that arrived just before the signal is
 * entitled to its full deadline — and shorter than whatever the platform
 * allows before SIGKILL, since being killed is exactly what this avoids.
 */
export type ShutdownOptions = {
  /** How long to keep serving after readiness starts failing. */
  drainMs: number;
  /** Hard deadline for the whole shutdown, measured from the signal. */
  graceMs: number;
  /** Called first, to make readiness fail. */
  onDraining?: () => void;
  /** Injected in tests, so a test never exits the runner. */
  exit?: (code: number) => void;
  log?: (message: string) => void;
};

export const SHUTDOWN_SIGNALS: NodeJS.Signals[] = ['SIGTERM', 'SIGINT'];

export function installShutdownHandlers(server: Server, options: ShutdownOptions): () => void {
  const exit = options.exit ?? ((code: number) => process.exit(code));
  const log = options.log ?? ((message: string) => console.log(message));
  let started = false;

  const shutdown = (signal: NodeJS.Signals): void => {
    if (started) {
      // A second signal is an operator saying they are done waiting. Honour it:
      // the alternative is that impatience gets you SIGKILL from the platform
      // instead, which is strictly worse than exiting on request.
      log(`${signal} again, exiting now`);
      exit(1);
      return;
    }
    started = true;
    log(`${signal} received, draining`);
    options.onDraining?.();

    const deadline = setTimeout(() => {
      log(`shutdown exceeded ${options.graceMs}ms, closing connections`);
      server.closeAllConnections();
      exit(1);
    }, options.graceMs);
    deadline.unref();

    const stopListening = setTimeout(() => {
      server.close(() => {
        clearTimeout(deadline);
        log('shutdown complete');
        exit(0);
      });
      server.closeIdleConnections();
    }, options.drainMs);
    stopListening.unref();
  };

  const handlers = SHUTDOWN_SIGNALS.map((signal) => {
    const handler = (): void => shutdown(signal);
    process.on(signal, handler);
    return { signal, handler };
  });

  // Returned so a test — or an embedder that owns its own signal handling —
  // can take them off again. Leaving them attached is what a long-lived
  // process wants and what a test suite very much does not.
  return () => {
    for (const { signal, handler } of handlers) process.off(signal, handler);
  };
}
