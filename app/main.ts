import { loadConfig } from './config.ts';
import { createVerifierServer } from './http/server.ts';
import { installShutdownHandlers } from './http/shutdown.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { fetchTrustAnchors } from '../src/trust/lotl.ts';

const config = loadConfig();

let anchors: TrustAnchors;
/**
 * When the loaded lists stop being current, for trust list mode.
 *
 * Undefined for pinned anchors: a PEM file is an operator's standing decision
 * with no publication schedule to outlive.
 */
let anchorsValidUntil: Date | undefined;

if (config.trust.mode === 'lotl') {
  console.log(`Fetching trust list: ${config.trust.lotlUrl}`);
  const result = await fetchTrustAnchors(config.trust, { territories: config.trust.territories });
  anchors = result.anchors;
  anchorsValidUntil = result.validUntil;
  for (const source of result.sources) {
    console.log(`  ${source.territory}  ${source.services} service certificate(s)  ${source.url}`);
  }
  for (const failure of result.failures) {
    console.warn(`  FAILED  ${failure.url}: ${failure.error}`);
  }
  console.log(`Trust anchors: ${anchors.certificates.length}`);
  if (anchorsValidUntil) {
    console.log(`  current until ${anchorsValidUntil.toISOString()} (earliest NextUpdate)`);
  }
} else {
  anchors = TrustAnchors.fromPem(config.trust.pinnedAnchorsPem!);
  console.log(`Trust anchors: ${anchors.certificates.length} (pinned)`);
}

if (/^https:\/\/localhost/.test(config.baseUrl)) {
  console.warn(
    '\nBASE_URL is still https://localhost — a wallet on a phone cannot reach that.\n' +
      'Set BASE_URL to a public https URL (e.g. a tunnel) before scanning the QR code.',
  );
}

/**
 * Re-read the trust lists, on a schedule that reacts to failure.
 *
 * A refresh that fails keeps the previous anchors rather than leaving the
 * verifier with none — but only until they pass the lists' own `NextUpdate`;
 * see `trustUnusable` below. That is what makes the retry interval a
 * availability decision rather than a housekeeping one: the gap between a
 * failure and the next attempt is time spent walking towards refusing all
 * traffic. So failures back off from `retryMs` instead of waiting out the full
 * `intervalMs`, doubling per consecutive failure so a long outage does not turn
 * into a tight loop against an endpoint that is already struggling.
 *
 * A chain of timeouts rather than `setInterval`, because the delay is not
 * constant and because an interval fires again whether or not the previous
 * fetch has finished — which against 42 national lists is how you end up with
 * several refreshes running at once.
 */
function scheduleTrustRefresh(delayMs: number, consecutiveFailures = 0): void {
  // ±10%, so that instances started together do not synchronise on the same
  // endpoint for the life of the deployment.
  const jittered = delayMs * (0.9 + Math.random() * 0.2);
  const timer = setTimeout(() => {
    void (async () => {
      try {
        const refreshed = await fetchTrustAnchors(config.trust, { territories: config.trust.territories });
        anchors = refreshed.anchors;
        anchorsValidUntil = refreshed.validUntil;
        console.log(`Trust list refreshed: ${anchors.certificates.length} anchors`);
        scheduleTrustRefresh(config.trustRefresh.intervalMs);
      } catch (error) {
        const failures = consecutiveFailures + 1;
        const backoff = Math.min(
          config.trustRefresh.retryMs * 2 ** (failures - 1),
          config.trustRefresh.intervalMs,
        );
        console.warn(
          `Trust list refresh failed (${failures} in a row), keeping ${anchors.certificates.length} anchors, ` +
            `retrying in ${Math.round(backoff / 1000)}s:`,
          error,
        );
        scheduleTrustRefresh(backoff, failures);
      }
    })();
    // unref so a pending refresh never holds the process open during shutdown.
  }, jittered);
  timer.unref();
}

if (config.trust.mode === 'lotl') scheduleTrustRefresh(config.trustRefresh.intervalMs);

/**
 * Why the anchor set can no longer be relied on, or undefined while it can.
 *
 * Refreshing keeps the previous anchors when it fails, which is right for an
 * endpoint that is briefly unreachable and wrong once the lists themselves have
 * lapsed: at that point the set in memory is precisely the stale copy
 * `checkTrustListFreshness` refuses on the way in. Keeping it because it
 * happens to already be loaded would put the check on the door and leave the
 * window open.
 */
function trustUnusable(): string | undefined {
  if (!anchorsValidUntil || Date.now() <= anchorsValidUntil.getTime()) return undefined;
  return (
    `the loaded trust lists were current only until ${anchorsValidUntil.toISOString()} ` +
    `and every refresh since has failed`
  );
}

/**
 * Set before the listener closes, so `/readyz` fails while requests already in
 * flight are still being answered. The two have to be separable: a readiness
 * probe that only fails once the socket is shut is telling a load balancer
 * something it has already found out the hard way.
 */
let draining = false;

const server = createVerifierServer(config, () => anchors, {
  trustUnusable,
  draining: () => draining,
});

server.listen(config.port, () => {
  console.log(`\neudi-rp-ts listening on http://localhost:${config.port}`);
  console.log(`  public base:   ${config.baseUrl}`);
  console.log(`  client_id:     ${config.clientIdPrefix}`);
  console.log(`  wallet scheme: ${config.walletScheme}`);
  console.log(`  requested vct: ${config.requestedVct}`);
  console.log(`  session limit: ${config.limits.sessions}`);
  console.log(
    `  rate limit:    ${config.limits.requestsPerWindow || 'off'} per ${config.limits.windowMs}ms per client`,
  );
});

installShutdownHandlers(server, {
  drainMs: config.shutdown.drainMs,
  graceMs: config.shutdown.graceMs,
  onDraining: () => {
    draining = true;
  },
});
