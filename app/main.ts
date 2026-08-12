import { loadConfig } from './config.ts';
import { createVerifierServer } from './http/server.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { fetchTrustAnchors } from '../src/trust/lotl.ts';

const config = loadConfig();

/** Re-read every 12 hours: a service withdrawn from a trusted list should not
 * stay trusted until the next restart. A refresh that fails keeps the previous
 * anchors rather than leaving the verifier with none — but only until they pass
 * the lists' own `NextUpdate`; see `trustUnusable` below. */
const TRUST_LIST_REFRESH_MS = 12 * 60 * 60 * 1000;

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

if (config.trust.mode === 'lotl') {
  const timer = setInterval(async () => {
    try {
      const refreshed = await fetchTrustAnchors(config.trust, { territories: config.trust.territories });
      anchors = refreshed.anchors;
      anchorsValidUntil = refreshed.validUntil;
      console.log(`Trust list refreshed: ${anchors.certificates.length} anchors`);
    } catch (error) {
      console.warn(`Trust list refresh failed, keeping ${anchors.certificates.length} anchors:`, error);
    }
  }, TRUST_LIST_REFRESH_MS);
  timer.unref();
}

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

createVerifierServer(config, () => anchors, { trustUnusable }).listen(config.port, () => {
  console.log(`\neudi-rp-ts listening on http://localhost:${config.port}`);
  console.log(`  public base:   ${config.baseUrl}`);
  console.log(`  client_id:     ${config.clientIdPrefix}`);
  console.log(`  wallet scheme: ${config.walletScheme}`);
  console.log(`  requested vct: ${config.requestedVct}`);
});
