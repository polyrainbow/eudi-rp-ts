import { loadConfig } from './config.ts';
import { createVerifierServer } from './http/server.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { fetchTrustAnchors } from '../src/trust/lotl.ts';

const config = loadConfig();

/** Re-read every 12 hours: a service withdrawn from a trusted list should not
 * stay trusted until the next restart. A refresh that fails keeps the previous
 * anchors rather than leaving the verifier with none. */
const TRUST_LIST_REFRESH_MS = 12 * 60 * 60 * 1000;

let anchors: TrustAnchors;
if (config.trust.mode === 'lotl') {
  console.log(`Fetching trust list: ${config.trust.lotlUrl}`);
  const result = await fetchTrustAnchors(config.trust, { territories: config.trust.territories });
  anchors = result.anchors;
  for (const source of result.sources) {
    console.log(`  ${source.territory}  ${source.services} service certificate(s)  ${source.url}`);
  }
  for (const failure of result.failures) {
    console.warn(`  FAILED  ${failure.url}: ${failure.error}`);
  }
  console.log(`Trust anchors: ${anchors.certificates.length}`);
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
      console.log(`Trust list refreshed: ${anchors.certificates.length} anchors`);
    } catch (error) {
      console.warn(`Trust list refresh failed, keeping ${anchors.certificates.length} anchors:`, error);
    }
  }, TRUST_LIST_REFRESH_MS);
  timer.unref();
}

createVerifierServer(config, () => anchors).listen(config.port, () => {
  console.log(`\neudi-rp-ts listening on http://localhost:${config.port}`);
  console.log(`  public base:   ${config.baseUrl}`);
  console.log(`  client_id:     ${config.clientIdPrefix}`);
  console.log(`  wallet scheme: ${config.walletScheme}`);
  console.log(`  requested vct: ${config.requestedVct}`);
});
