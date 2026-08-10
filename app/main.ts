import { loadConfig } from './config.ts';
import { createVerifierServer } from './http/server.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { fetchTrustAnchors } from '../src/trust/lotl.ts';

const config = loadConfig();

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

createVerifierServer(config, anchors).listen(config.port, () => {
  console.log(`\neudi-rp-ts listening on http://localhost:${config.port}`);
  console.log(`  public base:   ${config.baseUrl}`);
  console.log(`  client_id:     ${config.clientIdPrefix}`);
  console.log(`  wallet scheme: ${config.walletScheme}`);
  console.log(`  requested vct: ${config.requestedVct}`);
});
