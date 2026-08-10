/**
 * Starts authentication against the EU's *Testing* Relying Party Registration
 * service and waits for you to present a PID.
 *
 *   npm run register-rp
 *
 * The service issues access certificates under the EUDI Wallet Reference
 * Implementation's trust list, which is what makes the reference wallet accept
 * this verifier. Every one of its endpoints is keyed on `hash_pid`, and the
 * only way to obtain that is to present a PID from a wallet — so this script
 * gets you as far as the QR code and then waits for your phone.
 *
 * It deliberately stops at `hash_pid`. The remaining registration steps submit
 * your real legal identity, the attributes you intend to request and your
 * intended use; those are yours to enter, not something to generate. Continue
 * from the Swagger UI at https://registry.serviceproviders.eudiw.dev/apidocs/.
 */
import QRCode from 'qrcode';

const BASE = process.env['RPRS_BASE'] ?? 'https://registry.serviceproviders.eudiw.dev';
const POLL_INTERVAL_MS = 3000;
const TIMEOUT_MS = 5 * 60 * 1000;

const start = await fetch(`${BASE}/authentication`);
if (!start.ok) throw new Error(`${BASE}/authentication: HTTP ${start.status}`);
const { QR_code_url, presentation_id } = (await start.json()) as {
  QR_code_url: string;
  presentation_id: string;
};

console.log(await QRCode.toString(QR_code_url, { type: 'terminal', small: true }));
console.log('Scan with the EUDI reference wallet (it must already hold a PID), or open:\n');
console.log(`  ${QR_code_url}\n`);

const deadline = Date.now() + TIMEOUT_MS;
process.stdout.write('Waiting for the PID presentation');

while (Date.now() < deadline) {
  await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  process.stdout.write('.');

  const authorized = await fetch(
    `${BASE}/pid_authorization?presentation_id=${encodeURIComponent(presentation_id)}`,
  );
  if (!authorized.ok) continue;

  const pid = await fetch(`${BASE}/getpidoid4vp?presentation_id=${encodeURIComponent(presentation_id)}`, {
    method: 'POST',
  });
  if (!pid.ok) continue;

  const body = (await pid.json()) as { hash_pid?: string };
  if (!body.hash_pid) continue;

  console.log(`\n\nhash_pid: ${body.hash_pid}\n`);
  console.log('Every other endpoint takes this as `hash_pid`. Remaining steps, in order:');
  console.log('  law -> legal_person -> identifier -> legal_entity -> policy -> provider');
  console.log('  -> credential -> intended_use -> supervisory_authority -> wallet_rp');
  console.log('  -> POST /wallet_rp/certificate   (returns PKCS#12)');
  console.log(`\nSwagger UI: ${BASE}/apidocs/`);
  console.log('\nThen convert the P12 — see "Access certificates" in the README.');
  process.exit(0);
}

console.error('\n\nTimed out. Re-run to get a fresh QR code.');
process.exit(1);
