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
import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import QRCode from 'qrcode';

const BASE = process.env['RPRS_BASE'] ?? 'https://registry.serviceproviders.eudiw.dev';
const POLL_INTERVAL_MS = 3000;
const TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Write the QR as a PNG and open it.
 *
 * Terminal QR codes are drawn with half-block characters, which only line up
 * when the terminal renders lines with no leading. Most add a little, and the
 * gaps between rows are enough to stop a scanner reading the code. A PNG has
 * no such problem.
 */
async function showQrCode(url: string): Promise<void> {
  const file = join(tmpdir(), `eudi-rp-registration-${Date.now()}.png`);
  await writeFile(file, await QRCode.toBuffer(url, { errorCorrectionLevel: 'M', margin: 2, width: 512 }));

  const opener = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  spawn(opener, [file], { stdio: 'ignore', detached: true, shell: process.platform === 'win32' })
    .on('error', () => {})
    .unref();

  console.log(`QR code: ${file}`);
}

/**
 * `/getpidoid4vp` advertises `produces: application/json`, but its documented
 * 200 schema is a bare `string` and the service sends the hash unquoted — so
 * the body is text, and `response.json()` throws on it. Accept the object form
 * too, so this keeps working if that is ever tightened.
 */
function parseHashPid(body: string): string | undefined {
  const text = body.trim();
  if (!text) return undefined;
  if (text.startsWith('{')) return (JSON.parse(text) as { hash_pid?: string }).hash_pid;
  return text.replace(/^"|"$/g, '');
}

const start = await fetch(`${BASE}/authentication`);
if (!start.ok) throw new Error(`${BASE}/authentication: HTTP ${start.status}`);
const { QR_code_url, presentation_id } = (await start.json()) as {
  QR_code_url: string;
  presentation_id: string;
};

await showQrCode(QR_code_url);
console.log('\nScan it with the EUDI reference wallet (it must already hold a PID).');
console.log('On the phone itself, this deep link works directly:\n');
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

  const hashPid = parseHashPid(await pid.text());
  if (!hashPid) continue;

  console.log(`\n\nhash_pid: ${hashPid}\n`);
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
