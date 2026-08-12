import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { parsePointers, parseTrustServices, verifyTrustList } from '../src/trust/lotl.ts';
import { readNameConstraints } from '../src/trust/name-constraints.ts';
import { checkChainRevocation, readOcspResponders } from '../src/trust/revocation.ts';

/**
 * Has the world changed?
 *
 * Distinct from every other network test here, and the distinction is the whole
 * point of the file. Those ask *does our code still work against live
 * infrastructure* — a failure there is a bug. These ask *is what REPRODUCE.md
 * says still true* — a failure here means *nothing in `src/` is broken* and the
 * EU deployment has moved.
 *
 * That matters because several decisions in this project rest on measurements
 * rather than on reasoning, and a measurement goes stale silently. "Failing
 * closed on an unimplemented name form costs nothing" is true because 2 of 1897
 * anchors carry the extension and both use forms we implement. "Requiring
 * StatusStartingTime loses nothing" is true because every service published
 * carries one. Neither is true by construction; both are true today.
 *
 * So each assertion here fails **loudly, with what to do about it**, on the same
 * reasoning as `fixture-freshness.test.ts`: a scheduled job that warns is a job
 * nobody reads. Some of these failures would be *good* news — an OCSP responder
 * appearing, an upstream bug fixed — and a red build is still the only way to
 * find out.
 *
 * Runs weekly in `.github/workflows/network.yml`, never in the offline suite.
 */
const online = process.env['RUN_NETWORK_TESTS'] === '1';
const skip = online ? false : 'set RUN_NETWORK_TESTS=1';

const anchorDir = fileURLToPath(new URL('../anchors/', import.meta.url));
const fixtureDir = fileURLToPath(new URL('./fixtures/real/', import.meta.url));

const PID_ISSUER_CA_AIA = 'https://preprod.pki.eudiw.dev/aia/PIDIssuerCA02-UT.cacert.pem';
const JWT_VC_ISSUER_METADATA = 'https://issuer.eudiw.dev/.well-known/jwt-vc-issuer';
const EU_LOTL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

/** Prefix every failure, so CI output says what kind of failure it is. */
const news = (what: string, then: string) =>
  `EU INFRASTRUCTURE CHANGED — nothing in src/ is broken.\n\n  ${what}\n\n  Then: ${then}`;

describe('the reference PKI', { skip }, () => {
  it('still uses the CA certificate committed in anchors/', async () => {
    // Deployments point TRUST_ANCHORS_FILE at this file. If the EU rotates the
    // PID Issuer CA, every one of them starts rejecting every credential, and
    // nothing else here would notice until that happened in production.
    const response = await fetch(PID_ISSUER_CA_AIA);
    assert.equal(response.status, 200, `${PID_ISSUER_CA_AIA} did not answer`);

    const live = new X509Certificate(await response.text());
    const committed = new X509Certificate(
      readFileSync(`${anchorDir}eudiw-pid-issuer-ca.pem`, 'utf8'),
    );

    assert.equal(
      live.fingerprint256,
      committed.fingerprint256,
      news(
        `The PID Issuer CA published at ${PID_ISSUER_CA_AIA} is no longer the one in anchors/eudiw-pid-issuer-ca.pem.\n  live:      ${live.subject.split('\n')[0]} (${live.fingerprint256})\n  committed: ${committed.subject.split('\n')[0]} (${committed.fingerprint256})`,
        'replace anchors/eudiw-pid-issuer-ca.pem with the live certificate, refetch test/fixtures/real/, and note the rotation in REPRODUCE.md.',
      ),
    );
  });

  it('still publishes a CRL, and it is still fresh', async () => {
    // The project refuses a CRL past its nextUpdate, so a deployment with
    // CERT_REVOCATION_CHECK on depends on this CA continuing to republish
    // inside a two-day window. If it stops, verification fails closed for
    // everyone — that is correct behaviour and worth finding out about here
    // rather than from a user.
    const anchors = TrustAnchors.fromPem(readFileSync(`${anchorDir}eudiw-pid-issuer-ca.pem`, 'utf8'));
    const { decode } = await import('cbor2');
    const mdoc = decode(
      new Uint8Array(Buffer.from(readFileSync(`${fixtureDir}eudiw-pid-mdoc.txt`, 'utf8').trim(), 'base64url')),
    ) as { issuerAuth: [unknown, Map<number, unknown>, unknown, unknown] };
    const x5chain = mdoc.issuerAuth[1].get(33);
    const leaf = new X509Certificate(
      Buffer.from((Array.isArray(x5chain) ? x5chain[0] : x5chain) as Uint8Array),
    );

    const outcome = await checkChainRevocation([leaf, anchors.certificates[0]!], { now: new Date() });

    // `unavailable` is the interesting failure: unreachable, unverifiable, or
    // stale. `revoked` would be news of a different and more urgent kind.
    assert.notEqual(
      outcome.kind,
      'unavailable',
      news(
        `The PID Issuer CA's CRL could not be used: ${outcome.kind === 'unavailable' ? outcome.detail : ''}`,
        'if the CA has stopped republishing, deployments with CERT_REVOCATION_CHECK=true are failing closed. Check preprod.pki.eudiw.dev and update the CRL section of REPRODUCE.md.',
      ),
    );
    assert.notEqual(
      outcome.kind,
      'no-mechanism',
      news(
        'The PID chain no longer publishes a CRL distribution point.',
        'certificate revocation is now unenforceable against this issuer; say so in README "Certificate revocation" and in REPRODUCE.md.',
      ),
    );
  });

  it('still runs no OCSP responder', async () => {
    // REPRODUCE.md records that the AIA carries caIssuers only. The OCSP code
    // here is therefore exercised against fixtures alone, and the README says
    // so. If a responder appears, that stops being true — and the OCSP path
    // becomes testable against something nobody here wrote.
    const live = new X509Certificate(await (await fetch(PID_ISSUER_CA_AIA)).text());
    const responders = readOcspResponders(live);

    assert.deepEqual(
      responders,
      [],
      news(
        `The PID Issuer CA now advertises an OCSP responder: ${responders.join(', ')}`,
        'add a live OCSP assertion to the network suite, and correct the claim in README "Certificate revocation" and REPRODUCE.md that no reference responder exists.',
      ),
    );
  });
});

describe('the reference issuer', { skip }, () => {
  it('still does not support /.well-known/jwt-vc-issuer', async () => {
    // x5c is the only key-resolution route implemented, and the justification
    // in README "Open questions" is that it is the only one that works against
    // real EU infrastructure. That justification expires the day this endpoint
    // starts answering.
    const response = await fetch(JWT_VC_ISSUER_METADATA);

    assert.ok(
      !response.ok,
      news(
        `${JWT_VC_ISSUER_METADATA} now answers ${response.status}, where it returned 400 "Not supported".`,
        'issuer metadata key resolution is now possible; reconsider implementing it and update README "Open questions".',
      ),
    );
  });
});

/**
 * One pass over every national list, checking the measurements that decisions
 * were based on. Slow — roughly 20 MB and half a minute — which is why this is
 * weekly and not per-push.
 */
describe('the live trusted lists', { skip }, () => {
  it('still support every assumption the trust code makes', async (t) => {
    const lotlXml = await (await fetch(EU_LOTL)).text();
    verifyTrustList(lotlXml, { label: 'EU LOTL' });

    const pointers = parsePointers(lotlXml).filter(
      (pointer) =>
        pointer.mimeType === 'application/vnd.etsi.tsl+xml' &&
        !pointer.type.endsWith('EUlistofthelists'),
    );

    // Read the lists directly rather than inferring from what the parser
    // returned: the question is what is *published*, and an entry the parser
    // drops looks identical to one that was never there.
    const { DOMParser } = await import('@xmldom/xmldom');
    const xpath = (await import('xpath')).default;
    const select = xpath.useNamespaces({ tsl: 'http://uri.etsi.org/02231/v2#' });
    const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
    const text = (node: unknown) => ((node as Node | undefined)?.textContent ?? '').trim();
    const one = (nodes: unknown) => (Array.isArray(nodes) ? (nodes[0] as Node | undefined) : undefined);

    let grantedServices = 0;
    let missingStartingTime = 0;
    let identifiedWithoutCertificate = 0;
    const unimplementedForms = new Set<string>();
    const anchors: X509Certificate[] = [];
    const unreachable: string[] = [];

    for (const pointer of pointers) {
      let xml: string;
      try {
        xml = await (await fetch(pointer.url)).text();
      } catch {
        unreachable.push(pointer.territory);
        continue;
      }

      const document = new DOMParser().parseFromString(xml, 'text/xml');
      for (const service of select('//tsl:TSPService', document as unknown as Node) as Node[]) {
        const info = one(select('./tsl:ServiceInformation', service));
        if (!info || text(one(select('./tsl:ServiceStatus', info))) !== GRANTED) continue;
        grantedServices += 1;

        if (!text(one(select('./tsl:StatusStartingTime', info)))) missingStartingTime += 1;
        // A service may identify itself by subject name and key identifier
        // instead of by certificate, which leaves nothing to anchor a chain at.
        if ((select('.//tsl:X509Certificate', info) as Node[]).length === 0) {
          identifiedWithoutCertificate += 1;
        }
      }

      const parsed = parseTrustServices(xml, []);
      for (const entry of parsed) {
        anchors.push(entry.certificate);
        let constraints;
        try {
          constraints = readNameConstraints(entry.certificate);
        } catch {
          // Unreadable DER is already a rejection in path validation; it is not
          // what this test is about.
          continue;
        }
        if (!constraints) continue;
        for (const subtree of [...constraints.permitted, ...constraints.excluded]) {
          if (subtree.base.form === 'unsupported') unimplementedForms.add(subtree.base.label);
        }
      }
    }

    // Reported rather than asserted: a service that identifies itself by
    // subject name and key identifier instead of by certificate gives us no key
    // to anchor at, so it is correctly absent — but the number moving is worth
    // seeing. Liechtenstein and the UK published all of these on 2026-08-12.
    t.diagnostic(
      `${grantedServices} granted services across ${pointers.length - unreachable.length} lists; ` +
        `${identifiedWithoutCertificate} identify themselves without a certificate; ` +
        `${anchors.length} service entries yielded a certificate; ` +
        `unreachable: ${unreachable.join(', ') || 'none'}`,
    );

    // Bounds, not exact counts: these lists change continuously and an exact
    // figure would fail every week for no reason.
    assert.ok(
      anchors.length > 1500,
      news(
        `Only ${anchors.length} trust anchors were loaded from ${pointers.length - unreachable.length} lists, where about 2300 is normal. Unreachable: ${unreachable.join(', ') || 'none'}`,
        'a collapse this large usually means a parsing assumption broke rather than that the EU withdrew half its CAs. Check REPRODUCE.md for the last recorded count.',
      ),
    );

    assert.equal(
      missingStartingTime,
      0,
      news(
        `${missingStartingTime} granted services are published without a StatusStartingTime, which this project drops rather than assuming a start.`,
        'those services are now silently absent from the anchor set. Revisit the decision in src/trust/lotl.ts and the measurement in REPRODUCE.md.',
      ),
    );

    assert.deepEqual(
      [...unimplementedForms],
      [],
      news(
        `A CA on a trusted list now carries a Name Constraint in a form this project does not implement: ${[...unimplementedForms].join(', ')}`,
        'chains under that CA now fail closed with ISSUER_NAME_NOT_PERMITTED. Implement the form in src/trust/name-matching.ts — the "costs nothing today" argument in README "Name Constraints" no longer holds.',
      ),
    );
  });
});
