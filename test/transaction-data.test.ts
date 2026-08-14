/**
 * Transaction data: proving the holder agreed, not only that they are who they
 * say (OID4VP 1.0 §5.1, §8.4).
 *
 * Every request here carries a transaction data type this library has never
 * heard of, for the same reason every query in `generic-query.test.ts` is one
 * no preset builds: §5.1 leaves types out of scope, so if any of these needed a
 * change in `src/` the generalisation would not have happened.
 *
 * The hashes are computed here with `node:crypto` directly rather than with the
 * library's own helper. A test that hashes the way the implementation hashes
 * agrees with it by construction, including about the detail §B.3.3 is easiest
 * to get wrong — that the hash covers the base64url string as sent, not the
 * JSON it decodes to.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { VerificationEvent } from '../src/events.ts';
import { buildSessionTranscript } from '../src/mdoc/session-transcript.ts';
import type { VerifierIdentity } from '../src/oid4vp/identity.ts';
import type { DcqlQuery } from '../src/oid4vp/query.ts';
import { buildAuthorizationRequest } from '../src/oid4vp/request.ts';
import { type PresentationContext, verifyPresentationResponse } from '../src/oid4vp/response.ts';
import type { TransactionDataEntry } from '../src/oid4vp/transaction-data.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { buildDeviceResponse } from './mdoc-wallet.ts';
import { presentSdJwtVc } from './wallet.ts';

const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const real = fileURLToPath(new URL('./fixtures/real/', import.meta.url));
const anchorDir = fileURLToPath(new URL('../anchors/', import.meta.url));
const fixtures = JSON.parse(readFileSync(`${dir}credentials.json`, 'utf8'));
const anchors = TrustAnchors.fromPem(readFileSync(`${dir}trust-anchor.pem`, 'utf8'));

const identity: VerifierIdentity = {
  baseUrl: 'https://verifier.test',
  walletScheme: 'eudi-openid4vp://',
  clientIdPrefix: 'redirect_uri',
  clientDnsName: undefined,
  accessCertificateChainPem: undefined,
  accessCertificatePrivateKeyPem: undefined,
  requestTtlSeconds: 300,
  checkStatus: false,
  checkCertificateRevocation: false,
};

/** A payment authorisation, which is a type nothing in `src/` knows about. */
const PAYMENT: TransactionDataEntry = {
  type: 'urn:example:payment',
  credential_ids: ['holder'],
  payee: 'Kaffeehaus Sperl',
  amount: '4.20',
  currency: 'EUR',
};

const SD_JWT_QUERY: DcqlQuery = {
  credentials: [
    {
      id: 'holder',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['urn:eudi:pid:1'] },
      require_cryptographic_holder_binding: true,
      claims: [{ path: ['given_name'] }],
    },
  ],
};

/** §B.3.3: over the string the wallet received, base64url decoding not performed. */
const hashOf = (encoded: string, alg = 'sha256') =>
  createHash(alg).update(encoded, 'utf8').digest('base64url');

type RoundTrip = {
  transactionData?: readonly TransactionDataEntry[];
  /** What the wallet puts in the Key Binding JWT; undefined means it ignored the request. */
  kbClaims?: (sent: readonly string[]) => Record<string, unknown>;
  context?: Partial<PresentationContext<undefined>>;
  events?: VerificationEvent[];
};

async function roundTrip(options: RoundTrip = {}) {
  const request = await buildAuthorizationRequest(
    identity,
    SD_JWT_QUERY,
    options.transactionData ? { transactionData: options.transactionData } : {},
  );
  const sent = (request.requestPayload['transaction_data'] as string[] | undefined) ?? [];

  const credential = await presentSdJwtVc({
    issuedCredential: fixtures.issued.over18,
    holderPrivateJwk: fixtures.holderPrivateJwk,
    presentationFrame: { given_name: true },
    nonce: request.nonce,
    audience: request.requestPayload['client_id'] as string,
    ...(options.kbClaims ? { kbClaims: options.kbClaims(sent) } : {}),
  });

  const outcome = await verifyPresentationResponse(
    {
      config: identity,
      anchors,
      nonce: request.nonce,
      requestPayload: request.requestPayload,
      decryptionJwk: undefined,
      ...(options.events ? { onEvent: (event) => options.events!.push(event) } : {}),
      ...options.context,
    } as PresentationContext<undefined>,
    { vp_token: { holder: [credential] }, state: request.requestPayload['state'] as string },
  );

  return { outcome, request, sent };
}

/** What a conforming wallet returns for the entries it was sent. */
const authorise = (alg?: string) => (sent: readonly string[]) => ({
  transaction_data_hashes: sent.map((encoded) => hashOf(encoded, alg?.replace('-', ''))),
  ...(alg ? { transaction_data_hashes_alg: alg } : {}),
});

describe('putting transaction data on the request', () => {
  it('carries the entries as base64url JSON', async () => {
    const { request, sent } = await roundTrip({ transactionData: [PAYMENT] });

    assert.equal(sent.length, 1);
    assert.deepEqual(JSON.parse(Buffer.from(sent[0]!, 'base64url').toString('utf8')), PAYMENT);
    // In the payload the wallet is handed, and so inside the signature when the
    // request is signed — not a parameter bolted on beside it.
    assert.equal(request.requestPayload['transaction_data'], sent);
  });

  it('sends nothing when the request asks for no authorisation', async () => {
    const { request } = await roundTrip();

    assert.equal('transaction_data' in request.requestPayload, false);
  });

  it('refuses an entry naming a credential the query does not ask for', async () => {
    // The wallet's own answer to this is `invalid_transaction_data` (§8.5),
    // which arrives as a refusal with nothing to say which document was wrong.
    await assert.rejects(
      () =>
        buildAuthorizationRequest(identity, SD_JWT_QUERY, {
          transactionData: [{ ...PAYMENT, credential_ids: ['not_asked_for'] }],
        }),
      /authorises credential "not_asked_for", which the DCQL query does not ask for/,
    );
  });

  it('refuses an entry with no credential_ids, and an empty list of entries', async () => {
    await assert.rejects(
      () =>
        buildAuthorizationRequest(identity, SD_JWT_QUERY, {
          transactionData: [{ type: 'urn:example:payment' } as unknown as TransactionDataEntry],
        }),
      /has no credential_ids/,
    );
    await assert.rejects(
      () => buildAuthorizationRequest(identity, SD_JWT_QUERY, { transactionData: [] }),
      /present but empty/,
    );
  });

  it('refuses to authorise a credential that waives holder binding', async () => {
    // §B.3.3 makes this the wallet's duty to refuse, and it could hardly be
    // otherwise: the binding is the holder's signature, so waiving it asks for
    // an authorisation nobody signs.
    await assert.rejects(
      () =>
        buildAuthorizationRequest(
          identity,
          {
            credentials: [
              { ...SD_JWT_QUERY.credentials[0]!, require_cryptographic_holder_binding: false },
            ],
          },
          { transactionData: [PAYMENT] },
        ),
      /no signature to bind it to/,
    );
  });

  it('refuses a hash algorithm it could not check the answer with', async () => {
    // Caught while the request is still fixable: a wallet hashing with an
    // algorithm we cannot compute produces a presentation nothing can accept.
    await assert.rejects(
      () =>
        buildAuthorizationRequest(identity, SD_JWT_QUERY, {
          transactionData: [{ ...PAYMENT, transaction_data_hashes_alg: ['sha3-512'] }],
        }),
      /cannot compute/,
    );
  });
});

describe('a presentation that authorises the transaction', () => {
  it('is accepted, and says so once', async () => {
    const events: VerificationEvent[] = [];
    const { outcome } = await roundTrip({
      transactionData: [PAYMENT],
      kbClaims: authorise(),
      events,
    });

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
    const authorised = events.filter((event) => event.type === 'transaction.authorised');
    assert.equal(authorised.length, 1);
    assert.deepEqual((authorised[0] as { types: readonly string[] }).types, ['urn:example:payment']);
    assert.equal((authorised[0] as { format: string }).format, 'dc+sd-jwt');
  });

  it('records what was authorised without recording what it was', async () => {
    // The trail has to distinguish an authorisation from an identification and
    // must not become a ledger of what people bought.
    const events: VerificationEvent[] = [];
    const { sent } = await roundTrip({
      transactionData: [PAYMENT],
      kbClaims: authorise(),
      events,
    });

    const serialised = JSON.stringify(events);
    for (const secret of ['Kaffeehaus Sperl', '4.20', 'EUR', hashOf(sent[0]!), sent[0]!]) {
      assert.ok(!serialised.includes(secret), `event stream leaked ${secret}`);
    }
  });

  it('surfaces the hashes the holder signed', async () => {
    // Before this the Key Binding JWT was verified and then reduced to two
    // claims, so a hash the holder had signed was reachable by nobody.
    const { outcome, sent } = await roundTrip({
      transactionData: [PAYMENT],
      kbClaims: authorise(),
    });

    assert.equal(outcome.verified, true);
    assert.deepEqual(outcome.value.credentials[0]!.keyBinding?.transactionDataHashes, [hashOf(sent[0]!)]);
  });

  it('hashes the string that was sent, not the JSON it decodes to', async () => {
    // §B.3.3: "base64url decoding is not performed before hashing". A verifier
    // that decoded first would compute a hash no conforming wallet produces.
    const { outcome, sent } = await roundTrip({
      transactionData: [PAYMENT],
      kbClaims: (encoded) => ({
        transaction_data_hashes: encoded.map((entry) =>
          createHash('sha256').update(Buffer.from(entry, 'base64url')).digest('base64url'),
        ),
      }),
    });

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISMATCH');
    // And the same wallet hashing it the specified way is accepted, so this
    // pins the encoding rather than merely rejecting everything.
    const ok = await roundTrip({ transactionData: [PAYMENT], kbClaims: authorise() });
    assert.equal(ok.outcome.verified, true);
    assert.notEqual(hashOf(sent[0]!), createHash('sha256').update(Buffer.from(sent[0]!, 'base64url')).digest('base64url'));
  });

  it('accepts a hash algorithm the request offered', async () => {
    const { outcome } = await roundTrip({
      transactionData: [{ ...PAYMENT, transaction_data_hashes_alg: ['sha-384'] }],
      kbClaims: authorise('sha-384'),
    });

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
  });

  it('leaves alone an entry that names a different credential', async () => {
    // Two credentials, one transaction: the entry names only the first, so the
    // second has nothing to authorise and is not asked to.
    const query: DcqlQuery = {
      credentials: [
        SD_JWT_QUERY.credentials[0]!,
        { ...SD_JWT_QUERY.credentials[0]!, id: 'second' },
      ],
    };
    const request = await buildAuthorizationRequest(identity, query, { transactionData: [PAYMENT] });
    const sent = request.requestPayload['transaction_data'] as string[];

    const present = async (kbClaims?: Record<string, unknown>) =>
      await presentSdJwtVc({
        issuedCredential: fixtures.issued.over18,
        holderPrivateJwk: fixtures.holderPrivateJwk,
        presentationFrame: { given_name: true },
        nonce: request.nonce,
        audience: request.requestPayload['client_id'] as string,
        ...(kbClaims ? { kbClaims } : {}),
      });

    const outcome = await verifyPresentationResponse(
      {
        config: identity,
        anchors,
        nonce: request.nonce,
        requestPayload: request.requestPayload,
        decryptionJwk: undefined,
      } as PresentationContext<undefined>,
      {
        vp_token: {
          holder: [await present({ transaction_data_hashes: [hashOf(sent[0]!)] })],
          second: [await present()],
        },
        state: request.requestPayload['state'] as string,
      },
    );

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
  });
});

describe('a presentation that does not', () => {
  it('rejects a wallet that ignored the transaction data', async () => {
    // A wallet that does not support the parameter must refuse the request
    // outright (§8.4), so a presentation arriving without the binding means
    // nobody agreed to anything.
    const { outcome } = await roundTrip({ transactionData: [PAYMENT] });

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISSING');
  });

  it('rejects a hash over something else', async () => {
    const { outcome } = await roundTrip({
      transactionData: [PAYMENT],
      // The same shape, a different payee: what an attacker who can rewrite the
      // request but not forge a signature would need the holder to have signed.
      kbClaims: () => ({
        transaction_data_hashes: [
          hashOf(Buffer.from(JSON.stringify({ ...PAYMENT, payee: 'Someone Else' })).toString('base64url')),
        ],
      }),
    });

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISMATCH');
  });

  it('rejects a hash computed with an algorithm the request did not offer', async () => {
    const { outcome } = await roundTrip({
      transactionData: [{ ...PAYMENT, transaction_data_hashes_alg: ['sha-512'] }],
      kbClaims: authorise('sha-256'),
    });

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISMATCH');
  });

  it('applies the default only when the request stated no algorithm', async () => {
    // §B.3.3 defaults both sides to sha-256 independently. A response that
    // states none has used the default — which is wrong here, because the
    // request asked for sha-384 and the default is not among its values.
    const { outcome } = await roundTrip({
      transactionData: [{ ...PAYMENT, transaction_data_hashes_alg: ['sha-384'] }],
      kbClaims: (sent) => ({ transaction_data_hashes: sent.map((entry) => hashOf(entry, 'sha384')) }),
    });

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISMATCH');
  });

  it('rejects when one of two entries is unbound', async () => {
    // Every entry naming a credential must be bound by it: authorising the
    // payment is not authorising the terms. Reported as a mismatch rather than
    // as missing, and the line between the two codes is where the binding is
    // absent rather than where a single entry is: this wallet did sign
    // transaction data, and what it signed does not include this entry.
    const { outcome } = await roundTrip({
      transactionData: [PAYMENT, { ...PAYMENT, type: 'urn:example:terms' }],
      kbClaims: (sent) => ({ transaction_data_hashes: [hashOf(sent[0]!)] }),
    });

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISMATCH');
    assert.match((outcome as { detail: string }).detail, /urn:example:terms/);
  });

  it('rejects an empty hash list as no binding at all', async () => {
    const { outcome } = await roundTrip({
      transactionData: [PAYMENT],
      kbClaims: () => ({ transaction_data_hashes: [] }),
    });

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISSING');
  });

  it('refuses to read a malformed transaction_data as an absent one', async () => {
    // The failure that would matter most. "The request carried transaction
    // data" and "it carried none" are opposite verdicts about the same
    // presentation, so a parameter that degraded into the second would accept
    // an entirely unauthorised presentation as though nothing had been asked.
    // Each of these once did exactly that.
    const { request } = await roundTrip();
    const malformed = [
      'not an array',
      [],
      [{ type: 'urn:example:payment' }],
      [Buffer.from(JSON.stringify({ type: 'urn:example:payment' })).toString('base64url')],
      [Buffer.from('not json').toString('base64url')],
    ];

    for (const transaction_data of malformed) {
      const outcome = await verifyPresentationResponse(
        {
          config: identity,
          anchors,
          nonce: request.nonce,
          requestPayload: { ...request.requestPayload, transaction_data },
          decryptionJwk: undefined,
        } as PresentationContext<undefined>,
        { vp_token: { holder: ['not.even.read'] }, state: request.requestPayload['state'] as string },
      );

      assert.equal(outcome.verified, false, JSON.stringify(transaction_data));
      assert.equal((outcome as { reason: string }).reason, 'RESPONSE_INVALID');
      assert.match((outcome as { detail: string }).detail, /unreadable transaction_data/);
    }
  });

  it('rejects a stored request whose transaction data names an unasked credential', async () => {
    // Not reachable through `buildAuthorizationRequest`, which refuses it — but
    // a caller may assemble a payload itself, and an entry naming a credential
    // the query never asked for describes an authorisation no answer could
    // carry. Settled before anything is verified, so it is not reported as the
    // wallet's fault.
    const { request } = await roundTrip();
    const payload: Record<string, unknown> = {
      ...request.requestPayload,
      transaction_data: [
        Buffer.from(JSON.stringify({ ...PAYMENT, credential_ids: ['ghost'] })).toString('base64url'),
      ],
    };

    const outcome = await verifyPresentationResponse(
      {
        config: identity,
        anchors,
        nonce: request.nonce,
        requestPayload: payload,
        decryptionJwk: undefined,
      } as PresentationContext<undefined>,
      { vp_token: { holder: ['not.even.read'] }, state: payload['state'] as string },
    );

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'RESPONSE_INVALID');
    assert.match((outcome as { detail: string }).detail, /the query does not ask for/);
  });
});

describe('mdoc, where the type says where the hashes live', () => {
  const issuerSigned = readFileSync(`${real}eudiw-pid-mdoc.txt`, 'utf8').trim();
  const devicePrivateJwk = JSON.parse(readFileSync(`${real}mdoc-device-private-jwk.json`, 'utf8'));
  const mdocAnchors = TrustAnchors.fromPem(readFileSync(`${anchorDir}eudiw-pid-issuer-ca.pem`, 'utf8'));
  const DOCTYPE = 'eu.europa.ec.eudi.pid.1';
  const ELEMENT = { namespace: 'urn:example:payment', element: 'transaction_data' };

  const MDOC_QUERY: DcqlQuery = {
    credentials: [
      {
        id: 'holder',
        format: 'mso_mdoc',
        meta: { doctype_value: DOCTYPE },
        require_cryptographic_holder_binding: true,
        claims: [{ path: [DOCTYPE, 'family_name'] }],
      },
    ],
  };

  async function mdocRoundTrip(options: {
    deviceNameSpaces?: (sent: readonly string[]) => Record<string, Record<string, unknown>>;
    context?: Partial<PresentationContext<undefined>>;
  }) {
    const request = await buildAuthorizationRequest(identity, MDOC_QUERY, {
      transactionData: [PAYMENT],
    });
    const sent = request.requestPayload['transaction_data'] as string[];

    const deviceResponse = Buffer.from(
      buildDeviceResponse({
        issuerSigned,
        devicePrivateJwk,
        sessionTranscript: buildSessionTranscript({
          clientId: request.requestPayload['client_id'] as string,
          nonce: request.nonce,
          responseUri: request.requestPayload['response_uri'] as string,
        }),
        docType: DOCTYPE,
        ...(options.deviceNameSpaces ? { deviceNameSpaces: options.deviceNameSpaces(sent) } : {}),
      }),
    ).toString('base64url');

    return {
      sent,
      outcome: await verifyPresentationResponse(
        {
          config: identity,
          anchors: mdocAnchors,
          nonce: request.nonce,
          requestPayload: request.requestPayload,
          decryptionJwk: undefined,
          tolerateMalformedMdocValidity: true,
          ...options.context,
        } as PresentationContext<undefined>,
        { vp_token: { holder: [deviceResponse] }, state: request.requestPayload['state'] as string },
      ),
    };
  }

  it('accepts a device-signed element carrying the hashes, and audits it the same way', async () => {
    // The stream does not depend on the format: an authorisation is as
    // auditable in mdoc as in SD-JWT VC, on the same reasoning that keeps the
    // format from deciding whether the credential's status is checked.
    const events: VerificationEvent[] = [];
    const { outcome } = await mdocRoundTrip({
      deviceNameSpaces: (sent) => ({
        [ELEMENT.namespace]: { [ELEMENT.element]: sent.map((entry) => hashOf(entry)) },
      }),
      context: {
        mdocTransactionData: { [PAYMENT.type]: ELEMENT },
        onEvent: (event) => events.push(event),
      },
    });

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
    const authorised = events.filter((event) => event.type === 'transaction.authorised');
    assert.equal(authorised.length, 1);
    assert.equal((authorised[0] as { format: string }).format, 'mso_mdoc');
    assert.deepEqual((authorised[0] as { types: readonly string[] }).types, [PAYMENT.type]);
  });

  it('accepts the §B.3.3 pair carried as a map', async () => {
    const { outcome } = await mdocRoundTrip({
      deviceNameSpaces: (sent) => ({
        [ELEMENT.namespace]: {
          [ELEMENT.element]: {
            transaction_data_hashes: sent.map((entry) => hashOf(entry, 'sha384')),
            transaction_data_hashes_alg: 'sha-384',
          },
        },
      }),
      context: { mdocTransactionData: { [PAYMENT.type]: ELEMENT } },
    });

    // The request offered no algorithm, so sha-384 is not one of its values —
    // the map is read, and then refused on the same rule as SD-JWT VC.
    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISMATCH');
  });

  it('fails closed when nothing said where to look', async () => {
    // Being unable to look is not evidence that the holder agreed. The element
    // is there and correct; what is missing is the caller telling us the type
    // puts it there.
    const { outcome } = await mdocRoundTrip({
      deviceNameSpaces: (sent) => ({
        [ELEMENT.namespace]: { [ELEMENT.element]: sent.map((entry) => hashOf(entry)) },
      }),
    });

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISSING');
  });

  it('rejects an element that is absent', async () => {
    const { outcome } = await mdocRoundTrip({
      context: { mdocTransactionData: { [PAYMENT.type]: ELEMENT } },
    });

    assert.equal(outcome.verified, false);
    assert.equal((outcome as { reason: string }).reason, 'TRANSACTION_DATA_MISSING');
  });

  it('surfaces the device-signed elements either way', async () => {
    // What the caller needs to check a type this library was not told about.
    const { outcome, sent } = await mdocRoundTrip({
      deviceNameSpaces: (encoded) => ({
        [ELEMENT.namespace]: { [ELEMENT.element]: encoded.map((entry) => hashOf(entry)) },
      }),
      context: { mdocTransactionData: { [PAYMENT.type]: ELEMENT } },
    });

    assert.equal(outcome.verified, true);
    assert.deepEqual(outcome.value.credentials[0]!.deviceSignedClaims?.[ELEMENT.namespace], {
      [ELEMENT.element]: [hashOf(sent[0]!)],
    });
  });
});
