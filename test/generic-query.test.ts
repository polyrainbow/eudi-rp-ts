/**
 * The library asks whatever it is given, and checks the answer against that.
 *
 * Every query here is one no preset builds — attributes rather than a
 * predicate, two credentials rather than one, an id that is not `age_over_18`.
 * If any of them needed a change in `src/` to work, the generalisation would
 * not have happened: the point is that a caller's own question travels from
 * `buildAuthorizationRequest` through `verifyPresentationResponse` without the
 * library recognising it.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { DcqlQuery, SdJwtVcCredentialQuery } from '../src/oid4vp/query.ts';
import { buildAuthorizationRequest } from '../src/oid4vp/request.ts';
import {
  type PresentationContext,
  type PresentationPredicate,
  verifyPresentationResponse,
} from '../src/oid4vp/response.ts';
import type { VerifierIdentity } from '../src/oid4vp/identity.ts';
import type { VerificationEvent } from '../src/events.ts';
import { accept, reject } from '../src/result.ts';
import { TrustAnchors } from '../src/trust/anchors.ts';
import { presentSdJwtVc } from './wallet.ts';

const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
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

/** A query for two attributes, which is not a predicate about anything. */
const NAME_CREDENTIAL: SdJwtVcCredentialQuery = {
  id: 'holder_name',
  format: 'dc+sd-jwt',
  meta: { vct_values: ['urn:eudi:pid:1'] },
  require_cryptographic_holder_binding: true,
  claims: [{ path: ['given_name'] }, { path: ['family_name'] }],
};

const RESIDENCE_CREDENTIAL: SdJwtVcCredentialQuery = {
  id: 'residence',
  format: 'dc+sd-jwt',
  meta: { vct_values: ['urn:eudi:pid:1'] },
  require_cryptographic_holder_binding: true,
  claims: [{ path: ['issuing_country'] }],
};

const NAME_QUERY: DcqlQuery = { credentials: [NAME_CREDENTIAL] };

const NAME_FRAME = { given_name: true, family_name: true };

/** Build a request for `query` and answer it as a wallet would. */
async function roundTrip<T = undefined>(
  query: DcqlQuery,
  vpToken: (parts: { nonce: string; audience: string }) => Promise<Record<string, unknown>>,
  extra: Partial<PresentationContext<T>> = {},
) {
  const request = await buildAuthorizationRequest(identity, query);
  const audience = request.requestPayload['client_id'] as string;
  const token = await vpToken({ nonce: request.nonce, audience });

  const context = {
    config: identity,
    anchors,
    nonce: request.nonce,
    requestPayload: request.requestPayload,
    decryptionJwk: undefined,
    ...extra,
  } as PresentationContext<T>;

  const outcome = await verifyPresentationResponse<T>(context, {
    vp_token: token,
    state: request.requestPayload['state'] as string,
  });
  return { outcome, request };
}

const disclose = (frame: object) => async (parts: { nonce: string; audience: string }) =>
  await presentSdJwtVc({
    issuedCredential: fixtures.issued.over18,
    holderPrivateJwk: fixtures.holderPrivateJwk,
    presentationFrame: frame,
    ...parts,
  });

describe('a query the library does not recognise', () => {
  it('carries attributes through with no predicate at all', async () => {
    const { outcome } = await roundTrip(NAME_QUERY, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts)],
    }));

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
    assert.equal(outcome.value.credentials.length, 1);
    const [credential] = outcome.value.credentials;
    assert.equal(credential!.queryId, 'holder_name');
    assert.equal(credential!.format, 'dc+sd-jwt');
    assert.equal(credential!.claims['given_name'], 'Erika');
    assert.equal(credential!.claims['family_name'], 'Mustermann');
    // Nothing was asked beyond the credentials verifying, so nothing is claimed
    // beyond it. `predicate` is the caller's slot and it stayed empty.
    assert.equal(outcome.value.predicate, undefined);
  });

  it('advertises only the formats the query asks for', async () => {
    // A wallet refuses the whole request when the two disagree, so this is
    // derived from the query rather than stated beside it.
    const request = await buildAuthorizationRequest(identity, NAME_QUERY);
    const metadata = request.requestPayload['client_metadata'] as Record<string, unknown>;
    const formats = metadata['vp_formats_supported'] as Record<string, unknown>;

    assert.deepEqual(Object.keys(formats), ['dc+sd-jwt']);
  });

  it('indexes the answer by credential query id', async () => {
    const { outcome } = await roundTrip(NAME_QUERY, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts)],
    }));

    assert.equal(outcome.verified, true);
    assert.equal(outcome.value.byQueryId['holder_name']?.length, 1);
  });

  it('enforces the vct the query named, not one the library knows', async () => {
    const otherType: DcqlQuery = {
      credentials: [
        { ...NAME_CREDENTIAL, meta: { vct_values: ['urn:example:membership:1'] } },
      ],
    };
    const { outcome } = await roundTrip(otherType, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts)],
    }));

    assert.equal(outcome.verified, false);
    assert.equal(outcome.reason, 'UNEXPECTED_CREDENTIAL_TYPE');
  });

  it('accepts any one of several vct values', async () => {
    // `meta.vct_values` is a list in DCQL, so the verifier takes a list.
    const eitherType: DcqlQuery = {
      credentials: [
        { ...NAME_CREDENTIAL, meta: { vct_values: ['urn:example:membership:1', 'urn:eudi:pid:1'] } },
      ],
    };
    const { outcome } = await roundTrip(eitherType, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts)],
    }));

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
  });
});

describe('a caller-supplied predicate', () => {
  type Adult = { country: string };

  /** Nothing to do with age: a rule over an attribute the library never reads. */
  const issuedInGermany: PresentationPredicate<Adult> = (presented) => {
    const country = presented.credentials[0]?.claims['issuing_country'];
    return country === 'DE'
      ? accept({ value: { country }, evidence: 'issuing_country' })
      : reject('PREDICATE_NOT_SATISFIED', `Issued in ${String(country)}`);
  };

  const COUNTRY_QUERY: DcqlQuery = { credentials: [RESIDENCE_CREDENTIAL] };

  it('decides the verdict and its value', async () => {
    const events: VerificationEvent[] = [];
    const { outcome } = await roundTrip<Adult>(
      COUNTRY_QUERY,
      async (parts) => ({ residence: [await disclose({ issuing_country: true })(parts)] }),
      { predicate: issuedInGermany, onEvent: (event) => events.push(event) },
    );

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
    assert.equal(outcome.value.predicate.country, 'DE');

    // One verdict, and the predicate's evidence on it — the same discipline the
    // age predicate used to get from being built in.
    const verdicts = events.filter(
      (event) => event.type === 'verification.accepted' || event.type === 'verification.rejected',
    );
    assert.deepEqual(verdicts.map((event) => event.type), ['verification.accepted']);
    assert.equal((verdicts[0] as { evidence?: string }).evidence, 'issuing_country');
    assert.deepEqual((verdicts[0] as unknown as { credentialTypes: string[] }).credentialTypes, ['urn:eudi:pid:1']);
  });

  it('rejects a credential that verified, and records only that', async () => {
    const events: VerificationEvent[] = [];
    const elsewhere: PresentationPredicate<Adult> = () =>
      reject('PREDICATE_NOT_SATISFIED', 'not this one');

    const { outcome } = await roundTrip<Adult>(
      COUNTRY_QUERY,
      async (parts) => ({ residence: [await disclose({ issuing_country: true })(parts)] }),
      { predicate: elsewhere, onEvent: (event) => events.push(event) },
    );

    assert.equal(outcome.verified, false);
    assert.equal(outcome.reason, 'PREDICATE_NOT_SATISFIED');
    // The credential itself verified, so the trail still shows that much.
    assert.ok(events.some((event) => event.type === 'issuer.resolved'));
    assert.deepEqual(
      events
        .filter((e) => e.type === 'verification.accepted' || e.type === 'verification.rejected')
        .map((event) => event.type),
      ['verification.rejected'],
    );
  });
});

describe('the response has to answer the query, and no more', () => {
  /** Two credentials, both required: no `credential_sets` means all of them. */
  const BOTH: DcqlQuery = { credentials: [NAME_CREDENTIAL, RESIDENCE_CREDENTIAL] };

  it('verifies every credential a query asked for', async () => {
    const events: VerificationEvent[] = [];
    const { outcome } = await roundTrip(
      BOTH,
      async (parts) => ({
        holder_name: [await disclose(NAME_FRAME)(parts)],
        residence: [await disclose({ issuing_country: true })(parts)],
      }),
      { onEvent: (event) => events.push(event) },
    );

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
    assert.equal(outcome.value.credentials.length, 2);
    assert.deepEqual(Object.keys(outcome.value.byQueryId), ['holder_name', 'residence']);

    // Two credentials, one verdict. Two would be reporting an acceptance the
    // caller was never given.
    const verdicts = events.filter(
      (event) => event.type === 'verification.accepted' || event.type === 'verification.rejected',
    );
    assert.equal(verdicts.length, 1);
    assert.deepEqual((verdicts[0] as unknown as { credentialTypes: string[] }).credentialTypes, [
      'urn:eudi:pid:1',
      'urn:eudi:pid:1',
    ]);
  });

  it('rejects a response that leaves one of them out', async () => {
    const { outcome } = await roundTrip(BOTH, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts)],
    }));

    assert.equal(outcome.verified, false);
    assert.equal(outcome.reason, 'RESPONSE_INVALID');
    assert.match(outcome.detail, /residence/);
  });

  it('rejects an entry for something never asked about', async () => {
    const { outcome } = await roundTrip(NAME_QUERY, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts)],
      passport: [await disclose(NAME_FRAME)(parts)],
    }));

    assert.equal(outcome.verified, false);
    assert.equal(outcome.reason, 'RESPONSE_INVALID');
    assert.match(outcome.detail, /"passport", which was not requested/);
  });

  it('rejects a credential the query offered an alternative to', async () => {
    // Over-disclosure: with `credential_sets` either id answers, so both is one
    // credential more than the verifier had a basis to receive.
    const either: DcqlQuery = {
      ...BOTH,
      credential_sets: [{ options: [['holder_name'], ['residence']] }],
    };
    const { outcome } = await roundTrip(either, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts)],
      residence: [await disclose({ issuing_country: true })(parts)],
    }));

    assert.equal(outcome.verified, false);
    assert.equal(outcome.reason, 'RESPONSE_INVALID');
    assert.match(outcome.detail, /which the query did not need/);
  });

  it('keeps both when the query genuinely needs both', async () => {
    // The same two credentials under a query with no alternatives: neither is
    // surplus, because dropping either leaves the query unanswered.
    const { outcome } = await roundTrip(BOTH, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts)],
      residence: [await disclose({ issuing_country: true })(parts)],
    }));

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
  });

  it('refuses a second presentation where one was requested', async () => {
    const { outcome } = await roundTrip(NAME_QUERY, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts), await disclose(NAME_FRAME)(parts)],
    }));

    assert.equal(outcome.verified, false);
    assert.equal(outcome.reason, 'RESPONSE_INVALID');
    assert.match(outcome.detail, /2 Presentations; one was requested/);
  });

  it('accepts several when the query set `multiple`', async () => {
    const many: DcqlQuery = {
      credentials: [{ ...NAME_CREDENTIAL, multiple: true }],
    };
    const { outcome } = await roundTrip(many, async (parts) => ({
      holder_name: [await disclose(NAME_FRAME)(parts), await disclose(NAME_FRAME)(parts)],
    }));

    assert.equal(outcome.verified, true, JSON.stringify(outcome));
    assert.equal(outcome.value.byQueryId['holder_name']?.length, 2);
  });
});
