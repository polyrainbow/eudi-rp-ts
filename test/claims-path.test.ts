import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { readClaim, selectClaims, unsatisfiedClaims } from '../src/oid4vp/claims.ts';
import type { CredentialQuery } from '../src/oid4vp/query.ts';

describe('claims paths (OID4VP 1.0 §7)', () => {
  const claims = {
    given_name: 'Erika',
    age_equal_or_over: { '18': true, '65': false },
    address: { street: 'Hauptstr. 1', country: null },
    nationalities: ['DE', 'PT'],
    degrees: [{ type: 'BA' }, { type: 'MA' }],
  };

  it('walks object members', () => {
    assert.deepEqual(selectClaims(claims, ['given_name']), ['Erika']);
    assert.deepEqual(selectClaims(claims, ['age_equal_or_over', '18']), [true]);
  });

  it('selects a false value rather than treating it as absent', () => {
    // The age flag is a boolean and `false` is an answer. A truthiness check
    // here would report "not disclosed" for a wallet that disclosed "no".
    assert.deepEqual(selectClaims(claims, ['age_equal_or_over', '65']), [false]);
    assert.deepEqual(selectClaims(claims, ['address', 'country']), [null]);
  });

  it('selects nothing for a claim that is not there', () => {
    assert.deepEqual(selectClaims(claims, ['family_name']), []);
    assert.deepEqual(selectClaims(claims, ['age_equal_or_over', '21']), []);
  });

  it('indexes arrays, and selects every element for null', () => {
    assert.deepEqual(selectClaims(claims, ['nationalities', 1]), ['PT']);
    assert.deepEqual(selectClaims(claims, ['nationalities', null]), ['DE', 'PT']);
    assert.deepEqual(selectClaims(claims, ['degrees', null, 'type']), ['BA', 'MA']);
  });

  it('selects nothing when a component does not fit what it is applied to', () => {
    // Not an error: the question is whether the wallet delivered this claim,
    // and a response shaped unlike the query did not.
    assert.deepEqual(selectClaims(claims, ['given_name', 'first']), []);
    assert.deepEqual(selectClaims(claims, ['nationalities', 'DE']), []);
    assert.deepEqual(selectClaims(claims, ['given_name', null]), []);
    assert.deepEqual(selectClaims(claims, ['nationalities', 5]), []);
  });

  it('reads an mdoc namespace map with the same walk', () => {
    // §7.2: an mdoc path is always [namespace, element], which over
    // `{ namespace: { element: value } }` is an ordinary two-step object walk.
    const mdoc = { 'eu.europa.ec.eudi.pid.1': { age_over_18: true, birth_date: '1990-06-12' } };
    assert.equal(readClaim(mdoc, ['eu.europa.ec.eudi.pid.1', 'birth_date']), '1990-06-12');
    assert.equal(readClaim(mdoc, ['org.iso.18013.5.1', 'birth_date']), undefined);
  });

  it('readClaim gives up on a path that selects several', () => {
    // Returning the first would make a caller's one-value assumption look right.
    assert.equal(readClaim(claims, ['nationalities', null]), undefined);
    assert.equal(readClaim(claims, ['nationalities', 0]), 'DE');
  });
});

describe('did the wallet disclose what the query asked for', () => {
  const base = {
    id: 'pid',
    format: 'dc+sd-jwt',
    meta: { vct_values: ['urn:eudi:pid:1'] },
  } as const;

  const disclosed = { given_name: 'Erika', issuing_country: 'DE' };

  it('is satisfied by a query naming no claims', () => {
    // No `claims` asks for the whole credential; anything answers it.
    assert.equal(unsatisfiedClaims({ ...base } as CredentialQuery, disclosed), undefined);
  });

  it('requires every listed claim when there are no claim sets', () => {
    const query = {
      ...base,
      claims: [{ path: ['given_name'] }, { path: ['family_name'] }],
    } as CredentialQuery;

    assert.match(unsatisfiedClaims(query, disclosed)!, /family_name/);
  });

  it('is satisfied by any one claim set option', () => {
    const query = {
      ...base,
      claims: [
        { id: 'name', path: ['family_name'] },
        { id: 'country', path: ['issuing_country'] },
      ],
      claim_sets: [['name'], ['country']],
    } as CredentialQuery;

    assert.equal(unsatisfiedClaims(query, disclosed), undefined);
  });

  it('reports the options when none of them was disclosed', () => {
    const query = {
      ...base,
      claims: [
        { id: 'name', path: ['family_name'] },
        { id: 'birth', path: ['birthdate'] },
      ],
      claim_sets: [['name'], ['birth']],
    } as CredentialQuery;

    assert.match(unsatisfiedClaims(query, disclosed)!, /\[name\] or \[birth\]/);
  });

  it('treats a claim set option naming an unknown id as unsatisfiable', () => {
    const query = {
      ...base,
      claims: [{ id: 'country', path: ['issuing_country'] }],
      claim_sets: [['nothing_defines_this']],
    } as CredentialQuery;

    assert.ok(unsatisfiedClaims(query, disclosed));
  });

  it('enforces `values`, which nothing else does', () => {
    // DCQL says the wallet must only return the claim if the value matches. It
    // is the verifier's to check anyway — the wallet is the party the
    // constraint is aimed at.
    const query = {
      ...base,
      claims: [{ path: ['issuing_country'], values: ['PT'] }],
    } as CredentialQuery;

    assert.ok(unsatisfiedClaims(query, disclosed));
    assert.equal(
      unsatisfiedClaims({ ...query, claims: [{ path: ['issuing_country'], values: ['DE', 'PT'] }] } as CredentialQuery, disclosed),
      undefined,
    );
  });

  it('matches `values` against any element a wildcard selected', () => {
    const query = {
      ...base,
      claims: [{ path: ['nationalities', null], values: ['DE'] }],
    } as CredentialQuery;

    assert.equal(unsatisfiedClaims(query, { nationalities: ['PT', 'DE'] }), undefined);
    assert.ok(unsatisfiedClaims(query, { nationalities: ['PT', 'FR'] }));
  });
});
