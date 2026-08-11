import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { GeneralNameValue, NameConstraintSet } from '../src/trust/name-constraints.ts';
import { checkNames, matches } from '../src/trust/name-matching.ts';

const dns = (value: string): GeneralNameValue => ({ form: 'dNSName', value });
const email = (value: string): GeneralNameValue => ({ form: 'rfc822Name', value });
const uri = (value: string): GeneralNameValue => ({ form: 'uniformResourceIdentifier', value });
const ip = (value: string): GeneralNameValue => ({ form: 'iPAddress', value });

/** `C=PT, O=Example` as the parser would produce it. */
const dn = (...parts: string[]): GeneralNameValue => ({
  form: 'directoryName',
  rdns: parts.map((part) =>
    part.split('+').map((ava) => {
      const [type, value] = ava.split('=');
      return { type: type!, value };
    }),
  ),
});

const constraints = (set: Partial<NameConstraintSet>): NameConstraintSet => ({
  critical: true,
  permitted: [],
  excluded: [],
  ...set,
});

const subtree = (base: GeneralNameValue) => ({ base, minimum: 0, maximum: undefined });

describe('dNSName constraints', () => {
  it('is satisfied by adding labels to the left', () => {
    assert.equal(matches(dns('example.test'), dns('example.test')), true);
    assert.equal(matches(dns('www.example.test'), dns('example.test')), true);
    assert.equal(matches(dns('a.b.example.test'), dns('example.test')), true);
  });

  it('does not match a name that merely ends with the constraint', () => {
    // The trap: `endsWith` alone accepts this, and it is a different domain.
    assert.equal(matches(dns('example1.test'), dns('e1.test')), false);
    assert.equal(matches(dns('notexample.test'), dns('example.test')), false);
  });

  it('ignores case and a trailing root dot', () => {
    assert.equal(matches(dns('WWW.Example.TEST.'), dns('example.test')), true);
  });

  it('treats an empty constraint as no restriction', () => {
    assert.equal(matches(dns('anything.test'), dns('')), true);
  });
});

describe('rfc822Name constraints', () => {
  it('matches a whole mailbox exactly', () => {
    assert.equal(matches(email('someone@example.test'), email('someone@example.test')), true);
    assert.equal(matches(email('other@example.test'), email('someone@example.test')), false);
  });

  it('compares the host case-insensitively and the local part as given', () => {
    // The local part belongs to the receiving host; only the host is defined to
    // be case-insensitive.
    assert.equal(matches(email('Someone@EXAMPLE.test'), email('Someone@example.test')), true);
    assert.equal(matches(email('SOMEONE@example.test'), email('someone@example.test')), false);
  });

  it('matches every mailbox on a host', () => {
    assert.equal(matches(email('anyone@example.test'), email('example.test')), true);
    assert.equal(matches(email('anyone@other.test'), email('example.test')), false);
  });

  it('matches subdomains only when the constraint begins with a period', () => {
    assert.equal(matches(email('a@mail.example.test'), email('.example.test')), true);
    assert.equal(matches(email('a@example.test'), email('.example.test')), false);
    assert.equal(matches(email('a@mail.example.test'), email('example.test')), false);
  });

  it('does not match something that is not a mailbox', () => {
    assert.equal(matches(email('example.test'), email('example.test')), false);
  });
});

describe('uniformResourceIdentifier constraints', () => {
  it('applies to the host part, not the whole URI', () => {
    assert.equal(matches(uri('https://www.example.test/anything'), uri('.example.test')), true);
    assert.equal(matches(uri('https://example.test/'), uri('example.test')), true);
    assert.equal(matches(uri('https://example.test/'), uri('.example.test')), false);
  });

  it('does not match a URI with no host', () => {
    assert.equal(matches(uri('urn:example:test'), uri('example.test')), false);
    assert.equal(matches(uri('not a uri'), uri('example.test')), false);
  });
});

describe('iPAddress constraints', () => {
  it('masks the address before comparing', () => {
    assert.equal(matches(ip('10.1.2.3'), ip('10.0.0.0/8')), true);
    assert.equal(matches(ip('11.1.2.3'), ip('10.0.0.0/8')), false);
    assert.equal(matches(ip('192.0.2.42'), ip('192.0.2.0/24')), true);
    assert.equal(matches(ip('192.0.3.42'), ip('192.0.2.0/24')), false);
  });

  it('handles a prefix that does not fall on a byte boundary', () => {
    // 10.0.0.0/9 ends at 10.127.255.255, so the boundary sits inside the
    // second byte — the case a byte-wise comparison gets wrong.
    assert.equal(matches(ip('10.127.255.255'), ip('10.0.0.0/9')), true);
    assert.equal(matches(ip('10.128.0.0'), ip('10.0.0.0/9')), false);
    assert.equal(matches(ip('10.127.0.1'), ip('10.64.0.0/10')), true);
    assert.equal(matches(ip('10.63.255.255'), ip('10.64.0.0/10')), false);
  });

  it('matches IPv6, including a compressed constraint', () => {
    assert.equal(matches(ip('2001:db8::1'), ip('2001:db8::/32')), true);
    assert.equal(matches(ip('2001:db9::1'), ip('2001:db8::/32')), false);
  });

  it('never matches across address families', () => {
    assert.equal(matches(ip('10.0.0.1'), ip('::/0')), false);
    assert.equal(matches(ip('::1'), ip('0.0.0.0/0')), false);
  });

  it('treats a constraint with no mask as constraining nothing', () => {
    assert.equal(matches(ip('10.0.0.1'), ip('10.0.0.1')), false);
  });
});

describe('directoryName constraints', () => {
  it('matches when the constraint is an initial subsequence', () => {
    assert.equal(matches(dn('C=PT', 'O=Example', 'CN=Leaf'), dn('C=PT', 'O=Example')), true);
    assert.equal(matches(dn('C=PT', 'O=Example'), dn('C=PT', 'O=Example')), true);
  });

  it('does not match a suffix, or a divergent branch', () => {
    assert.equal(matches(dn('C=PT', 'O=Example'), dn('O=Example')), false);
    assert.equal(matches(dn('C=PT', 'O=Other'), dn('C=PT', 'O=Example')), false);
  });

  it('does not match a name shorter than the constraint', () => {
    assert.equal(matches(dn('C=PT'), dn('C=PT', 'O=Example')), false);
  });

  it('ignores case and surrounding whitespace in attribute values', () => {
    assert.equal(matches(dn('C=pt', 'O=  EXAMPLE  '), dn('C=PT', 'O=Example')), true);
  });

  it('treats an RDN as a set, so attribute order within it is not significant', () => {
    assert.equal(matches(dn('CN=Leaf+OU=Unit'), dn('OU=Unit+CN=Leaf')), true);
    assert.equal(matches(dn('CN=Leaf+OU=Unit'), dn('CN=Leaf')), false);
  });

  it('matches nothing when an attribute value could not be read as text', () => {
    // "We could not decode this" is not "these are equal".
    const unreadable: GeneralNameValue = {
      form: 'directoryName',
      rdns: [[{ type: '2.5.4.6', value: undefined }]],
    };
    assert.equal(matches(unreadable, dn('C=PT')), false);
    assert.equal(matches(unreadable, unreadable), false);
  });
});

describe('applying a constraint set to a certificate', () => {
  it('accepts a name inside the permitted subtree', () => {
    const failure = checkNames(
      [dns('www.example.test')],
      constraints({ permitted: [subtree(dns('example.test'))] }),
    );
    assert.equal(failure, undefined);
  });

  it('rejects a name outside every permitted subtree of its form', () => {
    const failure = checkNames(
      [dns('www.other.test')],
      constraints({ permitted: [subtree(dns('example.test'))] }),
    );
    assert.match(failure ?? '', /outside every permitted subtree/);
  });

  it('rejects a name inside an excluded subtree even when it is also permitted', () => {
    const failure = checkNames(
      [dns('evil.example.test')],
      constraints({
        permitted: [subtree(dns('example.test'))],
        excluded: [subtree(dns('evil.example.test'))],
      }),
    );
    assert.match(failure ?? '', /excluded subtree/);
  });

  it('leaves a form the constraints do not mention alone', () => {
    // A CA that permits only directoryNames says nothing about DNS names.
    const failure = checkNames(
      [dns('www.example.test'), dn('C=PT', 'O=Example')],
      constraints({ permitted: [subtree(dn('C=PT'))] }),
    );
    assert.equal(failure, undefined);
  });

  it('checks every name a certificate presents, not just the first', () => {
    const failure = checkNames(
      [dn('C=PT', 'O=Example'), dns('www.other.test')],
      constraints({ permitted: [subtree(dns('example.test'))] }),
    );
    assert.match(failure ?? '', /www\.other\.test/);
  });

  it('refuses a constraint in a form it cannot evaluate', () => {
    // Ignoring it would leave the path looking validated when the CA's one
    // statement about its own authority went unread.
    const failure = checkNames(
      [dns('www.example.test')],
      constraints({ permitted: [subtree({ form: 'unsupported', label: 'otherName' })] }),
    );
    assert.match(failure ?? '', /otherName name form, which is not implemented/);
  });

  it('refuses a subtree using minimum or maximum', () => {
    const failure = checkNames(
      [dns('www.example.test')],
      constraints({ permitted: [{ base: dns('example.test'), minimum: 2, maximum: undefined }] }),
    );
    assert.match(failure ?? '', /RFC 5280/);
  });

  it('accepts anything when there are no constraints at all', () => {
    assert.equal(checkNames([dns('anything.test')], constraints({})), undefined);
  });
});
