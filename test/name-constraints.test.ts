import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { certificateNames, readNameConstraints } from '../src/trust/name-constraints.ts';
import { createCa, issue } from './constrained-certs.ts';

describe('reading Name Constraints', () => {
  it('returns nothing for a certificate that carries none', async () => {
    const ca = await createCa('CN=Plain CA');
    assert.equal(readNameConstraints(ca.cert), undefined);
  });

  it('reads permitted and excluded subtrees of every form it supports', async () => {
    const ca = await createCa('CN=Constrained CA', {
      permitted: [
        { dNSName: 'example.test' },
        { directoryName: 'C=PT, O=Example' },
        { rfc822Name: 'example.test' },
        { uniformResourceIdentifier: 'example.test' },
        { iPAddress: '10.0.0.0/8' },
      ],
      excluded: [{ dNSName: 'evil.example.test' }],
    });

    const constraints = readNameConstraints(ca.cert);
    assert.ok(constraints);
    assert.equal(constraints.critical, true);
    assert.deepEqual(
      constraints.permitted.map((subtree) => subtree.base.form),
      ['dNSName', 'directoryName', 'rfc822Name', 'uniformResourceIdentifier', 'iPAddress'],
    );

    const [dns, dir, , , ip] = constraints.permitted;
    assert.deepEqual(dns!.base, { form: 'dNSName', value: 'example.test' });
    // The DER holds address and mask as one double-length octet string; the
    // parser hands it back as CIDR.
    assert.deepEqual(ip!.base, { form: 'iPAddress', value: '10.0.0.0/8' });
    assert.deepEqual(dir!.base, {
      form: 'directoryName',
      rdns: [
        [{ type: '2.5.4.6', value: 'PT' }],
        [{ type: '2.5.4.10', value: 'Example' }],
      ],
    });

    assert.equal(constraints.excluded.length, 1);
    assert.deepEqual(constraints.excluded[0]!.base, { form: 'dNSName', value: 'evil.example.test' });
  });

  it('keeps a name form it cannot evaluate rather than dropping it', async () => {
    // Silently ignoring a constraint is worse than not checking constraints at
    // all: the chain would look validated. The form is named so a rejection can
    // say which one defeated it.
    const ca = await createCa('CN=Odd CA', { permitted: [{ registeredID: '1.2.3.4' }] });

    const constraints = readNameConstraints(ca.cert);
    assert.deepEqual(constraints?.permitted[0]?.base, { form: 'unsupported', label: 'registeredID' });
  });

  it('carries minimum and maximum rather than discarding them', async () => {
    // RFC 5280 4.2.1.10 requires minimum 0 and maximum absent. Reading them
    // here is what lets the check reject a subtree that says otherwise.
    const ca = await createCa('CN=Ranged CA', {
      permitted: [{ dNSName: 'example.test' }],
      minimum: 2,
      maximum: 5,
    });

    const subtree = readNameConstraints(ca.cert)?.permitted[0];
    assert.equal(subtree?.minimum, 2);
    assert.equal(subtree?.maximum, 5);
  });

  it('records whether the extension is critical', async () => {
    const ca = await createCa('CN=Lax CA', {
      permitted: [{ dNSName: 'example.test' }],
      critical: false,
    });
    assert.equal(readNameConstraints(ca.cert)?.critical, false);
  });
});

describe('the names a certificate presents', () => {
  it('reads the subject DN as a directoryName', async () => {
    const ca = await createCa('CN=Root');
    const leaf = await issue(ca, 'C=PT, O=Example, CN=Leaf');

    assert.deepEqual(certificateNames(leaf.cert), [
      {
        form: 'directoryName',
        rdns: [
          [{ type: '2.5.4.6', value: 'PT' }],
          [{ type: '2.5.4.10', value: 'Example' }],
          [{ type: '2.5.4.3', value: 'Leaf' }],
        ],
      },
    ]);
  });

  it('reads every subject alternative name alongside it', async () => {
    const ca = await createCa('CN=Root');
    const leaf = await issue(ca, 'CN=Leaf', {
      subjectAltNames: [{ dNSName: 'a.example.test' }, { rfc822Name: 'someone@example.test' }],
    });

    assert.deepEqual(
      certificateNames(leaf.cert).map((name) => name.form),
      ['directoryName', 'dNSName', 'rfc822Name'],
    );
  });

  it('contributes nothing for an empty subject DN', async () => {
    // The shape used by certificates that carry their identity entirely in the
    // SAN. An empty DN is not a name to be constrained.
    const ca = await createCa('CN=Root');
    const leaf = await issue(ca, '', { subjectAltNames: [{ dNSName: 'a.example.test' }] });

    assert.deepEqual(certificateNames(leaf.cert), [{ form: 'dNSName', value: 'a.example.test' }]);
  });

  it('keeps the attributes of a multi-valued RDN together', async () => {
    // `CN=Leaf+OU=Unit` is one RDN holding two attributes. Treating it as two
    // RDNs would compare a prefix that does not exist.
    const ca = await createCa('CN=Root');
    const leaf = await issue(ca, 'O=Example, CN=Leaf+OU=Unit');

    const [subject] = certificateNames(leaf.cert);
    assert.equal(subject?.form, 'directoryName');
    assert.equal(subject.form === 'directoryName' ? subject.rdns.length : -1, 2);
    const second = subject.form === 'directoryName' ? subject.rdns[1]! : [];
    assert.equal(second.length, 2, 'the multi-valued RDN must stay one RDN');
    assert.deepEqual(
      [...second].map((a) => a.type).sort(),
      ['2.5.4.11', '2.5.4.3'],
    );
  });
});
