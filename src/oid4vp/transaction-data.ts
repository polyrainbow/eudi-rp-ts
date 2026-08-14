import { createHash } from 'node:crypto';
import { type DcqlQuery, credentialQueryById } from './query.ts';

/**
 * Transaction data (OID4VP 1.0 §5.1 and §8.4): what the End-User is authorising,
 * bound to the same key that proves possession of the Credential.
 *
 * Without it a verified presentation says *this holder, holding a credential we
 * trust, answered this nonce for this verifier*. That is identification. With
 * it the same signature also says *and they agreed to this* — this amount to
 * this payee, this document hash — which is what makes a presentation an
 * authorisation rather than a login. §8.4 puts it plainly: the mechanism
 * "enables a binding between the user's identification/authentication and the
 * user's authorization".
 *
 * **This module defines no transaction data type, and neither does the rest of
 * the library.** §5.1 leaves the values of `type` and every parameter beyond
 * `type` and `credential_ids` out of scope, so a type is the caller's to write
 * exactly as a DCQL query is — see `src/presets/`. What is implemented here is
 * the part that is not type-specific: encoding the objects onto the request,
 * reading them back off it, and checking the hashes a presentation returned
 * against the strings that were actually sent.
 *
 * The hash profile is §B.3.3's, defined there for SD-JWT VC and reused by any
 * mdoc type that chooses it. Two details of it are easy to get wrong and both
 * are load-bearing:
 *
 *  - the hash is computed **over the base64url string as sent**, not over the
 *    JSON it decodes to — "base64url decoding is not performed before hashing"
 *    (§B.3.3). Two encoders that disagree about key order or spacing produce
 *    different strings and therefore different hashes, which is why
 *    `readTransactionData` reads back the strings the request carried rather
 *    than re-encoding the objects that produced them. The same reason
 *    `oid4vp/response.ts` reads the DCQL query back off the payload.
 *  - the algorithm defaults to `sha-256` on **both** sides independently: the
 *    request omitting `transaction_data_hashes_alg` means the wallet must use
 *    sha-256, and the response omitting it means it did.
 */

/**
 * One transaction data object, before encoding (OID4VP 1.0 §5.1).
 *
 * `type` and `credential_ids` are the two parameters this specification
 * defines; everything else belongs to the type and passes through untouched.
 */
export type TransactionDataEntry = {
  /**
   * REQUIRED. Identifies the type, which determines every other parameter.
   * §5.1 recommends a collision-resistant name.
   */
  type: string;
  /**
   * REQUIRED, non-empty. The Credential Query ids that may authorise this
   * transaction — so a transaction is bound to a specific credential in the
   * same request, not to the request as a whole.
   */
  credential_ids: readonly [string, ...string[]];
  /**
   * OID4VP 1.0 §B.3.3. Non-empty when present; one of these MUST be what the
   * wallet hashes with. Absent means `sha-256`, which is also the only value
   * §B.3.3 requires an implementation to support.
   */
  transaction_data_hashes_alg?: readonly string[];
  [parameter: string]: unknown;
};

/**
 * What a presentation returned for the hash profile.
 *
 * SD-JWT VC carries it as two top-level Key Binding JWT claims (§B.3.3); an
 * mdoc type that adopts the profile carries the same two values in a
 * device-signed data element it names itself (§B.2.1). Either way it is inside
 * the holder's signature by the time it reaches here, which is the whole point
 * — `alg` is `undefined` when the presentation stated none, and the default
 * then applies.
 */
export type TransactionDataBinding = {
  hashes: readonly string[];
  alg: string | undefined;
};

/** Why a presentation does not authorise a transaction. */
export type TransactionDataFailure = {
  /**
   * `missing` — the presentation carries no binding at all for an entry that
   * named its Credential Query. `mismatch` — it carries one, over something
   * else, or hashed with an algorithm the request did not offer.
   * `unsupported-alg` — the wallet named an algorithm this library cannot
   * compute, so nothing is known either way and it fails closed.
   */
  kind: 'missing' | 'mismatch' | 'unsupported-alg';
  detail: string;
};

/**
 * IANA "Named Information Hash Algorithm" names (§B.3.3) mapped to the Node
 * digest names, and the set of them is the promise: an algorithm outside this
 * table cannot be checked, so a presentation naming one is refused rather than
 * accepted unverified.
 *
 * Exported to be read, on the same terms as `RECOGNISED_CRITICAL_EXTENSIONS`.
 * `sha-256` is the only one §B.3.3 makes mandatory; the other two cost a line
 * each and spare a caller from choosing between the spec's registry and what
 * happens to be implemented.
 */
export const SUPPORTED_HASH_ALGORITHMS: ReadonlyMap<string, string> = new Map([
  ['sha-256', 'sha256'],
  ['sha-384', 'sha384'],
  ['sha-512', 'sha512'],
]);

/** §B.3.3: absent on either side means sha-256. */
export const DEFAULT_HASH_ALGORITHM = 'sha-256';

/**
 * Encode transaction data objects for the `transaction_data` request parameter,
 * checking first that the request being built is one a wallet can answer.
 *
 * Throws rather than returning an `Outcome`, because everything it rejects is
 * the caller's own request being wrong — the same reason `verifySdJwtVc` throws
 * when asked to require key binding without a nonce. A `credential_ids` naming
 * a Credential Query that is not in the query is the one worth catching here in
 * particular: the wallet's own answer to it is `invalid_transaction_data`
 * (§8.5), which arrives as a refusal with nothing to say which of the two
 * documents was wrong.
 */
export function encodeTransactionData(
  entries: readonly TransactionDataEntry[],
  query: DcqlQuery,
): string[] {
  if (entries.length === 0) {
    throw new Error('transactionData is present but empty; omit it instead (OID4VP 1.0 §5.1)');
  }

  return entries.map((entry, index) => {
    const where = `transactionData[${index}]`;
    if (typeof entry.type !== 'string' || entry.type === '') {
      throw new Error(`${where} has no type`);
    }
    if (!Array.isArray(entry.credential_ids) || entry.credential_ids.length === 0) {
      throw new Error(`${where} ("${entry.type}") has no credential_ids`);
    }
    for (const id of entry.credential_ids) {
      const credential = credentialQueryById(query, id);
      if (!credential) {
        throw new Error(
          `${where} ("${entry.type}") authorises credential "${id}", which the DCQL query does not ask for`,
        );
      }
      // §B.3.3: "The transaction data mechanism requires the use of an SD-JWT
      // VC with Cryptographic Holder Binding. Wallets MUST reject requests with
      // transaction data types that have the `require_cryptographic_holder_binding`
      // parameter set to `false`." It could hardly be otherwise — the binding
      // *is* the holder's signature, so waiving it asks for an authorisation
      // nobody signs. Only an explicit `false` is a problem; the default is true.
      if (credential.require_cryptographic_holder_binding === false) {
        throw new Error(
          `${where} ("${entry.type}") authorises credential "${id}", which sets ` +
            'require_cryptographic_holder_binding to false — there would be no signature to bind it to',
        );
      }
    }
    // Checked here rather than at verification time: a wallet hashing with an
    // algorithm we cannot compute produces a presentation nothing can accept,
    // and the request is the last point at which that is still fixable.
    const algs = entry.transaction_data_hashes_alg;
    if (algs !== undefined) {
      if (!Array.isArray(algs) || algs.length === 0) {
        throw new Error(`${where} ("${entry.type}") has an empty transaction_data_hashes_alg`);
      }
      for (const alg of algs) {
        if (!SUPPORTED_HASH_ALGORITHMS.has(alg)) {
          throw new Error(
            `${where} ("${entry.type}") asks for hash algorithm "${String(alg)}", which this library cannot compute ` +
              `(supported: ${[...SUPPORTED_HASH_ALGORITHMS.keys()].join(', ')})`,
          );
        }
      }
    }

    return Buffer.from(JSON.stringify(entry), 'utf8').toString('base64url');
  });
}

/**
 * The transaction data as it was sent.
 *
 * The strings, not the objects: the hash is over the string a wallet received
 * (§B.3.3), so re-encoding the entries to check a hash would compare against
 * something the wallet never saw. Same discipline as reading the DCQL query
 * back off the payload — the request that was actually sent is the authority.
 *
 * `undefined` means the request asked for no authorisation. Anything present
 * and unreadable throws instead, because the two are opposite verdicts.
 */
export function readTransactionData(
  requestPayload: Record<string, unknown>,
): readonly string[] | undefined {
  const value = requestPayload['transaction_data'];
  if (value === undefined) return undefined;

  // Anything else throws rather than reading as absent, and the difference is
  // the whole safety of this function: a request that carried transaction data
  // and a request that carried none are opposite verdicts about the same
  // presentation, so a malformed parameter that degraded into "none" would
  // accept an unauthorised presentation as though nothing had been asked.
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('transaction_data is present but not a non-empty array (OID4VP 1.0 §5.1)');
  }
  if (!value.every((entry) => typeof entry === 'string')) {
    throw new Error('transaction_data contains an entry that is not a string');
  }
  return value as string[];
}

/**
 * Decode one encoded entry.
 *
 * Validates the two parameters §5.1 defines and nothing else — the rest belong
 * to the type. `credential_ids` is checked here rather than where it is read
 * because every later step indexes into it, and an entry that cannot say which
 * credential authorises it is not an entry that should be reasoned about.
 */
export function decodeTransactionData(encoded: string): TransactionDataEntry {
  const decoded: unknown = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
    throw new Error('transaction data entry is not a JSON object');
  }
  const entry = decoded as TransactionDataEntry;
  if (typeof entry.type !== 'string' || entry.type === '') {
    throw new Error('transaction data entry has no type');
  }
  if (
    !Array.isArray(entry.credential_ids) ||
    entry.credential_ids.length === 0 ||
    !entry.credential_ids.every((id) => typeof id === 'string')
  ) {
    throw new Error(`transaction data entry "${entry.type}" has no credential_ids`);
  }
  const algs = entry.transaction_data_hashes_alg;
  if (algs !== undefined && (!Array.isArray(algs) || !algs.every((alg) => typeof alg === 'string'))) {
    throw new Error(`transaction data entry "${entry.type}" has an unreadable transaction_data_hashes_alg`);
  }
  return entry;
}

/**
 * The hash of one entry, base64url, over the encoded string itself.
 *
 * Not over the decoded JSON: §B.3.3 says base64url decoding is not performed
 * before hashing, and a verifier that decoded first would compute a hash no
 * conforming wallet ever produces.
 */
export function transactionDataHash(encoded: string, alg: string): string {
  const nodeAlg = SUPPORTED_HASH_ALGORITHMS.get(alg);
  if (!nodeAlg) throw new Error(`Unsupported hash algorithm "${alg}"`);
  return createHash(nodeAlg).update(encoded, 'utf8').digest('base64url');
}

/**
 * Whether a presentation authorises one transaction data entry, or why not.
 *
 * Returns `undefined` when it does, in the shape `unsatisfiedClaims` uses: the
 * caller turns the failure into the rejection, so every reason code stays in
 * one place rather than being minted in each module that can detect one.
 */
export function unauthorisedTransaction(
  encoded: string,
  entry: TransactionDataEntry,
  binding: TransactionDataBinding | undefined,
): TransactionDataFailure | undefined {
  const allowed = entry.transaction_data_hashes_alg ?? [DEFAULT_HASH_ALGORITHM];

  if (!binding || binding.hashes.length === 0) {
    return {
      kind: 'missing',
      detail: `the presentation carries no transaction data hash for "${entry.type}"`,
    };
  }

  // §B.3.3: the response states the algorithm only when the request did, so
  // silence here means the default rather than "unknown".
  const alg = binding.alg ?? DEFAULT_HASH_ALGORITHM;
  if (!allowed.includes(alg)) {
    return {
      kind: 'mismatch',
      detail:
        `"${entry.type}" was hashed with ${alg}, which the request did not offer ` +
        `(${allowed.join(', ')})`,
    };
  }
  if (!SUPPORTED_HASH_ALGORITHMS.has(alg)) {
    return {
      kind: 'unsupported-alg',
      detail: `"${entry.type}" was hashed with ${alg}, which this library cannot compute`,
    };
  }

  if (!binding.hashes.includes(transactionDataHash(encoded, alg))) {
    return {
      kind: 'mismatch',
      detail:
        `the presentation's transaction data hash does not cover the "${entry.type}" entry that was sent — ` +
        'the wallet authorised something else',
    };
  }

  return undefined;
}
