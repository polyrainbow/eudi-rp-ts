import { decode, encode } from 'cbor2';

/**
 * CBOR helpers for mdoc.
 *
 * `cbor2` decodes a CBOR map to a plain object when its keys are strings and to
 * a `Map` when they are not, and mdoc uses both — string keys for the security
 * object, integer labels for COSE headers and keys. Every accessor here copes
 * with either so the calling code does not have to remember which it is.
 */
export type CborValue = unknown;

/** A CBOR tag as `cbor2` surfaces it. Tag 24 wraps embedded CBOR. */
export const TAG_EMBEDDED_CBOR = 24;
export const TAG_DATE_TIME = 0;

export function get(container: unknown, key: string | number): unknown {
  if (container instanceof Map) return container.get(key);
  if (typeof container === 'object' && container !== null) {
    return (container as Record<string | number, unknown>)[key];
  }
  return undefined;
}

export function entriesOf(container: unknown): [string | number, unknown][] {
  if (container instanceof Map) return [...container.entries()] as [string | number, unknown][];
  if (typeof container === 'object' && container !== null) {
    return Object.entries(container as Record<string, unknown>);
  }
  return [];
}

/** The value inside a CBOR tag, or the value itself when untagged. */
export function untag(value: unknown): unknown {
  if (value && typeof value === 'object') {
    const tagged = value as { contents?: unknown; value?: unknown };
    if (tagged.contents !== undefined) return tagged.contents;
    if (tagged.value !== undefined && 'tag' in (value as object)) return tagged.value;
  }
  return value;
}

/** Decode a `bstr .cbor Foo`: a byte string whose content is itself CBOR. */
export function decodeEmbedded(value: unknown): unknown {
  const bytes = untag(value);
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('Expected embedded CBOR byte string');
  }
  return decode(bytes);
}

/**
 * A CBOR byte string as a plain `Uint8Array`.
 *
 * The copy is not incidental. `cbor2` decodes byte strings to Node `Buffer`s,
 * and re-encoding a `Buffer` produces `{"type":"Buffer","data":[...]}` rather
 * than a CBOR byte string — which silently corrupts any structure rebuilt for
 * signature verification, and fails in a way that looks like a bad signature.
 */
export function toBytes(value: unknown): Uint8Array {
  const raw = untag(value);
  if (raw instanceof Uint8Array) return new Uint8Array(raw);
  throw new Error('Expected a CBOR byte string');
}

/**
 * Encode `#6.24(bstr)` — a CBOR tag 24 wrapping a byte string.
 *
 * mdoc uses this wrapper wherever one structure embeds another's exact bytes:
 * IssuerSignedItemBytes, MobileSecurityObjectBytes, DeviceNameSpacesBytes.
 * Rebuilding it by hand matters because digests and signatures cover the
 * wrapped encoding, so re-serialising the decoded value would not reproduce it.
 */
export function encodeTag24(contents: Uint8Array): Uint8Array {
  const length = contents.length;
  let header: number[];
  if (length < 24) header = [0x40 + length];
  else if (length < 0x100) header = [0x58, length];
  else if (length < 0x10000) header = [0x59, length >> 8, length & 0xff];
  else header = [0x5a, (length >>> 24) & 0xff, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff];

  return Uint8Array.from([0xd8, 0x18, ...header, ...contents]);
}

export { decode, encode };
