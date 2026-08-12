import { X509Certificate } from 'node:crypto';

/**
 * A period during which a trust service held a given status.
 *
 * `until` is undefined for the entry still in effect. Half-open: `from` is
 * inclusive, `until` exclusive, so consecutive entries in a status history do
 * not both cover the instant one ends and the next begins.
 */
export type GrantedInterval = { from: Date; until: Date | undefined };

/**
 * A certificate together with when it was a *granted* trust service.
 *
 * ETSI TS 119 612 lists a service's current status and, usually, the history
 * that preceded it. Reducing that to "is it granted today" answers only one
 * question; keeping the intervals lets the same anchor set answer it at any
 * instant — see `TrustAnchors.findEqual`.
 */
export type TrustServiceEntry = {
  certificate: X509Certificate;
  granted: GrantedInterval[];
};

type Anchor = {
  certificate: X509Certificate;
  /**
   * When this anchor was granted, or undefined for an anchor that carries no
   * status history at all.
   *
   * Undefined is not "never": a pinned anchor loaded from PEM is a deliberate
   * decision by the operator, with no list to qualify it, so it is trusted
   * whenever it is asked about. Only anchors that came from a trust list have
   * intervals, because only they have a published status to evaluate.
   */
  granted: GrantedInterval[] | undefined;
};

/**
 * The set of certificates we are willing to terminate a chain at.
 *
 * Populated either from PEM on disk or from the EU List of Trusted Lists;
 * nothing downstream distinguishes them except that trust list anchors carry
 * the period they were granted for.
 */
export class TrustAnchors {
  readonly #anchors: Anchor[];

  private constructor(anchors: Anchor[]) {
    this.#anchors = anchors;
  }

  static fromCertificates(certificates: X509Certificate[]): TrustAnchors {
    return new TrustAnchors(certificates.map((certificate) => ({ certificate, granted: undefined })));
  }

  static fromPem(pem: string | string[]): TrustAnchors {
    const blocks = (Array.isArray(pem) ? pem : [pem]).flatMap(
      (p) => p.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [],
    );
    if (blocks.length === 0) throw new Error('No PEM certificates found in trust anchor input');
    return TrustAnchors.fromCertificates(blocks.map((b) => new X509Certificate(b)));
  }

  /**
   * Build from trust list services, merging entries for the same certificate.
   *
   * One certificate can identify more than one service — a CA that runs both a
   * qualified certificate service and a timestamping service, say — and the two
   * can have been granted over different periods. Merging keeps the union, so
   * the certificate is an anchor whenever *some* service it identifies was
   * granted, rather than only during whichever entry happened to be parsed last.
   */
  static fromTrustServices(entries: TrustServiceEntry[]): TrustAnchors {
    const byFingerprint = new Map<string, Anchor>();

    for (const entry of entries) {
      const key = entry.certificate.fingerprint256;
      const existing = byFingerprint.get(key);
      if (existing) {
        existing.granted = [...(existing.granted ?? []), ...entry.granted];
      } else {
        byFingerprint.set(key, { certificate: entry.certificate, granted: [...entry.granted] });
      }
    }

    return new TrustAnchors([...byFingerprint.values()]);
  }

  /** Every anchor certificate, whenever it was granted. */
  get certificates(): readonly X509Certificate[] {
    return this.#anchors.map((anchor) => anchor.certificate);
  }

  /** The anchors that were granted at `at`. */
  certificatesAt(at: Date): X509Certificate[] {
    return this.#anchors.filter((anchor) => grantedAt(anchor, at)).map((a) => a.certificate);
  }

  /**
   * An anchor that is byte-identical to `cert`.
   *
   * `at` is the instant to evaluate the trust list status against. Omitting it
   * ignores status history entirely, which is only correct when the caller has
   * no time to evaluate at; every path validation inside this library passes one.
   */
  findEqual(cert: X509Certificate, at?: Date): X509Certificate | undefined {
    return this.#anchors.find(
      (anchor) => anchor.certificate.fingerprint256 === cert.fingerprint256 && grantedAt(anchor, at),
    )?.certificate;
  }

  /** An anchor whose key signed `cert`, and which was granted at `at`. */
  findIssuerOf(cert: X509Certificate, at?: Date): X509Certificate | undefined {
    return this.#anchors.find(
      (anchor) =>
        grantedAt(anchor, at) &&
        cert.checkIssued(anchor.certificate) &&
        cert.verify(anchor.certificate.publicKey),
    )?.certificate;
  }
}

function grantedAt(anchor: Anchor, at: Date | undefined): boolean {
  // No status history to evaluate, or no instant to evaluate it at.
  if (anchor.granted === undefined || at === undefined) return true;
  return anchor.granted.some(
    (interval) => at >= interval.from && (interval.until === undefined || at < interval.until),
  );
}
