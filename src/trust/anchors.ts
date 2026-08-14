import { X509Certificate } from 'node:crypto';
import { type QualificationElement, qualifiersFor } from './service-extensions.ts';

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
  /**
   * What the service's `ServiceInformationExtensions` said about it
   * (TS 119 612 §5.5.9), or absent for a service that published none.
   *
   * Optional because a caller may build entries of their own, and because most
   * services publish nothing here. Absent is "the list said nothing", never
   * "the list said no": a service with no `Qualifications` is not a service
   * declaring its certificates unqualified.
   */
  qualification?: {
    /** `AdditionalServiceInformation` URIs: what the service is provided for. */
    serviceInformation: string[];
    /** The rules deriving qualifiers for the certificates this service issues. */
    qualifications: QualificationElement[];
  };
};

/**
 * What the trusted lists say about a certificate issued under an anchor.
 *
 * Derived per certificate rather than stored per anchor, because that is what
 * `Qualifications` is: a rule set over end-entity certificates, not a property
 * of the CA. Two certificates from one CA can qualify differently.
 */
export type ServiceQualification = {
  /** `AdditionalServiceInformation` URIs of the services this anchor identifies. */
  serviceInformation: string[];
  /** Qualifier URIs that apply to the certificate (TS 119 615 §4.4). */
  qualifiers: string[];
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
  /**
   * The extensions of every service this certificate identifies, merged.
   *
   * Undefined for a pinned anchor, on the same reading as `granted`: a PEM on
   * disk is an operator's decision with no list to qualify it, and reporting an
   * empty qualification would say the lists found nothing to say when no list
   * was consulted.
   */
  qualification: NonNullable<TrustServiceEntry['qualification']> | undefined;
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
    return new TrustAnchors(
      certificates.map((certificate) => ({ certificate, granted: undefined, qualification: undefined })),
    );
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
        existing.qualification = mergeQualification(existing.qualification, entry.qualification);
      } else {
        byFingerprint.set(key, {
          certificate: entry.certificate,
          granted: [...entry.granted],
          qualification: mergeQualification(undefined, entry.qualification),
        });
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

  /**
   * What the trusted lists say about `certificate`, issued under `anchor`.
   *
   * `undefined` when the anchor came from PEM rather than a list, or when its
   * services published no extensions — "nothing was said", which a caller must
   * not read as "nothing qualifies". An empty `qualifiers` array *is* an answer:
   * the rules were evaluated and none matched.
   *
   * Deriving rather than storing is the point. `Qualifications` is a rule set
   * over the certificates a CA issues, so the answer depends on the certificate
   * being asked about, and two leaves under one anchor can differ.
   */
  qualify(anchor: X509Certificate, certificate: X509Certificate): ServiceQualification | undefined {
    const found = this.#anchors.find((a) => a.certificate.fingerprint256 === anchor.fingerprint256);
    if (!found?.qualification) return undefined;
    return {
      serviceInformation: [...found.qualification.serviceInformation],
      qualifiers: qualifiersFor(certificate, found.qualification.qualifications),
    };
  }
}

/**
 * Union two services' extensions, for a certificate that identifies both.
 *
 * The same merge `granted` gets, and for the same reason: one certificate can
 * identify a qualified certificate service and a timestamping service, and
 * neither one's silence contradicts the other's statement. Qualification rules
 * concatenate rather than combine, because each `QualificationElement` is
 * evaluated on its own and contributes its qualifiers independently.
 */
function mergeQualification(
  existing: Anchor['qualification'],
  incoming: TrustServiceEntry['qualification'],
): Anchor['qualification'] {
  if (!incoming) return existing;
  return {
    serviceInformation: [
      ...new Set([...(existing?.serviceInformation ?? []), ...incoming.serviceInformation]),
    ],
    qualifications: [...(existing?.qualifications ?? []), ...incoming.qualifications],
  };
}

function grantedAt(anchor: Anchor, at: Date | undefined): boolean {
  // No status history to evaluate, or no instant to evaluate it at.
  if (anchor.granted === undefined || at === undefined) return true;
  return anchor.granted.some(
    (interval) => at >= interval.from && (interval.until === undefined || at < interval.until),
  );
}
