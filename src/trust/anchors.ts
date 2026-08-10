import { X509Certificate } from 'node:crypto';

/**
 * The set of certificates we are willing to terminate a chain at.
 *
 * In Phase 1 this is loaded from PEM on disk. In Phase 2 the same class is
 * populated from the EU List of Trusted Lists, so nothing downstream changes.
 */
export class TrustAnchors {
  readonly #anchors: X509Certificate[];

  private constructor(anchors: X509Certificate[]) {
    this.#anchors = anchors;
  }

  static fromPem(pem: string | string[]): TrustAnchors {
    const blocks = (Array.isArray(pem) ? pem : [pem]).flatMap(
      (p) => p.match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g) ?? [],
    );
    if (blocks.length === 0) throw new Error('No PEM certificates found in trust anchor input');
    return new TrustAnchors(blocks.map((b) => new X509Certificate(b)));
  }

  get certificates(): readonly X509Certificate[] {
    return this.#anchors;
  }

  /** An anchor that is byte-identical to `cert`. */
  findEqual(cert: X509Certificate): X509Certificate | undefined {
    return this.#anchors.find((anchor) => anchor.fingerprint256 === cert.fingerprint256);
  }

  /** An anchor whose key signed `cert`. */
  findIssuerOf(cert: X509Certificate): X509Certificate | undefined {
    return this.#anchors.find(
      (anchor) => cert.checkIssued(anchor) && cert.verify(anchor.publicKey),
    );
  }
}
