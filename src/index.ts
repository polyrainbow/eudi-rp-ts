/**
 * eudi-rp-ts — verify EUDI credentials from Node.
 *
 * This is the library. It reads no configuration, opens no ports and logs
 * nothing; callers pass explicit options and receive typed outcomes. The demo
 * relying party in `app/` is one consumer of it, not part of it.
 *
 * Everything exported here is public API and changes only with the major
 * version. Anything reachable by deep import is not.
 */

// Outcomes. Every failure ends at exactly one ReasonCode.
export type { Outcome, Rejected, ReasonCode, Verified } from './result.ts';
export { accept, reject } from './result.ts';

// SD-JWT VC verification. The mdoc half is `verifyMdoc`, further down — one of
// two formats each, neither of them "the credential" in general.
//
// `VerifiedCredential` is the exception and is meant to be: it is the shared
// result shape both formats produce, which is why the mdoc path in
// `oid4vp/response.ts` returns one too.
export { verifySdJwtVc, verifyAgeOver18SdJwtVc } from './verify.ts';
export type {
  AgeResult,
  KeyBindingExpectation,
  VerifiedCredential,
  VerifySdJwtVcOptions,
} from './verify.ts';

// The age predicate, usable on its own against already-verified claims.
export { evaluateAgeOver18SdJwt, evaluateAgeOver18Mdoc } from './predicate/age.ts';
export type { AgeEvidence } from './predicate/age.ts';

// Trust anchors: pinned, or from an ETSI TS 119 612 trust list.
export { TrustAnchors } from './trust/anchors.ts';
export type { GrantedInterval, TrustServiceEntry } from './trust/anchors.ts';
export {
  checkTrustListFreshness,
  fetchTrustAnchors,
  parsePointers,
  parseServiceCertificates,
  parseTrustServices,
  verifyTrustList,
} from './trust/lotl.ts';
export type { Pointer, TrustListOptions, TrustListResult } from './trust/lotl.ts';
export { resolveIssuerCertificateChain, resolveIssuerKeyFromX5c } from './trust/issuer-key.ts';
export type { PathValidationOptions, ResolvedIssuer } from './trust/issuer-key.ts';
// RFC 5280 §6.1.4 (o). The set is exported to be *read*: it is the list of
// extensions this library claims to act on, and a caller deciding whether that
// is enough for their trust decision should not have to take it on faith.
export {
  RECOGNISED_CRITICAL_EXTENSIONS,
  unrecognisedCriticalExtensions,
} from './trust/critical-extensions.ts';
// Certificate policies (RFC 5280 §6.1): reachable from PathValidationOptions,
// so the type is public even though the state machine behind it is not.
export type { CertificatePolicyOptions } from './trust/policy-tree.ts';
export { checkStatusList, createStatusChecker, createStatusListCache } from './trust/status.ts';
// Certificate revocation: CRL and OCSP, a different question from the above.
export {
  checkChainRevocation,
  createRevocationCache,
  readCrlDistributionPoints,
  readOcspResponders,
  revocationRejection,
  revocationVia,
} from './trust/revocation.ts';
export type { RevocationCheckOptions, RevocationOutcome } from './trust/revocation.ts';
export type {
  StatusCheckOptions,
  StatusChecker,
  StatusListReference,
  StatusOutcome,
} from './trust/status.ts';

// Outbound HTTP with a deadline, a size limit, and a TTL cache for status and
// trust lists. The defaults are policy, so they are exported to be read or
// overridden rather than rediscovered.
export {
  DEFAULT_ALLOWED_PROTOCOLS,
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_REDIRECTS,
  DEFAULT_TIMEOUT_MS,
  TtlCache,
  fetchBytes,
  fetchText,
} from './fetching.ts';
export type { CacheOptions, FetchOptions } from './fetching.ts';

// ISO/IEC 18013-5 mdoc, verified through the same trust layer.
export { verifyMdoc } from './mdoc/verify.ts';
export type { MdocVerifyOptions, VerifiedMdoc } from './mdoc/verify.ts';
export { parseCoseSign1, verifyCoseSign1, coseAlg, coseX5Chain, coseKeyToPublicKey } from './mdoc/cose.ts';
export type { CoseSign1 } from './mdoc/cose.ts';
export { verifyDeviceResponse, verifyAgeOver18Mdoc } from './mdoc/device-response.ts';
export type {
  AgeOver18MdocOptions,
  DeviceResponseOptions,
  VerifiedDeviceResponse,
} from './mdoc/device-response.ts';
export { buildSessionTranscript, jwkThumbprint } from './mdoc/session-transcript.ts';
export type { HandoverParameters } from './mdoc/session-transcript.ts';

// OID4VP: build a request for a query, validate the response against it.
export { buildAuthorizationRequest } from './oid4vp/request.ts';
export type { BuiltRequest } from './oid4vp/request.ts';
export { verifyPresentationResponse } from './oid4vp/response.ts';
export type {
  PredicateResult,
  PresentationContext,
  PresentationPredicate,
  PresentedCredential,
  PresentedCredentials,
  PresentedFormat,
  VerifiedPresentation,
} from './oid4vp/response.ts';
// The DCQL query, and the readers that turn one into checks on the answer.
// A query is read back as well as sent, and what it asks for is what the
// response is checked against — so the library builds none of its own.
export {
  credentialQueryById,
  mdocNamespaces,
  queryFormats,
  unsatisfiedRequirement,
} from './oid4vp/query.ts';
// Reading a response with the claims path that asked for it (OID4VP 1.0 §7),
// and checking that the wallet disclosed what the query required.
export { readClaim, selectClaims, unsatisfiedClaims } from './oid4vp/claims.ts';
export type {
  ClaimsPath,
  ClaimsQuery,
  CredentialQuery,
  CredentialSetQuery,
  DcqlQuery,
  MdocCredentialQuery,
  SdJwtVcCredentialQuery,
} from './oid4vp/query.ts';

// Presets: one question asked one way, in a form the library itself has no
// opinion about. Everything here is composed from the exports above, so a
// caller asking something else writes the same two pieces — a query, and a
// predicate over the answer — without touching the verification path.
export {
  AGE_OVER_18_MDOC_QUERY_ID,
  AGE_OVER_18_SD_JWT_QUERY_ID,
  ageOver18Predicate,
  ageOver18Query,
} from './presets/age-over-18.ts';
export type { AgeOver18QueryOptions } from './presets/age-over-18.ts';
export { PID_MDOC_DOCTYPE, PID_MDOC_NAMESPACE, PID_VCT } from './presets/eudi-pid.ts';
export { clientId, responseUri, verifierBaseUrl, x509Hash } from './oid4vp/identity.ts';
export type { ClientIdPrefix, VerifierIdentity } from './oid4vp/identity.ts';

// Structured events for auditing and metrics. The library never logs.
// `withoutVerdict` is exported because a caller composing its own verifier on
// top of these needs the same discipline the library applies internally: let
// the intermediate events through, withhold the verdict until it is one.
export { noopSink, withoutVerdict } from './events.ts';
export type { CredentialFormat, EventSink, VerificationEvent } from './events.ts';

// Primitives, exported because a caller supplying their own callbacks needs them.
export {
  DEFAULT_ALLOWED_ALGS,
  MIN_RSA_MODULUS_BITS,
  SUPPORTED_JWS_ALGS,
  importPublicJwk,
  isSupportedAlg,
  keyUnusableFor,
  unsupportedKeyReason,
  verifyJws,
} from './crypto.ts';
export type { JwsAlg } from './crypto.ts';
