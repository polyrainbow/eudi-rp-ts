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

// Credential verification.
export { verifyCredential, verifyAgeOver18 } from './verify.ts';
export type {
  AgeResult,
  KeyBindingExpectation,
  VerifiedCredential,
  VerifyCredentialOptions,
} from './verify.ts';

// The age predicate, usable on its own against already-verified claims.
export { evaluateAgeOver18, evaluateAgeOver18Mdoc } from './predicate/age.ts';
export type { AgeEvidence } from './predicate/age.ts';

// Trust anchors: pinned, or from an ETSI TS 119 612 trust list.
export { TrustAnchors } from './trust/anchors.ts';
export { fetchTrustAnchors, parsePointers, parseServiceCertificates, verifyTrustList } from './trust/lotl.ts';
export type { Pointer, TrustListOptions, TrustListResult } from './trust/lotl.ts';
export { resolveIssuerCertificateChain, resolveIssuerKeyFromX5c } from './trust/issuer-key.ts';
export type { PathValidationOptions, ResolvedIssuer } from './trust/issuer-key.ts';
export { createStatusChecker, createStatusListCache } from './trust/status.ts';
export type { StatusCheckOptions, StatusChecker, StatusOutcome } from './trust/status.ts';

// Outbound HTTP with a deadline, and a TTL cache for status and trust lists.
export { DEFAULT_TIMEOUT_MS, TtlCache, fetchText } from './fetching.ts';
export type { CacheOptions, FetchOptions } from './fetching.ts';

// ISO/IEC 18013-5 mdoc, verified through the same trust layer.
export { verifyMdoc } from './mdoc/verify.ts';
export type { MdocVerifyOptions, VerifiedMdoc } from './mdoc/verify.ts';
export { parseCoseSign1, verifyCoseSign1, coseAlg, coseX5Chain, coseKeyToPublicKey } from './mdoc/cose.ts';
export type { CoseSign1 } from './mdoc/cose.ts';
export { verifyDeviceResponse } from './mdoc/device-response.ts';
export type { DeviceResponseOptions, VerifiedDeviceResponse } from './mdoc/device-response.ts';
export { buildSessionTranscript, jwkThumbprint } from './mdoc/session-transcript.ts';
export type { HandoverParameters } from './mdoc/session-transcript.ts';

// OID4VP: build a request, validate the response.
export { buildAuthorizationRequest } from './oid4vp/request.ts';
export type { BuiltRequest } from './oid4vp/request.ts';
export { verifyPresentationResponse } from './oid4vp/response.ts';
export type { PresentationContext, PresentedFormat, VerifiedPresentation } from './oid4vp/response.ts';
export {
  ageOver18Query,
  CREDENTIAL_QUERY_ID,
  MDOC_CREDENTIAL_QUERY_ID,
  PID_MDOC_NAMESPACE,
} from './oid4vp/query.ts';
export { clientId, responseUri } from './oid4vp/identity.ts';
export type { ClientIdPrefix, VerifierIdentity } from './oid4vp/identity.ts';

// Structured events for auditing and metrics. The library never logs.
export { noopSink } from './events.ts';
export type { EventSink, VerificationEvent } from './events.ts';

// Primitives, exported because a caller supplying their own callbacks needs them.
export { DEFAULT_ALLOWED_ALGS, SUPPORTED_JWS_ALGS, isSupportedAlg, verifyJws } from './crypto.ts';
export type { JwsAlg } from './crypto.ts';
