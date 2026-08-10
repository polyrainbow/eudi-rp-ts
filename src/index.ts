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
export { evaluateAgeOver18 } from './predicate/age.ts';
export type { AgeEvidence } from './predicate/age.ts';

// Trust anchors: pinned, or from an ETSI TS 119 612 trust list.
export { TrustAnchors } from './trust/anchors.ts';
export { fetchTrustAnchors, parsePointers, parseServiceCertificates, verifyTrustList } from './trust/lotl.ts';
export type { Pointer, TrustListOptions, TrustListResult } from './trust/lotl.ts';
export { resolveIssuerKeyFromX5c } from './trust/issuer-key.ts';
export type { ResolvedIssuer } from './trust/issuer-key.ts';
export { createStatusChecker } from './trust/status.ts';
export type { StatusCheckOptions, StatusChecker } from './trust/status.ts';

// OID4VP: build a request, validate the response.
export { buildAuthorizationRequest } from './oid4vp/request.ts';
export type { BuiltRequest } from './oid4vp/request.ts';
export { verifyPresentationResponse } from './oid4vp/response.ts';
export type { PresentationContext } from './oid4vp/response.ts';
export { ageOver18Query, CREDENTIAL_QUERY_ID } from './oid4vp/query.ts';
export { clientId, responseUri } from './oid4vp/identity.ts';
export type { ClientIdPrefix, VerifierIdentity } from './oid4vp/identity.ts';

// Primitives, exported because a caller supplying their own callbacks needs them.
export { ALLOWED_JWS_ALG } from './crypto.ts';
