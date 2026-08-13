/**
 * Identifiers for the EUDI Person Identification Data credential.
 *
 * Constants rather than code: they are what a caller writing their own DCQL
 * query needs in order to name the PID, and they were previously buried in the
 * one query this library happened to build.
 *
 * The doc type and the namespace being the same string is a property of the
 * PID, not of mdoc. An ISO mDL has doc type `org.iso.18013.5.1.mDL` and
 * namespace `org.iso.18013.5.1`, so anything that treats one as the other is
 * right here and wrong in general.
 */

/** SD-JWT VC type identifier (EUDI PID Rulebook, ARF 2.4 chapter 4). */
export const PID_VCT = 'urn:eudi:pid:1';

/** mdoc doc type, per the same rulebook. */
export const PID_MDOC_DOCTYPE = 'eu.europa.ec.eudi.pid.1';

/** mdoc namespace holding the PID's elements. Equal to the doc type — see above. */
export const PID_MDOC_NAMESPACE = 'eu.europa.ec.eudi.pid.1';
