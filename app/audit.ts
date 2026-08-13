import type { EventSink, VerificationEvent } from '../src/index.ts';

/**
 * What the demo decides its verification events become: one JSON object per
 * line on stdout.
 *
 * The library never logs — it emits typed events and this is the application
 * making the choice, which is the whole point of the seam. A real deployment
 * would send the same records to whatever it already keeps, and the shape here
 * is chosen so that swapping `write` for that is the only edit needed.
 *
 * JSON lines rather than prose because an audit trail is read by grep and by
 * whatever ingests logs, not by a person watching a terminal — and because the
 * events are already structured, so rendering them into sentences would only
 * throw that away.
 *
 * **Every field of every event is logged verbatim, deliberately.** Events carry
 * no personal data by construction and `test/hardening.test.ts` asserts it, so
 * the application does not have to know which fields are safe — that guarantee
 * belongs to the library and is tested there. Filtering here would silently
 * become the place where the guarantee is presumed instead of proved.
 */

/** Adding a field to a record is a decision; this is the only place it happens. */
function write(record: Record<string, unknown>): void {
  console.log(JSON.stringify({ at: new Date().toISOString(), ...record }));
}

/**
 * A sink for one presentation.
 *
 * The presentation id is the correlation key, and without it the trail is
 * unusable the moment two holders present at once: the events interleave and
 * nothing says which verification a line belongs to. The library cannot supply
 * it — it has no notion of a session — so the application binds it here.
 *
 * The id is a random UUID this server minted for this exchange. It identifies a
 * presentation, never a person, and survives no longer than the session does.
 */
export function auditSink(presentation: string): EventSink {
  return (event: VerificationEvent) => write({ presentation, ...event });
}

/**
 * The application's own audit lines, for what the library cannot see: that a
 * presentation was requested at all, and the rejections this server makes
 * before any verifier runs.
 *
 * "What was asked for, of whom, when, and what was decided" needs the asking as
 * much as the deciding, and the library is only ever handed the answer.
 */
export function auditPresentation(presentation: string, event: string, detail?: Record<string, unknown>): void {
  write({ presentation, type: event, ...detail });
}
