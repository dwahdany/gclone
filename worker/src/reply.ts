// The Worker's JSON answers. Every error, on every route, is `{ "error": "<code>", "message": "…" }`.

import { maskedEmail, type GoogleFailure } from "./google";

/** An answer plus the error code that goes into the log line. */
export interface Reply {
  response: Response;
  error?: string;
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Reply {
  return {
    response: new Response(JSON.stringify(body), {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        ...headers,
      },
    }),
  };
}

export function fail(status: number, error: string, message: string, headers: Record<string, string> = {}): Reply {
  return { ...json(status, { error, message }, headers), error };
}

/** The address is masked (`s***@example.net`): `/device/poll` is open to anyone, and whoever entered a caller's user
 *  code at Google agreed to show the address to the app, not to that caller. The web routes answer the same way. */
export function notAllowed(email: string | undefined, headers: Record<string, string> = {}): Reply {
  const masked = maskedEmail(email);
  const who = masked === null ? "This Google account" : `The Google account ${masked}`;
  return fail(403, "email_not_allowed", `${who} is not allowed to sign in here.`, headers);
}

/** `remedy` completes "remove gclone at …; then ". */
export function scopeNotAllowed(excess: string[], remedy = "run `gclone login` again"): Reply {
  // Scope names are not secrets, but they are Google's text: only plain ones are echoed, and only a few. They come last,
  // so a client that shortens the message keeps the remedy.
  const named = excess.filter((entry) => /^[A-Za-z0-9:\/._-]{1,100}$/.test(entry)).slice(0, 3);
  const what = named.length > 0 ? ` Not asked for: ${named.join(", ")}${named.length < excess.length ? ", ..." : ""}` : "";
  return fail(
    403,
    "scope_not_allowed",
    `Google granted more access than gclone asks for, so nothing was handed out. If you did not expect this, remove gclone at https://myaccount.google.com/permissions; then ${remedy}.${what}`,
  );
}

export function googleFailure(r: GoogleFailure, headers: Record<string, string> = {}): Reply {
  return fail(r.status, r.error, r.message, headers);
}
