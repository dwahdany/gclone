// The Worker's HTML pages. `/` and `/callback` are the hosted viewer's page: the bytes of the deployed `index.html`
// with the status line put in — or, in a deployment without the viewer's files, the plain home page below. `/privacy`
// is the privacy statement (Google asks an OAuth app for a home page and a privacy policy). Nothing of a request ever
// gets into a page.

import viewerHeaders from "./headers.json";

/** The header set of the viewer's page (`/`, `/callback`). The same set is written into `dist/_headers` for the static
 *  files (`/a/*`, `/sw.js`), which the asset layer serves without running the Worker: scripts/headers-file.mjs. */
export const VIEWER_HEADERS: Readonly<Record<string, string>> = viewerHeaders;
export const VIEWER_CSP: string = viewerHeaders["Content-Security-Policy"];

/** The two pages the Worker writes itself: no script, no external resource. */
const HTML_HEADERS: Record<string, string> = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "Strict-Transport-Security": viewerHeaders["Strict-Transport-Security"],
};

const STYLE = `
body { font: 16px/1.5 system-ui, sans-serif; color: #1c1c1c; background: #f6f5f1; margin: 0; padding: 2rem 1rem; }
main { max-width: 36rem; margin: 0 auto; background: #fff; border: 1px solid #dcd9d0; border-radius: 8px; padding: 1.5rem 2rem 2rem; }
h1 { font-size: 1.3rem; margin: 0 0 1rem; }
code { font: 0.95em ui-monospace, monospace; background: #efede6; border-radius: 3px; padding: 0.1em 0.3em; }
.status { color: #555; font-size: 0.9rem; }
@media (prefers-color-scheme: dark) {
  body { color: #e8e6e1; background: #16161a; }
  main { background: #202026; border-color: #3a3a44; }
  code { background: #303039; }
  .status { color: #aaa; }
}`;

/** `title` and `bodyHtml` are literals of this file. */
function html(title: string, bodyHtml: string): Response {
  const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${title}</title>
<style>${STYLE}
</style>
</head>
<body>
<main>
<h1>${title}</h1>
${bodyHtml}
</main>
</body>
</html>
`;
  return new Response(page, { status: 200, headers: HTML_HEADERS });
}

/** What `/` reports. `viewer_not_configured`: every `gclone login` and every device works; the hosted viewer's
 *  sign-in (`/web/*`) answers `500 server_misconfigured` until its three secrets are set. */
export type Status = "ready" | "viewer_not_configured" | "not_configured";

export const STATUS_LINE: Record<Status, string> = {
  ready: "Status: ready",
  viewer_not_configured: "Status: ready. The web viewer is not configured: it needs GOOGLE_LEGACY_CLIENT_ID, GOOGLE_LEGACY_CLIENT_SECRET and SEAL_KEY.",
  not_configured: "Status: not configured",
};

/** Where the status line goes in the viewer's `index.html`. */
export const STATUS_MARKER = "<!--gclone-status-->";

/** The viewer's page: `index.html` as deployed, with the status line in place of the marker. The same bytes for `/`
 *  and `/callback` and for every query: nothing of the request is read. */
export function viewerPage(indexHtml: string, status: Status): Response {
  // A function as the replacement: no `$` pattern of the status text is ever interpreted.
  const page = indexHtml.replace(STATUS_MARKER, () => STATUS_LINE[status]);
  return new Response(page, { status: 200, headers: { ...VIEWER_HEADERS, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

/** `/` and `/callback` of a deployment without the viewer's files (no assets binding, or no `index.html` in it): what
 *  the Worker is, and its status. The sign-in helper for `gclone login` does not depend on those files. */
export function homePage(status: Status): Response {
  return html(
    "gclone sign-in helper",
    `<p>This is the private sign-in helper of one person's gclone, a tool that syncs encrypted files to their own Google Drive.
It lets that person's own devices sign in to Google; only its owner can sign in here, and it serves nobody else.</p>
<p>There is nothing to do on this page: a sign-in starts with <code>gclone login</code> in a terminal, and the code that
terminal shows is entered at Google. Never enter a code that someone sent you.</p>
<p>The web viewer's files are not part of this deployment.</p>
<p><a href="/privacy">Privacy</a></p>
<p class="status">${STATUS_LINE[status]}</p>`,
  );
}

export function privacyPage(): Response {
  return html(
    "Privacy",
    `<p>This service signs its owner's gclone devices, and the owner's browser for the web viewer on this site, in to Google.
It is not offered to anyone else.</p>
<p><strong>Google data it touches.</strong> During a sign-in it reads the e-mail address of the Google account, only to check
that the account belongs to the owner. The access it requests (<code>drive.file</code>) covers only the Google Drive files that
gclone itself created; it cannot see any other file. Those files are encrypted on the device before they are uploaded, and
file data never passes through this service: devices, and the web viewer in the owner's browser, talk to Google Drive directly.
The viewer decrypts files in the browser; the passphrase and the keys of a vault never leave it.</p>
<p><strong>What it stores.</strong> Nothing on the server: it has no database. The tokens Google issues are passed on only
to the owner's own devices and are not kept here.</p>
<p><strong>Cookies.</strong> One, and only after the owner signed in to the web viewer: <code>__Host-gclone-web</code>. It holds
that browser's Google sign-in for gclone (a refresh token and the account's e-mail address), encrypted so that only this
service can open it. Scripts cannot read it, it is sent to this site only, it stops working 12 hours after the sign-in
(30 days if "stay signed in" was chosen), and "Sign out" removes it. There is no other cookie and no tracking.</p>
<p><strong>In the browser.</strong> Besides that cookie the web viewer keeps, in the browser's own storage for this site, the
sort order chosen in the file list and a few short-lived markers in the tab: one random value for the minutes of a sign-in,
and notes that let the page say so when the browser closed it in the middle of unlocking. It stores no key, nothing derived
from the passphrase, no file name and no file content. "Sign out" clears this storage.</p>
<p><strong>What it logs.</strong> No request content: no addresses, codes or tokens. For each request it logs only the route,
the status and an error code. Cloudflare, the hosting platform, processes request metadata (IP address, time, URL path) under
its own terms.</p>
<p><strong>Sharing.</strong> Nothing is shared with anyone, except that the hosting platform and Google take part in the
sign-in as described above.</p>
<p><strong>Withdrawing access.</strong> Remove the app at
<a href="https://myaccount.google.com/permissions" rel="noreferrer">https://myaccount.google.com/permissions</a>.</p>
<p><a href="/">Home</a></p>`,
  );
}
