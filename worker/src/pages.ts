// The two HTML pages (Google asks an OAuth app for a home page and a privacy policy). Static: no script, no external
// resource, and nothing from a request.

const HTML_HEADERS: Record<string, string> = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
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

/** What the home page reports: `legacy_incomplete` = ready for every login and every device that signed in with gclone
 *  0.2.0 or later, but exactly one of the two GOOGLE_LEGACY_CLIENT_* secrets is set. */
export type Status = "ready" | "legacy_incomplete" | "not_configured";

const STATUS_LINE: Record<Status, string> = {
  ready: "Status: ready",
  legacy_incomplete:
    "Status: ready. Warning: only one of GOOGLE_LEGACY_CLIENT_ID and GOOGLE_LEGACY_CLIENT_SECRET is set; logins made before gclone 0.2.0 cannot be refreshed until both are set or both are deleted.",
  not_configured: "Status: not configured",
};

export function homePage(status: Status): Response {
  return html(
    "gclone sign-in helper",
    `<p>This is the private sign-in helper of one person's gclone, a tool that syncs encrypted files to their own Google Drive.
It lets that person's own devices sign in to Google; only its owner can sign in here, and it serves nobody else.</p>
<p>There is nothing to do on this page: a sign-in starts with <code>gclone login</code> in a terminal, and the code that
terminal shows is entered at Google. Never enter a code that someone sent you.</p>
<p><a href="/privacy">Privacy</a></p>
<p class="status">${STATUS_LINE[status]}</p>`,
  );
}

export function privacyPage(): Response {
  return html(
    "Privacy",
    `<p>This service signs its owner's gclone devices in to Google. It is not offered to anyone else.</p>
<p><strong>Google data it touches.</strong> During a sign-in it reads the e-mail address of the Google account, only to check
that the account belongs to the owner. The access it requests (<code>drive.file</code>) covers only the Google Drive files that
gclone itself created; it cannot see any other file. Those files are encrypted on the device before they are uploaded, and
file data never passes through this service: devices talk to Google Drive directly.</p>
<p><strong>What it stores.</strong> Nothing. It has no database and sets no cookies. The tokens Google issues are passed on only
to the owner's own devices and are not kept here.</p>
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
