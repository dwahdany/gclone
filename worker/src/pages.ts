// The HTML pages. No script, no external resource; every dynamic value goes through escapeHtml.

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
.check { font: 700 2rem ui-monospace, monospace; letter-spacing: 0.1em; text-align: center; margin: 1.5rem 0; }
.go { display: block; text-align: center; background: #1a56c4; color: #fff; font-weight: 600; text-decoration: none; border-radius: 6px; padding: 0.8rem 1rem; margin-top: 1.5rem; }
.warn { border-left: 4px solid #b3261e; padding-left: 0.8rem; }
.status { color: #555; font-size: 0.9rem; }
textarea { box-sizing: border-box; width: 100%; height: 9rem; font: 0.9rem ui-monospace, monospace; padding: 0.6rem; word-break: break-all; resize: none; }
@media (prefers-color-scheme: dark) {
  body { color: #e8e6e1; background: #16161a; }
  main { background: #202026; border-color: #3a3a44; }
  code { background: #303039; }
  .status { color: #aaa; }
  textarea { color: #e8e6e1; background: #16161a; border-color: #3a3a44; }
}`;

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => (c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : c === '"' ? "&quot;" : "&#39;"));
}

/** Escapes `text` and renders its `backtick spans` as <code>. */
function prose(text: string): string {
  return escapeHtml(text).replace(/`([^`]+)`/g, "<code>$1</code>");
}

export function html(status: number, title: string, bodyHtml: string): Response {
  const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<style>${STYLE}
</style>
</head>
<body>
<main>
<h1>${escapeHtml(title)}</h1>
${bodyHtml}
</main>
</body>
</html>
`;
  return new Response(page, { status, headers: HTML_HEADERS });
}

export function homePage(configured: boolean): Response {
  return html(
    200,
    "gclone sign-in helper",
    `<p>This is the private sign-in helper of one person's gclone, a tool that syncs encrypted files to their own Google Drive.
It lets that person's own devices sign in to Google; only its owner can sign in here, and it serves nobody else.</p>
<p><a href="/privacy">Privacy</a></p>
<p class="status">Status: ${configured ? "ready" : "not configured"}</p>`,
  );
}

export function privacyPage(): Response {
  return html(
    200,
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

/** The /login answer in both modes: the check code and the one link to Google. Advisory only — whoever holds the link to
 *  Google can skip this page; the confirmation that cannot be skipped is finishPage. */
export function confirmPage(checkCode: string, googleUrl: string, loopback: boolean): Response {
  const code = escapeHtml(checkCode);
  const intro = loopback
    ? "gclone on this computer wants to sign in to Google Drive. Continue only if you just ran <code>gclone login</code> on this computer and its terminal shows the check code"
    : "A gclone device without a browser wants to sign in to Google Drive. Continue only if you started <code>gclone login</code> yourself and its terminal shows the check code";
  return html(
    200,
    "Sign in to gclone",
    `<p>${intro} <strong>${code}</strong>.</p>
<p class="check">${code}</p>
<p class="warn">If someone sent you this link, close this page.</p>
<a class="go" href="${escapeHtml(googleUrl)}" rel="noreferrer">Continue with Google</a>`,
  );
}

/** The /callback answer to Google's redirect, in both modes: the check code again, and the one link that releases the grant.
 *  This is the confirmation nobody can skip — a link straight to Google's consent screen bypasses the /login page, but
 *  Google sends every browser here, and only this page holds the link that completes the login. */
export function finishPage(checkCode: string, continueUrl: string, loopback: boolean): Response {
  const code = escapeHtml(checkCode);
  const intro = loopback
    ? "You approved access at Google, but nothing is signed in yet. gclone on this computer is waiting for the last step. Finish only if you just ran <code>gclone login</code> on this computer and its terminal shows the check code"
    : "You approved access at Google, but nothing is signed in yet. A gclone device without a browser is waiting for the last step. Finish only if you started <code>gclone login</code> yourself and its terminal shows the check code";
  return html(
    200,
    "Finish signing in to gclone",
    `<p>${intro} <strong>${code}</strong>.</p>
<p class="check">${code}</p>
<p class="warn">If the code differs, or if someone sent you the link that led here, close this page: someone else is trying to
sign in to your Google Drive. Never send the address of this page to anyone.</p>
<p class="status">This page works for 2 minutes.</p>
<a class="go" href="${escapeHtml(continueUrl)}" rel="noreferrer">Finish signing in</a>`,
  );
}

/** Paste mode, the last step of /callback: the one string the user carries to the terminal. */
export function codePage(pasteString: string): Response {
  return html(
    200,
    "Almost done",
    `<p>Paste this code into the terminal where <code>gclone login</code> is waiting, right away: it stops working 2 minutes
after the previous page appeared.</p>
<textarea readonly autofocus spellcheck="false" aria-label="gclone sign-in code">${escapeHtml(pasteString)}</textarea>
<p class="warn">Never send it — or the address of this page — to anyone.</p>`,
  );
}

export function errorPage(status: number, message: string): Response {
  return html(status, status === 200 ? "Sign-in stopped" : "Sign-in failed", `<p>${prose(message)}</p>`);
}
