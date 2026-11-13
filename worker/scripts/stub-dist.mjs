// Makes sure `dist/` — the directory wrangler.jsonc uploads as the Worker's static assets — exists.
//
// The real content of `dist/` is the hosted viewer's bundle, written by the viewer's build (README.md, "The viewer's
// files"). Without one, wrangler refuses to start (`wrangler dev`, the tests) and to deploy, so this script writes a
// PLACEHOLDER with the same layout: a page for `/` that says what the Worker is and that the viewer is not part of
// the deployment, an empty Service Worker script, the `_headers` file and one build directory. A Worker deployed
// with the placeholder is the plain sign-in helper for `gclone login`.
//
// It never touches a `dist/` that holds anything but a placeholder: a built bundle is left alone.
//
// Plain Node, no dependency. Usage: node scripts/stub-dist.mjs [path/to/dist]

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { headersFile } from "./headers-file.mjs";

/** No build has this id: the first 16 hex digits of a SHA-256 are never all zero in practice, and the manifest says "stub". */
export const STUB_BUILD = "0000000000000000";
/** Where the Worker puts the status line (src/pages.ts, STATUS_MARKER). */
const STATUS_MARKER = "<!--gclone-status-->";

const STYLE = `body { font: 16px/1.5 system-ui, sans-serif; color: #1c1c1c; background: #f6f5f1; margin: 0; padding: 2rem 1rem; }
main { max-width: 36rem; margin: 0 auto; background: #fff; border: 1px solid #dcd9d0; border-radius: 8px; padding: 1.5rem 2rem 2rem; }
h1 { font-size: 1.3rem; margin: 0 0 1rem; }
code { font: 0.95em ui-monospace, monospace; background: #efede6; border-radius: 3px; padding: 0.1em 0.3em; }
.status { color: #555; font-size: 0.9rem; }
@media (prefers-color-scheme: dark) {
  body { color: #e8e6e1; background: #16161a; }
  main { background: #202026; border-color: #3a3a44; }
  code { background: #303039; }
  .status { color: #aaa; }
}
`;

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>gclone sign-in helper</title>
<link rel="stylesheet" href="/a/${STUB_BUILD}/stub.css">
</head>
<body>
<main>
<h1>gclone sign-in helper</h1>
<p>This is the private sign-in helper of one person's gclone, a tool that syncs encrypted files to their own Google Drive.
It lets that person's own devices sign in to Google; only its owner can sign in here, and it serves nobody else.</p>
<p>There is nothing to do on this page: a sign-in starts with <code>gclone login</code> in a terminal, and the code that
terminal shows is entered at Google. Never enter a code that someone sent you.</p>
<p>The web viewer's files are not part of this deployment.</p>
<p><a href="/privacy">Privacy</a></p>
<p class="status">${STATUS_MARKER}</p>
</main>
</body>
</html>
`;

const SERVICE_WORKER = `// gclone: placeholder, build ${STUB_BUILD}. The web viewer's files are not part of this deployment; this script handles nothing.\n`;

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** The placeholder's files, by path below `dist/`. */
export function stubFiles() {
  const manifest = {
    version: "0.0.0",
    commit: "",
    tag: "",
    build: STUB_BUILD,
    rustc: "",
    wasm_bindgen: "",
    stub: true,
    files: { "stub.css": sha256(STYLE) },
  };
  return {
    "index.html": PAGE,
    "sw.js": SERVICE_WORKER,
    _headers: headersFile(),
    [`a/${STUB_BUILD}/stub.css`]: STYLE,
    [`a/${STUB_BUILD}/manifest.json`]: `${JSON.stringify(manifest, null, 2)}\n`,
  };
}

/** What `dir` holds: "missing" (nothing that wrangler could upload), "stub" (a placeholder, of any age) or "built". */
export function distKind(dir) {
  if (!existsSync(join(dir, "index.html"))) return "missing";
  try {
    return JSON.parse(readFileSync(join(dir, "a", STUB_BUILD, "manifest.json"), "utf8")).stub === true ? "stub" : "built";
  } catch {
    return "built";
  }
}

/** Writes the placeholder into `dir` unless a built bundle is there. Returns what was found before. */
export function ensureDist(dir) {
  const before = distKind(dir);
  if (before === "built") return before;
  // A placeholder is written again, so that it always matches this script and src/headers.json. Nothing is deleted.
  for (const [path, text] of Object.entries(stubFiles())) {
    const file = join(dir, path);
    mkdirSync(join(file, ".."), { recursive: true });
    writeFileSync(file, text);
  }
  return before;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = process.argv[2] ?? fileURLToPath(new URL("../dist", import.meta.url));
  const before = ensureDist(dir);
  console.log(
    before === "built"
      ? `stub-dist: ${dir} holds a built viewer; left as it is`
      : `stub-dist: ${dir} holds the placeholder (no web viewer): the Worker is the plain sign-in helper`,
  );
}
