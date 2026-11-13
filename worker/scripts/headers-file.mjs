// The text of `dist/_headers`: the header set of src/headers.json — the one the Worker itself sets on `/` and
// `/callback` (src/pages.ts) — for the static files that the asset layer serves without running the Worker
// (`/a/*` and `/sw.js`; wrangler.jsonc, "assets"). One function, so that the viewer's build, the placeholder
// (stub-dist.mjs) and the check of a built `dist/` all write and expect the same bytes.
//
// Plain Node, no dependency. Usage: node scripts/headers-file.mjs   (prints the text)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** The paths the asset layer answers by itself. A worker script — the Service Worker, and every `importScripts`
 *  target under `/a/` — is governed by the Content-Security-Policy of its own response, hence the whole set on both. */
export const ASSET_RULES = ["/a/*", "/sw.js"];

/** src/headers.json: an object of header name → value, in the order they are written. */
export function readHeaders(file = fileURLToPath(new URL("../src/headers.json", import.meta.url))) {
  const headers = JSON.parse(readFileSync(file, "utf8"));
  if (headers === null || typeof headers !== "object" || Array.isArray(headers)) throw new Error(`${file}: not a JSON object`);
  for (const [name, value] of Object.entries(headers)) {
    // One rule line each: a name the `_headers` syntax can carry, a value without a line break.
    if (!/^[A-Za-z][A-Za-z0-9-]*$/.test(name) || typeof value !== "string" || !/^[\x20-\x7e]+$/.test(value) || value !== value.trim()) {
      throw new Error(`${file}: the header ${JSON.stringify(name)} cannot be written into a _headers file`);
    }
  }
  return headers;
}

/** `_headers` as Workers Static Assets reads it: a path pattern, then its indented `Name: value` lines. `\n` line ends. */
export function headersFile(headers = readHeaders()) {
  const lines = Object.entries(headers).map(([name, value]) => `  ${name}: ${value}\n`);
  return ASSET_RULES.map((rule) => `${rule}\n${lines.join("")}`).join("");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.stdout.write(headersFile());
