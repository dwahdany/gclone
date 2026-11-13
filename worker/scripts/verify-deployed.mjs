// Compares what a host serves with the viewer bundle of a release:
//
//   node scripts/verify-deployed.mjs https://<host> v0.4.0
//   node scripts/verify-deployed.mjs https://<host> --dist <dir>     (a local build; no attestation is involved)
//
// The expected bytes come from releaseBundle(tag) (release-bundle.mjs) — a fresh download whose attestation is
// verified — and never from `worker/dist/`. Compared: `/` and `/callback` (the page, with the Worker's status line
// taken out again), `/sw.js`, and every file of the build directory, the manifest included; and on each the header
// set of the bundle's `_headers`.
//
// What a pass proves: the static files and the page served to THESE requests are the release's. What it cannot prove:
// that the Worker does not answer other requests differently — whoever controls the Worker or the domain can serve
// one visitor another page (docs/SPEC.md §1.3). It finds an accident, a stale deployment and a changed asset.
//
// Node built-ins and `gh` only. Makes two requests that run the Worker (`/`, `/callback`); the rest are static files.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { STATUS_MARKER, checkDist, describe, sha256 } from "./check-dist.mjs";
import { command, releaseBundle } from "./release-bundle.mjs";

/** The line the Worker puts where the marker was: plain text, no markup. */
const STATUS_LINE = /^Status: [A-Za-z0-9 ,.:_'()-]{1,300}$/;

/** `https://host[:port]` — or plain http on this machine, for a local `wrangler dev`. */
export function hostOrigin(text) {
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error(`${JSON.stringify(text)} is not a URL: expected https://<host>`);
  }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) throw new Error(`${text}: the viewer is served over https only`);
  if (url.pathname !== "/" || url.search !== "" || url.hash !== "" || url.username !== "" || url.password !== "") throw new Error(`${text}: expected the host only, https://<host>`);
  return url.origin;
}

/** The header set of a `_headers` text: the lines of its first rule. */
export function headerSet(text) {
  const set = {};
  const lines = text.split("\n");
  for (const line of lines.slice(1)) {
    if (!line.startsWith("  ")) break;
    const colon = line.indexOf(":");
    set[line.slice(2, colon).toLowerCase()] = line.slice(colon + 1).trim();
  }
  return set;
}

/**
 * Compares `origin` with the bundle at `path` (whose `files` are `{ path: sha256 }`).
 * Returns `{ differences: [sentence], status, checked }`.
 */
export async function verifyDeployed(origin, bundle, { fetch: get = fetch } = {}) {
  const differences = [];
  const read = (path) => readFileSync(join(bundle.path, path));
  const headers = headerSet(read("_headers").toString("utf8"));
  const page = read("index.html").toString("utf8");
  const [before, after] = page.split(STATUS_MARKER);
  let status = "";
  let checked = 0;

  const ask = async (path) => {
    let res;
    try {
      res = await get(origin + path, { redirect: "manual", cache: "no-store", headers: { "cache-control": "no-cache", "user-agent": "gclone-verify-deployed" } });
    } catch (error) {
      differences.push(`${path}: no answer (${error.cause?.code ?? error.message})`);
      return null;
    }
    const body = Buffer.from(await res.arrayBuffer());
    checked++;
    if (res.status !== 200) {
      differences.push(`${path}: status ${res.status}${res.headers.get("location") ? ` → ${res.headers.get("location")}` : ""}, expected 200`);
      return null;
    }
    for (const [name, value] of Object.entries(headers)) {
      const got = res.headers.get(name);
      if (got !== value) differences.push(`${path}: header ${name} is ${got === null ? "missing" : JSON.stringify(got)}, the release sets ${JSON.stringify(value)}`);
    }
    return body;
  };

  // The page: the release's bytes around one status line.
  for (const path of ["/", "/callback"]) {
    const body = await ask(path);
    if (body === null) continue;
    const text = body.toString("utf8");
    const line = text.startsWith(before) && text.endsWith(after) && text.length >= page.length - STATUS_MARKER.length ? text.slice(before.length, text.length - after.length) : null;
    if (line === null || !Buffer.from(text, "utf8").equals(body)) differences.push(`${path}: the page differs from the release's index.html`);
    else if (!STATUS_LINE.test(line)) differences.push(`${path}: where the status line belongs, the page holds ${JSON.stringify(line.slice(0, 80))}`);
    else if (path === "/") status = line;
    else if (line !== status && status !== "") differences.push(`${path}: another status line than / (${JSON.stringify(line)})`);
  }

  // The static files, byte for byte.
  for (const path of Object.keys(bundle.files).sort()) {
    if (path === "index.html" || path === "_headers") continue;
    const body = await ask(`/${path}`);
    if (body !== null && sha256(body) !== bundle.files[path]) differences.push(`/${path}: differs from the release (${body.length} bytes served)`);
  }
  return { differences, status, checked };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await command("verify-deployed", async () => {
    const args = process.argv.slice(2);
    const usage = "usage: node scripts/verify-deployed.mjs https://<host> <tag>\n       node scripts/verify-deployed.mjs https://<host> --dist <dir>";
    if (args.length < 2 || args.length > 3) throw new Error(usage);
    const origin = hostOrigin(args[0]);
    let bundle;
    let what;
    if (args[1] === "--dist") {
      if (args[2] === undefined) throw new Error(usage);
      const checked = checkDist(args[2]);
      bundle = { path: args[2], files: checked.files, build: checked.build, remove() {} };
      what = `the local build in ${args[2]} (${describe(checked)}) — NOT a release: no attestation was checked`;
    } else {
      if (args.length !== 2) throw new Error(usage);
      bundle = releaseBundle(args[1]);
      what = `release ${bundle.tag} of ${bundle.repo} (version ${bundle.version}, build ${bundle.build}, tarball sha256 ${bundle.tarball.sha256}, attestation verified)`;
    }
    try {
      const { differences, status, checked } = await verifyDeployed(origin, bundle);
      if (differences.length > 0) {
        throw new Error(`${origin} does NOT serve ${what}:\n${differences.map((d) => `  - ${d}`).join("\n")}`);
      }
      console.log(`verify-deployed: ${origin} serves ${what}`);
      console.log(`  ${checked} answers compared: the page (/ and /callback), /sw.js and every file of /a/${bundle.build}/, each with the release's headers`);
      console.log(`  the page says: ${status}`);
      console.log("  This covers the static files and the page as served to these requests, not what the Worker may answer to others.");
    } finally {
      bundle.remove();
    }
  });
}
