// Checks a `dist/` — the directory wrangler uploads as the Worker's static assets — before it is packed, unpacked or
// deployed (README.md, "The viewer's files"). The rules:
//
//   - `dist/` holds exactly `index.html`, `sw.js`, `_headers` and `a/`; `a/` holds exactly one directory, named by 16
//     hex digits (the build). Nothing else: no `_redirects` (it would act before the Worker), no second build.
//   - every file of `a/<build>/` is a plain file with an extension of js, css, svg, wasm or json, is at most 25 MiB,
//     and is listed in `a/<build>/manifest.json` with its SHA-256; the manifest lists nothing that is not there and
//     names the build its directory is named by.
//   - `_headers` is the text written from src/headers.json (scripts/headers-file.mjs).
//   - `index.html` holds the status marker exactly once; every resource it loads is under `/a/<build>/`; it has no
//     inline script, no inline style, no event-handler attribute, no `<base>` and no `<meta http-equiv>`.
//   - `sw.js` names the same build, and no build marker is left unstamped.
//   - a built viewer names the Drive host once, in `drive.js` (the one host the page's policy lets it talk to).
//
// With `release: "<tag>"` the bundle must also say that it is the build of that tag: `tag` and `version` of the
// manifest, a clean commit, not the placeholder.
//
// Plain Node, no dependency: it runs in the release job that builds the bundle, which installs no npm package.
// Usage: node scripts/check-dist.mjs [path/to/dist] [--release <tag>] [--not-a-release]

import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { headersFile } from "./headers-file.mjs";

export const STATUS_MARKER = "<!--gclone-status-->";
export const BUILD_MARK = "__GCLONE_BUILD__";
export const TOP = ["_headers", "a", "index.html", "sw.js"];
export const EXTENSIONS = ["js", "css", "svg", "wasm", "json"];
export const MAX_FILE = 25 * 1024 * 1024; // Workers Static Assets' limit for one file
export const DRIVE_HOST = "www.googleapis.com";
const MANIFEST_KEYS = ["build", "commit", "files", "rustc", "tag", "version", "wasm_bindgen"];
// Attributes whose value the browser fetches, on any element. `href` is one only on <link> and <use>/<image>:
// on <a> it is a place to go, not a thing to load.
const LOADING = ["src", "srcset", "data", "poster", "action", "formaction", "manifest", "ping", "background", "icon", "codebase", "archive", "xlink:href"];

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** The version a release tag names: `v0.4.0` → `0.4.0`. Null for anything else. */
export function tagVersion(tag) {
  return typeof tag === "string" && /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(tag) ? tag.slice(1) : null;
}

/**
 * The tags of an HTML text, in order: `{ name, attrs: [[name, value]], text }` — `text` is the raw content of a
 * `<script>` or `<style>` element. Small and strict on purpose: the page is ours, and anything this does not
 * understand is reported by the caller as a tag it cannot check.
 */
export function htmlTags(html) {
  const tags = [];
  let at = 0;
  while (at < html.length) {
    const open = html.indexOf("<", at);
    if (open < 0) break;
    if (html.startsWith("<!--", open)) {
      const end = html.indexOf("-->", open + 4);
      at = end < 0 ? html.length : end + 3;
      continue;
    }
    const head = /^<(\/?)([A-Za-z][A-Za-z0-9:-]*)/.exec(html.slice(open, open + 80));
    if (!head) {
      // `<!doctype …>` and a stray `<`
      at = open + 1;
      continue;
    }
    const name = head[2].toLowerCase();
    let i = open + head[0].length;
    const attrs = [];
    let closed = false;
    while (i < html.length) {
      while (i < html.length && /[\s/]/.test(html[i])) i++;
      if (html[i] === ">") {
        i++;
        closed = true;
        break;
      }
      const start = i;
      while (i < html.length && !/[\s=>/]/.test(html[i])) i++;
      if (i === start) {
        i++; // a character that starts no attribute name (`=` first): skip it
        continue;
      }
      const attr = html.slice(start, i).toLowerCase();
      while (i < html.length && /\s/.test(html[i])) i++;
      let value = "";
      if (html[i] === "=") {
        i++;
        while (i < html.length && /\s/.test(html[i])) i++;
        if (html[i] === '"' || html[i] === "'") {
          const quote = html[i];
          const end = html.indexOf(quote, i + 1);
          value = html.slice(i + 1, end < 0 ? html.length : end);
          i = end < 0 ? html.length : end + 1;
        } else {
          const from = i;
          while (i < html.length && !/[\s>]/.test(html[i])) i++;
          value = html.slice(from, i);
        }
      }
      attrs.push([attr, value]);
    }
    const tag = { name: head[1] === "/" ? `/${name}` : name, attrs, text: "", closed };
    if (head[1] === "" && (name === "script" || name === "style")) {
      const end = html.toLowerCase().indexOf(`</${name}`, i);
      tag.text = html.slice(i, end < 0 ? html.length : end);
      i = end < 0 ? html.length : end;
    }
    tags.push(tag);
    at = i;
  }
  return tags;
}

/** What is wrong with the page, as sentences. `build` is the 16 hex digits its resources must be under. */
export function pageProblems(html, build) {
  const problems = [];
  const count = html.split(STATUS_MARKER).length - 1;
  if (count !== 1) problems.push(`index.html holds the status marker ${STATUS_MARKER} ${count} times, not once`);
  if (html.includes(BUILD_MARK)) problems.push(`index.html still holds the unstamped build marker ${BUILD_MARK}`);
  const base = `/a/${build}/`;
  const own = (url) => url.startsWith(base) && /^[A-Za-z0-9._-]+$/.test(url.slice(base.length));
  for (const tag of htmlTags(html)) {
    const where = `index.html, <${tag.name}>`;
    if (!tag.closed) problems.push(`${where}: the tag does not end`);
    if (tag.name === "base") problems.push(`${where}: a <base> element changes where every address points`);
    if (tag.name === "style") problems.push(`${where}: inline style`);
    if (tag.name === "script") {
      if (tag.text.trim() !== "") problems.push(`${where}: inline script`);
      if (!tag.attrs.some(([name]) => name === "src")) problems.push(`${where}: a script without src`);
    }
    for (const [name, value] of tag.attrs) {
      const url = value.trim();
      if (name === "style") problems.push(`${where}: an inline style attribute`);
      if (name.startsWith("on")) problems.push(`${where}: the event-handler attribute ${name}`);
      if (name === "http-equiv") problems.push(`${where}: http-equiv (a policy or a redirect set from inside the page)`);
      if (name === "srcdoc") problems.push(`${where}: srcdoc (a document inside the page)`);
      if (/^(javascript|data|blob|vbscript):/i.test(url.replace(/[\s\0]/g, ""))) problems.push(`${where}: ${name}="${url.slice(0, 40)}"`);
      const loads = LOADING.includes(name) || (name === "href" && tag.name !== "a" && tag.name !== "area");
      if (!loads) continue;
      // `<use href="#id">` points into the page itself.
      if ((tag.name === "use" || tag.name === "image") && /^#[A-Za-z][A-Za-z0-9_-]*$/.test(url)) continue;
      const urls = name === "srcset" ? url.split(",").map((part) => part.trim().split(/\s+/)[0]) : [url];
      for (const one of urls) {
        if (!own(one)) problems.push(`${where}: ${name}="${one.slice(0, 80)}" is not a file of /a/${build}/`);
      }
    }
  }
  return problems;
}

/**
 * Reads and checks `dir`. Returns `{ ok, problems, build, stub, manifest, files }`, where `files` is every file of
 * the directory by its path below it (`index.html`, `a/<build>/app.js`, …) with its SHA-256.
 */
export function inspectDist(dir, { release } = {}) {
  const problems = [];
  const files = {};
  const result = { ok: false, problems, build: "", stub: false, manifest: null, files };
  const kind = (path) => {
    try {
      const stat = lstatSync(path);
      return stat.isSymbolicLink() ? "link" : stat.isDirectory() ? "dir" : stat.isFile() ? "file" : "other";
    } catch {
      return "missing";
    }
  };
  if (kind(dir) !== "dir") {
    problems.push(`${dir} is not a directory`);
    return result;
  }
  const top = readdirSync(dir).sort();
  for (const name of top) if (!TOP.includes(name)) problems.push(`${name}: not part of a bundle (a bundle is index.html, sw.js, _headers and a/)`);
  for (const name of TOP) {
    const want = name === "a" ? "dir" : "file";
    const got = kind(join(dir, name));
    if (got !== want) problems.push(`${name}: ${got === "missing" ? "missing" : `a ${got}, not a ${want}`}`);
  }
  if (problems.length > 0) return result;
  for (const name of ["index.html", "sw.js", "_headers"]) files[name] = sha256(readFileSync(join(dir, name)));

  const builds = readdirSync(join(dir, "a")).sort();
  if (builds.length !== 1 || !/^[0-9a-f]{16}$/.test(builds[0]) || kind(join(dir, "a", builds[0])) !== "dir") {
    problems.push(`a/ must hold exactly one directory named by 16 hex digits; it holds: ${builds.join(", ") || "nothing"}`);
    return result;
  }
  const build = (result.build = builds[0]);
  const buildDir = join(dir, "a", build);
  const names = readdirSync(buildDir).sort();
  const bytes = new Map();
  for (const name of names) {
    const path = `a/${build}/${name}`;
    const got = kind(join(buildDir, name));
    if (got !== "file") {
      problems.push(`${path}: a ${got}, not a file`);
      continue;
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name) || !EXTENSIONS.includes(name.split(".").pop())) {
      problems.push(`${path}: not a name with one of the extensions ${EXTENSIONS.join(", ")}`);
    }
    const content = readFileSync(join(buildDir, name));
    if (content.length > MAX_FILE) problems.push(`${path}: ${content.length} bytes, more than the ${MAX_FILE} the asset layer takes`);
    bytes.set(name, content);
    files[path] = sha256(content);
  }

  // The manifest: the list of the build's files.
  let manifest = null;
  if (!bytes.has("manifest.json")) {
    problems.push(`a/${build}/manifest.json is missing`);
  } else {
    try {
      manifest = JSON.parse(bytes.get("manifest.json").toString("utf8"));
    } catch {
      problems.push(`a/${build}/manifest.json is not JSON`);
    }
    if (manifest !== null && (typeof manifest !== "object" || Array.isArray(manifest))) {
      problems.push(`a/${build}/manifest.json is not a JSON object`);
      manifest = null;
    }
  }
  if (manifest !== null) {
    result.manifest = manifest;
    result.stub = manifest.stub === true;
    for (const key of Object.keys(manifest)) {
      if (!MANIFEST_KEYS.includes(key) && key !== "stub") problems.push(`manifest.json: the unknown key ${JSON.stringify(key)}`);
    }
    for (const key of MANIFEST_KEYS) {
      const want = key === "files" ? "object" : "string";
      const value = manifest[key];
      if (typeof value !== want || value === null || Array.isArray(value)) problems.push(`manifest.json: "${key}" must be ${want === "object" ? "an object" : "a string"}`);
    }
    if ("stub" in manifest && manifest.stub !== true) problems.push('manifest.json: "stub" is either true or absent');
    if (manifest.build !== build) problems.push(`manifest.json names the build ${JSON.stringify(manifest.build)}, its directory is a/${build}/`);
    const listed = manifest.files !== null && typeof manifest.files === "object" && !Array.isArray(manifest.files) ? manifest.files : {};
    for (const name of names) {
      if (name === "manifest.json" || !bytes.has(name)) continue;
      if (!Object.hasOwn(listed, name)) problems.push(`a/${build}/${name} is not listed in manifest.json`);
      else if (listed[name] !== files[`a/${build}/${name}`]) problems.push(`a/${build}/${name} is not the file manifest.json lists (another SHA-256)`);
    }
    for (const name of Object.keys(listed)) {
      if (name === "manifest.json") problems.push("manifest.json lists itself");
      else if (!bytes.has(name)) problems.push(`manifest.json lists ${JSON.stringify(name)}, which is not in a/${build}/`);
    }
  }

  // The three files outside the build directory.
  if (readFileSync(join(dir, "_headers"), "utf8") !== headersFile()) {
    problems.push("_headers is not the text written from src/headers.json (node scripts/headers-file.mjs)");
  }
  problems.push(...pageProblems(readFileSync(join(dir, "index.html"), "utf8"), build));
  const worker = readFileSync(join(dir, "sw.js"), "utf8");
  if (worker.includes(BUILD_MARK)) problems.push(`sw.js still holds the unstamped build marker ${BUILD_MARK}`);
  if (!worker.includes(build)) problems.push(`sw.js does not name the build ${build}`);
  for (const other of worker.match(/\/a\/[0-9a-f]{16}\b/g) ?? []) {
    if (other !== `/a/${build}`) problems.push(`sw.js names another build: ${other}`);
  }

  if (!result.stub) {
    if (worker.split(`const BUILD = '${build}';`).length !== 2) problems.push(`sw.js must hold the line const BUILD = '${build}'; exactly once`);
    // The Drive host: one place. The page's policy (connect-src) names it, and the viewer's tests swap exactly it.
    for (const [name, content] of [["index.html", readFileSync(join(dir, "index.html"))], ["sw.js", Buffer.from(worker)], ...[...bytes].map(([file, value]) => [`a/${build}/${file}`, value])]) {
      const times = content.toString("latin1").split(DRIVE_HOST).length - 1;
      const want = name === `a/${build}/drive.js` ? 1 : 0;
      if (times !== want) problems.push(`${name} names ${DRIVE_HOST} ${times} time(s); the host is named once, in drive.js`);
    }
    if (!bytes.has("drive.js")) problems.push(`a/${build}/drive.js is missing`);
  }

  if (release !== undefined) {
    const version = tagVersion(release);
    if (version === null) problems.push(`${JSON.stringify(release)} is not a release tag (v<major>.<minor>.<patch>)`);
    if (result.stub) problems.push("this is the placeholder, not a built viewer");
    if (manifest !== null) {
      if (manifest.tag !== release) problems.push(`manifest.json says tag ${JSON.stringify(manifest.tag)}, expected ${JSON.stringify(release)}`);
      if (version !== null && manifest.version !== version) problems.push(`manifest.json says version ${JSON.stringify(manifest.version)}, the tag ${release} is version ${version}`);
      if (!/^[0-9a-f]{40}$/.test(String(manifest.commit))) problems.push(`manifest.json says commit ${JSON.stringify(manifest.commit)}: not a clean commit`);
    }
  }
  result.ok = problems.length === 0;
  return result;
}

/** As inspectDist, but throws one Error that lists every problem. */
export function checkDist(dir, options = {}) {
  const result = inspectDist(dir, options);
  if (!result.ok) throw new Error(`check-dist: ${dir} is not a bundle that can be ${options.release === undefined ? "deployed" : `released as ${options.release}`}:\n${result.problems.map((p) => `  - ${p}`).join("\n")}`);
  return result;
}

/** One line that says what a checked bundle is. */
export function describe(result) {
  if (result.stub) return `the placeholder (no web viewer), build ${result.build}`;
  const { version, tag, rustc, commit } = result.manifest;
  return `gclone viewer ${version}, build ${result.build}, ${tag === "" ? "no tag" : `tag ${tag}`}, commit ${commit || "unknown"}, ${rustc || "unknown rustc"}`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const at = args.indexOf("--release");
  const release = at >= 0 ? args.splice(at, 2)[1] : undefined;
  if (at >= 0 && release === undefined) {
    console.error("check-dist: --release needs a tag");
    process.exit(2);
  }
  // `npm run deploy:dev`: the one line that says what is about to be deployed without the release check.
  const dev = args.indexOf("--not-a-release");
  if (dev >= 0) args.splice(dev, 1);
  const dir = args[0] ?? fileURLToPath(new URL("../dist", import.meta.url));
  try {
    const result = checkDist(dir, { release });
    if (dev >= 0) console.log(`deploy:dev: NOT a release build, deployed without the release check — ${describe(result)}`);
    else console.log(`check-dist: ok — ${describe(result)}; ${Object.keys(result.files).length} files`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
