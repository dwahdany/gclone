// Tests of headers-file.mjs and stub-dist.mjs (plain Node, `node --test`, run by `npm test`): the `_headers` text
// written from src/headers.json, and the placeholder `dist/` — which has the layout a built viewer has, so that
// wrangler, the Worker and the checks of a built `dist/` meet the same shape. Nothing outside a temporary directory
// is written.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ASSETS, parseJsonc } from "./check-config.mjs";
import { ASSET_RULES, headersFile, readHeaders } from "./headers-file.mjs";
import { STUB_BUILD, distKind, ensureDist, stubFiles } from "./stub-dist.mjs";

const headers = readHeaders();

function inTempDir(run) {
  const dir = mkdtempSync(join(tmpdir(), "gclone-dist-"));
  try {
    return run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Every file below `dir`, as paths with `/`. */
function tree(dir, prefix = "") {
  return readdirSync(dir, { withFileTypes: true })
    .flatMap((entry) => (entry.isDirectory() ? tree(join(dir, entry.name), `${prefix}${entry.name}/`) : [`${prefix}${entry.name}`]))
    .sort();
}

test("src/headers.json is the header set of the design, in its order", () => {
  assert.deepEqual(Object.keys(headers), [
    "Content-Security-Policy",
    "Referrer-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security",
  ]);
  const csp = headers["Content-Security-Policy"];
  assert.deepEqual(csp.split("; "), [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self'",
    "img-src 'self'",
    "media-src 'self'",
    "frame-src 'self'",
    "worker-src 'self'",
    "connect-src 'self' https://www.googleapis.com",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types gclone",
  ]);
  assert.equal(headers["Strict-Transport-Security"], "max-age=63072000; includeSubDomains");
  // No caching rule: it would also apply to the 404 of a file that a deployment has not propagated yet.
  assert.ok(!Object.keys(headers).some((name) => /^cache-control$/i.test(name)));
});

test("_headers: the whole set for /a/* and for /sw.js, one `Name: value` line each, \\n line ends", () => {
  const text = headersFile();
  assert.deepEqual(ASSET_RULES, ["/a/*", "/sw.js"]);
  // the paths the asset layer answers without the Worker are exactly the exceptions of run_worker_first
  assert.deepEqual(ASSETS.run_worker_first, ["/*", ...ASSET_RULES.map((rule) => `!${rule}`)]);
  const lines = text.split("\n");
  assert.equal(lines.pop(), "");
  const per = Object.keys(headers).length + 1;
  assert.equal(lines.length, 2 * per);
  for (const [i, rule] of ASSET_RULES.entries()) {
    const block = lines.slice(i * per, (i + 1) * per);
    assert.equal(block[0], rule);
    assert.deepEqual(block.slice(1), Object.entries(headers).map(([name, value]) => `  ${name}: ${value}`));
  }
  assert.ok(!text.includes("\r"));
  // within the limits of the format: at most 100 rules, lines of at most 2,000 characters
  assert.ok(lines.every((line) => line.length <= 2000));
  // the same text for the same input, and the argument is what is written
  assert.equal(headersFile(), text);
  assert.equal(headersFile({ "X-A": "1" }), "/a/*\n  X-A: 1\n/sw.js\n  X-A: 1\n");
});

test("a header that the _headers syntax cannot carry is refused, not written", () => {
  inTempDir((dir) => {
    const file = join(dir, "headers.json");
    const refused = (value) => {
      writeFileSync(file, JSON.stringify(value));
      assert.throws(() => readHeaders(file), /headers\.json/);
    };
    refused([]);
    refused(null);
    refused({ "X-A": "line one\nline two" });
    refused({ "X-A": "" });
    refused({ "X-A": " padded " });
    refused({ "X-A": 7 });
    refused({ "X A": "x" });
    refused({ "/a/*": "x" });
    refused({ "! X-A": "x" });
    refused({ "X-A": "café" });
    writeFileSync(file, JSON.stringify({ "X-A": "fine" }));
    assert.deepEqual(readHeaders(file), { "X-A": "fine" });
  });
});

test("the placeholder has the layout of a built viewer: index.html, sw.js, _headers and one build directory", () => {
  const files = stubFiles();
  assert.match(STUB_BUILD, /^[0-9a-f]{16}$/);
  assert.deepEqual(Object.keys(files).sort(), ["_headers", `a/${STUB_BUILD}/manifest.json`, `a/${STUB_BUILD}/stub.css`, "index.html", "sw.js"]);
  assert.equal(files._headers, headersFile());
  // the page: the status marker exactly once; no inline script, style or event handler (the page's CSP has none of
  // them); every reference goes to this build's directory or to the Worker's own /privacy
  const page = files["index.html"];
  assert.equal(page.split("<!--gclone-status-->").length, 2);
  assert.ok(!/<script|<style|\sstyle=|\son[a-z]+=/i.test(page));
  const references = [...page.matchAll(/(?:href|src)="([^"]*)"/g)].map((m) => m[1]);
  assert.deepEqual(references, [`/a/${STUB_BUILD}/stub.css`, "/privacy"]);
  assert.ok(page.includes("Never enter a code that someone sent you."));
  assert.ok(page.includes("The web viewer's files are not part of this deployment."));
  // the Service Worker script names the build and does nothing
  assert.ok(files["sw.js"].includes(STUB_BUILD));
  assert.ok(files["sw.js"].split("\n").every((line) => line === "" || line.startsWith("//")));
  // the manifest lists every other file of the build directory with its SHA-256, and says what it is
  const manifest = JSON.parse(files[`a/${STUB_BUILD}/manifest.json`]);
  assert.equal(manifest.stub, true);
  assert.equal(manifest.build, STUB_BUILD);
  assert.equal(manifest.tag, "");
  assert.deepEqual(manifest.files, { "stub.css": createHash("sha256").update(files[`a/${STUB_BUILD}/stub.css`]).digest("hex") });
  for (const text of Object.values(files)) assert.ok(text.endsWith("\n") && !text.includes("\r"));
});

test("ensureDist writes the placeholder where there is nothing, refreshes a placeholder, and never touches a built viewer", () => {
  inTempDir((dir) => {
    const dist = join(dir, "dist");
    assert.equal(distKind(dist), "missing");
    assert.equal(ensureDist(dist), "missing");
    assert.equal(distKind(dist), "stub");
    assert.deepEqual(tree(dist), Object.keys(stubFiles()).sort());
    for (const [path, text] of Object.entries(stubFiles())) assert.equal(readFileSync(join(dist, path), "utf8"), text);

    // a placeholder of an older version of the script is brought up to date
    writeFileSync(join(dist, "_headers"), "/a/*\n  X-Old: 1\n");
    assert.equal(ensureDist(dist), "stub");
    assert.equal(readFileSync(join(dist, "_headers"), "utf8"), headersFile());

    // an empty directory, or one without a page, is "missing" too
    const empty = join(dir, "empty");
    mkdirSync(empty);
    assert.equal(ensureDist(empty), "missing");
    assert.equal(distKind(empty), "stub");

    // a built viewer: a page, another build directory, no placeholder manifest — every byte stays
    const built = join(dir, "built");
    mkdirSync(join(built, "a", "0123456789abcdef"), { recursive: true });
    const mine = { "index.html": "<!doctype html><p><!--gclone-status--></p>", "sw.js": "// the real one", _headers: "/a/*\n  X-Mine: 1\n", "a/0123456789abcdef/manifest.json": '{"build":"0123456789abcdef","files":{}}' };
    for (const [path, text] of Object.entries(mine)) writeFileSync(join(built, path), text);
    assert.equal(distKind(built), "built");
    assert.equal(ensureDist(built), "built");
    assert.deepEqual(tree(built), Object.keys(mine).sort());
    for (const [path, text] of Object.entries(mine)) assert.equal(readFileSync(join(built, path), "utf8"), text);
    // … also one that happens to carry a directory of the placeholder's name without the placeholder's mark
    mkdirSync(join(built, "a", STUB_BUILD));
    writeFileSync(join(built, "a", STUB_BUILD, "manifest.json"), '{"build":"0000000000000000","files":{}}');
    assert.equal(ensureDist(built), "built");
    writeFileSync(join(built, "a", STUB_BUILD, "manifest.json"), "not json");
    assert.equal(ensureDist(built), "built");
    assert.equal(readFileSync(join(built, "index.html"), "utf8"), mine["index.html"]);
  });
});

test("wrangler.jsonc uploads ./dist, which git ignores", () => {
  const config = parseJsonc(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  assert.equal(config.assets.directory, "./dist");
  const ignored = readFileSync(new URL("../.gitignore", import.meta.url), "utf8").split("\n");
  assert.ok(ignored.includes("dist/"));
});
