// Tests of check-dist.mjs (plain Node, `node --test`, run by `npm test`): every rule of a deployable `dist/`, each
// with an example that breaks it. Nothing outside a temporary directory is written.

import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkDist, describe, htmlTags, inspectDist, pageProblems, sha256, tagVersion } from "./check-dist.mjs";
import { headersFile } from "./headers-file.mjs";
import { FAKE_BUILD, fakeBundleFiles, inTempDir, writeTree } from "./selftest-bundle.mjs";
import { STUB_BUILD, ensureDist, stubFiles } from "./stub-dist.mjs";

const B = FAKE_BUILD;
const script = fileURLToPath(new URL("./check-dist.mjs", import.meta.url));

/** The problems of the made-up bundle after `change(files)` (and `after(dir)` on the written tree). */
function problemsOf(change = () => {}, { options = {}, after = () => {}, bundle = {} } = {}) {
  return inTempDir((dir) => {
    const files = fakeBundleFiles(bundle);
    change(files);
    writeTree(dir, files);
    after(dir);
    return inspectDist(dir, options).problems;
  });
}

/** Rewrites the manifest of `files` with `edit(manifest)`. */
function editManifest(files, edit) {
  const path = `a/${B}/manifest.json`;
  const manifest = JSON.parse(files[path]);
  edit(manifest);
  files[path] = `${JSON.stringify(manifest, null, 2)}\n`;
}

const expectOne = (problems, pattern) => {
  assert.ok(problems.some((p) => pattern.test(p)), `expected a problem matching ${pattern}, got:\n${problems.join("\n") || "(none)"}`);
};

test("the made-up bundle and the placeholder pass; a release needs more", () => {
  assert.deepEqual(problemsOf(), []);
  assert.deepEqual(problemsOf(() => {}, { options: { release: "v9.8.7" } }), []);
  inTempDir((dir) => {
    ensureDist(dir);
    const result = checkDist(dir);
    assert.equal(result.stub, true);
    assert.equal(result.build, STUB_BUILD);
    assert.deepEqual(Object.keys(result.files).sort(), Object.keys(stubFiles()).sort());
    for (const [path, text] of Object.entries(stubFiles())) assert.equal(result.files[path], sha256(text));
    assert.match(describe(result), /placeholder/);
    // … but it is nobody's release
    assert.throws(() => checkDist(dir, { release: "v0.4.0" }), /placeholder/);
  });
  inTempDir((dir) => {
    writeTree(dir, fakeBundleFiles());
    const result = checkDist(dir, { release: "v9.8.7" });
    assert.equal(result.build, B);
    assert.equal(result.stub, false);
    assert.equal(Object.keys(result.files).length, 9);
    assert.match(describe(result), /gclone viewer 9\.8\.7, build 0123456789abcdef, tag v9\.8\.7/);
  });
});

test("dist/ holds index.html, sw.js, _headers and a/ with one build directory — nothing else", () => {
  expectOne(problemsOf((f) => (f._redirects = "/ /elsewhere 302\n")), /_redirects: not part of a bundle/);
  expectOne(problemsOf((f) => (f["robots.txt"] = "")), /robots\.txt: not part of a bundle/);
  expectOne(problemsOf((f) => (f[".DS_Store"] = "")), /\.DS_Store: not part of a bundle/);
  expectOne(problemsOf((f) => delete f["sw.js"]), /sw\.js: missing/);
  expectOne(problemsOf((f) => delete f["index.html"]), /index\.html: missing/);
  expectOne(problemsOf((f) => delete f._headers), /_headers: missing/);
  expectOne(problemsOf((f) => (f["a/fedcba9876543210/manifest.json"] = "{}")), /exactly one directory/);
  expectOne(problemsOf((f) => (f["a/stray.js"] = "")), /exactly one directory/);
  expectOne(problemsOf(() => {}, { bundle: { build: "0123456789ABCDEF" } }), /exactly one directory/);
  expectOne(problemsOf(() => {}, { bundle: { build: "0123" } }), /exactly one directory/);
  expectOne(problemsOf((f) => (f[`a/${B}/sub/x.js`] = "")), new RegExp(`a/${B}/sub: a dir, not a file`));
  expectOne(problemsOf(() => {}, { after: (dir) => symlinkSync("/etc/hosts", join(dir, "a", B, "hosts.js")) }), /hosts\.js: a link, not a file/);
  expectOne(problemsOf(() => {}, { after: (dir) => (rmSync(join(dir, "sw.js")), symlinkSync(join(dir, "index.html"), join(dir, "sw.js"))) }), /sw\.js: a link, not a file/);
  assert.match(inspectDist("/nonexistent/gclone-dist").problems[0], /not a directory/);
});

test("every file of the build directory: an allowed extension, at most 25 MiB, listed in the manifest with its SHA-256", () => {
  const add = (name, content = "x") => (f) => {
    f[`a/${B}/${name}`] = content;
    editManifest(f, (m) => (m.files[name] = sha256(content)));
  };
  for (const name of ["page.html", "app.js.map", "notes.txt", "README", "x.wasm.gz", ".hidden.js"]) {
    expectOne(problemsOf(add(name)), /not a name with one of the extensions js, css, svg, wasm, json/);
  }
  assert.deepEqual(problemsOf(add("extra.css")), []);
  expectOne(problemsOf((f) => (f[`a/${B}/unlisted.js`] = "x")), /unlisted\.js is not listed in manifest\.json/);
  expectOne(problemsOf((f) => (f[`a/${B}/app.js`] = "changed")), /app\.js is not the file manifest\.json lists/);
  expectOne(problemsOf((f) => delete f[`a/${B}/shell.css`]), /manifest\.json lists "shell\.css", which is not in/);
  expectOne(problemsOf((f) => delete f[`a/${B}/manifest.json`]), /manifest\.json is missing/);
  expectOne(problemsOf((f) => (f[`a/${B}/manifest.json`] = "not json")), /manifest\.json is not JSON/);
  expectOne(problemsOf((f) => (f[`a/${B}/manifest.json`] = "[]")), /not a JSON object/);
  expectOne(problemsOf((f) => editManifest(f, (m) => (m.build = "fedcba9876543210"))), /names the build "fedcba9876543210"/);
  expectOne(problemsOf((f) => editManifest(f, (m) => delete m.rustc)), /"rustc" must be a string/);
  expectOne(problemsOf((f) => editManifest(f, (m) => (m.files = []))), /"files" must be an object/);
  expectOne(problemsOf((f) => editManifest(f, (m) => (m.note = "x"))), /unknown key "note"/);
  expectOne(problemsOf((f) => editManifest(f, (m) => (m.stub = false))), /"stub" is either true or absent/);
  expectOne(problemsOf((f) => editManifest(f, (m) => (m.files["manifest.json"] = "0".repeat(64)))), /lists itself/);
  expectOne(problemsOf(add("big.wasm", Buffer.alloc(25 * 1024 * 1024 + 1))), /big\.wasm: 26214401 bytes, more than/);
});

test("_headers is the text written from src/headers.json", () => {
  expectOne(problemsOf((f) => (f._headers = `${headersFile()}/a/*\n  Cache-Control: public, max-age=31536000, immutable\n`)), /_headers is not the text/);
  expectOne(problemsOf((f) => (f._headers = headersFile().replace("'none'", "'self'"))), /_headers is not the text/);
  expectOne(problemsOf((f) => (f._headers = headersFile().replaceAll("\n", "\r\n"))), /_headers is not the text/);
  expectOne(problemsOf((f) => (f._headers = "")), /_headers is not the text/);
});

test("index.html: the status marker once, resources only from /a/<build>/, nothing inline", () => {
  const page = (edit) => (f) => (f["index.html"] = edit(f["index.html"]));
  const inBody = (html) => page((p) => p.replace("</body>", `${html}\n</body>`));
  expectOne(problemsOf(page((p) => p.replace("<!--gclone-status-->", ""))), /status marker <!--gclone-status--> 0 times/);
  expectOne(problemsOf(inBody("<!--gclone-status-->")), /status marker <!--gclone-status--> 2 times/);
  expectOne(problemsOf(inBody("<script>alert(1)</script>")), /<script>: inline script/);
  expectOne(problemsOf(inBody("<script></script>")), /<script>: a script without src/);
  expectOne(problemsOf(inBody(`<script src="/a/${B}/app.js">go()</script>`)), /inline script/);
  expectOne(problemsOf(inBody("<style>p { color: red }</style>")), /<style>: inline style/);
  expectOne(problemsOf(inBody('<p style="color: red">x</p>')), /<p>: an inline style attribute/);
  expectOne(problemsOf(inBody('<p STYLE = "color: red">x</p>')), /<p>: an inline style attribute/);
  expectOne(problemsOf(inBody('<button onclick="go()">x</button>')), /event-handler attribute onclick/);
  expectOne(problemsOf(inBody("<img src=x onerror=go()>")), /event-handler attribute onerror/);
  expectOne(problemsOf(inBody("<body onload=go()>")), /event-handler attribute onload/);
  expectOne(problemsOf(inBody('<script src="https://cdn.example/lib.js"></script>')), /src="https:\/\/cdn\.example\/lib\.js" is not a file of/);
  expectOne(problemsOf(inBody('<script src="//cdn.example/lib.js"></script>')), /is not a file of/);
  expectOne(problemsOf(inBody('<script src="/a/fedcba9876543210/app.js"></script>')), /is not a file of/);
  expectOne(problemsOf(inBody(`<script src="/a/${B}/../../x.js"></script>`)), /is not a file of/);
  expectOne(problemsOf(inBody('<script src="app.js"></script>')), /is not a file of/);
  expectOne(problemsOf(inBody('<link rel="stylesheet" href="https://fonts.example/css">')), /<link>: href="https:\/\/fonts\.example\/css" is not a file of/);
  expectOne(problemsOf(inBody('<link rel="manifest" href="/site.webmanifest">')), /is not a file of/);
  expectOne(problemsOf(inBody('<img src="https://tracker.example/p.gif">')), /<img>: src=/);
  expectOne(problemsOf(inBody(`<img srcset="/a/${B}/icon.svg 1x, https://x.example/i.png 2x">`)), /srcset="https:\/\/x\.example\/i\.png"/);
  expectOne(problemsOf(inBody('<iframe src="https://example.com/"></iframe>')), /<iframe>: src=/);
  expectOne(problemsOf(inBody('<iframe srcdoc="<p>x</p>"></iframe>')), /srcdoc/);
  expectOne(problemsOf(inBody('<form action="https://collect.example/"></form>')), /<form>: action=/);
  expectOne(problemsOf(inBody('<object data="/x.swf"></object>')), /<object>: data=/);
  expectOne(problemsOf(inBody('<use href="/sprite.svg#a"/>')), /<use>: href=/);
  expectOne(problemsOf(inBody('<a href="javascript:go()">x</a>')), /<a>: href="javascript:go\(\)"/);
  expectOne(problemsOf(inBody('<a href=" JaVa\tScript:go()">x</a>')), /<a>: href=/);
  expectOne(problemsOf(inBody('<a href="data:text/html,x">x</a>')), /<a>: href="data:/);
  expectOne(problemsOf(page((p) => p.replace("<head>", '<head><base href="https://evil.example/">'))), /<base>/);
  expectOne(problemsOf(page((p) => p.replace("<head>", '<head><meta http-equiv="refresh" content="0; url=https://evil.example/">'))), /http-equiv/);
  expectOne(problemsOf(page((p) => p.replace("<head>", '<head><meta http-equiv="Content-Security-Policy" content="default-src *">'))), /http-equiv/);
  expectOne(problemsOf(page((p) => p.replace(`/a/${B}/shell.css`, "/a/__GCLONE_BUILD__/shell.css"))), /unstamped build marker/);
  expectOne(problemsOf(inBody('<p title="unfinished')), /the tag does not end/);
  // what is allowed: links to go to, a fragment in <use>, elements without a source
  assert.deepEqual(problemsOf(inBody('<a href="/privacy">p</a><a href="#list">l</a><svg><use href="#s-lock"/></svg><video id="v"></video><noscript><link rel="stylesheet" href="/a/' + B + '/shell.css"></noscript>')), []);
  // a commented-out tag is not a tag
  assert.deepEqual(problemsOf(inBody("<!-- <script>alert(1)</script> -->")), []);
});

test("the HTML reader sees tags as a browser does", () => {
  const names = (html) => htmlTags(html).map((tag) => tag.name);
  assert.deepEqual(names("<!doctype html><P>x</P><br/>"), ["p", "/p", "br"]);
  assert.deepEqual(htmlTags("<a href=x title='a b' data-x>")[0].attrs, [["href", "x"], ["title", "a b"], ["data-x", ""]]);
  assert.deepEqual(htmlTags('<img alt="a > b" src="x">')[0].attrs, [["alt", "a > b"], ["src", "x"]]);
  assert.equal(htmlTags("<script>if (a < b) { '</p>' }</script><p>")[0].text, "if (a < b) { '</p>' }");
  assert.deepEqual(names("<script>x</script><p>"), ["script", "/script", "p"]);
  assert.deepEqual(names("a < b <p>"), ["p"]);
  assert.deepEqual(pageProblems("<p><!--gclone-status--></p>", B), []);
});

test("sw.js names the build of the directory, once, stamped", () => {
  expectOne(problemsOf((f) => (f["sw.js"] = "'use strict';\n")), /sw\.js does not name the build/);
  expectOne(problemsOf((f) => (f["sw.js"] = "const BUILD = '__GCLONE_BUILD__';\n")), /unstamped build marker/);
  expectOne(problemsOf((f) => (f["sw.js"] += "importScripts('/a/fedcba9876543210/core.js');\n")), /sw\.js names another build: \/a\/fedcba9876543210/);
  expectOne(problemsOf((f) => (f["sw.js"] = `// build ${B}\n`)), /must hold the line const BUILD/);
  expectOne(problemsOf((f) => (f["sw.js"] += `const BUILD = '${B}';\n`)), /must hold the line const BUILD/);
});

test("a built viewer names the Drive host once, in drive.js", () => {
  const add = (name, content) => (f) => {
    f[`a/${B}/${name}`] = content;
    editManifest(f, (m) => (m.files[name] = sha256(content)));
  };
  expectOne(problemsOf(add("other.js", "fetch('https://www.googleapis.com/drive/v3/files')")), /other\.js names www\.googleapis\.com 1 time/);
  expectOne(problemsOf(add("drive.js", "const A = 'https://www.googleapis.com', B = 'https://www.googleapis.com';")), /drive\.js names www\.googleapis\.com 2 time/);
  expectOne(problemsOf(add("drive.js", "const A = 'https://storage.example';")), /drive\.js names www\.googleapis\.com 0 time/);
  expectOne(problemsOf((f) => (f["sw.js"] += "// https://www.googleapis.com\n")), /sw\.js names www\.googleapis\.com/);
  expectOne(problemsOf((f) => (f["index.html"] = f["index.html"].replace("</body>", "<p>www.googleapis.com</p></body>"))), /index\.html names www\.googleapis\.com/);
});

test("a release: the tag, its version, a clean commit", () => {
  const release = (change, tag = "v9.8.7") => problemsOf(change, { options: { release: tag } });
  expectOne(release(() => {}, "v9.8.8"), /says tag "v9\.8\.7", expected "v9\.8\.8"/);
  expectOne(release((f) => editManifest(f, (m) => (m.tag = ""))), /says tag "", expected "v9\.8\.7"/);
  expectOne(release((f) => editManifest(f, (m) => (m.version = "9.8.6"))), /says version "9\.8\.6", the tag v9\.8\.7 is version 9\.8\.7/);
  expectOne(release((f) => editManifest(f, (m) => (m.commit += "+changes"))), /not a clean commit/);
  expectOne(release((f) => editManifest(f, (m) => (m.commit = ""))), /not a clean commit/);
  expectOne(release(() => {}, "9.8.7"), /is not a release tag/);
  expectOne(release(() => {}, "v9.8"), /is not a release tag/);
  assert.equal(tagVersion("v0.4.0"), "0.4.0");
  assert.equal(tagVersion("v10.20.30"), "10.20.30");
  for (const bad of ["0.4.0", "v0.4", "v0.4.0-rc1", "v01.2.3", "v1.2.3\n", "", undefined, 7]) assert.equal(tagVersion(bad), null);
});

test("the command: status 0 and one line for a good dist/, status 1 and every problem for a bad one", () => {
  inTempDir((dir) => {
    writeTree(dir, fakeBundleFiles());
    const good = spawnSync(process.execPath, [script, dir, "--release", "v9.8.7"], { encoding: "utf8" });
    assert.equal(good.status, 0, good.stderr);
    assert.match(good.stdout, /^check-dist: ok — gclone viewer 9\.8\.7, build 0123456789abcdef, tag v9\.8\.7, .*; 9 files\n$/);
    writeFileSync(join(dir, "_redirects"), "/ /x 302\n");
    mkdirSync(join(dir, "a", "fedcba9876543210"));
    const bad = spawnSync(process.execPath, [script, dir], { encoding: "utf8" });
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /is not a bundle that can be deployed/);
    assert.match(bad.stderr, /_redirects/);
    assert.equal(spawnSync(process.execPath, [script, dir, "--release"], { encoding: "utf8" }).status, 2);
  });
});

test("the viewer's own build passes (skipped while web-core/pkg is not built)", async (t) => {
  const pkg = fileURLToPath(new URL("../../web-core/pkg", import.meta.url));
  if (!existsSync(join(pkg, "core.wasm")) || !existsSync(join(pkg, "build.json"))) return t.skip("web-core/pkg is not built");
  const { build } = await import("../viewer/build.mjs");
  const tag = `v${JSON.parse(readFileSync(join(pkg, "build.json"), "utf8")).version}`;
  inTempDir((dir) => {
    const done = build({ out: join(dir, "dist"), pkg, commit: "0".repeat(40), tag });
    const result = checkDist(join(dir, "dist"), { release: tag });
    assert.equal(result.build, done.build);
    assert.equal(result.stub, false);
    // two builds of the same inputs are the same tree
    build({ out: join(dir, "again"), pkg, commit: "0".repeat(40), tag });
    assert.deepEqual(checkDist(join(dir, "again")).files, result.files);
  });
});
