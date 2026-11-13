// What the scripts' own tests share (check-dist.selftest.mjs, release-bundle.selftest.mjs): a small made-up bundle
// that satisfies check-dist, a tar writer, and a stand-in for the GitHub CLI. Test code only; plain Node.

import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { gzipSync } from "node:zlib";
import { headersFile } from "./headers-file.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

export const FAKE_BUILD = "0123456789abcdef";
export const FAKE_COMMIT = "0123456789abcdef0123456789abcdef01234567";

/** Runs `run(dir)` with a temporary directory that is removed afterwards — when `run` returns, or when its promise settles. */
export function inTempDir(run) {
  const dir = mkdtempSync(join(tmpdir(), "gclone-selftest-"));
  const remove = () => rmSync(dir, { recursive: true, force: true });
  let result;
  try {
    result = run(dir);
  } catch (error) {
    remove();
    throw error;
  }
  if (result instanceof Promise) return result.finally(remove);
  remove();
  return result;
}

/** The files of a made-up built viewer, by path below `dist/`: the layout and the rules of a real one, a few bytes each. */
export function fakeBundleFiles({ build = FAKE_BUILD, tag = "v9.8.7", version = "9.8.7", commit = FAKE_COMMIT, extra = {} } = {}) {
  const own = {
    "app.js": "'use strict';\n// the page\n",
    "drive.js": "'use strict';\nconst ORIGIN = 'https://www.googleapis.com';\n",
    "core.wasm": Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]),
    "shell.css": "body { margin: 0; }\n",
    "icon.svg": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>\n',
    ...extra,
  };
  const manifest = {
    build,
    commit,
    files: Object.fromEntries(Object.entries(own).map(([name, content]) => [name, sha256(content)]).sort(([a], [b]) => (a < b ? -1 : 1))),
    rustc: "rustc 1.99.1 (test)",
    tag,
    version,
    wasm_bindgen: "0.2.130",
  };
  const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>gclone</title>
<link rel="icon" type="image/svg+xml" href="/a/${build}/icon.svg">
<link rel="stylesheet" href="/a/${build}/shell.css">
<script src="/a/${build}/app.js" defer></script>
</head>
<body>
<svg class="sprite" aria-hidden="true"><symbol id="s-lock" viewBox="0 0 24 24"><path d="M0 0"/></symbol></svg>
<svg class="i"><use href="#s-lock"/></svg>
<p><a href="/privacy">Privacy</a> <a href="./">Top</a> <a href="https://accounts.google.com/Logout" rel="noreferrer noopener">Google</a></p>
<p class="state"><!--gclone-status--></p>
<template id="app"><img id="preview" alt=""><iframe id="frame" title="preview"></iframe></template>
</body>
</html>
`;
  const files = {
    "index.html": page,
    "sw.js": `'use strict';\nconst BUILD = '${build}';\nconst BASE = \`/a/\${BUILD}/\`;\n`,
    _headers: headersFile(),
    [`a/${build}/manifest.json`]: `${JSON.stringify(manifest, null, 2)}\n`,
  };
  for (const [name, content] of Object.entries(own)) files[`a/${build}/${name}`] = content;
  return files;
}

/** Writes `files` (`{ path: text | Buffer }`) below `dir`. */
export function writeTree(dir, files) {
  for (const [path, content] of Object.entries(files)) {
    const file = join(dir, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, content);
  }
  return dir;
}

/** Every file below `dir` as `{ path: Buffer }`. */
export function readTree(dir, prefix = "") {
  const files = {};
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (entry.isDirectory()) Object.assign(files, readTree(join(dir, entry.name), `${prefix}${entry.name}/`));
    else files[`${prefix}${entry.name}`] = readFileSync(join(dir, entry.name));
  }
  return files;
}

/**
 * A ustar archive. `members` are `[name, content]` for a file, `[name, null]` for a directory, or
 * `{ name, content, type, linkname, prefix }` for anything a test wants to plant.
 */
export function tar(members) {
  const blocks = [];
  for (const member of members) {
    const { name, content = null, type = content === null ? "5" : "0", linkname = "", prefix = "" } = Array.isArray(member) ? { name: member[0], content: member[1] } : member;
    const body = content === null ? Buffer.alloc(0) : Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, "utf8");
    header.write(type === "5" ? "0000755\0" : "0000644\0", 100, 8, "latin1");
    header.write("0000000\0", 108, 8, "latin1");
    header.write("0000000\0", 116, 8, "latin1");
    header.write(`${body.length.toString(8).padStart(11, "0")}\0`, 124, 12, "latin1");
    header.write(`${(1577836800).toString(8).padStart(11, "0")}\0`, 136, 12, "latin1");
    header.fill(32, 148, 156);
    header.write(type, 156, 1, "latin1");
    header.write(linkname, 157, 100, "utf8");
    header.write("ustar\0" + "00", 257, 8, "latin1");
    header.write(prefix, 345, 155, "utf8");
    let sum = 0;
    for (const byte of header) sum += byte;
    header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "latin1");
    blocks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

/** The tarball of a bundle as the release workflow packs it: the directories, then every file, by name. */
export function bundleTarball(files) {
  const names = Object.keys(files).sort();
  const dirs = [...new Set(names.flatMap((name) => name.split("/").slice(0, -1).map((_, i, parts) => `${parts.slice(0, i + 1).join("/")}/`)))].sort();
  return gzipSync(tar([...dirs.map((dir) => [dir, null]), ...names.map((name) => [name, files[name]])]));
}

/**
 * A stand-in for `gh` in a directory to put on PATH. It serves `release download` from `<state>/releases/<tag>/` and
 * accepts `attestation verify` for a file only when `<state>/attested.json` lists its SHA-256 with the repository,
 * the signer workflow, the source ref and — where `--source-digest` is given — the commit that the command line
 * names: which is what the real one binds together. `release verify-asset` passes only for a file that
 * `<state>/immutable.json` lists for that tag and repository, as the real one does for an immutable release.
 * Every call is appended to `<state>/calls.jsonl`.
 */
export function fakeGh(dir) {
  const bin = join(dir, "bin");
  const state = join(dir, "gh-state");
  mkdirSync(bin, { recursive: true });
  mkdirSync(join(state, "releases"), { recursive: true });
  writeFileSync(join(state, "attested.json"), "[]");
  writeFileSync(join(state, "immutable.json"), "[]");
  writeFileSync(join(state, "calls.jsonl"), "");
  const script = join(dir, "fake-gh.mjs");
  writeFileSync(
    script,
    `import { createHash } from "node:crypto";
import { appendFileSync, copyFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
const state = ${JSON.stringify(state)};
const args = process.argv.slice(2);
appendFileSync(join(state, "calls.jsonl"), JSON.stringify(args) + "\\n");
const option = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
if (args[0] === "release" && args[1] === "download") {
  const file = join(state, "releases", args[2], option("--pattern"));
  if (!existsSync(file)) {
    console.error("release not found, or no assets match the pattern");
    process.exit(1);
  }
  copyFileSync(file, join(option("--dir"), option("--pattern")));
  process.exit(0);
}
if (args[0] === "attestation" && args[1] === "verify") {
  const digest = createHash("sha256").update(readFileSync(args[2])).digest("hex");
  const commit = option("--source-digest");
  const ok = JSON.parse(readFileSync(join(state, "attested.json"), "utf8")).some(
    (a) => a.sha256 === digest && a.repo === option("--repo") && a.repo + "/" + a.workflow === option("--signer-workflow") && a.ref === option("--source-ref") && (commit === undefined || a.commit === commit),
  );
  if (!ok || !args.includes("--deny-self-hosted-runners")) {
    console.error("x verification failed: no attestation matches the policy for sha256:" + digest);
    process.exit(1);
  }
  console.log("ok: verification succeeded");
  process.exit(0);
}
if (args[0] === "release" && args[1] === "verify-asset") {
  const digest = createHash("sha256").update(readFileSync(args[3])).digest("hex");
  const ok = JSON.parse(readFileSync(join(state, "immutable.json"), "utf8")).some((r) => r.tag === args[2] && r.repo === option("--repo") && r.sha256 === digest);
  if (!ok) {
    console.error("no attestations for tag " + args[2]);
    process.exit(1);
  }
  console.log("ok: the asset is part of the immutable release " + args[2]);
  process.exit(0);
}
console.error("fake gh: unexpected command " + args.join(" "));
process.exit(2);
`,
  );
  writeFileSync(join(bin, "gh"), `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(script)} "$@"\n`);
  chmodSync(join(bin, "gh"), 0o755);
  return {
    bin,
    command: join(bin, "gh"),
    /**
     * Publishes `bytes` as an asset of `tag`; with `attest`, also records the attestation the release workflow makes
     * (for a build from `commit`); with `immutable`, GitHub's attestation of an immutable release with that asset.
     */
    publish(tag, name, bytes, { attest = true, immutable = true, repo = "owner/project", workflow = ".github/workflows/release.yml", ref = `refs/tags/${tag}`, commit = FAKE_COMMIT } = {}) {
      mkdirSync(join(state, "releases", tag), { recursive: true });
      writeFileSync(join(state, "releases", tag, name), bytes);
      const add = (file, entry) => {
        const list = JSON.parse(readFileSync(join(state, file), "utf8"));
        list.push(entry);
        writeFileSync(join(state, file), JSON.stringify(list));
      };
      if (attest) add("attested.json", { sha256: sha256(bytes), repo, workflow, ref, commit });
      if (immutable) add("immutable.json", { sha256: sha256(bytes), repo, tag });
    },
    calls: () => readFileSync(join(state, "calls.jsonl"), "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)),
  };
}
