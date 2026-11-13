// Tests of the release tooling (plain Node, `node --test`, run by `npm test`): release-bundle.mjs, fetch-viewer.mjs,
// check-release.mjs (the gate of `npm run deploy`) and verify-deployed.mjs, against a stand-in for `gh` on PATH and a
// local HTTP server. Nothing is downloaded, verified at GitHub, deployed or written outside a temporary directory.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { inspectDist, sha256 } from "./check-dist.mjs";
import { readHeaders } from "./headers-file.mjs";
import { checkout, compareFiles, immutableArgs, readTarball, releaseBundle, tarballName, verifyArgs } from "./release-bundle.mjs";
import { FAKE_BUILD, FAKE_COMMIT, bundleTarball, fakeBundleFiles, fakeGh, inTempDir, readTree, tar, writeTree } from "./selftest-bundle.mjs";
import { ensureDist } from "./stub-dist.mjs";
import { headerSet, hostOrigin } from "./verify-deployed.mjs";

const TAG = "v9.8.7";
const REPO = "owner/project";
const NAME = tarballName("9.8.7");
const B = FAKE_BUILD;
const scripts = fileURLToPath(new URL(".", import.meta.url));

/**
 * The commit this checkout is at: what fetch-viewer and check-release, run as commands, hold a release to. The
 * made-up release of the command tests is "built from" it (the fake commit where the tests run outside a checkout).
 */
const HERE = checkout();
const HEAD = HERE?.commit ?? FAKE_COMMIT;

/** A directory that holds `git` and nothing else, for the PATH of the commands: they ask it for the checkout's commit. */
const GIT_ONLY = (() => {
  if (HERE === null) return null;
  const real = (process.env.PATH ?? "")
    .split(":")
    .map((part) => join(part, "git"))
    .find((candidate) => existsSync(candidate));
  if (real === undefined) return null;
  const dir = mkdtempSync(join(tmpdir(), "gclone-selftest-git-"));
  symlinkSync(real, join(dir, "git"));
  process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
  return dir;
})();

/** Runs one of the scripts as a command with `gh` resolved from `bin` (and from nowhere else) — and `git` as it is. */
function run(script, args, { bin, repo = REPO, env: extra = {} } = {}) {
  return new Promise((resolve) => {
    const path = [bin ?? join(tmpdir(), "gclone-no-such-directory"), ...(GIT_ONLY === null ? [] : [GIT_ONLY])];
    const env = { ...process.env, PATH: path.join(":"), GCLONE_REPO: repo, ...extra };
    delete env.GCLONE_GH;
    if (!("GCLONE_MUTABLE_RELEASE" in extra)) delete env.GCLONE_MUTABLE_RELEASE;
    const child = spawn(process.execPath, [join(scripts, script), ...args], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

/** A fake `gh` with the made-up bundle published as the immutable release v9.8.7, attested as built from this checkout's commit. */
function published(dir, { files = fakeBundleFiles(), attest = true, immutable = true } = {}) {
  const gh = fakeGh(dir);
  const tarball = bundleTarball(files);
  gh.publish(TAG, NAME, tarball, { attest, immutable, repo: REPO, commit: HEAD });
  return { gh, files, tarball };
}

const leftovers = () => readdirSync(tmpdir()).filter((name) => name.startsWith("gclone-viewer-release-"));

/** The made-up bundle served as the Worker and the asset layer serve it. `change` may alter an answer. */
async function serve(files, change = (path, answer) => answer) {
  const set = readHeaders();
  let hits = 0;
  const server = createServer((req, res) => {
    hits++;
    const path = new URL(req.url, "http://x").pathname;
    let answer = null;
    if (path === "/" || path === "/callback") answer = { status: 200, headers: { ...set, "content-type": "text/html; charset=utf-8" }, body: Buffer.from(String(files["index.html"]).replace("<!--gclone-status-->", "Status: ready")) };
    else if (path === "/sw.js" || path.startsWith("/a/")) {
      const content = files[path.slice(1)];
      if (content !== undefined) answer = { status: 200, headers: { ...set }, body: Buffer.from(content) };
    }
    answer = change(path, answer ?? { status: 404, headers: {}, body: Buffer.alloc(0) });
    res.writeHead(answer.status, answer.headers);
    res.end(answer.body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { origin: `http://127.0.0.1:${server.address().port}`, hits: () => hits, close: () => new Promise((resolve) => server.close(resolve)) };
}

test("releaseBundle: downloads the tag's tarball, verifies its attestation with exactly the documented command, unpacks, checks", () =>
  inTempDir((dir) => {
    const { gh, files, tarball } = published(dir);
    const before = leftovers();
    const bundle = releaseBundle(TAG, { repo: REPO, gh: gh.command });
    try {
      assert.equal(bundle.tag, TAG);
      assert.equal(bundle.version, "9.8.7");
      assert.equal(bundle.build, B);
      assert.equal(bundle.tarball.sha256, sha256(tarball));
      assert.deepEqual(Object.keys(bundle.files).sort(), Object.keys(files).sort());
      for (const [path, content] of Object.entries(files)) assert.equal(bundle.files[path], sha256(content));
      assert.deepEqual(Object.keys(readTree(bundle.path)).sort(), Object.keys(files).sort());

      assert.equal(bundle.immutable, true);
      assert.equal(bundle.commit, null, "no commit was asked for");
      const calls = gh.calls();
      assert.equal(calls.length, 3);
      assert.deepEqual(calls[0].slice(0, 7), ["release", "download", TAG, "--repo", REPO, "--pattern", NAME]);
      const downloaded = calls[1][2];
      assert.deepEqual(calls[1], ["attestation", "verify", downloaded, "--repo", REPO, "--signer-workflow", `${REPO}/.github/workflows/release.yml`, "--source-ref", `refs/tags/${TAG}`, "--deny-self-hosted-runners"]);
      // … and the release itself: this file, of this tag, of an immutable release
      assert.deepEqual(calls[2], ["release", "verify-asset", TAG, downloaded, "--repo", REPO]);
      assert.deepEqual(verifyArgs("x.tar.gz", "o/r", "v1.2.3"), ["attestation", "verify", "x.tar.gz", "--repo", "o/r", "--signer-workflow", "o/r/.github/workflows/release.yml", "--source-ref", "refs/tags/v1.2.3", "--deny-self-hosted-runners"]);
      assert.deepEqual(verifyArgs("x.tar.gz", "o/r", "v1.2.3", "c".repeat(40)).slice(-2), ["--source-digest", "c".repeat(40)]);
      assert.deepEqual(immutableArgs("x.tar.gz", "o/r", "v1.2.3"), ["release", "verify-asset", "v1.2.3", "x.tar.gz", "--repo", "o/r"]);
    } finally {
      bundle.remove();
    }
    assert.deepEqual(leftovers(), before, "the temporary directory is removed");
  }));

test("releaseBundle fails closed: no gh, no attestation, another repository, another tag, a re-packed tarball, no such release", () =>
  inTempDir((dir) => {
    const before = leftovers();
    const { gh, files } = published(dir);
    // no gh at all
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: join(dir, "no-such-gh") }), /GitHub CLI .* was not found.*without that the bundle is not used/s);
    // not a tag
    for (const bad of ["9.8.7", "v9.8", "latest", "v9.8.7 --repo evil/x", "", undefined]) assert.throws(() => releaseBundle(bad, { repo: REPO, gh: gh.command }), /is not a release tag/);
    assert.throws(() => releaseBundle(TAG, { repo: "not a repo", gh: gh.command }), /is not a GitHub repository/);
    // no such release
    assert.throws(() => releaseBundle("v1.0.0", { repo: REPO, gh: gh.command }), /downloading gclone-viewer-1\.0\.0\.tar\.gz of release v1\.0\.0 of owner\/project failed/);
    // the attestation is for another repository's workflow
    assert.throws(() => releaseBundle(TAG, { repo: "mallory/project", gh: gh.command }), /verifying the attestation .* failed/s);
    // a release whose asset was never attested
    const unsigned = fakeGh(join(dir, "unsigned"));
    unsigned.publish(TAG, NAME, bundleTarball(files), { attest: false });
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: unsigned.command }), /verifying the attestation .* failed.*no attestation matches/s);
    // an attestation made on a branch, not on the tag
    const branch = fakeGh(join(dir, "branch"));
    branch.publish(TAG, NAME, bundleTarball(files), { repo: REPO, ref: "refs/heads/main" });
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: branch.command }), /verifying the attestation/);
    // … or by another workflow of the repository
    const other = fakeGh(join(dir, "other"));
    other.publish(TAG, NAME, bundleTarball(files), { repo: REPO, workflow: ".github/workflows/ci.yml" });
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: other.command }), /verifying the attestation/);
    // the asset was replaced by a re-packed one (one byte of one file differs): the attestation is for other bytes
    const swapped = fakeGh(join(dir, "swapped"));
    swapped.publish(TAG, NAME, bundleTarball(files), { repo: REPO });
    swapped.publish(TAG, NAME, bundleTarball({ ...files, [`a/${B}/app.js`]: "'use strict';\n// the pagE\n" }), { attest: false });
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: swapped.command }), /verifying the attestation/);
    // an attested tarball of ANOTHER version published under this tag: the bundle says which release it is
    const mislabeled = fakeGh(join(dir, "mislabeled"));
    mislabeled.publish(TAG, NAME, bundleTarball(fakeBundleFiles({ tag: "v9.8.6", version: "9.8.6" })), { repo: REPO });
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: mislabeled.command }), /says tag "v9\.8\.6", expected "v9\.8\.7"/);
    assert.deepEqual(leftovers(), before, "nothing is left behind by a failure");
  }));

test("releaseBundle holds the release to a commit: the one the deploying checkout is at", () =>
  inTempDir((dir) => {
    const gh = fakeGh(dir);
    const built = "a".repeat(40);
    gh.publish(TAG, NAME, bundleTarball(fakeBundleFiles()), { repo: REPO, commit: built });
    const before = leftovers();
    const bundle = releaseBundle(TAG, { repo: REPO, gh: gh.command, commit: built });
    try {
      assert.equal(bundle.commit, built);
      assert.deepEqual(gh.calls()[1].slice(-2), ["--source-digest", built]);
    } finally {
      bundle.remove();
    }
    // A checkout at another commit — main, an older tag — or a tag that was moved since the release was built:
    // the bytes are attested, but not as built from what is about to be deployed with them.
    const other = "b".repeat(40);
    assert.throws(
      () => releaseBundle(TAG, { repo: REPO, gh: gh.command, commit: other }),
      new RegExp(`is attested, but it was not built from commit ${other}, which this checkout is at.*git checkout v9\\.8\\.7.*the tag was moved`, "s"),
    );
    // An attestation that fails for another reason is reported as that, commit or not.
    const unsigned = fakeGh(join(dir, "unsigned"));
    unsigned.publish(TAG, NAME, bundleTarball(fakeBundleFiles()), { attest: false, repo: REPO });
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: unsigned.command, commit: built }), /verifying the attestation .*from commit a{40}\) failed.*no attestation matches/s);
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: gh.command, commit: "v9.8.7" }), /is not a commit/);
    assert.deepEqual(leftovers(), before, "nothing is left behind");
  }));

test("releaseBundle wants an immutable release: a release whose tag can still be moved is used only when it is named", () =>
  inTempDir((dir) => {
    const gh = fakeGh(dir);
    const tarball = bundleTarball(fakeBundleFiles());
    gh.publish(TAG, NAME, tarball, { repo: REPO, immutable: false });
    const before = leftovers();
    assert.throws(
      () => releaseBundle(TAG, { repo: REPO, gh: gh.command, mutable: "" }),
      /verifying that gclone-viewer-9\.8\.7\.tar\.gz is an asset of the immutable release v9\.8\.7 of owner\/project failed.*no attestations for tag v9\.8\.7.*is not an immutable release.*whoever|is not an immutable release.*GCLONE_MUTABLE_RELEASE=v9\.8\.7/s,
    );
    // naming another tag does not help
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: gh.command, mutable: "v9.8.6" }), /GCLONE_MUTABLE_RELEASE=v9\.8\.7/);
    // named: used, with a warning, and the result says what it is
    const warnings = [];
    const bundle = releaseBundle(TAG, { repo: REPO, gh: gh.command, mutable: TAG, warn: (line) => warnings.push(line) });
    try {
      assert.equal(bundle.immutable, false);
      assert.equal(warnings.length, 1);
      assert.match(warnings[0], /^warning: release v9\.8\.7 of owner\/project is NOT immutable .*can still be changed by anyone who can push/);
    } finally {
      bundle.remove();
    }
    // The attestation is still required: an unattested file of a named release is refused before the release is asked.
    const unsigned = fakeGh(join(dir, "unsigned"));
    unsigned.publish(TAG, NAME, tarball, { attest: false, immutable: false, repo: REPO });
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: unsigned.command, mutable: TAG }), /verifying the attestation/);
    assert.deepEqual(unsigned.calls().map((call) => call.slice(0, 2).join(" ")), ["release download", "attestation verify"]);
    // An immutable release with ANOTHER file under the asset's name (replaced after publication, were that possible).
    const replaced = fakeGh(join(dir, "replaced"));
    replaced.publish(TAG, NAME, tarball, { repo: REPO });
    replaced.publish(TAG, NAME, bundleTarball(fakeBundleFiles({ extra: { "app.js": "'use strict';\n// other\n" } })), { repo: REPO, immutable: false });
    assert.throws(() => releaseBundle(TAG, { repo: REPO, gh: replaced.command, mutable: "" }), /is not an immutable release, or gclone-viewer-9\.8\.7\.tar\.gz is not the file it was published with/);
    assert.deepEqual(leftovers(), before, "nothing is left behind");
  }));

test("the tarball reader takes plain files under a bundle's names and refuses everything else", () => {
  const files = fakeBundleFiles();
  const good = readTarball(bundleTarball(files));
  assert.deepEqual([...good.keys()].sort(), Object.keys(files).sort());
  for (const [path, content] of Object.entries(files)) assert.ok(good.get(path).equals(Buffer.from(content)));
  // as `tar -C dist .` names them
  const dotted = readTarball(gzipSync(tar([["./", null], ["./a/", null], [`./a/${B}/`, null], ["./index.html", "x"], [`./a/${B}/app.js`, "y"]])));
  assert.deepEqual([...dotted.keys()], ["index.html", `a/${B}/app.js`]);
  // a long name split into prefix and name
  assert.deepEqual([...readTarball(gzipSync(tar([{ name: "app.js", prefix: `a/${B}`, content: "y" }]))).keys()], [`a/${B}/app.js`]);

  const refused = (members, pattern) => assert.throws(() => readTarball(gzipSync(tar(members))), pattern);
  refused([["../evil.js", "x"]], /not a file of a bundle/);
  refused([[`a/${B}/../../evil.js`, "x"]], /not a file of a bundle/);
  refused([["/etc/cron.d/x", "x"]], /not a file of a bundle/);
  refused([["_redirects", "/ /x 302"]], /not a file of a bundle/);
  refused([[`a/${B}/sub/x.js`, "x"]], /not a file of a bundle/);
  refused([["a/short/x.js", "x"]], /not a file of a bundle/);
  refused([["node_modules/", null]], /directory "node_modules\/", which a bundle does not have/);
  refused([{ name: "sw.js", type: "2", linkname: "/etc/passwd", content: "" }], /not a plain file/);
  refused([{ name: "sw.js", type: "1", linkname: "index.html", content: "" }], /not a plain file/);
  refused([{ name: "pax_global_header", type: "g", content: "52 comment=x\n" }], /not a plain file/);
  refused([{ name: "././@PaxHeader", type: "x", content: "30 path=../../evil\n" }], /not a plain file/);
  refused([{ name: "././@LongLink", type: "L", content: "x" }], /not a plain file/);
  refused([["sw.js", "a"], ["sw.js", "b"]], /"sw\.js" twice/);
  const whole = tar([["sw.js", "x".repeat(2000)]]);
  assert.throws(() => readTarball(gzipSync(whole.subarray(0, 1024))), /cut short/);
  assert.throws(() => readTarball(gzipSync(whole.subarray(0, whole.length - 1024))), /cut short/);
  assert.throws(() => readTarball(gzipSync(Buffer.concat([whole, Buffer.from("more")]))), /data after its end/);
  const damaged = Buffer.from(whole);
  damaged[0] ^= 1;
  assert.throws(() => readTarball(gzipSync(damaged)), /wrong checksum/);
  assert.throws(() => readTarball(Buffer.from("not gzip")), /does not unpack/);
  assert.throws(() => readTarball(gzipSync(Buffer.alloc(129 * 1024 * 1024))), /does not unpack/);
});

test("fetch-viewer: replaces dist/ with the verified bundle; a failed verification leaves dist/ as it was", async () => {
  await inTempDir(async (dir) => {
    const { gh, files } = published(dir);
    const { fetchViewer, replaceDist } = await import("./fetch-viewer.mjs");
    // over the placeholder
    const dist = join(dir, "dist");
    ensureDist(dist);
    const done = fetchViewer(TAG, { dist, repo: REPO, gh: gh.command });
    assert.equal(done.build, B);
    assert.deepEqual(Object.keys(readTree(dist)).sort(), Object.keys(files).sort());
    assert.deepEqual(compareFiles(done.files, inspectDist(dist).files), []);
    // into nothing, and over an older bundle
    const fresh = join(dir, "fresh", "dist");
    fetchViewer(TAG, { dist: fresh, repo: REPO, gh: gh.command });
    assert.ok(existsSync(join(fresh, "a", B, "manifest.json")));
    writeTree(join(dir, "old"), fakeBundleFiles({ build: "fedcba9876543210", tag: "v9.8.6", version: "9.8.6" }));
    fetchViewer(TAG, { dist: join(dir, "old"), repo: REPO, gh: gh.command });
    assert.deepEqual(readdirSync(join(dir, "old", "a")), [B]);
    // a dist/ with something that is no bundle is not touched
    writeFileSync(join(dist, "notes.txt"), "mine");
    assert.throws(() => fetchViewer(TAG, { dist, repo: REPO, gh: gh.command }), /holds notes\.txt, which is not part of a bundle/);
    assert.throws(() => replaceDist(dist, fresh), /notes\.txt/);
    assert.equal(readFileSync(join(dist, "notes.txt"), "utf8"), "mine");

    // the command, with gh found on PATH
    const viaPath = join(dir, "via-path");
    const ok = await run("fetch-viewer.mjs", [TAG, "--dist", viaPath], { bin: gh.bin });
    assert.equal(ok.status, 0, ok.stderr);
    assert.match(ok.stdout, /^fetch-viewer: .*via-path is the viewer of owner\/project v9\.8\.7\n {2}version {3}9\.8\.7\n {2}build {5}0123456789abcdef\n/);
    assert.match(ok.stdout, / {2}tarball {3}gclone-viewer-9\.8\.7\.tar\.gz {2}sha256 [0-9a-f]{64}\n/);
    assert.match(ok.stdout, / {2}release {3}immutable \(gh release verify-asset\)/);
    assert.deepEqual(Object.keys(readTree(viaPath)).sort(), Object.keys(files).sort());
    // As a command in a git checkout it holds the release to the commit the checkout is at.
    const verify = gh.calls().filter((call) => call[1] === "verify").at(-1);
    if (HERE === null) {
      assert.ok(!verify.includes("--source-digest"));
      assert.match(ok.stdout, /this is not a git checkout/);
    } else {
      assert.deepEqual(verify.slice(-2), ["--source-digest", HERE.commit]);
      assert.match(ok.stdout, new RegExp(`built from this checkout's commit ${HERE.commit}`));
    }
    // A release that is not immutable: refused, and nothing is written; named, it is fetched with the warning.
    const mutable = fakeGh(join(dir, "mutable"));
    mutable.publish(TAG, NAME, bundleTarball(files), { repo: REPO, immutable: false, commit: HEAD });
    const refused = await run("fetch-viewer.mjs", [TAG, "--dist", join(dir, "never")], { bin: mutable.bin });
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /^fetch-viewer: verifying that gclone-viewer-9\.8\.7\.tar\.gz is an asset of the immutable release/);
    assert.ok(!existsSync(join(dir, "never")));
    const named = await run("fetch-viewer.mjs", [TAG, "--dist", join(dir, "named")], { bin: mutable.bin, env: { GCLONE_MUTABLE_RELEASE: TAG } });
    assert.equal(named.status, 0, named.stderr);
    assert.match(named.stderr, /^warning: release v9\.8\.7 of owner\/project is NOT immutable/);
    assert.match(named.stdout, / {2}release {3}NOT immutable/);
  });
});

test("the commands stop when the verification fails: fetch-viewer, check-release and verify-deployed", async () => {
  await inTempDir(async (dir) => {
    const files = fakeBundleFiles();
    const unsigned = fakeGh(join(dir, "unsigned"));
    unsigned.publish(TAG, NAME, bundleTarball(files), { attest: false, repo: REPO });
    const dist = writeTree(join(dir, "dist"), files);
    const host = await serve(files);
    try {
      // check-release (what `npm run deploy` runs before wrangler): the dist/ is byte for byte the tarball's, and still no
      const gate = await run("check-release.mjs", [dist], { bin: unsigned.bin });
      assert.equal(gate.status, 1);
      assert.match(gate.stderr, /^check-release: verifying the attestation of gclone-viewer-9\.8\.7\.tar\.gz .* failed/);
      // verify-deployed: no request is made to the host before the release is verified
      const verify = await run("verify-deployed.mjs", [host.origin, TAG], { bin: unsigned.bin });
      assert.equal(verify.status, 1);
      assert.match(verify.stderr, /^verify-deployed: verifying the attestation/);
      assert.equal(host.hits(), 0);
      // without gh on PATH at all
      for (const [script, args] of [["check-release.mjs", [dist]], ["verify-deployed.mjs", [host.origin, TAG]], ["fetch-viewer.mjs", [TAG, "--dist", join(dir, "never")]]]) {
        const result = await run(script, args, {});
        assert.equal(result.status, 1, script);
        assert.match(result.stderr, /GitHub CLI .* was not found/, script);
        assert.equal(result.stdout, "", script);
      }
      // fetch-viewer with a failing verification: the directory stays as it was
      const kept = join(dir, "kept");
      ensureDist(kept);
      const before = readTree(kept);
      const fetched = await run("fetch-viewer.mjs", [TAG, "--dist", kept], { bin: unsigned.bin });
      assert.equal(fetched.status, 1);
      assert.match(fetched.stderr, /^fetch-viewer: verifying the attestation/);
      assert.deepEqual(readTree(kept), before);
      assert.equal(host.hits(), 0);
      // usage
      assert.equal((await run("fetch-viewer.mjs", [], { bin: unsigned.bin })).status, 1);
      assert.equal((await run("verify-deployed.mjs", [host.origin], { bin: unsigned.bin })).status, 1);
    } finally {
      await host.close();
    }
  });
});

test("check-release, the gate of `npm run deploy`: only the release's bytes pass — one changed byte, one extra file, a local build do not", async () => {
  await inTempDir(async (dir) => {
    const { gh, files } = published(dir);
    const dist = writeTree(join(dir, "dist"), files);
    const good = await run("check-release.mjs", [dist], { bin: gh.bin });
    assert.equal(good.status, 0, good.stderr);
    assert.match(good.stdout, /^check-release: dist\/ is the attested viewer of owner\/project v9\.8\.7 — version 9\.8\.7, build 0123456789abcdef, 9 files, tarball sha256 [0-9a-f]{64}\n/);
    // the gate verified again: a download and the verifications of its own
    assert.deepEqual(gh.calls().map((call) => call.slice(0, 2).join(" ")), ["release download", "attestation verify", "release verify-asset"]);
    if (HERE !== null) {
      assert.deepEqual(gh.calls()[1].slice(-2), ["--source-digest", HERE.commit], "held to the commit of the checkout that is deployed");
      assert.match(good.stdout, new RegExp(`check-release: the release was built from commit ${HERE.commit}, which this checkout is at; the release is immutable`));
    }

    // one byte changed in one file (as an npm dependency's install script could): the manifest no longer matches
    // it, and it is not the release's file
    const changed = writeTree(join(dir, "changed"), { ...files, [`a/${B}/app.js`]: "'use strict';\n// the pagE\n" });
    let result = await run("check-release.mjs", [changed], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /is NOT the viewer of release v9\.8\.7; nothing is deployed/);
    assert.match(result.stderr, new RegExp(`a/${B}/app\\.js: differs from release v9\\.8\\.7`));
    // the same build and commit on both sides: it is ./dist that was changed, and fetching again is the cure
    assert.match(result.stderr, /something changed \.\/dist after it was fetched.*Fetch it again: node scripts\/fetch-viewer\.mjs v9\.8\.7/s);

    // … also when the change is made consistently (the manifest updated to match): still not the release's bytes
    const consistent = fakeBundleFiles({ extra: { "app.js": "'use strict';\n// the pagE\n" } });
    result = await run("check-release.mjs", [writeTree(join(dir, "consistent"), consistent)], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(`a/${B}/app\\.js: differs from release v9\\.8\\.7`));
    assert.match(result.stderr, new RegExp(`a/${B}/manifest\\.json: differs from release v9\\.8\\.7`));

    // the page changed
    result = await run("check-release.mjs", [writeTree(join(dir, "page"), { ...files, "index.html": String(files["index.html"]).replace("Privacy", "Privacy ") })], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /index\.html: differs from release v9\.8\.7/);

    // one extra file
    const extra = fakeBundleFiles({ extra: { "extra.js": "// added\n" } });
    result = await run("check-release.mjs", [writeTree(join(dir, "extra"), extra)], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(`a/${B}/extra\\.js: in dist/, not in release v9\\.8\\.7`));
    result = await run("check-release.mjs", [writeTree(join(dir, "redirects"), { ...files, _redirects: "/ https://evil.example/ 302\n" })], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /_redirects/);

    // one file missing
    const fewer = { ...files };
    delete fewer[`a/${B}/icon.svg`];
    result = await run("check-release.mjs", [writeTree(join(dir, "fewer"), fewer)], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(`a/${B}/icon\\.svg: in release v9\\.8\\.7, missing in dist/`));

    // a local build (no tag), the placeholder, nothing at all: not a release, and gh is not even asked
    const callsBefore = gh.calls().length;
    result = await run("check-release.mjs", [writeTree(join(dir, "local"), fakeBundleFiles({ tag: "", commit: `${"0".repeat(40)}+changes` }))], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /holds a local build .*, not the viewer of a release\.\n.*npm run deploy:dev/s);
    ensureDist(join(dir, "stub"));
    result = await run("check-release.mjs", [join(dir, "stub")], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /holds the placeholder, not the viewer of a release/);
    result = await run("check-release.mjs", [join(dir, "nothing")], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /holds no bundle/);
    assert.equal(gh.calls().length, callsBefore);

    // a dist/ that names a tag whose release holds other bytes
    result = await run("check-release.mjs", [writeTree(join(dir, "claims"), fakeBundleFiles({ tag: "v9.8.6", version: "9.8.6" }))], { bin: gh.bin });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /downloading gclone-viewer-9\.8\.6\.tar\.gz of release v9\.8\.6/);
  });
});

test("a tag that was moved after the fetch: the gate says that the RELEASE changed, and does not advise fetching again", async () => {
  await inTempDir(async (dir) => {
    // What was fetched and reviewed: the release as it was built from the checkout's commit.
    const fetched = fakeBundleFiles({ commit: HEAD });
    const dist = writeTree(join(dir, "dist"), fetched);
    // Since then the tag was moved and the release workflow built — and attested — another viewer under the same
    // name. (An immutable release cannot be changed like this; this is the repository that never turned that on,
    // with the release named so that the scripts look at it at all.)
    const moved = fakeBundleFiles({ build: "fedcba9876543210", commit: "e".repeat(40), extra: { "app.js": "'use strict';\n// someone else's page\n" } });
    const gh = fakeGh(join(dir, "moved"));
    gh.publish(TAG, NAME, bundleTarball(moved), { repo: REPO, immutable: false, commit: HEAD });
    const result = await run("check-release.mjs", [dist], { bin: gh.bin, env: { GCLONE_MUTABLE_RELEASE: TAG } });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /is NOT the viewer of release v9\.8\.7; nothing is deployed/);
    assert.match(result.stderr, new RegExp(`dist/ holds build ${B} of commit ${HEAD}; release v9\\.8\\.7 now holds build fedcba9876543210 of commit e{40} \\(tarball sha256 [0-9a-f]{64}\\)`));
    assert.match(result.stderr, /THE RELEASE WAS CHANGED after it was fetched: a tag that was moved and built again\. Do not simply fetch again/);
    assert.doesNotMatch(result.stderr, /Fetch it again/);
    // Without the name it does not even get that far: the release is not immutable.
    const plain = await run("check-release.mjs", [dist], { bin: gh.bin });
    assert.equal(plain.status, 1);
    assert.match(plain.stderr, /is not an immutable release/);

    // The same for a host: what it serves is no longer "the release", and the message says which of the two may have moved.
    const host = await serve(fetched);
    try {
      const verify = await run("verify-deployed.mjs", [host.origin, TAG], { bin: gh.bin, env: { GCLONE_MUTABLE_RELEASE: TAG } });
      assert.equal(verify.status, 1);
      assert.match(verify.stderr, /does NOT serve release v9\.8\.7 of owner\/project \(version 9\.8\.7, build fedcba9876543210, commit e{40}, tarball sha256 [0-9a-f]{64}, attestation verified, release NOT immutable\)/);
      assert.match(verify.stderr, /either the deployment changed, or the release did\..*if THEY differ, the tag was moved; do not redeploy from it/s);
    } finally {
      await host.close();
    }
  });
});

test("package.json: `deploy` runs check-config, then the release check, then wrangler; `deploy:dev` says what it deploys", () => {
  const { scripts: npm } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(npm.deploy, "node scripts/check-config.mjs && node scripts/check-release.mjs && wrangler deploy");
  assert.equal(npm["deploy:dev"], "node scripts/check-config.mjs && node scripts/stub-dist.mjs && node scripts/check-dist.mjs --not-a-release && wrangler deploy");
  // no script deploys without check-config, and none but these two deploys
  for (const [name, text] of Object.entries(npm)) if (/wrangler deploy(?! --dry-run)/.test(text)) assert.ok(["deploy", "deploy:dev"].includes(name), name);
});

test("verify-deployed: a host that serves the release passes; one different byte, a missing header, another page do not", async () => {
  await inTempDir(async (dir) => {
    const { gh, files } = published(dir);
    const target = `/a/${B}/app.js`;
    const cases = [
      { name: "the release", change: (path, answer) => answer, ok: true },
      {
        name: "one different byte in one file",
        change: (path, answer) => (path === target ? { ...answer, body: Buffer.from("'use strict';\n// the pagE\n") } : answer),
        expect: new RegExp(`${target}: differs from the release \\(26 bytes served\\)`),
      },
      {
        name: "another Service Worker",
        change: (path, answer) => (path === "/sw.js" ? { ...answer, body: Buffer.concat([answer.body, Buffer.from("fetch('https://evil.example/')\n")]) } : answer),
        expect: /\/sw\.js: differs from the release/,
      },
      {
        name: "a script added to the page",
        change: (path, answer) => (path === "/" ? { ...answer, body: Buffer.from(answer.body.toString().replace("</body>", '<script src="https://evil.example/x.js"></script></body>')) } : answer),
        expect: /\/: the page differs from the release's index\.html/,
      },
      {
        name: "markup in place of the status line",
        change: (path, answer) => (path === "/callback" ? { ...answer, body: Buffer.from(answer.body.toString().replace("Status: ready", "Status: ready<script src=//evil.example></script>")) } : answer),
        expect: /\/callback: where the status line belongs, the page holds "Status: ready<script/,
      },
      {
        name: "a file that is not there (an older deployment)",
        change: (path, answer) => (path === `/a/${B}/core.wasm` ? { status: 404, headers: {}, body: Buffer.alloc(0) } : answer),
        expect: /core\.wasm: status 404, expected 200/,
      },
      {
        name: "a weaker policy on a script",
        change: (path, answer) => (path === target ? { ...answer, headers: { ...answer.headers, "Content-Security-Policy": "default-src *" } } : answer),
        expect: new RegExp(`${target}: header content-security-policy is "default-src \\*", the release sets`),
      },
      {
        name: "no HSTS on the page",
        change: (path, answer) => {
          if (path !== "/") return answer;
          const headers = { ...answer.headers };
          delete headers["Strict-Transport-Security"];
          return { ...answer, headers };
        },
        expect: /\/: header strict-transport-security is missing/,
      },
      {
        name: "a redirect",
        change: (path, answer) => (path === "/" ? { status: 302, headers: { location: "https://elsewhere.example/" }, body: Buffer.alloc(0) } : answer),
        expect: /\/: status 302 → https:\/\/elsewhere\.example\/, expected 200/,
      },
    ];
    for (const { name, change, ok, expect } of cases) {
      const host = await serve(files, change);
      try {
        const result = await run("verify-deployed.mjs", [host.origin, TAG], { bin: gh.bin });
        if (ok) {
          assert.equal(result.status, 0, `${name}: ${result.stderr}`);
          assert.match(result.stdout, /^verify-deployed: http:\/\/127\.0\.0\.1:\d+ serves release v9\.8\.7 of owner\/project \(version 9\.8\.7, build 0123456789abcdef, commit [0-9a-f]{40}, tarball sha256 [0-9a-f]{64}, attestation verified, immutable release\)\n/);
          // It deploys nothing, so it holds the release to no checkout: it runs from any machine, at any commit.
          assert.ok(gh.calls().every((call) => !call.includes("--source-digest")));
          assert.match(result.stdout, /the page says: Status: ready\n/);
          // `/`, `/callback`, `/sw.js` and the six files of the build directory
          assert.equal(host.hits(), 9);
        } else {
          assert.equal(result.status, 1, name);
          assert.match(result.stderr, /does NOT serve release v9\.8\.7/, name);
          assert.match(result.stderr, expect, name);
        }
      } finally {
        await host.close();
      }
    }

    // against a local build: --dist, no gh involved; it never reads another directory
    const local = writeTree(join(dir, "local"), fakeBundleFiles({ tag: "", commit: "" }));
    const host = await serve(fakeBundleFiles({ tag: "", commit: "" }));
    try {
      const result = await run("verify-deployed.mjs", [host.origin, "--dist", local], {});
      assert.equal(result.status, 0, result.stderr);
      assert.match(result.stdout, /serves the local build in .* — NOT a release: no attestation was checked/);
    } finally {
      await host.close();
    }
    // a host that is down
    const down = await run("verify-deployed.mjs", ["http://127.0.0.1:9", "--dist", local], {});
    assert.equal(down.status, 1);
    assert.match(down.stderr, /\/: no answer/);
  });
});

test("verify-deployed takes an https host, or this machine", () => {
  assert.equal(hostOrigin("https://viewer.example"), "https://viewer.example");
  assert.equal(hostOrigin("https://viewer.example/"), "https://viewer.example");
  assert.equal(hostOrigin("http://127.0.0.1:8787"), "http://127.0.0.1:8787");
  assert.equal(hostOrigin("http://localhost:8787/"), "http://localhost:8787");
  for (const bad of ["http://viewer.example", "viewer.example", "https://viewer.example/callback", "https://viewer.example/?x=1", "https://user@viewer.example", "ftp://viewer.example", ""]) {
    assert.throws(() => hostOrigin(bad), /expected|https only/, bad);
  }
  assert.deepEqual(headerSet("/a/*\n  X-A: 1\n  X-B: a: b\n/sw.js\n  X-A: 1\n"), { "x-a": "1", "x-b": "a: b" });
});

test("compareFiles: nothing missing, nothing extra, every hash equal", () => {
  assert.deepEqual(compareFiles({ a: "1", b: "2" }, { a: "1", b: "2" }), []);
  assert.deepEqual(compareFiles({ a: "1", b: "2" }, { a: "1", b: "3", c: "4" }), ["b: differs from the release", "c: in this copy, not in the release"]);
  assert.deepEqual(compareFiles({ a: "1", b: "2" }, { a: "1" }), ["b: in the release, missing in this copy"]);
  assert.deepEqual(compareFiles({ a: "1" }, { __proto__: null }), ["a: in the release, missing in this copy"]);
});
