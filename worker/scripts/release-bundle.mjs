// The viewer bundle of a release, verified: the one function that fetch-viewer.mjs, check-release.mjs (`npm run
// deploy`) and verify-deployed.mjs take their expected bytes from.
//
//   releaseBundle("v0.4.0")  →  { path, build, files: { "<path below dist>": "<sha256>" }, … }
//
// 1. Downloads `gclone-viewer-<version>.tar.gz` of that tag's GitHub release into a new temporary directory.
// 2. `gh attestation verify <tarball> --repo <owner>/<repo>
//        --signer-workflow <owner>/<repo>/.github/workflows/release.yml
//        --source-ref refs/tags/<tag> --deny-self-hosted-runners`
//    — the build-provenance attestation that the release workflow made for exactly these bytes. It is stored by GitHub
//    outside the release's files and names the repository, the workflow file, the tag and the commit. This FAILS
//    CLOSED: no `gh`, no attestation, another workflow, another ref → no bundle. SHA256SUMS is never consulted.
//    With `commit` (the scripts that deploy pass the commit their checkout is at) also `--source-digest <commit>`:
//    the bundle was built from the very commit whose Worker code is about to be deployed with it.
// 3. `gh release verify-asset <tag> <tarball> --repo <owner>/<repo>` — GitHub's own attestation of the release, which
//    exists only for an IMMUTABLE release and binds the tag, the commit it points at and the digests of its files.
//    The attestation of step 2 follows the tag: without immutability, whoever can push a tag can move this one and
//    let the release workflow attest other bytes under the same name. Fails closed too; a release that was published
//    before the repository made its releases immutable is used only when GCLONE_MUTABLE_RELEASE names its tag.
// 4. Unpacks there (its own reader: plain files under the names a bundle has, nothing else) and runs check-dist on it.
//
// Node built-ins and the `gh` command only — no npm package, so that it runs before `npm ci` and from a clean
// checkout on any machine. The repository is `GCLONE_REPO` (as for install.sh), else the one below.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { MAX_FILE, checkDist, sha256, tagVersion } from "./check-dist.mjs";

/** The repository whose releases hold the bundle; override with GCLONE_REPO. */
export const DEFAULT_REPO = "dwahdany/gclone";
/** The workflow whose signature counts, below the repository. */
export const SIGNER_WORKFLOW = ".github/workflows/release.yml";
/** A bundle is well under a megabyte packed; anything near this is not one. */
export const MAX_TARBALL = 64 * 1024 * 1024;
const MAX_UNPACKED = 128 * 1024 * 1024;
/** The names a bundle's files have, below `dist/`. */
const MEMBER = /^(?:index\.html|sw\.js|_headers|a\/[0-9a-f]{16}\/[A-Za-z0-9][A-Za-z0-9._-]*)$/;
const DIRECTORY = /^(?:a|a\/[0-9a-f]{16})$/;

export const tarballName = (version) => `gclone-viewer-${version}.tar.gz`;

class ReleaseError extends Error {}
const fail = (message) => {
  throw new ReleaseError(message);
};

/**
 * The files of a bundle's tarball: `Map<path, Buffer>`. Refuses everything a bundle does not consist of — a link, a
 * device, a path outside the layout, a name twice, an extended header — instead of unpacking it.
 */
export function readTarball(gz) {
  let tar;
  try {
    tar = gunzipSync(gz, { maxOutputLength: MAX_UNPACKED });
  } catch (error) {
    fail(`the tarball does not unpack (${error.code ?? error.message})`);
  }
  const text = (block, from, to) => {
    const part = block.subarray(from, to);
    const end = part.indexOf(0);
    return part.subarray(0, end < 0 ? part.length : end).toString("utf8");
  };
  const octal = (block, from, to, what) => {
    const field = text(block, from, to).trim();
    if (!/^[0-7]+$/.test(field)) fail(`the tarball has a header with an unreadable ${what}`);
    return Number.parseInt(field, 8);
  };
  const files = new Map();
  let at = 0;
  let ended = false;
  while (at + 512 <= tar.length) {
    const block = tar.subarray(at, at + 512);
    at += 512;
    if (block.every((byte) => byte === 0)) {
      ended = true;
      break;
    }
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : block[i];
    if (sum !== octal(block, 148, 156, "checksum")) fail("the tarball has a header with a wrong checksum");
    const prefix = text(block, 345, 500);
    let name = (prefix === "" ? "" : `${prefix}/`) + text(block, 0, 100);
    if (name.startsWith("./")) name = name.slice(2);
    const type = String.fromCharCode(block[156]);
    const size = octal(block, 124, 136, "size");
    if (type === "5") {
      const dir = name.replace(/\/+$/, "");
      if (size !== 0 || (dir !== "" && dir !== "." && !DIRECTORY.test(dir))) fail(`the tarball holds the directory ${JSON.stringify(name)}, which a bundle does not have`);
      continue;
    }
    if (type !== "0" && type !== "\0") fail(`the tarball holds ${JSON.stringify(name)}, which is not a plain file (type ${JSON.stringify(type)})`);
    if (!MEMBER.test(name)) fail(`the tarball holds ${JSON.stringify(name)}, which is not a file of a bundle`);
    if (files.has(name)) fail(`the tarball holds ${JSON.stringify(name)} twice`);
    if (size > MAX_FILE || at + size > tar.length) fail(`the tarball's ${JSON.stringify(name)} is cut short or too large`);
    files.set(name, Buffer.from(tar.subarray(at, at + size)));
    at += Math.ceil(size / 512) * 512;
  }
  if (!ended) fail("the tarball is cut short");
  if (!tar.subarray(at).every((byte) => byte === 0)) fail("the tarball holds data after its end");
  return files;
}

/** Runs `gh`; `{ ok: true, out }`, or `{ ok: false, message }` with what it said. No `gh` at all throws. */
function tryGh(gh, args, what) {
  try {
    return { ok: true, out: execFileSync(gh, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 16 * 1024 * 1024 }) };
  } catch (error) {
    if (error.code === "ENOENT") {
      fail(`the GitHub CLI (\`${gh}\`) was not found. It verifies the release bundle's attestation, and without that the bundle is not used. Install it (https://cli.github.com, or nix-shell -p gh) and sign in once (gh auth login).`);
    }
    const said = `${error.stderr ?? ""}${error.stdout ?? ""}`.trim();
    return { ok: false, message: `${what} failed (${gh} ${args.slice(0, 2).join(" ")}, exit ${error.status ?? error.signal ?? "?"})${said === "" ? "" : `:\n${said.replace(/^/gm, "    ")}`}` };
  }
}

function runGh(gh, args, what) {
  const done = tryGh(gh, args, what);
  if (!done.ok) fail(done.message);
  return done.out;
}

/**
 * The arguments of the verification, as documented above. One place, so that the tests can hold the scripts to it.
 * `commit`: also require that the bundle was built from this commit (40 hex digits).
 */
export function verifyArgs(tarball, repo, tag, commit = null) {
  const args = ["attestation", "verify", tarball, "--repo", repo, "--signer-workflow", `${repo}/${SIGNER_WORKFLOW}`, "--source-ref", `refs/tags/${tag}`, "--deny-self-hosted-runners"];
  return commit === null ? args : [...args, "--source-digest", commit];
}

/** The arguments of the release's own check (step 3): it passes only for an asset of an immutable release. */
export function immutableArgs(tarball, repo, tag) {
  return ["release", "verify-asset", tag, tarball, "--repo", repo];
}

/**
 * The commit the git checkout around `dir` is at (HEAD, 40 hex digits), and the paths below `dir` that differ from it
 * — or null where there is no checkout (a source archive) or no git. The scripts that deploy hold the release to it.
 */
export function checkout(dir = fileURLToPath(new URL("..", import.meta.url))) {
  const git = (args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  try {
    const commit = git(["rev-parse", "--verify", "HEAD"]).trim();
    if (!/^[0-9a-f]{40}$/.test(commit)) return null;
    const changed = git(["status", "--porcelain", "--", "."])
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => line.slice(3));
    return { commit, changed };
  } catch {
    return null;
  }
}

/**
 * Downloads, verifies and unpacks the bundle of `tag`. Returns
 * `{ tag, version, repo, path, build, files, manifest, tarball: { name, sha256, bytes }, commit, immutable, remove() }`:
 * `path` is the unpacked `dist/` in a temporary directory of its own, which `remove()` deletes; `commit` is the commit
 * the attestation was held to (null: none was asked for); `immutable` is false only for a release that
 * GCLONE_MUTABLE_RELEASE (or `mutable`) names. Throws (and leaves nothing behind) when any step fails.
 */
export function releaseBundle(
  tag,
  { repo = process.env.GCLONE_REPO || DEFAULT_REPO, gh = process.env.GCLONE_GH || "gh", commit = null, mutable = process.env.GCLONE_MUTABLE_RELEASE || "", warn = (line) => console.error(line) } = {},
) {
  const version = tagVersion(tag);
  if (version === null) fail(`${JSON.stringify(tag)} is not a release tag: expected v<major>.<minor>.<patch>, like v0.4.0`);
  if (!/^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9._-]+$/.test(repo)) fail(`${JSON.stringify(repo)} is not a GitHub repository (OWNER/NAME)`);
  if (commit !== null && !/^[0-9a-f]{40}$/.test(commit)) fail(`${JSON.stringify(commit)} is not a commit (40 hex digits)`);
  const name = tarballName(version);
  const work = mkdtempSync(join(tmpdir(), "gclone-viewer-release-"));
  const remove = () => rmSync(work, { recursive: true, force: true });
  try {
    const download = join(work, "download");
    mkdirSync(download);
    runGh(gh, ["release", "download", tag, "--repo", repo, "--pattern", name, "--dir", download], `downloading ${name} of release ${tag} of ${repo}`);
    const got = readdirSync(download);
    if (got.length !== 1 || got[0] !== name) fail(`release ${tag} of ${repo} has no ${name} (the download left: ${got.join(", ") || "nothing"})`);
    const tarball = join(download, name);
    const size = statSync(tarball).size;
    if (size > MAX_TARBALL) fail(`${name} is ${size} bytes: not a viewer bundle`);

    // The trust anchor. Before a single byte of the tarball is interpreted.
    const what = `verifying the attestation of ${name} (built by ${repo}/${SIGNER_WORKFLOW} on refs/tags/${tag}${commit === null ? "" : `, from commit ${commit}`})`;
    const verified = tryGh(gh, verifyArgs(tarball, repo, tag, commit), what);
    if (!verified.ok) {
      // Is it the commit alone? Then the bytes are the release's, and what does not fit is this checkout — or the tag.
      if (commit !== null && tryGh(gh, verifyArgs(tarball, repo, tag), what).ok) {
        fail(
          `${name} of release ${tag} is attested, but it was not built from commit ${commit}, which this checkout is at. ` +
            `The Worker's code is deployed from the checkout and the viewer from the release: both have to be the release's commit. ` +
            `Check out the tag (git checkout ${tag}) and run this again. If this checkout IS at ${tag}, the tag was moved after the release was built: do not deploy, find out why.`,
        );
      }
      fail(verified.message);
    }

    // The release itself: immutable, with this file among its assets (step 3 above).
    const fixed = tryGh(gh, immutableArgs(tarball, repo, tag), `verifying that ${name} is an asset of the immutable release ${tag} of ${repo}`);
    if (!fixed.ok) {
      if (mutable !== tag) {
        fail(
          `${fixed.message}\n` +
            `Release ${tag} is not an immutable release, or ${name} is not the file it was published with. The attestation of the build follows the tag; ` +
            `only an immutable release fixes the tag, its commit and its files, so that nobody who can push a tag can move this one and have other bytes attested under the same name. ` +
            `Turn on "Immutable releases" in the repository's settings (it holds for releases published afterwards). ` +
            `To use a release that was published before that, name it: GCLONE_MUTABLE_RELEASE=${tag}`,
        );
      }
      warn(`warning: release ${tag} of ${repo} is NOT immutable (GCLONE_MUTABLE_RELEASE=${tag}): its tag and files can still be changed by anyone who can push to the repository. The build's attestation was verified; compare the tarball's SHA-256 and the commit below with what you recorded when you first fetched it.`);
    }

    const bytes = readFileSync(tarball);
    const path = join(work, "dist");
    for (const [member, content] of readTarball(bytes)) {
      const file = join(path, member);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, content);
    }
    const checked = checkDist(path, { release: tag });
    return { tag, version, repo, path, build: checked.build, files: checked.files, manifest: checked.manifest, tarball: { name, sha256: sha256(bytes), bytes: size }, commit, immutable: fixed.ok, remove };
  } catch (error) {
    remove();
    throw error;
  }
}

/**
 * Compares two `{ path: sha256 }` lists. Returns the differences as sentences: nothing missing, nothing extra,
 * every hash equal — or it is not the same tree.
 */
export function compareFiles(expected, actual, { expectedName = "the release", actualName = "this copy" } = {}) {
  const differences = [];
  for (const path of Object.keys(expected).sort()) {
    if (!Object.hasOwn(actual, path)) differences.push(`${path}: in ${expectedName}, missing in ${actualName}`);
    else if (actual[path] !== expected[path]) differences.push(`${path}: differs from ${expectedName}`);
  }
  for (const path of Object.keys(actual).sort()) {
    if (!Object.hasOwn(expected, path)) differences.push(`${path}: in ${actualName}, not in ${expectedName}`);
  }
  return differences;
}

/** Runs `main` as a command: its Error becomes one message on stderr and exit status 1. */
export async function command(name, main) {
  try {
    await main();
  } catch (error) {
    console.error(`${name}: ${error instanceof Error ? error.message : error}`);
    process.exitCode = 1;
  }
}
