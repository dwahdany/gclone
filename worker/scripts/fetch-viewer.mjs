// Puts the viewer bundle of a release into `dist/`, the directory `wrangler deploy` uploads:
//
//   node scripts/fetch-viewer.mjs v0.4.0 [--dist <dir>]
//
// The bundle comes from releaseBundle() (release-bundle.mjs): downloaded from the tag's GitHub release, its
// build-provenance attestation verified with `gh`, unpacked and checked. Only then is `dist/` replaced with that
// tree. Prints the version, the build id and the tarball's SHA-256.
//
// It replaces a `dist/` that holds a bundle or the placeholder, and refuses one that holds anything else.
// Node built-ins and `gh` only: it runs before `npm ci`.

import { cpSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { TOP, inspectDist } from "./check-dist.mjs";
import { command, compareFiles, releaseBundle } from "./release-bundle.mjs";

/** Replaces the bundle in `dist` with the tree at `from`. Only what a bundle consists of is ever removed. */
export function replaceDist(dist, from) {
  if (existsSync(dist)) {
    const other = readdirSync(dist).filter((name) => !TOP.includes(name));
    if (other.length > 0) throw new Error(`${dist} holds ${other.join(", ")}, which is not part of a bundle; remove it first`);
    for (const name of TOP) rmSync(join(dist, name), { recursive: true, force: true });
  }
  mkdirSync(dist, { recursive: true });
  for (const name of TOP) cpSync(join(from, name), join(dist, name), { recursive: true });
}

export function fetchViewer(tag, { dist = fileURLToPath(new URL("../dist", import.meta.url)), ...options } = {}) {
  const bundle = releaseBundle(tag, options);
  try {
    replaceDist(dist, bundle.path);
    // What is on disk now is what was verified, byte for byte.
    const differences = compareFiles(bundle.files, inspectDist(dist, { release: tag }).files, { expectedName: "the release", actualName: dist });
    if (differences.length > 0) throw new Error(`${dist} is not the release bundle after copying it:\n${differences.map((d) => `  - ${d}`).join("\n")}`);
    return { ...bundle, dist };
  } finally {
    bundle.remove();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await command("fetch-viewer", () => {
    const args = process.argv.slice(2);
    const at = args.indexOf("--dist");
    const dist = at >= 0 ? args.splice(at, 2)[1] : undefined;
    if (args.length !== 1 || (at >= 0 && dist === undefined)) throw new Error("usage: node scripts/fetch-viewer.mjs <tag> [--dist <dir>]     (for example v0.4.0; the default directory is worker/dist)");
    const done = fetchViewer(args[0], dist === undefined ? {} : { dist });
    console.log(`fetch-viewer: ${done.dist} is the viewer of ${done.repo} ${done.tag}`);
    console.log(`  version   ${done.version}`);
    console.log(`  build     ${done.build}`);
    console.log(`  commit    ${done.manifest.commit}`);
    console.log(`  tarball   ${done.tarball.name}  sha256 ${done.tarball.sha256}`);
    console.log(`  verified  attestation of ${done.repo}/.github/workflows/release.yml on refs/tags/${done.tag}`);
    console.log("Next: npm ci && npm run deploy");
  });
}
