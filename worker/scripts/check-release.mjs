// The last check before `wrangler deploy` (`npm run deploy`): `dist/` is, byte for byte, the attested viewer bundle
// of the release its manifest names.
//
//   node scripts/check-release.mjs [path/to/dist]
//
// It reads the tag from `dist/a/<build>/manifest.json`, calls releaseBundle(tag) again — a fresh download and a fresh
// verification of the attestation, never a look at what fetch-viewer left — and compares every file: nothing missing,
// nothing extra, every SHA-256 equal. A `dist/` that anything changed after the fetch (an npm dependency's install
// script, an editor), one without a tag (a local build) and the placeholder do not pass; those are deployed with
// `npm run deploy:dev`, which says what it deploys.
//
// Node built-ins and `gh` only.

import { fileURLToPath } from "node:url";
import { describe, inspectDist } from "./check-dist.mjs";
import { command, compareFiles, releaseBundle } from "./release-bundle.mjs";

export function checkRelease(dist, options = {}) {
  const local = inspectDist(dist);
  const hint = "Fetch a release (node scripts/fetch-viewer.mjs <tag>), or deploy this one as what it is: npm run deploy:dev";
  if (local.manifest === null) throw new Error(`${dist} holds no bundle:\n${local.problems.map((p) => `  - ${p}`).join("\n")}\n${hint}`);
  if (local.stub) throw new Error(`${dist} holds the placeholder, not the viewer of a release.\n${hint}`);
  const tag = local.manifest.tag;
  if (typeof tag !== "string" || tag === "") throw new Error(`${dist} holds a local build (${describe(local)}), not the viewer of a release.\n${hint}`);
  const bundle = releaseBundle(tag, options);
  try {
    const differences = [...local.problems, ...compareFiles(bundle.files, local.files, { expectedName: `release ${tag}`, actualName: "dist/" })];
    if (differences.length > 0) {
      throw new Error(`${dist} is NOT the viewer of release ${tag}; nothing is deployed:\n${differences.map((d) => `  - ${d}`).join("\n")}\nFetch it again: node scripts/fetch-viewer.mjs ${tag}`);
    }
    return { tag, build: bundle.build, version: bundle.version, files: Object.keys(bundle.files).length, tarball: bundle.tarball, repo: bundle.repo };
  } finally {
    bundle.remove();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await command("check-release", () => {
    const done = checkRelease(process.argv[2] ?? fileURLToPath(new URL("../dist", import.meta.url)));
    console.log(`check-release: dist/ is the attested viewer of ${done.repo} ${done.tag} — version ${done.version}, build ${done.build}, ${done.files} files, tarball sha256 ${done.tarball.sha256}`);
  });
}
