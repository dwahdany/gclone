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
// In a git checkout the attestation is also held to the commit the checkout is at (`--source-digest`): the Worker's
// code that `wrangler deploy` bundles comes from the checkout, the viewer from the release, and the two belong to
// one commit. The release must be immutable (release-bundle.mjs, step 3). When `dist/` and the release differ, the
// message says whether the release itself is no longer what was fetched — a moved tag — instead of advising a new
// fetch, which would deploy exactly the bytes that were swapped in.
//
// Node built-ins and `gh` only.

import { fileURLToPath } from "node:url";
import { describe, inspectDist } from "./check-dist.mjs";
import { checkout, command, compareFiles, releaseBundle } from "./release-bundle.mjs";

/** What to make of a `dist/` that is not the release's bytes: was it changed, or was the release? */
export function mismatchAdvice(tag, local, bundle) {
  const was = `build ${local.build ?? "?"} of commit ${local.commit ?? "?"}`;
  const now = `build ${bundle.build} of commit ${bundle.manifest.commit} (tarball sha256 ${bundle.tarball.sha256})`;
  if (local.build !== bundle.build || local.commit !== bundle.manifest.commit) {
    return (
      `dist/ holds ${was}; release ${tag} now holds ${now}.\n` +
      `Either dist/ was not fetched from this release, or THE RELEASE WAS CHANGED after it was fetched: a tag that was moved and built again. ` +
      `Do not simply fetch again — that would deploy whatever the tag points at now. Compare with what fetch-viewer printed when you fetched ` +
      `(build, commit, tarball SHA-256), look at \`git log -1 ${tag}\` and at the release page, and deploy only once you know why they differ.`
    );
  }
  return `Both name ${was}: something changed ./dist after it was fetched (an install script, an editor). Fetch it again: node scripts/fetch-viewer.mjs ${tag}`;
}

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
      const mine = { build: local.build ?? null, commit: local.manifest.commit ?? null };
      throw new Error(`${dist} is NOT the viewer of release ${tag}; nothing is deployed:\n${differences.map((d) => `  - ${d}`).join("\n")}\n${mismatchAdvice(tag, mine, bundle)}`);
    }
    return { tag, build: bundle.build, version: bundle.version, files: Object.keys(bundle.files).length, tarball: bundle.tarball, repo: bundle.repo, commit: bundle.commit, immutable: bundle.immutable };
  } finally {
    bundle.remove();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await command("check-release", () => {
    const here = checkout();
    const done = checkRelease(process.argv[2] ?? fileURLToPath(new URL("../dist", import.meta.url)), { commit: here?.commit ?? null });
    console.log(`check-release: dist/ is the attested viewer of ${done.repo} ${done.tag} — version ${done.version}, build ${done.build}, ${done.files} files, tarball sha256 ${done.tarball.sha256}`);
    if (here === null) console.log("check-release: this is not a git checkout — the release's commit was not compared with the Worker's code that is deployed with it");
    else {
      console.log(`check-release: the release was built from commit ${here.commit}, which this checkout is at${done.immutable ? "; the release is immutable" : ""}`);
      // What `wrangler deploy` bundles is the working tree: say where it is not that commit (a `routes` entry in wrangler.jsonc is expected).
      if (here.changed.length > 0) console.log(`check-release: note — the working tree differs from that commit in: ${here.changed.join(", ")}`);
    }
  });
}
