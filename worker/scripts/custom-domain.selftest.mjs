// Tests of custom-domain.mjs (plain Node, `node --test`, run by `npm test`): the edit setup.sh makes to
// wrangler.jsonc when the Worker is to be served from a host name of one's own. Works on the text of the shipped
// file; the file itself is never written.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { parseJsonc, problems } from "./check-config.mjs";
import { hostProblem, withCustomDomain } from "./custom-domain.mjs";

const shippedFile = fileURLToPath(new URL("../wrangler.jsonc", import.meta.url));
const committed = readFileSync(shippedFile, "utf8");

// The committed file may already carry its owner's custom domain (the output of custom-domain.mjs). The tests
// start from the workers.dev shape, so that one edit is undone on the text first.
const shipped = committed
  .split("\n")
  .filter((line) => !/^\s*"routes":\s*\[\{ "pattern": "[^"]+", "custom_domain": true \}\],\s*$/.test(line))
  .join("\n")
  .replace('  "workers_dev": false,', '  "workers_dev": true,');

test("the committed file is the workers.dev configuration or exactly one custom-domain edit away from it", () => {
  const config = parseJsonc(shipped);
  assert.equal(config.workers_dev, true);
  assert.equal(config.routes, undefined);
  const now = parseJsonc(committed);
  assert.deepEqual(problems(now), []);
  if (now.routes !== undefined) {
    assert.equal(now.workers_dev, false);
    assert.equal(now.routes.length, 1);
    assert.equal(withCustomDomain(shipped, now.routes[0].pattern), committed);
  }
});

test("a host of one's own: the only route, workers.dev off, every security requirement still met", () => {
  const out = withCustomDomain(shipped, "auth.example.org");
  const config = parseJsonc(out);
  assert.deepEqual(config.routes, [{ pattern: "auth.example.org", custom_domain: true }]);
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.deepEqual(problems(config), []);
  // nothing else changed: the same file but for one rewritten and one added line, comments included
  const [before, after] = [shipped.split("\n"), out.split("\n")];
  assert.equal(after.length, before.length + 1);
  const added = after.filter((line) => !before.includes(line));
  assert.deepEqual(added, ['  "workers_dev": false,', '  "routes": [{ "pattern": "auth.example.org", "custom_domain": true }],']);
  assert.deepEqual(
    before.filter((line) => !after.includes(line)),
    ['  "workers_dev": true,'],
  );
  assert.ok(out.startsWith("// gclone's auth Worker."));
});

test("running it again changes nothing; another host replaces the entry", () => {
  const once = withCustomDomain(shipped, "auth.example.org");
  assert.equal(withCustomDomain(once, "auth.example.org"), once);
  const moved = parseJsonc(withCustomDomain(once, "gclone.example.co.uk"));
  assert.deepEqual(moved.routes, [{ pattern: "gclone.example.co.uk", custom_domain: true }]);
  assert.equal(moved.workers_dev, false);
});

test("what is not a host name of one's own is refused", () => {
  for (const host of [
    "",
    "https://auth.example.org",
    "auth.example.org/",
    "auth.example.org:443",
    "localhost",
    "Auth.Example.org",
    "auth..example.org",
    "-auth.example.org",
    "auth.example.org ",
    "192.168.1.10",
    "gclone-auth.acct.workers.dev",
    'x", "evil": true, "y": "z.example.org',
  ]) {
    assert.notEqual(hostProblem(host), null, host);
    assert.throws(() => withCustomDomain(shipped, host), undefined, host);
  }
  for (const host of ["auth.example.org", "example.org", "gclone.wahdany.eu", "a-b.c1.example.co.uk"]) {
    assert.equal(hostProblem(host), null, host);
  }
});

test("a file that is not the shipped shape is refused rather than guessed at", () => {
  assert.throws(() => withCustomDomain(shipped.replace('  "workers_dev": true,\n', ""), "auth.example.org"), /workers_dev/);
  assert.throws(() => withCustomDomain(shipped.replace('"preview_urls": false', '"preview_urls": true'), "auth.example.org"), /security requirement/);
});

test("the command line writes the file it is given, and only on a change", () => {
  const dir = mkdtempSync(join(tmpdir(), "gclone-custom-domain-"));
  try {
    const file = join(dir, "wrangler.jsonc");
    writeFileSync(file, shipped);
    const script = fileURLToPath(new URL("./custom-domain.mjs", import.meta.url));
    const run = (...args) => execFileSync(process.execPath, [script, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assert.match(run("auth.example.org", file), /now serves the Worker from auth\.example\.org only/);
    assert.equal(readFileSync(file, "utf8"), withCustomDomain(shipped, "auth.example.org"));
    assert.match(run("auth.example.org", file), /already serves/);
    assert.throws(() => run("https://auth.example.org", file), /bare host name/);
    assert.equal(readFileSync(file, "utf8"), withCustomDomain(shipped, "auth.example.org"));
    // the checker accepts what was written
    execFileSync(process.execPath, [fileURLToPath(new URL("./check-config.mjs", import.meta.url)), file], { stdio: "ignore" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(readFileSync(shippedFile, "utf8"), committed, "the committed file is untouched");
});
