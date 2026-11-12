// Test of the one computed value in setup.sh's Google console checklist (plain Node, `node --test`, run by `npm test`).
// `./setup.sh --authorized-domain HOST` only prints; nothing is installed, deployed or asked.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const setup = fileURLToPath(new URL("../setup.sh", import.meta.url));
const authorizedDomain = (host) => execFileSync("sh", [setup, "--authorized-domain", host], { encoding: "utf8" }).trimEnd();

test("workers.dev: the account's subdomain, which is a registrable domain", () => {
  assert.equal(authorizedDomain("gclone-auth.example-account.workers.dev"), "example-account.workers.dev");
});

test("a custom domain: the registrable domain, never the Worker's own host name (Google refuses a subdomain there)", () => {
  for (const [host, domain] of [
    ["auth.example.org", "example.org"],
    ["gclone.auth.example.org", "example.org"],
  ]) {
    const line = authorizedDomain(host);
    assert.ok(line.startsWith(`${domain} `), line);
    assert.notEqual(line.split(" ")[0], host);
    // it is a guess (public suffixes such as .co.uk have two labels), and the checklist says so
    assert.match(line, /registrable domain of .*not the host itself/);
  }
  assert.equal(authorizedDomain("example.org"), "example.org");
});

test("setup.sh is valid shell and settles the host name before the first deploy", () => {
  execFileSync("sh", ["-n", setup]);
  const text = readFileSync(setup, "utf8");
  // the host name is asked for, and written into wrangler.jsonc, before anything is deployed or registered at Google
  const asked = text.indexOf("node scripts/custom-domain.mjs");
  const deployed = text.indexOf("npx wrangler deploy");
  const checklist = text.indexOf("Application type: TVs and Limited Input devices");
  assert.ok(asked > 0 && asked < deployed && deployed < checklist, "order: choose the host, deploy, then the Google checklist");
  // with a host of one's own, that host is the auth URL of the checklist and of the final `gclone login` line
  assert.ok(text.includes('auth_url="https://$custom_host"'));
});

test("the checklist asks for a device-flow client and the script puts exactly the three secrets", () => {
  const text = readFileSync(setup, "utf8");
  // the device authorization grant: no redirect URI to register, no "Web application" client
  assert.ok(!/Web application|Authorized redirect URI|\/callback/.test(text));
  assert.deepEqual(
    [...text.matchAll(/^put_secret ([A-Z_]+) /gm)].map((m) => m[1]),
    ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "ALLOWED_EMAILS"],
  );
  // no sealing key any more, so nothing has to generate one
  assert.ok(!/SEAL_KEY|openssl/.test(text));
});
