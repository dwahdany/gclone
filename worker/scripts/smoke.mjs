// Smoke test of the Worker together with its static assets, the way wrangler wires them: starts `wrangler dev` on
// `dist/` (a built viewer, or the placeholder of stub-dist.mjs) and asserts the routing and header table of the README
// ("How it works") with plain HTTP requests — which paths the asset layer answers without running the Worker, which
// reach the Worker, the header set on each, and the https rule.
//
// Local only: nothing is deployed, and no request reaches Google (the secrets are made-up values, and only routes
// that answer before Google would be asked are called). Needs `npm ci` (for wrangler). Node built-ins otherwise.
//
// Usage: node scripts/smoke.mjs        (npm run smoke)

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, inspectDist } from "./check-dist.mjs";
import { headersFile, readHeaders } from "./headers-file.mjs";
import { ensureDist } from "./stub-dist.mjs";
import { verifyDeployed } from "./verify-deployed.mjs";

const worker = fileURLToPath(new URL("..", import.meta.url));
const dist = join(worker, "dist");
/** The host the Worker believes it is served from. Never contacted. */
const HOST = "viewer.example";
const STATUS_MARKER = "<!--gclone-status-->";
const CLEAR_COOKIE = "__Host-gclone-web=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0";
// Made-up values: enough for "Status: ready", and never sent anywhere (see the list of requests below).
const VARS = {
  GOOGLE_CLIENT_ID: "smoke-device.apps.googleusercontent.com",
  GOOGLE_CLIENT_SECRET: "smoke-device-secret",
  GOOGLE_LEGACY_CLIENT_ID: "smoke-web.apps.googleusercontent.com",
  GOOGLE_LEGACY_CLIENT_SECRET: "smoke-web-secret",
  SEAL_KEY: Buffer.alloc(32, 7).toString("base64"),
  ALLOWED_EMAILS: "nobody@example.com",
};

let checks = 0;
const failures = [];
function check(what, ok, detail = "") {
  checks++;
  if (!ok) failures.push(`${what}${detail === "" ? "" : `: ${detail}`}`);
}
const equal = (what, got, want) => check(what, got === want, `got ${JSON.stringify(got)}, expected ${JSON.stringify(want)}`);

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/** `wrangler dev` with the Worker told that it is served as `<protocol>://viewer.example`. */
async function startDev(protocol) {
  const [port, inspector] = [await freePort(), await freePort()];
  const state = mkdtempSync(join(tmpdir(), "gclone-smoke-"));
  const args = [
    "dev",
    "--ip", "127.0.0.1",
    "--port", String(port),
    "--inspector-port", String(inspector),
    "--local-upstream", HOST,
    "--upstream-protocol", protocol,
    "--persist-to", state,
    "--show-interactive-dev-session=false",
    ...Object.entries(VARS).flatMap(([name, value]) => ["--var", `${name}:${value}`]),
  ];
  const child = spawn(join(worker, "node_modules", ".bin", "wrangler"), args, {
    cwd: worker,
    detached: true, // its own process group, so that workerd goes down with it
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1", NO_COLOR: "1" },
  });
  let output = "";
  child.stdout.on("data", (chunk) => (output += chunk));
  child.stderr.on("data", (chunk) => (output += chunk));
  let exited = false;
  child.once("exit", () => (exited = true));
  const origin = `http://127.0.0.1:${port}`;
  const stop = async () => {
    if (!exited) {
      try {
        process.kill(-child.pid, "SIGTERM");
      } catch {
        // already gone
      }
      await new Promise((resolve) => (exited ? resolve() : child.once("exit", resolve)));
    }
    rmSync(state, { recursive: true, force: true });
  };
  // Ready when an asset is answered (the asset layer and the Worker start together).
  for (let attempt = 0; ; attempt++) {
    if (exited || attempt > 240) {
      await stop();
      throw new Error(`wrangler dev did not come up:\n${output}`);
    }
    try {
      const res = await fetch(`${origin}/sw.js`);
      await res.arrayBuffer();
      if (res.status === 200) break;
    } catch {
      // not listening yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return {
    origin,
    stop,
    /** How many requests the Worker itself has handled: it logs one JSON line for each. */
    workerRuns: () => [...output.matchAll(/^\{"route":.*\}$/gm)].length,
    logLines: () => [...output.matchAll(/^\{"route":.*\}$/gm)].map((m) => JSON.parse(m[0])),
  };
}

async function request(dev, path, init = {}) {
  const res = await fetch(dev.origin + path, { redirect: "manual", ...init });
  return { status: res.status, headers: res.headers, body: Buffer.from(await res.arrayBuffer()) };
}

/** A POST as the viewer's page sends it. wrangler dev maps the local origin to the upstream one, as it does the URL. */
const post = (dev, path, json, headers = {}) =>
  request(dev, path, { method: "POST", headers: { "content-type": "application/json", origin: dev.origin, ...headers }, body: JSON.stringify(json) });

/** A POST as the gclone command sends it: no `Origin` (a device route refuses a request that names a page as its sender). */
const devicePost = (dev, path, json) =>
  request(dev, path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(json) });

/** Waits until the Worker has logged `count` requests (its log line is written after the answer). */
async function settled(dev, count) {
  for (let attempt = 0; attempt < 80 && dev.workerRuns() < count; attempt++) await new Promise((resolve) => setTimeout(resolve, 50));
  return dev.workerRuns();
}

function expectHeaderSet(what, headers, set) {
  for (const [name, value] of Object.entries(set)) equal(`${what}: ${name}`, headers.get(name), value);
}

/** Every file below `dir`, as paths with `/`. */
function filesBelow(dir, prefix = "") {
  return readdirSync(dir, { withFileTypes: true })
    .flatMap((entry) => (entry.isDirectory() ? filesBelow(join(dir, entry.name), `${prefix}${entry.name}/`) : [`${prefix}${entry.name}`]))
    .sort();
}

const errorCode = (res) => {
  try {
    return JSON.parse(res.body.toString("utf8")).error;
  } catch {
    return `(not JSON: ${res.body.toString("utf8").slice(0, 60)})`;
  }
};

async function main() {
  const kind = ensureDist(dist);
  const set = readHeaders();
  const builds = readdirSync(join(dist, "a"));
  if (builds.length !== 1 || !/^[0-9a-f]{16}$/.test(builds[0])) throw new Error(`dist/a must hold exactly one build directory, found: ${builds.join(", ")}`);
  const build = builds[0];
  const buildFiles = filesBelow(join(dist, "a", build));
  const index = readFileSync(join(dist, "index.html"), "utf8");
  check("dist/_headers is the text written from src/headers.json", readFileSync(join(dist, "_headers"), "utf8") === headersFile());
  // What is served below is a dist/ that could be deployed (scripts/check-dist.mjs).
  const inspected = inspectDist(dist);
  check("dist/ passes check-dist", inspected.ok, inspected.problems.join("; "));
  console.log(`smoke: dist/ holds ${kind === "built" ? "a built viewer" : "the placeholder"}, build ${build} (${buildFiles.length} file(s))${inspected.ok ? `: ${describe(inspected)}` : ""}`);

  // ---------- served as https://viewer.example ----------
  let dev = await startDev("https");
  try {
    // The Worker's pages.
    const home = await request(dev, "/");
    equal("GET /: status", home.status, 200);
    equal("GET /: content-type", home.headers.get("content-type"), "text/html; charset=utf-8");
    equal("GET /: cache-control", home.headers.get("cache-control"), "no-store");
    expectHeaderSet("GET /", home.headers, set);
    equal("GET /: the bytes of dist/index.html with the status line", home.body.toString("utf8"), index.replace(STATUS_MARKER, () => "Status: ready"));
    const callback = await request(dev, "/callback?state=AAAAAAAAAAAAAAAAAAAAAA&code=4/0Asmoke-code&iss=https://accounts.google.com");
    equal("GET /callback?…: status", callback.status, 200);
    check("GET /callback?…: the same bytes as /", callback.body.equals(home.body));
    expectHeaderSet("GET /callback", callback.headers, set);
    equal("GET /callback: cache-control", callback.headers.get("cache-control"), "no-store");
    const privacy = await request(dev, "/privacy");
    equal("GET /privacy: status", privacy.status, 200);
    equal("GET /privacy: content-type", privacy.headers.get("content-type"), "text/html; charset=utf-8");
    let runs = await settled(dev, 3);
    equal("the Worker ran for /, /callback and /privacy", runs, 3);

    // The asset layer: /a/<build>/* and /sw.js, with the _headers rules, without running the Worker.
    for (const path of ["sw.js", ...buildFiles.map((file) => `a/${build}/${file}`)]) {
      const res = await request(dev, `/${path}`);
      equal(`GET /${path}: status`, res.status, 200);
      check(`GET /${path}: the file's bytes`, res.body.equals(readFileSync(join(dist, path))));
      expectHeaderSet(`GET /${path}`, res.headers, set);
      equal(`GET /${path}: cache-control`, res.headers.get("cache-control"), "public, max-age=0, must-revalidate");
      const etag = res.headers.get("etag");
      check(`GET /${path}: an ETag`, typeof etag === "string" && etag !== "");
      const again = await request(dev, `/${path}`, { headers: { "if-none-match": etag ?? "" } });
      equal(`GET /${path} with If-None-Match: status`, again.status, 304);
    }
    equal("GET /sw.js: content-type", (await request(dev, "/sw.js")).headers.get("content-type"), "text/javascript; charset=utf-8");
    for (const path of [`/a/${build}/nope.js`, "/a/nope", "/a/", `/a/${build}/`]) {
      const res = await request(dev, path);
      equal(`GET ${path}: status`, res.status, 404);
      equal(`GET ${path}: an empty body (the asset layer's 404, not the Worker's JSON)`, res.body.length, 0);
    }
    equal(`POST /a/${build}/manifest.json: status (the asset layer's)`, (await request(dev, `/a/${build}/manifest.json`, { method: "POST" })).status, 405);
    // One request to the Worker closes the series: its log line is the only new one.
    await request(dev, "/privacy");
    runs = await settled(dev, 4);
    equal("the Worker did not run for any /a/* or /sw.js request", runs, 4);

    // Everything else reaches the Worker — the other files of the directory included: they are not served as files.
    for (const path of ["/index.html", "/_headers", "/a", `/A/${build}/manifest.json`, "/sw.js/", "/SW.js", "/v/AAAAAAAAAAAAAAAAAAAAAA", "/favicon.ico", "/login", "/token"]) {
      const res = await request(dev, path);
      equal(`GET ${path}: status`, res.status, 404);
      equal(`GET ${path}: the Worker's JSON 404`, errorCode(res), "not_found");
      equal(`GET ${path}: cache-control`, res.headers.get("cache-control"), "no-store");
    }

    // The script of a Service Worker that is not the viewer's — a registration that whoever served this origin before
    // left in a browser, asking for its update: the Worker's answer tells the browser to drop this site's data
    // (docs/SECURITY.md, "After a change of hands"). The asset layer says nothing of the kind: `/sw.js` is the viewer's own, and
    // a script someone planted under /a/ is out of this switch's reach.
    const asScript = { "service-worker": "script", "sec-fetch-dest": "serviceworker", "sec-fetch-site": "same-origin" };
    for (const path of ["/planted-sw.js", "/v/sw.js", "/SW.js"]) {
      const res = await request(dev, path, { headers: asScript });
      equal(`GET ${path} as a Service Worker's script: status`, res.status, 404);
      equal(`GET ${path} as a Service Worker's script: clear-site-data`, res.headers.get("clear-site-data"), '"cache", "storage"');
    }
    equal("GET /planted-sw.js as an ordinary request: no clear-site-data", (await request(dev, "/planted-sw.js")).headers.get("clear-site-data"), null);
    const own = await request(dev, "/sw.js", { headers: asScript });
    equal("GET /sw.js as a Service Worker's script: status", own.status, 200);
    equal("GET /sw.js as a Service Worker's script: no clear-site-data", own.headers.get("clear-site-data"), null);
    const planted = await request(dev, `/a/${build}/planted-sw.js`, { headers: asScript });
    equal(`GET /a/${build}/planted-sw.js as a Service Worker's script: the asset layer's 404`, `${planted.status} ${planted.body.length}`, "404 0");
    equal(`GET /a/${build}/planted-sw.js as a Service Worker's script: no clear-site-data (the Worker does not run there)`, planted.headers.get("clear-site-data"), null);

    // The viewer's sign-in routes (none of these makes the Worker ask Google).
    const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const started = await post(dev, "/web/start", { challenge, state: "AAAAAAAAAAAAAAAAAAAAAA" });
    equal("POST /web/start: status", started.status, 200);
    const url = new URL(JSON.parse(started.body.toString("utf8")).authorization_url);
    equal("POST /web/start: Google's authorization endpoint", url.origin + url.pathname, "https://accounts.google.com/o/oauth2/v2/auth");
    equal("POST /web/start: redirect_uri", url.searchParams.get("redirect_uri"), `https://${HOST}/callback`);
    equal("POST /web/start: client_id", url.searchParams.get("client_id"), VARS.GOOGLE_LEGACY_CLIENT_ID);
    equal("POST /web/start: code_challenge", url.searchParams.get("code_challenge"), challenge);
    const noSession = await post(dev, "/web/refresh", {});
    equal("POST /web/refresh without a cookie: status", noSession.status, 401);
    equal("POST /web/refresh without a cookie: error", errorCode(noSession), "no_session");
    const badCookie = await post(dev, "/web/refresh", {}, { cookie: "__Host-gclone-web=AAAA" });
    equal("POST /web/refresh with a cookie that does not open: status", badCookie.status, 401);
    equal("POST /web/refresh with a cookie that does not open: the cookie is cleared", badCookie.headers.get("set-cookie"), CLEAR_COOKIE);
    const foreign = await post(dev, "/web/refresh", {}, { origin: "https://evil.example" });
    equal("POST /web/refresh from another origin: status", foreign.status, 403);
    equal("POST /web/refresh from another origin: error", errorCode(foreign), "cross_origin");
    const malformed = await post(dev, "/web/token", { code: "x y", verifier: "short" });
    equal("POST /web/token, malformed: status", malformed.status, 400);
    const out = await post(dev, "/web/logout", {});
    equal("POST /web/logout: status", out.status, 200);
    equal("POST /web/logout: body", out.body.toString("utf8"), "{}");
    equal("POST /web/logout: set-cookie", out.headers.get("set-cookie"), CLEAR_COOKIE);
    equal("POST /web/logout: clear-site-data", out.headers.get("clear-site-data"), '"storage"');
    for (const path of ["/web/start", "/web/token", "/web/refresh", "/web/logout", "/device/start", "/device/poll", "/refresh"]) {
      const res = await request(dev, path);
      equal(`GET ${path}: status`, res.status, 405);
      equal(`GET ${path}: allow`, res.headers.get("allow"), "POST");
      check(`GET ${path}: no CORS header`, ![...res.headers.keys()].some((name) => name.startsWith("access-control-")));
    }
    // The device routes, as far as they go without Google.
    const wrongType = await request(dev, "/device/start", { method: "POST", headers: { "content-type": "text/plain" }, body: "{}" });
    equal("POST /device/start, text/plain: status", wrongType.status, 415);
    const legacy = await devicePost(dev, "/refresh", { refresh_token: "1//0smoke-refresh-token-xyz" });
    equal("POST /refresh without \"client\": status", legacy.status, 400);
    equal("POST /refresh without \"client\": error", errorCode(legacy), "invalid_grant");
    equal("POST /refresh, malformed token: error", errorCode(await devicePost(dev, "/refresh", { refresh_token: "x", client: "device" })), "invalid_request");
    // A web page is not a device: a request that says where a page sent it from is refused, unread.
    const fromPage = await post(dev, "/refresh", { refresh_token: "1//0smoke-refresh-token-xyz", client: "device" }, { origin: "https://evil.example" });
    equal("POST /refresh from a web page: status", fromPage.status, 403);
    equal("POST /refresh from a web page: error", errorCode(fromPage), "cross_origin");

    // The log: one line per Worker request, with route, status and error code — and nothing else.
    await settled(dev, 4 + 10 + 4 + 7 + 7 + 3);
    const lines = dev.logLines();
    check("every log line has only route, status and error", lines.every((line) => Object.keys(line).every((key) => ["route", "status", "error"].includes(key))));
    check("no log line carries a query string or a code", !JSON.stringify(lines).includes("smoke-code") && !JSON.stringify(lines).includes("?"));
    check("the callback is logged by its route", lines.some((line) => line.route === "/callback" && line.status === 200));

    // The comparison the owner runs against the deployed host (scripts/verify-deployed.mjs), here against the Worker
    // and the asset layer on this machine: every file of dist/ is served as it is, with the header set.
    if (inspected.ok) {
      const verified = await verifyDeployed(dev.origin, { path: dist, files: inspected.files });
      check("verify-deployed: the host serves dist/ byte for byte, with its headers", verified.differences.length === 0, verified.differences.join("; "));
      equal("verify-deployed: the status line it found", verified.status, "Status: ready");
      equal("verify-deployed: answers compared", verified.checked, 2 + 1 + buildFiles.length);
    }
  } finally {
    await dev.stop();
  }

  // ---------- served as http://viewer.example: nothing is served over plain http ----------
  dev = await startDev("http");
  try {
    for (const path of ["/", "/callback?code=4/0Asmoke-code&state=y", "/privacy", "/nowhere?x=1"]) {
      const res = await request(dev, path);
      equal(`http GET ${path}: status`, res.status, 308);
      equal(`http GET ${path}: no body`, res.body.length, 0);
      // wrangler dev rewrites the upstream host in a Location header to its own address; path and query are the Worker's.
      const location = res.headers.get("location") ?? "";
      check(`http GET ${path}: Location keeps path and query`, location.endsWith(path), location);
    }
    equal("http HEAD /: status", (await request(dev, "/", { method: "HEAD" })).status, 308);
    for (const path of ["/web/refresh", "/web/logout", "/device/start", "/refresh"]) {
      const res = await post(dev, path, {}, { cookie: "__Host-gclone-web=AAAA" });
      equal(`http POST ${path}: status`, res.status, 400);
      equal(`http POST ${path}: error`, errorCode(res), "https_required");
      equal(`http POST ${path}: no cookie is set or cleared`, res.headers.get("set-cookie"), null);
    }
  } finally {
    await dev.stop();
  }

  if (failures.length > 0) {
    console.error(`smoke: ${failures.length} of ${checks} checks failed:`);
    for (const failure of failures) console.error(`  - ${failure}`);
    process.exit(1);
  }
  console.log(`smoke: ok (${checks} checks: the Worker's pages and JSON routes, the asset layer's files and headers, the https rule)`);
}

main().catch((e) => {
  console.error(`smoke: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
