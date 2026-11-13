// Asserts the security-relevant keys of wrangler.jsonc (README.md, "Configuration"). Runs before the tests on every `npm test`.
// Plain Node, no dependency. Usage: node scripts/check-config.mjs [path/to/wrangler.jsonc]

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// The file is checked against an ALLOWLIST: a key that is not named here is refused, whatever it is. A list of
// forbidden keys would have to know every binding type Cloudflare has or will have (`unsafe.bindings` alone can attach
// any of them), and it is the unknown key that gives the Worker storage, another service to talk to, or a second
// place where requests end up.
const TOP_LEVEL = ["$schema", "name", "main", "compatibility_date", "compatibility_flags", "workers_dev", "preview_urls", "routes", "observability", "ratelimits", "assets"];
const OBSERVABILITY = {
  "": ["enabled", "head_sampling_rate", "redact_query_string", "logs", "traces"],
  logs: ["enabled", "head_sampling_rate", "invocation_logs"],
  traces: ["enabled"],
};
const ROUTE = ["pattern", "custom_domain", "zone_id", "zone_name"];
const RATE_LIMIT = ["name", "namespace_id", "simple"];
// The module the runtime loads: it exports the handler and nothing else.
const MAIN = "src/entry.ts";
// The hosted viewer's static files: read-only, uploaded with the Worker, changed only by a deploy. Not storage. The
// whole object is fixed, key by key and value by value:
//   - `/a/*` and `/sw.js` are answered by the asset layer and never run the Worker (they cost no Worker request and
//     meet no rate limit); every other path runs the Worker first, which alone decides what it means — `/index.html`,
//     `/_headers` and anything else in the directory are not reachable as files;
//   - no HTML path rewriting and no single-page fallback: the asset layer does no routing of its own.
export const ASSETS = {
  directory: "./dist",
  binding: "ASSETS",
  run_worker_first: ["/*", "!/a/*", "!/sw.js"],
  html_handling: "none",
  not_found_handling: "none",
};

// Why the keys someone is most likely to add are refused. (Device codes and tokens travel in POST bodies. One URL does
// carry a secret: Google's redirect to /callback has the authorization code in its query — single-use, and useless
// without the verifier in the browser tab — which is what the query-string rule is for. Nothing of a request is kept
// beyond the Worker's own log line.) A key that is neither allowed nor listed here gets the general reason.
const FORBIDDEN = {
  vars: "ALLOWED_EMAILS must be a secret only: a var of that name blocks `wrangler secret put` and is reset by every deploy",
  env: "wrangler environments are not used: an environment does not inherit bindings, so `wrangler deploy --env <name>` would deploy a Worker without the rate limiter",
  unsafe: "`unsafe.bindings` can attach a binding of any type, storage included",
  kv_namespaces: "the Worker has no storage",
  d1_databases: "the Worker has no storage",
  r2_buckets: "the Worker has no storage",
  durable_objects: "the Worker has no storage",
  migrations: "the Worker has no Durable Objects",
  queues: "the Worker has no storage",
  hyperdrive: "the Worker has no storage",
  vectorize: "the Worker has no storage",
  analytics_engine_datasets: "the Worker has no storage",
  secrets_store_secrets: "the Worker's secrets are plain Worker secrets",
  pipelines: "the Worker has no storage",
  workflows: "the Worker has no storage",
  services: "the Worker has no service binding",
  dispatch_namespaces: "the Worker has no service binding",
  triggers: "the Worker has no cron trigger",
  tail_consumers: "a tail consumer receives every request, out of this Worker's control",
  streaming_tail_consumers: "a tail consumer receives every request, out of this Worker's control",
  logpush: "Logpush exports every request's metadata out of the account",
  destinations: "an observability destination exports logs or traces, with the request metadata attached to them, out of the account",
};
const NOT_ALLOWED = "only the keys the Worker needs are allowed; RATE_LIMIT and the read-only ASSETS (the viewer's static files) are its only bindings";

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Every problem found in a parsed wrangler configuration; empty = fine. */
export function problems(config) {
  const found = [];
  if (!isObject(config)) return ["the configuration is not a JSON object"];

  /** Reports every key of `node` that is not in `allowed`. */
  const only = (node, allowed, path) => {
    if (!isObject(node)) return;
    for (const key of Object.keys(node)) {
      if (allowed.includes(key)) continue;
      const here = path === "" ? key : `${path}.${key}`;
      found.push(`"${here}" must not be set: ${Object.hasOwn(FORBIDDEN, key) ? FORBIDDEN[key] : NOT_ALLOWED}`);
    }
  };
  only(config, TOP_LEVEL, "");
  only(config.observability, OBSERVABILITY[""], "observability");
  only(config.observability?.logs, OBSERVABILITY.logs, "observability.logs");
  only(config.observability?.traces, OBSERVABILITY.traces, "observability.traces");

  if (config.routes !== undefined) {
    if (!Array.isArray(config.routes)) found.push('"routes" must be a list');
    else config.routes.forEach((route, i) => (isObject(route) ? only(route, ROUTE, `routes[${i}]`) : null));
  }

  if (config.observability?.logs?.invocation_logs !== false) {
    found.push('"observability.logs.invocation_logs" must be false: invocation logs store every request with its full URL and headers');
  }
  // Cloudflare attaches the request that triggered an invocation to every stored log event and to every trace,
  // not only to invocation logs: the Worker's own one-line logs would carry the full URL as metadata.
  if (config.observability?.redact_query_string !== true) {
    found.push('"observability.redact_query_string" must be true: the URL attached to every stored log event would keep its query string');
  }
  if (config.observability?.traces?.enabled !== false) {
    found.push('"observability.traces.enabled" must be false: traces record every request URL');
  }
  if (config.preview_urls !== false) {
    found.push('"preview_urls" must be false: versioned preview hosts would keep old versions of the Worker reachable, outside any zone rule');
  }

  if (config.main !== MAIN) {
    found.push(`"main" must be ${JSON.stringify(MAIN)}: the module that exports the handler and nothing else`);
  }

  // Exactly the object above: nothing missing, nothing added, nothing changed.
  if (!isObject(config.assets)) {
    found.push(`"assets" must be ${JSON.stringify(ASSETS)}`);
  } else {
    only(config.assets, Object.keys(ASSETS), "assets");
    for (const [key, value] of Object.entries(ASSETS)) {
      if (JSON.stringify(config.assets[key]) !== JSON.stringify(value)) found.push(`"assets.${key}" must be ${JSON.stringify(value)}`);
    }
  }

  const limits = config.ratelimits;
  if (!Array.isArray(limits) || limits.length !== 1) {
    found.push('"ratelimits" must hold exactly one entry, the RATE_LIMIT binding');
  } else {
    const [entry] = limits;
    only(entry, RATE_LIMIT, "ratelimits[0]");
    if (entry?.name !== "RATE_LIMIT") found.push('the "ratelimits" entry must be named RATE_LIMIT');
    if (typeof entry?.namespace_id !== "string" || !/^[0-9]+$/.test(entry.namespace_id)) {
      found.push('the RATE_LIMIT entry needs a "namespace_id" that is an integer in a string');
    }
    if (entry?.simple?.limit !== 30 || entry?.simple?.period !== 60 || Object.keys(entry.simple).length !== 2) {
      found.push('the RATE_LIMIT entry must be "simple": { "limit": 30, "period": 60 }');
    }
  }
  return found;
}

/** wrangler.jsonc as this project writes it: JSON plus whole-line `//` comments, lines ending in a line feed.
 *
 *  What this reader drops as a comment must be what wrangler drops, or a key could sit where only wrangler sees it.
 *  wrangler's reader ends a `//` comment at a line feed, at a carriage return, and at U+2028 and U+2029; a line here
 *  ends at a line feed only. So a file with a carriage return that no line feed follows, or with one of the two
 *  separators, is refused outright: `// note\r"kv_namespaces": […]` would be one comment line to this check and a
 *  binding to wrangler — and most diff views draw it as one line too. */
export function parseJsonc(text) {
  const stray = /\r(?!\n)|[\u2028\u2029]/.exec(text);
  if (stray !== null) {
    const code = stray[0].codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
    const line = text.slice(0, stray.index).split("\n").length;
    throw new Error(
      `line ${line} holds U+${code} (${code === "000D" ? "a carriage return without a line feed" : "a Unicode line separator"}): wrangler ends a // comment there and this check does not, so the file must use plain line feeds`,
    );
  }
  return JSON.parse(
    text
      .split("\n")
      .filter((line) => !/^\s*\/\//.test(line))
      .join("\n"),
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const file = process.argv[2] ?? fileURLToPath(new URL("../wrangler.jsonc", import.meta.url));
  let found;
  try {
    found = problems(parseJsonc(readFileSync(file, "utf8")));
  } catch (e) {
    found = [`cannot read it: ${e instanceof Error ? e.message : e}`];
  }
  if (found.length > 0) {
    console.error(`check-config: ${file} breaks a security requirement of the auth Worker:`);
    for (const p of found) console.error(`  - ${p}`);
    process.exit(1);
  }
  console.log(
    "check-config: wrangler.jsonc ok (only allowed keys; no URL query string in logs or traces, no export, no vars, no environments, RATE_LIMIT 30/60 s and the read-only ASSETS as the only bindings, the fixed asset routing, no preview hosts)",
  );
}
