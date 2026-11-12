// Asserts the security-relevant keys of wrangler.jsonc (README.md, "Configuration"). Runs before the tests on every `npm test`.
// Plain Node, no dependency. Usage: node scripts/check-config.mjs [path/to/wrangler.jsonc]

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Bindings and settings that would give the Worker storage, a schedule, another Worker to talk to,
// or a second place where request URLs end up.
const FORBIDDEN = {
  vars: "ALLOWED_EMAILS must be a secret only: a var of that name blocks `wrangler secret put` and is reset by every deploy",
  kv_namespaces: "the Worker has no storage",
  d1_databases: "the Worker has no storage",
  r2_buckets: "the Worker has no storage",
  durable_objects: "the Worker has no storage",
  migrations: "the Worker has no Durable Objects",
  queues: "the Worker has no storage",
  hyperdrive: "the Worker has no storage",
  vectorize: "the Worker has no storage",
  analytics_engine_datasets: "the Worker has no storage",
  secrets_store_secrets: "the four secrets are plain Worker secrets",
  pipelines: "the Worker has no storage",
  workflows: "the Worker has no storage",
  assets: "the Worker serves no files",
  services: "the Worker has no service binding",
  dispatch_namespaces: "the Worker has no service binding",
  triggers: "the Worker has no cron trigger",
  tail_consumers: "a tail consumer receives every request URL, /callback?code=… included",
  streaming_tail_consumers: "a tail consumer receives every request URL, /callback?code=… included",
  logpush: "Logpush exports every request URL, /callback?code=… included",
  destinations: "an observability destination exports logs or traces, with the request metadata attached to them, out of the account",
};

/** Every problem found in a parsed wrangler configuration; empty = fine. */
export function problems(config) {
  const found = [];
  if (config === null || typeof config !== "object" || Array.isArray(config)) return ["the configuration is not a JSON object"];

  // Environments (`env.<name>`) deploy with their own copy of these keys, so the walk covers the whole tree.
  const walk = (node, path) => {
    if (node === null || typeof node !== "object") return;
    for (const [key, value] of Object.entries(node)) {
      const here = path === "" ? key : `${path}.${key}`;
      if (Object.hasOwn(FORBIDDEN, key) && !(key === "logpush" && value === false)) found.push(`"${here}" must not be set: ${FORBIDDEN[key]}`);
      if (key === "invocation_logs" && value !== false) found.push(`"${here}" must be false`);
      if (key === "redact_query_string" && value !== true) found.push(`"${here}" must be true`);
      if (key === "preview_urls" && value !== false) found.push(`"${here}" must be false`);
      if (key === "traces" && value?.enabled !== false) found.push(`"${here}.enabled" must be false`);
      walk(value, here);
    }
  };
  walk(config, "");

  if (config.observability?.logs?.invocation_logs !== false) {
    found.push('"observability.logs.invocation_logs" must be false: invocation logs store every full URL, /callback?code=… included');
  }
  // Cloudflare attaches the request that triggered an invocation to every stored log event and to every trace,
  // not only to invocation logs: the Worker's own one-line logs would carry /callback?code=… as metadata.
  if (config.observability?.redact_query_string !== true) {
    found.push('"observability.redact_query_string" must be true: the URL attached to every stored log event would keep its query string, /callback?code=… included');
  }
  if (config.observability?.traces?.enabled !== false) {
    found.push('"observability.traces.enabled" must be false: traces record every request URL');
  }
  if (config.preview_urls !== false) {
    found.push('"preview_urls" must be false: versioned preview hosts would keep old versions of the Worker reachable, outside any zone rule');
  }

  const limits = config.ratelimits;
  if (!Array.isArray(limits) || limits.length !== 1) {
    found.push('"ratelimits" must hold exactly one entry, the RATE_LIMIT binding');
  } else {
    const [entry] = limits;
    if (entry?.name !== "RATE_LIMIT") found.push('the "ratelimits" entry must be named RATE_LIMIT');
    if (typeof entry?.namespace_id !== "string" || !/^[0-9]+$/.test(entry.namespace_id)) {
      found.push('the RATE_LIMIT entry needs a "namespace_id" that is an integer in a string');
    }
    if (entry?.simple?.limit !== 30 || entry?.simple?.period !== 60) {
      found.push('the RATE_LIMIT entry must be "simple": { "limit": 30, "period": 60 }');
    }
  }
  return found;
}

/** wrangler.jsonc as this project writes it: JSON plus whole-line `//` comments. */
export function parseJsonc(text) {
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
  console.log("check-config: wrangler.jsonc ok (no URL query string in logs or traces, no export, no vars, RATE_LIMIT 30/60 s, no storage, no preview hosts)");
}
