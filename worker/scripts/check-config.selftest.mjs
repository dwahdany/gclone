// Tests of check-config.mjs itself (plain Node, `node --test`; run by `npm test` between the check and Vitest —
// the file name avoids `.test.` so that Vitest, which runs inside the Workers runtime, does not pick it up):
// the shipped wrangler.jsonc passes, and every weakening of a security-relevant key is reported.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ASSETS, parseJsonc, problems } from "./check-config.mjs";

const shipped = () => parseJsonc(readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"));

/** The shipped configuration with one change applied. */
function changed(change) {
  const config = shipped();
  change(config);
  return problems(config);
}

function reports(found, part) {
  assert.ok(
    found.some((p) => p.includes(part)),
    `expected a problem mentioning ${JSON.stringify(part)}, got ${JSON.stringify(found)}`,
  );
}

test("the shipped wrangler.jsonc has no problem", () => {
  assert.deepEqual(problems(shipped()), []);
});

test("the shipped file pins every logging switch explicitly", () => {
  const { observability, preview_urls } = shipped();
  assert.deepEqual(observability, { enabled: true, redact_query_string: true, logs: { invocation_logs: false }, traces: { enabled: false } });
  assert.equal(preview_urls, false);
});

test("the configuration as it was shipped before — invocation logs off and nothing else — is refused", () => {
  const found = changed((c) => {
    c.observability = { enabled: true, logs: { invocation_logs: false } };
    delete c.preview_urls;
  });
  reports(found, '"observability.redact_query_string" must be true');
  reports(found, '"observability.traces.enabled" must be false');
  reports(found, '"preview_urls" must be false');
});

test("query strings must be redacted in logs and traces", () => {
  reports(changed((c) => delete c.observability.redact_query_string), "redact_query_string");
  reports(changed((c) => (c.observability.redact_query_string = false)), "redact_query_string");
});

test("invocation logs must be off", () => {
  reports(changed((c) => delete c.observability.logs), "invocation_logs");
  reports(changed((c) => (c.observability.logs.invocation_logs = true)), "invocation_logs");
  reports(changed((c) => delete c.observability), "invocation_logs");
});

test("traces must be pinned off", () => {
  reports(changed((c) => delete c.observability.traces), "traces");
  reports(changed((c) => (c.observability.traces = {})), "traces");
  reports(changed((c) => (c.observability.traces.enabled = true)), "traces");
});

test("nothing may export logs or traces", () => {
  reports(changed((c) => (c.observability.logs.destinations = ["otel"])), '"observability.logs.destinations" must not be set');
  reports(changed((c) => (c.observability.traces.destinations = [])), '"observability.traces.destinations" must not be set');
  reports(changed((c) => (c.tail_consumers = [{ service: "x" }])), "tail_consumers");
  reports(changed((c) => (c.streaming_tail_consumers = [{ service: "x" }])), "streaming_tail_consumers");
  reports(changed((c) => (c.logpush = true)), "logpush");
  // the key itself is outside the allowlist: also with the harmless value
  reports(changed((c) => (c.logpush = false)), '"logpush" must not be set');
});

test("no preview hosts", () => {
  reports(changed((c) => delete c.preview_urls), "preview_urls");
  reports(changed((c) => (c.preview_urls = true)), "preview_urls");
});

test("a custom-domain route is allowed", () => {
  assert.deepEqual(
    changed((c) => {
      c.workers_dev = false;
      c.routes = [{ pattern: "auth.example.org", custom_domain: true }];
    }),
    [],
  );
});

test("the static assets are exactly the viewer's: the fixed object, key by key and value by value", () => {
  assert.deepEqual(shipped().assets, {
    directory: "./dist",
    binding: "ASSETS",
    run_worker_first: ["/*", "!/a/*", "!/sw.js"],
    html_handling: "none",
    not_found_handling: "none",
  });
  assert.deepEqual(shipped().assets, ASSETS);
  // missing, or not an object
  reports(changed((c) => delete c.assets), '"assets" must be');
  reports(changed((c) => (c.assets = "./dist")), '"assets" must be');
  reports(changed((c) => (c.assets = [])), '"assets" must be');
  // every key is needed …
  for (const key of Object.keys(ASSETS)) {
    const found = changed((c) => delete c.assets[key]);
    reports(found, `"assets.${key}" must be`);
    assert.equal(found.length, 1, key);
  }
  // … with exactly its value: another directory (a folder with other files in it), another binding name
  reports(changed((c) => (c.assets.directory = ".")), '"assets.directory" must be "./dist"');
  reports(changed((c) => (c.assets.directory = "dist")), '"assets.directory" must be "./dist"');
  reports(changed((c) => (c.assets.binding = "FILES")), '"assets.binding" must be "ASSETS"');
  // the Worker must run first for everything but /a/* and /sw.js: the asset layer would otherwise hand out
  // /index.html without the Worker's headers and status line, /_headers, and whatever else the directory holds
  for (const value of [false, undefined, ["/*"], ["/*", "!/a/*"], ["/*", "!/sw.js", "!/a/*"], ["/*", "!/a/*", "!/sw.js", "!/index.html"], ["/web/*", "/device/*"], [], "/*"]) {
    reports(changed((c) => (c.assets.run_worker_first = value)), '"assets.run_worker_first" must be ["/*","!/a/*","!/sw.js"]');
  }
  // … and for nothing less: with `true` every static file would cost a Worker request and meet the rate limit
  reports(changed((c) => (c.assets.run_worker_first = true)), '"assets.run_worker_first" must be');
  // no routing by the asset layer: no /index.html for /, no .html guessing, no single-page fallback, no 404 page
  for (const value of ["auto-trailing-slash", "force-trailing-slash", "drop-trailing-slash", undefined]) {
    reports(changed((c) => (c.assets.html_handling = value)), '"assets.html_handling" must be "none"');
  }
  for (const value of ["single-page-application", "404-page", undefined]) {
    reports(changed((c) => (c.assets.not_found_handling = value)), '"assets.not_found_handling" must be "none"');
  }
  // nothing added
  reports(changed((c) => (c.assets.serve_directly = true)), '"assets.serve_directly" must not be set');
  reports(changed((c) => (c.assets.experimental_serve_directly = false)), '"assets.experimental_serve_directly" must not be set');
});

test('"main" is src/entry.ts, the module that exports the handler and nothing else', () => {
  assert.equal(shipped().main, "src/entry.ts");
  reports(changed((c) => (c.main = "src/index.ts")), '"main" must be "src/entry.ts"');
  reports(changed((c) => (c.main = "./src/entry.ts")), '"main" must be "src/entry.ts"');
  reports(changed((c) => delete c.main), '"main" must be "src/entry.ts"');
});

test("no vars, no storage, and exactly the one rate-limit binding", () => {
  reports(changed((c) => (c.vars = { ALLOWED_EMAILS: "" })), '"vars" must not be set');
  reports(changed((c) => (c.kv_namespaces = [])), "kv_namespaces");
  // every kind of storage, and everything else that was refused before the viewer's files came, is still refused
  for (const key of ["kv_namespaces", "d1_databases", "r2_buckets", "durable_objects", "migrations", "queues", "hyperdrive", "vectorize", "analytics_engine_datasets", "pipelines", "workflows", "secrets_store_secrets", "services", "dispatch_namespaces", "triggers"]) {
    const found = changed((c) => (c[key] = []));
    reports(found, `"${key}" must not be set`);
    assert.equal(found.length, 1, key);
  }
  // the old Workers Sites key is not the assets binding
  reports(changed((c) => (c.site = { bucket: "./dist" })), '"site" must not be set');
  reports(changed((c) => delete c.ratelimits), "ratelimits");
  reports(changed((c) => (c.ratelimits[0].simple.limit = 3000)), "RATE_LIMIT");
  reports(changed((c) => (c.ratelimits[0].simple.extra = 1)), "RATE_LIMIT");
  reports(changed((c) => (c.ratelimits[0].other = true)), '"ratelimits[0].other" must not be set');
  reports(changed((c) => c.ratelimits.push({ ...c.ratelimits[0], name: "GLOBAL" })), "exactly one entry");
  reports(changed((c) => (c.ratelimits = [])), "exactly one entry");
  assert.deepEqual(problems(null), ["the configuration is not a JSON object"]);
  assert.deepEqual(problems([]), ["the configuration is not a JSON object"]);
});

test("the check is an allowlist: a key it does not know is refused, whatever it is", () => {
  // binding types and settings that a list of forbidden names had missed
  for (const key of ["ai", "browser", "send_email", "containers", "vpc_services", "mtls_certificates", "images", "version_metadata", "wasm_modules", "a_binding_type_of_next_year"]) {
    const found = changed((c) => (c[key] = { binding: "X" }));
    reports(found, `"${key}" must not be set`);
    assert.equal(found.length, 1, key);
  }
  // … and the same inside the subtrees that are allowed
  reports(changed((c) => (c.observability.logs.persist = true)), '"observability.logs.persist" must not be set');
  reports(changed((c) => (c.observability.export = {})), '"observability.export" must not be set');
  reports(changed((c) => (c.observability.traces.head_sampling_rate = 1)), '"observability.traces.head_sampling_rate" must not be set');
  reports(changed((c) => (c.routes = [{ pattern: "auth.example.org", custom_domain: true, script: "other" }])), '"routes[0].script" must not be set');
  reports(changed((c) => (c.routes = "auth.example.org")), '"routes" must be a list');
  // what the shipped file may additionally carry
  assert.deepEqual(
    changed((c) => {
      c.compatibility_flags = ["nodejs_compat"];
      c.observability.head_sampling_rate = 1;
      c.observability.logs.enabled = true;
    }),
    [],
  );
});

test("`unsafe` is refused: unsafe.bindings can attach a binding of any type", () => {
  const found = changed((c) => (c.unsafe = { bindings: [{ name: "STORE", type: "kv_namespace", namespace_id: "0123456789abcdef0123456789abcdef" }] }));
  reports(found, '"unsafe" must not be set');
  reports(found, "binding of any type");
  reports(changed((c) => (c.unsafe = {})), '"unsafe" must not be set');
});

test("environments are refused: `wrangler deploy --env` would deploy without the rate limiter", () => {
  // an environment inherits no bindings: one without the limiter, with a weak one, or with storage
  const environments = [
    { production: { ratelimits: [] } },
    { production: {} },
    { production: { ratelimits: [{ name: "RATE_LIMIT", namespace_id: "1001", simple: { limit: 100000, period: 60 } }] } },
    { p: { kv_namespaces: [{ binding: "STORE", id: "x" }] } },
    { p: { vars: { ALLOWED_EMAILS: "" } } },
    { staging: { observability: { redact_query_string: false, traces: { enabled: true } } } },
    // … and one that repeats the shipped configuration exactly: still an environment
    { copy: shipped() },
    {},
  ];
  for (const env of environments) {
    const found = changed((c) => (c.env = env));
    reports(found, '"env" must not be set');
    reports(found, "without the rate limiter");
  }
});

test("a key cannot hide behind a comment: a line break that only wrangler sees is refused, whatever follows it", () => {
  const text = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");
  const lines = text.split("\n");
  // A comment line between two keys of the object, and a key that the allowlist refuses.
  const at = lines.findIndex((line) => line.includes('"name": "gclone-auth"')) + 1;
  assert.ok(at > 0, "the shipped file names the Worker");
  const comment = "  // the name of the Worker";
  const hidden = '  "kv_namespaces": [{ "binding": "STASH", "id": "0123456789abcdef0123456789abcdef" }],';
  const withLines = (...added) => [...lines.slice(0, at), ...added, ...lines.slice(at)].join("\n");
  assert.deepEqual(parseJsonc(withLines(comment)), shipped());
  // The control: on a line of its own the key is seen, and refused by the allowlist.
  const plain = withLines(comment, hidden);
  reports(problems(parseJsonc(plain)), '"kv_namespaces" must not be set');
  // Behind the comment, after a break that ends the comment for wrangler and not for a reader of lines.
  for (const [separator, named] of [
    ["\r", "U+000D"],
    ["\u2028", "U+2028"],
    ["\u2029", "U+2029"],
  ]) {
    const smuggled = withLines(`${comment}${separator}${hidden}`);
    assert.throws(() => parseJsonc(smuggled), (error) => error.message.includes(named) && error.message.includes(`line ${at + 1} `) && error.message.includes("plain line feeds"), named);
    // … wherever it stands: also inside a string, or as the file's last character
    assert.throws(() => parseJsonc(text.replace('"gclone-auth"', `"gclone-auth${separator}"`)), /plain line feeds/, named);
    assert.throws(() => parseJsonc(`${text}${separator}`), /plain line feeds/, named);
  }
  // Windows line ends are line feeds with a carriage return before them: the same lines for both readers.
  assert.deepEqual(parseJsonc(text.replaceAll("\n", "\r\n")), shipped());
  assert.deepEqual(problems(parseJsonc(plain.replaceAll("\n", "\r\n"))), problems(parseJsonc(plain)));
});
