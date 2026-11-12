// Tests of check-config.mjs itself (plain Node, `node --test`; run by `npm test` between the check and Vitest —
// the file name avoids `.test.` so that Vitest, which runs inside the Workers runtime, does not pick it up):
// the shipped wrangler.jsonc passes, and every weakening of a security-relevant key is reported.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { parseJsonc, problems } from "./check-config.mjs";

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

test("no vars, no storage, and exactly the one rate-limit binding", () => {
  reports(changed((c) => (c.vars = { ALLOWED_EMAILS: "" })), '"vars" must not be set');
  reports(changed((c) => (c.kv_namespaces = [])), "kv_namespaces");
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
