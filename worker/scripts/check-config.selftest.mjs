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
  reports(changed((c) => (c.env = { staging: { observability: { redact_query_string: false } } })), '"env.staging.observability.redact_query_string" must be true');
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
  reports(changed((c) => (c.env = { staging: { observability: { traces: { enabled: true } } } })), '"env.staging.observability.traces.enabled" must be false');
});

test("nothing may export logs or traces", () => {
  reports(changed((c) => (c.observability.logs.destinations = ["otel"])), '"observability.logs.destinations" must not be set');
  reports(changed((c) => (c.observability.traces.destinations = [])), '"observability.traces.destinations" must not be set');
  reports(changed((c) => (c.tail_consumers = [{ service: "x" }])), "tail_consumers");
  reports(changed((c) => (c.streaming_tail_consumers = [{ service: "x" }])), "streaming_tail_consumers");
  reports(changed((c) => (c.logpush = true)), "logpush");
  assert.deepEqual(
    changed((c) => (c.logpush = false)),
    [],
  );
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
  reports(changed((c) => c.ratelimits.push({ ...c.ratelimits[0], name: "GLOBAL" })), "exactly one entry");
  assert.deepEqual(problems(null), ["the configuration is not a JSON object"]);
});
