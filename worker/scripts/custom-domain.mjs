// Puts the Worker on a host name of your own (README.md, "Custom domain and rate-limiting rule"): rewrites the two
// keys of wrangler.jsonc that decide where the Worker is served — `"workers_dev": false` and one `"routes"` entry
// with `"custom_domain": true` — and nothing else. Comments stay. Running it again with the same host changes
// nothing; with another host it replaces the entry. Nothing is deployed and no network is used: run
// `npx wrangler deploy` afterwards. setup.sh calls this when you choose your own host name.
//
// Plain Node, no dependency. Usage: node scripts/custom-domain.mjs HOST [path/to/wrangler.jsonc]

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseJsonc, problems } from "./check-config.mjs";

/** `null` when `host` is a plain lower-case DNS host name of a domain of one's own; otherwise what is wrong with it. */
export function hostProblem(host) {
  if (typeof host !== "string" || host === "") return "no host name given";
  if (/[/:@?#\s]/.test(host)) return "give the bare host name, without https://, a port or a path (for example auth.example.org)";
  if (host !== host.toLowerCase()) return "write the host name in lower case";
  if (host.length > 253) return "the host name is too long";
  const labels = host.split(".");
  if (labels.length < 2) return "a host name on your own domain has at least two labels (for example auth.example.org)";
  if (!labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return "that is not a DNS host name";
  if (/^[0-9]+$/.test(labels.at(-1))) return "an IP address cannot be a custom domain";
  if (host === "workers.dev" || host.endsWith(".workers.dev")) {
    return "a workers.dev host is not a custom domain: it is what the Worker has without one";
  }
  return null;
}

/**
 * The text of wrangler.jsonc with the Worker served from `host` only. Throws when the file is not the shipped
 * shape (one top-level `"workers_dev"` line and one `"preview_urls"` line) or when the result would break a
 * security requirement of check-config.mjs.
 */
export function withCustomDomain(text, host) {
  const wrong = hostProblem(host);
  if (wrong !== null) throw new Error(wrong);
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.split(/\r?\n/);
  const top = (key) => {
    const found = lines.flatMap((line, i) => (new RegExp(`^  "${key}"\\s*:`).test(line) ? [i] : []));
    return found;
  };
  const workersDev = top("workers_dev");
  if (workersDev.length !== 1) throw new Error('expected exactly one top-level "workers_dev" line in wrangler.jsonc');
  lines[workersDev[0]] = '  "workers_dev": false,';

  const entry = `  "routes": [{ "pattern": ${JSON.stringify(host)}, "custom_domain": true }],`;
  const routes = top("routes");
  if (routes.length > 1) throw new Error('expected at most one top-level "routes" line in wrangler.jsonc');
  if (routes.length === 1) {
    if (!/\]\s*,?\s*$/.test(lines[routes[0]])) throw new Error('the "routes" entry spans several lines; edit it by hand');
    lines[routes[0]] = entry;
  } else {
    const preview = top("preview_urls");
    if (preview.length !== 1) throw new Error('expected exactly one top-level "preview_urls" line in wrangler.jsonc');
    lines.splice(preview[0] + 1, 0, entry);
  }

  const out = lines.join(eol);
  const config = parseJsonc(out);
  const found = problems(config);
  if (found.length > 0) throw new Error(`the result would break a security requirement: ${found.join("; ")}`);
  const [route, ...more] = config.routes ?? [];
  if (config.workers_dev !== false || more.length > 0 || route?.pattern !== host || route?.custom_domain !== true) {
    throw new Error("the edit did not produce the expected configuration; edit wrangler.jsonc by hand (README.md)");
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const host = process.argv[2];
  const file = process.argv[3] ?? fileURLToPath(new URL("../wrangler.jsonc", import.meta.url));
  try {
    const before = readFileSync(file, "utf8");
    const after = withCustomDomain(before, host);
    if (after === before) {
      console.log(`custom-domain: ${file} already serves the Worker from ${host} only`);
    } else {
      writeFileSync(file, after);
      console.log(`custom-domain: ${file} now serves the Worker from ${host} only (workers.dev host off). Keep this change.`);
    }
  } catch (e) {
    console.error(`custom-domain: ${e instanceof Error ? e.message : e}`);
    process.exit(1);
  }
}
