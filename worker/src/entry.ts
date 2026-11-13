// The module the Workers runtime loads: nothing but the handler. (With static assets configured, wrangler refuses a
// main module that has other named exports; the constants and `handle` stay in index.ts, which the tests import.)

import { defaultDeps, handle, type Env } from "./index";

export default { fetch: (request: Request, env: Env) => handle(request, env, defaultDeps) } satisfies ExportedHandler<Env>;
