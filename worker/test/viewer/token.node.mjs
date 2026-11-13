// token.js in Node (`node --test`): one request at a time, a token is reused until a minute
// before it runs out, and what the Worker refuses is told apart by its code.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadViewer } from './env.mjs';

const { gclone } = loadViewer();

function worker(answers) {
  const calls = [];
  let clock = 1_800_000_000_000;
  const fetch = async (url, init) => {
    calls.push({ url, init });
    const answer = answers.shift();
    if (!answer) throw new Error('no answer left');
    if (answer.wait) await answer.wait;
    if (answer.network) throw new TypeError('fetch failed');
    return new Response(answer.text ?? JSON.stringify(answer.body), { status: answer.status ?? 200, headers: { 'Content-Type': 'application/json' } });
  };
  const token = gclone.createToken({ fetch, now: () => clock });
  return { token, calls, advance: (ms) => { clock += ms; }, now: () => clock };
}

const grant = (n, seconds = 3599) => ({ body: { access_token: `token-${n}`, expires_in: seconds, scope: 's', email: 'owner@example.com', session_expires_in: 43000 } });

test('get(): one POST to /web/refresh, with the cookie and JSON, and never a token in storage or the address', async () => {
  const w = worker([grant(1)]);
  assert.equal(await w.token.get(false), 'token-1');
  assert.equal(w.calls.length, 1);
  const { url, init } = w.calls[0];
  assert.equal(url, '/web/refresh');
  assert.equal(init.method, 'POST');
  assert.equal(init.headers['Content-Type'], 'application/json');
  assert.equal(init.body, '{}');
  assert.equal(init.credentials, 'same-origin');
  assert.deepEqual(w.token.session(), { email: 'owner@example.com', expires: w.now() + 43000 * 1000 });
});

test('single flight: callers that ask together share one request', async () => {
  let release;
  const w = worker([{ ...grant(1), wait: new Promise((resolve) => { release = resolve; }) }, grant(2)]);
  const asked = [w.token.get(false), w.token.get(false), w.token.get(true), w.token.get(false)];
  release();
  assert.deepEqual(await Promise.all(asked), ['token-1', 'token-1', 'token-1', 'token-1']);
  assert.equal(w.calls.length, 1);
});

test('a token is reused until 60 s before it runs out; force asks again', async () => {
  const w = worker([grant(1, 3600), grant(2, 3600), grant(3, 3600)]);
  await w.token.get(false);
  w.advance(3600 * 1000 - 61 * 1000);
  assert.equal(await w.token.get(false), 'token-1');
  assert.deepEqual(w.token.peek(), { token: 'token-1', exp: w.now() + 61 * 1000 });
  w.advance(2000);
  assert.equal(w.token.peek(), null);
  assert.equal(await w.token.get(false), 'token-2');
  assert.equal(await w.token.get(true), 'token-3', 'the store refused the token in hand');
  assert.equal(w.calls.length, 3);
});

test('seed(): a token from another context is used, and never replaces a newer one', async () => {
  const w = worker([grant(9)]);
  w.token.seed('seeded', w.now() + 3000 * 1000);
  assert.equal(await w.token.get(false), 'seeded');
  w.token.seed('older', w.now() + 1000 * 1000);
  assert.equal(await w.token.get(false), 'seeded');
  w.token.seed('', w.now() + 9000 * 1000);
  w.token.seed(null, 0);
  assert.equal(await w.token.get(false), 'seeded');
  assert.equal(w.calls.length, 0);
  w.token.forget();
  assert.equal(await w.token.get(false), 'token-9');
});

test('refusals carry the Worker\'s code; a failed request does not poison the next', async () => {
  const w = worker([
    { status: 401, body: { error: 'no_session', message: 'Sign in.' } },
    { status: 403, body: { error: 'email_not_allowed', message: 'o***@example.com may not use this viewer.' } },
    { status: 502, text: '<html>bad gateway</html>' },
    { network: true },
    { status: 200, body: { expires_in: 3600 } },
    grant(5),
  ]);
  await assert.rejects(w.token.get(false), (e) => e instanceof gclone.TokenError && e.code === 'no_session' && e.status === 401);
  await assert.rejects(w.token.get(false), (e) => e.code === 'email_not_allowed' && /may not use/.test(e.message));
  await assert.rejects(w.token.get(false), (e) => e.code === 'http_502' && /status 502/.test(e.message));
  await assert.rejects(w.token.get(false), (e) => e.code === 'unreachable');
  await assert.rejects(w.token.get(false), (e) => e.code === 'bad_answer');
  assert.equal(await w.token.get(false), 'token-5');
});
