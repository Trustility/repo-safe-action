import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DEFAULT_API_URL,
  UUIDV4_RE,
  assertNoRawData,
  buildEventData,
  buildRequest,
  formatApiError,
  isCanonicalAgentId,
  isValidNonce,
  makeNonce,
  requestProof,
  run,
} from '../src/sign-and-emit.mjs';

const AGENT = '123e4567-e89b-42d3-a456-426614174000';
const ENV = {
  INPUT_API_KEY: 'tk_test_key_never_logged',
  INPUT_POLICY_REF: 'pol:baseline@1',
  INPUT_AGENT_ID: AGENT,
  GITHUB_REPOSITORY: 'Trustility/example',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_SHA: 'a'.repeat(40),
  GITHUB_WORKFLOW: 'CI',
  GITHUB_EVENT_NAME: 'push',
  GITHUB_RUN_ID: '123',
  GITHUB_RUN_ATTEMPT: '1',
};

function outputs() {
  const dir = mkdtempSync(join(tmpdir(), 'repo-safe-action-'));
  const file = join(dir, 'output');
  return { dir, file, read: () => readFileSync(file, 'utf8') };
}

test('contract defaults to current domain and sends only Bearer authentication', () => {
  const request = buildRequest(ENV, new Date('2026-09-21T12:00:00.000Z'));
  assert.equal(request.url, `${DEFAULT_API_URL}/v1/proofs`);
  assert.equal(request.init.headers.Authorization, 'Bearer tk_test_key_never_logged');
  const body = JSON.parse(request.init.body);
  assert.equal(body.agentId, AGENT);
  assert.deepEqual(Object.keys(body.eventData).sort(), ['ci', 'event', 'ref', 'repo', 'run_attempt', 'run_id', 'sha', 'workflow']);
  assert.equal(body.eventData.actor, undefined);
  assert.ok(isValidNonce(body.nonce));
  assert.equal(body.ts_hint, '2026-09-21T12:00:00.000Z');
});

test('agent id is canonical lowercase UUIDv4 only', () => {
  assert.equal(UUIDV4_RE.test(AGENT), true);
  assert.equal(isCanonicalAgentId(AGENT), true);
  assert.equal(isCanonicalAgentId(AGENT.toUpperCase()), false);
  assert.equal(isCanonicalAgentId('123e4567-e89b-12d3-a456-426614174000'), false);
  assert.equal(isCanonicalAgentId(''), false);
});

test('generated nonces are fresh and satisfy the platform invariant', () => {
  const values = new Set(Array.from({ length: 100 }, makeNonce));
  assert.equal(values.size, 100);
  for (const value of values) assert.equal(isValidNonce(value), true);
});

test('missing key, policy, or agent fails before fetch and never reveals the key', async () => {
  let calls = 0;
  const fetchSpy = async () => { calls += 1; throw new Error('network should not be called'); };
  await assert.rejects(() => requestProof({ ...ENV, INPUT_API_KEY: '' }, fetchSpy), /api-key is required/);
  await assert.rejects(() => requestProof({ ...ENV, INPUT_AGENT_ID: 'not-an-agent' }, fetchSpy), /canonical lowercase UUIDv4/);
  await assert.rejects(() => requestProof({ ...ENV, INPUT_POLICY_REF: '' }, fetchSpy), /policy-ref is required/);
  assert.equal(calls, 0);
  await assert.rejects(() => run({ ...ENV, INPUT_API_KEY: 'super-secret-key' }, async () => ({
    status: 401,
    text: async () => JSON.stringify({ error: 'UNAUTHENTICATED', message: 'super-secret-key' }),
  })), (error) => !error.message.includes('super-secret-key'));
});

test('raw and normalized sensitive keys are rejected before network', () => {
  for (const key of ['source', 'source_code', 'source-code', 'apiKey', 'clientIdentity', 'AUTH-header', 'prompt']) {
    assert.throws(() => assertNoRawData({ [key]: 'forbidden' }), /not an allowed abstract CI coordinate/);
  }
  assert.doesNotThrow(() => assertNoRawData({ repo: 'org/repo', sha: 'abc', run_id: '1' }));
  assert.deepEqual(buildEventData({ GITHUB_ACTOR: 'human', SECRET: 'x', INPUT_EVENT_DATA: '{"body":"x"}' }).actor, undefined);
});

test('error mapper gives actionable current API remediations', () => {
  const cases = [
    [401, 'UNAUTHENTICATED', 'api-key'],
    [400, 'AGENT_REQUIRED', 'agent-id'],
    [400, 'INVALID_AGENT_ID', 'canonical lowercase UUIDv4'],
    [403, 'AGENT_NOT_OWNED', 'Claim'],
    [404, 'UNKNOWN_POLICY', 'policy'],
    [403, 'POLICY_NOT_OWNED', 'owned'],
    [422, 'POLICY_INACTIVE', 'active'],
    [419, 'CLOCK_SKEW', 'clock'],
    [401, 'EXPIRED_TIMESTAMP', 'immediately'],
    [409, 'NONCE_REPLAY', 'fresh'],
    [400, 'WEAK_NONCE', 'generate the nonce'],
    [409, 'DUPLICATE_HASH', 'event coordinates'],
    [400, 'INVALID_SIGNATURE', 'Ed25519'],
    [400, 'INVALID_SCHEMA', 'inputs'],
    [400, 'RAW_DATA_REJECTED', 'sensitive'],
    [429, 'RATE_LIMITED', 'Slow down'],
    [500, 'INTERNAL', 'Retry'],
  ];
  for (const [status, code, expected] of cases) assert.match(formatApiError(status, { error: code }), new RegExp(expected, 'i'));
});

test('failed and non-fatal API responses expose outputs without raw response or key', async () => {
  const output = outputs();
  const env = { ...ENV, GITHUB_OUTPUT: output.file, INPUT_FAIL_ON_ERROR: 'false' };
  const result = await run(env, async () => ({
    status: 401,
    text: async () => JSON.stringify({ error: 'UNAUTHENTICATED', message: 'raw-key-must-not-appear' }),
  }));
  assert.equal(result.status, 'failed');
  assert.match(output.read(), /status=failed/);
  assert.doesNotMatch(output.read(), /raw-key-must-not-appear|tk_test_key_never_logged/);
  rmSync(output.dir, { recursive: true, force: true });
});

test('nonce replay gets one automatic retry with a fresh nonce', async () => {
  const output = outputs();
  const env = { ...ENV, GITHUB_OUTPUT: output.file };
  const requests = [];
  let attempt = 0;
  const result = await run(env, async (_url, init) => {
    requests.push(JSON.parse(init.body));
    attempt += 1;
    return attempt === 1
      ? { status: 409, text: async () => JSON.stringify({ error: 'NONCE_REPLAY' }) }
      : { status: 201, text: async () => JSON.stringify({ proofId: 'proof:test', vc: 'jwt', eventHash: requests[1].eventHash }) };
  });
  assert.equal(result.status, 'emitted');
  assert.equal(requests.length, 2);
  assert.notEqual(requests[0].nonce, requests[1].nonce);
  assert.match(output.read(), /status=emitted/);
  rmSync(output.dir, { recursive: true, force: true });
});

test('README workflow has current action inputs and no obsolete domain or event-data input', () => {
  const action = readFileSync(new URL('../action.yml', import.meta.url), 'utf8');
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.match(action, /default: 'https:\/\/trustility\.ai'/);
  assert.match(action, /api-key:/);
  assert.match(action, /agent-id:[\s\S]*required: true/);
  assert.doesNotMatch(action, /event-data:/);
  assert.match(readme, /Trustility\/repo-safe-action@main/);
  assert.match(readme, /TRUSTILITY_API_KEY/);
  assert.match(readme, /TRUSTILITY_AGENT_ID/);
  assert.doesNotMatch(readme, /api\.trustility\.io/);
});