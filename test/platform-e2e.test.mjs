import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildRequest, formatApiError, run } from '../src/sign-and-emit.mjs';

const platformDir = process.env.TRUSTILITY_PLATFORM_DIR;

test(
  'action emits against the current platform checkout, never production',
  { skip: platformDir ? false : 'Set TRUSTILITY_PLATFORM_DIR to a local platform checkout; production is never used.' },
  async () => {
  const imp = async (relative) => import(pathToFileURL(join(platformDir, relative)).href);
  const [{ createApp }, { Keystore }, { InstrumentedJwksResolver, LocalKeystoreSource }, { Metrics }, { InMemoryNonceStore }, { MemoryProofStore }, { MemoryAccountStore }, { MemoryApiKeyStore }, { MemorySubscriptionStore }, { MemoryFunnelEventStore }, { MemoryStripeEventStore }, { MemoryAgentStore }, { MemoryAccountPolicyStore }, { RateLimiter }] = await Promise.all([
    imp('src/api/app.ts'),
    imp('src/keys/keystore.ts'),
    imp('src/keys/jwks-resolver.ts'),
    imp('src/sentinel/metrics.ts'),
    imp('src/proof/nonce.ts'),
    imp('src/store/proofs.ts'),
    imp('src/store/accounts.ts'),
    imp('src/store/api-keys.ts'),
    imp('src/store/subscriptions.ts'),
    imp('src/store/funnel-events.ts'),
    imp('src/store/stripe-events.ts'),
    imp('src/store/agents.ts'),
    imp('src/store/policies.ts'),
    imp('src/auth/rate-limit.ts'),
  ]);
  const keystore = await Keystore.create();
  const metrics = new Metrics();
  const agents = new MemoryAgentStore();
  const policies = new MemoryAccountPolicyStore();
  const deps = {
    keystore,
    jwksResolver: new InstrumentedJwksResolver(new LocalKeystoreSource(keystore), metrics),
    policies,
    proofs: new MemoryProofStore(),
    nonces: new InMemoryNonceStore(),
    metrics,
    accounts: new MemoryAccountStore(),
    apiKeys: new MemoryApiKeyStore(),
    subscriptions: new MemorySubscriptionStore(),
    funnelEvents: new MemoryFunnelEventStore(() => false),
    githubOAuth: null,
    authRateLimiter: new RateLimiter({ windowMs: 60_000, max: 100 }),
    stripeEvents: new MemoryStripeEventStore(),
    stripe: null,
    agents,
    emitRateLimiter: new RateLimiter({ windowMs: 60_000, max: 100 }),
  };
  const account = (await deps.accounts.create({ githubId: 'action-e2e', githubLogin: 'action-e2e' })).account;
  const issued = await deps.apiKeys.issue(account.id);
  const agentId = '123e4567-e89b-42d3-a456-426614174000';
  await agents.claim(account.id, agentId);
  const policy = await policies.create({
    accountId: account.id,
    agentId,
    name: 'Action E2E',
    clauses: [{ kind: 'human_approval_required' }],
  });
  const otherAccount = (await deps.accounts.create({ githubId: 'action-other', githubLogin: 'action-other' })).account;
  const otherKey = await deps.apiKeys.issue(otherAccount.id);
  const otherAgent = '123e4567-e89b-42d3-a456-426614174001';
  await agents.claim(otherAccount.id, otherAgent);
  const otherPolicy = await policies.create({
    accountId: otherAccount.id,
    agentId: otherAgent,
    name: 'Other account policy',
    clauses: [{ kind: 'human_approval_required' }],
  });
  const inactivePolicy = await policies.create({
    accountId: account.id,
    agentId,
    name: 'Inactive policy',
    clauses: [{ kind: 'human_approval_required' }],
  });
  const server = http.createServer(createApp(deps));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const outputDir = mkdtempSync(join(tmpdir(), 'repo-safe-action-e2e-'));
  const output = join(outputDir, 'output');
  const env = {
    INPUT_API_URL: base,
    INPUT_API_KEY: issued.plaintext,
    INPUT_POLICY_REF: policy.policyId,
    INPUT_AGENT_ID: agentId,
    INPUT_PROOF_TYPE: 'Integrity',
    GITHUB_REPOSITORY: 'example/blank',
    GITHUB_REF: 'refs/heads/main',
    GITHUB_SHA: 'a'.repeat(40),
    GITHUB_WORKFLOW: 'E2E',
    GITHUB_EVENT_NAME: 'push',
    GITHUB_RUN_ID: '99',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_OUTPUT: output,
  };
  const post = async (body, key = issued.plaintext) => {
    const response = await fetch(`${base}/v1/proofs`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${key}` },
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  };
  const actionBody = (overrides = {}, now = new Date()) => buildRequest({ ...env, ...overrides }, now).body;
  const observed = [];
  const assertCode = async (label, expectedStatus, expectedCode, body, key = issued.plaintext) => {
    const result = await post(body, key);
    observed.push({ label, status: result.status, code: result.body.error });
    assert.equal(result.status, expectedStatus, label);
    assert.equal(result.body.error, expectedCode, label);
    assert.match(formatApiError(result.status, result.body), /Trustility rejected the proof/);
    return result;
  };
  try {
    const accepted = await run(env);
    assert.equal(accepted.status, 'emitted');
    const outputText = await import('node:fs/promises').then(({ readFile }) => readFile(output, 'utf8'));
    assert.match(outputText, /status=emitted/);
    assert.match(outputText, /proof-id=proof:/);
    assert.match(outputText, /event-hash=sha256:[a-f0-9]{64}/);

    await assertCode('missing key', 401, 'UNAUTHENTICATED', actionBody(), '');
    await assertCode('invalid key', 401, 'UNAUTHENTICATED', actionBody(), 'tk_invalid');

    let fetchCalls = 0;
    await assert.rejects(
      () => run({ ...env, INPUT_AGENT_ID: 'NOT-A-UUID' }, async () => { fetchCalls += 1; throw new Error('must not fetch'); }),
      /canonical lowercase UUIDv4/,
    );
    assert.equal(fetchCalls, 0);
    await assertCode('unowned agent', 403, 'AGENT_NOT_OWNED', actionBody({ INPUT_AGENT_ID: '123e4567-e89b-42d3-a456-426614174002' }));
    await assertCode('unknown policy', 404, 'UNKNOWN_POLICY', actionBody({ INPUT_POLICY_REF: 'pol:does-not-exist@99' }));
    await assertCode('policy not owned', 403, 'POLICY_NOT_OWNED', actionBody({ INPUT_POLICY_REF: otherPolicy.policyId }));

    const deactivated = await fetch(`${base}/v1/policies/${inactivePolicy.policyId}/deactivate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${issued.plaintext}` },
    });
    assert.equal(deactivated.status, 200);
    await assertCode('inactive policy', 422, 'POLICY_INACTIVE', actionBody({ INPUT_POLICY_REF: inactivePolicy.policyId }));

    await assertCode('expired timestamp', 401, 'EXPIRED_TIMESTAMP', actionBody({}, new Date(Date.now() - 10 * 60_000)));
    await assertCode('clock skew', 419, 'CLOCK_SKEW', actionBody({}, new Date(Date.now() - 60_000)));
    await assertCode('weak nonce', 400, 'WEAK_NONCE', { ...actionBody({ GITHUB_RUN_ID: 'weak' }), nonce: 'aaaaaaaaaaaaaaaaaaaaaaaa' });
    await assertCode('invalid signature', 400, 'INVALID_SIGNATURE', { ...actionBody({ GITHUB_RUN_ID: 'sig' }), signature: '0'.repeat(128), agentPublicKey: '00' });
    await assertCode('invalid schema', 400, 'INVALID_SCHEMA', { ...actionBody({ GITHUB_RUN_ID: 'schema' }), eventData: undefined });
    await assertCode('raw data rejected', 400, 'RAW_DATA_REJECTED', { ...actionBody({ GITHUB_RUN_ID: 'raw' }), eventData: { content: 'must never be sent' } });

    const replay = actionBody({ GITHUB_RUN_ID: 'replay-first' });
    const replayFirst = await post(replay);
    assert.equal(replayFirst.status, 201);
    await assertCode(
      'nonce replay',
      409,
      'NONCE_REPLAY',
      { ...actionBody({ GITHUB_RUN_ID: 'replay-second' }), nonce: replay.nonce },
    );

    const duplicate = actionBody({ GITHUB_RUN_ID: 'duplicate' });
    const duplicateFirst = await post(duplicate);
    assert.equal(duplicateFirst.status, 201);
    await assertCode('duplicate hash', 409, 'DUPLICATE_HASH', { ...duplicate, nonce: actionBody({ GITHUB_RUN_ID: 'different-nonce' }).nonce });
    console.log(`E2E negative API statuses: ${JSON.stringify(observed)}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(outputDir, { recursive: true, force: true });
  }
  },
);