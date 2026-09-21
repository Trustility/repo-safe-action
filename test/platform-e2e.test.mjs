import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { run } from '../src/sign-and-emit.mjs';

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
  try {
    const accepted = await run(env);
    assert.equal(accepted.status, 'emitted');
    const outputText = await import('node:fs/promises').then(({ readFile }) => readFile(output, 'utf8'));
    assert.match(outputText, /status=emitted/);
    assert.match(outputText, /proof-id=proof:/);
    assert.match(outputText, /event-hash=sha256:[a-f0-9]{64}/);

    await assert.rejects(
      () => run({ ...env, INPUT_API_KEY: 'tk_invalid', GITHUB_OUTPUT: join(outputDir, 'invalid') }),
      /UNAUTHENTICATED|api-key/i,
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(outputDir, { recursive: true, force: true });
  }
  },
);