#!/usr/bin/env node
/**
 * Trustility Repo-Safe Proof — authenticated emit step.
 *
 * Only a closed allowlist of abstract GitHub coordinates leaves the runner. Source, diffs,
 * patches, logs, secrets, credentials, tokens, and human/client identity fields are never read
 * from the environment or accepted as event data.
 */
import { createHash, createPrivateKey, randomBytes, sign as ed25519Sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { appendFileSync } from 'node:fs';

export const DEFAULT_API_URL = 'https://trustility.ai';
export const UUIDV4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EVENT_KEYS = ['ci', 'repo', 'ref', 'sha', 'workflow', 'event', 'run_id', 'run_attempt'];
const SENSITIVE_KEY_PARTS = [
  'source', 'code', 'diff', 'patch', 'log', 'secret', 'token', 'password', 'credential',
  'key', 'apikey', 'auth', 'header', 'cookie', 'email', 'message', 'content', 'body',
  'prompt', 'client', 'customer', 'identity', 'actor', 'amount', 'recipient', 'subject',
];

/** Recursively sort object keys so canonicalization is order-independent. */
export function sortValue(v) {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortValue(v[k]);
    return out;
  }
  return v;
}

export function canonicalize(obj) {
  return JSON.stringify(sortValue(obj));
}

export function normalizeFloats(obj, decimals = 6) {
  if (typeof obj === 'number' && !Number.isInteger(obj)) return parseFloat(obj.toFixed(decimals));
  if (Array.isArray(obj)) return obj.map((item) => normalizeFloats(item, decimals));
  if (obj !== null && typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[k] = normalizeFloats(v, decimals);
    return out;
  }
  return obj;
}

export function computeEventHash(eventData) {
  const canonical = canonicalize(normalizeFloats(eventData));
  return `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
}

function normalizedKey(key) {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Defense-in-depth guard for callers/tests. Production input is closed at buildEventData(), so
 * arbitrary event data is never read. The normalized-substring check catches camelCase, kebab,
 * snake, and case variants such as apiKey, client_identity, and source-diff.
 */
export function assertNoRawData(obj, path = 'eventData') {
  if (Array.isArray(obj)) {
    obj.forEach((x, i) => assertNoRawData(x, `${path}[${i}]`));
    return;
  }
  if (obj && typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      const normalized = normalizedKey(key);
      if (SENSITIVE_KEY_PARTS.some((part) => normalized.includes(part))) {
        throw new Error(`Refusing to emit: "${path}.${key}" is not an allowed abstract CI coordinate.`);
      }
      assertNoRawData(obj[key], `${path}.${key}`);
    }
  }
}

export function buildEventData(env) {
  const eventData = {
    ci: 'github-actions',
    repo: env.GITHUB_REPOSITORY ?? null,
    ref: env.GITHUB_REF ?? null,
    sha: env.GITHUB_SHA ?? null,
    workflow: env.GITHUB_WORKFLOW ?? null,
    event: env.GITHUB_EVENT_NAME ?? null,
    run_id: env.GITHUB_RUN_ID ?? null,
    run_attempt: env.GITHUB_RUN_ATTEMPT ?? null,
  };
  assertNoRawData(eventData);
  return eventData;
}

export function isCanonicalAgentId(value) {
  return typeof value === 'string' && UUIDV4_RE.test(value);
}

export function makeNonce() {
  return randomBytes(32).toString('base64url');
}

export function isValidNonce(nonce) {
  return typeof nonce === 'string'
    && /^[A-Za-z0-9_-]{22,256}$/.test(nonce)
    && new Set(nonce).size >= 4;
}

export function loadAgentKey(jwkJson) {
  let jwk;
  try {
    jwk = JSON.parse(jwkJson);
  } catch {
    throw new Error('agent-key is not valid JSON; remove it or provide a valid Ed25519 JWK for optional signing.');
  }
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.d || !jwk.x) {
    throw new Error('agent-key must be an Ed25519 private JWK; it is optional signing only, not API authentication.');
  }
  const privateKey = createPrivateKey({ key: jwk, format: 'jwk' });
  const publicKeyHex = Buffer.from(jwk.x, 'base64url').toString('hex');
  return { privateKey, publicKeyHex };
}

export function signEventHash(privateKey, eventHash) {
  return ed25519Sign(null, Buffer.from(eventHash, 'utf8'), privateKey).toString('hex');
}

function setOutput(name, value, env = process.env) {
  const file = env.GITHUB_OUTPUT;
  if (file) appendFileSync(file, `${name}=${String(value).replace(/\r?\n/g, '')}\n`);
}

function safeApiError(status, code) {
  const fixes = {
    UNAUTHENTICATED: 'Add a valid, unrevoked API key as the api-key secret; the action sends it as Authorization: Bearer.',
    AGENT_REQUIRED: 'Set agent-id to the canonical lowercase UUIDv4 of an agent claimed by this API-key account.',
    AGENT_NOT_OWNED: 'Claim this UUIDv4 under the same account as the API key, then retry.',
    UNKNOWN_POLICY: 'Create the policy first and set policy-ref to its exact reference.',
    POLICY_INACTIVE: 'Use an active policy reference or create a new policy version.',
    CLOCK_SKEW: 'Synchronize the runner clock and retry; the API returned a short timestamp window.',
    EXPIRED_TIMESTAMP: 'Retry immediately with the action-generated timestamp; do not provide a timestamp yourself.',
    NONCE_REPLAY: 'Retry with a fresh action-generated nonce; do not cache or reuse requests.',
    INVALID_AGENT_ID: 'Set agent-id to a canonical lowercase UUIDv4, for example 123e4567-e89b-42d3-a456-426614174000.',
  };
  const action = fixes[code] ?? 'Check the policy reference and API configuration, then retry. Do not share the API key.';
  return `Trustility rejected the proof (HTTP ${status}, ${code || 'UNKNOWN_ERROR'}). ${action}`;
}

export function formatApiError(status, body = {}) {
  const code = typeof body?.error === 'string' ? body.error : '';
  return safeApiError(status, code);
}

function validationError(message) {
  const error = new Error(message);
  error.code = 'INPUT_INVALID';
  return error;
}

function inputConfig(env) {
  const apiUrl = (env.INPUT_API_URL || DEFAULT_API_URL).trim().replace(/\/+$/, '');
  const apiKey = (env.INPUT_API_KEY || '').trim();
  const policyRef = (env.INPUT_POLICY_REF || '').trim();
  const proofType = (env.INPUT_PROOF_TYPE || 'Integrity').trim();
  const agentId = (env.INPUT_AGENT_ID || '').trim();
  if (!apiKey) throw validationError('Trustility api-key is required. Add the TRUSTILITY_API_KEY secret to the workflow and pass it to api-key.');
  if (!policyRef) throw validationError('Trustility policy-ref is required. Create or select an active policy before running the action.');
  if (!agentId) throw validationError('Trustility agent-id is required. Claim an agent and pass its canonical lowercase UUIDv4.');
  if (!isCanonicalAgentId(agentId)) throw validationError('Trustility agent-id must be a canonical lowercase UUIDv4, for example 123e4567-e89b-42d3-a456-426614174000.');
  return { apiUrl, apiKey, policyRef, proofType, agentId };
}

export function buildRequest(env, now = new Date()) {
  const { apiUrl, apiKey, policyRef, proofType, agentId } = inputConfig(env);
  const eventData = buildEventData(env);
  const eventHash = computeEventHash(eventData);
  const nonce = makeNonce();
  const tsHint = now.toISOString();
  const body = { type: proofType, eventData, policyRef, nonce, ts_hint: tsHint, agentId };
  const agentKeyJwk = (env.INPUT_AGENT_KEY || '').trim();
  if (agentKeyJwk) {
    const { privateKey, publicKeyHex } = loadAgentKey(agentKeyJwk);
    body.agentPublicKey = publicKeyHex;
    body.signature = signEventHash(privateKey, eventHash);
  }
  return {
    url: `${apiUrl}/v1/proofs`,
    init: {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(body),
    },
    eventHash,
    nonce,
    tsHint,
    body,
  };
}

async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

async function requestProof(env, fetchImpl = fetch, now = new Date()) {
  const request = buildRequest(env, now);
  const response = await fetchImpl(request.url, request.init);
  const body = await readJson(response);
  return { request, response, body };
}

async function run(env = process.env, fetchImpl = fetch) {
  const failOnError = (env.INPUT_FAIL_ON_ERROR || 'true').trim() !== 'false';
  let result;
  try {
    result = await requestProof(env, fetchImpl);
    if (result.response.status === 409 && result.body?.error === 'NONCE_REPLAY') {
      result = await requestProof(env, fetchImpl, new Date());
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid action configuration.';
    setOutput('status', 'failed', env);
    if (failOnError) throw error;
    console.log(`WARNING (non-fatal): ${message}`);
    return { status: 'failed', error: message };
  }
  if (result.response.status === 201) {
    setOutput('proof-id', result.body.proofId ?? '', env);
    setOutput('vc', result.body.vc ?? '', env);
    setOutput('event-hash', result.body.eventHash ?? result.request.eventHash, env);
    setOutput('status', 'emitted', env);
    console.log(`Proof emitted: ${result.body.proofId ?? '(no id returned)'}`);
    return { status: 'emitted', body: result.body };
  }
  setOutput('status', 'failed', env);
  setOutput('event-hash', result.request.eventHash, env);
  const message = formatApiError(result.response.status, result.body);
  if (failOnError) throw new Error(message);
  console.log(`WARNING (non-fatal): ${message}`);
  return { status: 'failed', error: message };
}

export { inputConfig, requestProof, run };

const invokedDirectly = import.meta.url === pathToFileURL(process.argv[1] ?? '').href;
if (invokedDirectly) {
  run().catch((err) => {
    console.error(`::error::${err.message}`);
    process.exit(1);
  });
}