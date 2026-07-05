#!/usr/bin/env node
/**
 * Trustility Repo-Safe Proof — emit step.
 *
 * Builds a small, abstracted description of the CI action (repo, ref, commit sha, workflow,
 * event), hashes it with RFC 8785 (JCS) + SHA-256, optionally signs that hash with an
 * Ed25519 agent key, and posts it to the Trustility proof rail. Only the hash leaves the
 * runner — never source, diffs, logs, or secrets.
 *
 * Dependency-free: uses Node's built-in crypto and fetch only.
 */
import { createHash, createPrivateKey, sign as ed25519Sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { appendFileSync } from 'node:fs';

const BANNED_FIELDS = ['amount', 'recipient', 'email', 'content', 'message', 'subject', 'body', 'password', 'secret', 'token', 'apikey', 'api_key'];

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

/**
 * Minimal RFC 8785 (JCS): recursive key-sort + ECMAScript JSON.stringify. RFC 8785 string and
 * number serialization is defined on ECMAScript semantics, so for JSON produced by JSON.parse
 * this reproduces the proof rail's canonicalize() output.
 */
export function canonicalize(obj) {
  return JSON.stringify(sortValue(obj));
}

/**
 * Mirror the proof rail: non-integer numbers are rounded to 6 decimals BEFORE canonicalization.
 * Without this, a signed proof whose event-data carries a >6dp float would hash differently
 * server-side and be rejected with INVALID_SIGNATURE.
 */
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

/** Refuse to emit if the metadata carries raw sensitive fields (proofs-not-data). */
export function assertNoRawData(obj, path = 'eventData') {
  if (Array.isArray(obj)) {
    obj.forEach((x, i) => assertNoRawData(x, `${path}[${i}]`));
    return;
  }
  if (obj && typeof obj === 'object') {
    for (const k of Object.keys(obj)) {
      if (BANNED_FIELDS.includes(k.toLowerCase())) {
        throw new Error(`Refusing to emit: "${path}.${k}" looks like raw sensitive data. This action proves a hash of abstracted metadata, not raw content.`);
      }
      assertNoRawData(obj[k], `${path}.${k}`);
    }
  }
}

export function loadAgentKey(jwkJson) {
  let jwk;
  try {
    jwk = JSON.parse(jwkJson);
  } catch {
    throw new Error('agent-key must be a JSON JWK string.');
  }
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.d || !jwk.x) {
    throw new Error('agent-key must be an Ed25519 private JWK ({ kty: "OKP", crv: "Ed25519", d, x }).');
  }
  const privateKey = createPrivateKey({ key: jwk, format: 'jwk' });
  const publicKeyHex = Buffer.from(jwk.x, 'base64url').toString('hex');
  return { privateKey, publicKeyHex };
}

/** Ed25519 is deterministic (RFC 8032); this returns the raw 64-byte signature as hex. */
export function signEventHash(privateKey, eventHash) {
  return ed25519Sign(null, Buffer.from(eventHash, 'utf8'), privateKey).toString('hex');
}

export function buildEventData(env, extra) {
  const base = {
    ci: 'github-actions',
    repo: env.GITHUB_REPOSITORY ?? null,
    ref: env.GITHUB_REF ?? null,
    sha: env.GITHUB_SHA ?? null,
    workflow: env.GITHUB_WORKFLOW ?? null,
    event: env.GITHUB_EVENT_NAME ?? null,
    run_id: env.GITHUB_RUN_ID ?? null,
    run_attempt: env.GITHUB_RUN_ATTEMPT ?? null,
    actor: env.GITHUB_ACTOR ?? null,
  };
  return { ...base, ...(extra ?? {}) };
}

function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (file) appendFileSync(file, `${name}=${String(value).replace(/\r?\n/g, '')}\n`);
}

async function main() {
  const apiUrl = (process.env.INPUT_API_URL ?? '').trim().replace(/\/+$/, '');
  const policyRef = (process.env.INPUT_POLICY_REF ?? '').trim();
  const proofType = (process.env.INPUT_PROOF_TYPE ?? 'Integrity').trim();
  const agentId = (process.env.INPUT_AGENT_ID ?? '').trim();
  const agentKeyJwk = (process.env.INPUT_AGENT_KEY ?? '').trim();
  const failOnError = (process.env.INPUT_FAIL_ON_ERROR ?? 'true').trim() !== 'false';

  if (!apiUrl) throw new Error('api-url is required.');
  if (!policyRef) throw new Error('policy-ref is required.');

  let extra = {};
  const rawExtra = (process.env.INPUT_EVENT_DATA ?? '').trim();
  if (rawExtra && rawExtra !== '{}') {
    try {
      extra = JSON.parse(rawExtra);
    } catch {
      throw new Error('event-data must be valid JSON.');
    }
  }

  const eventData = buildEventData(process.env, extra);
  assertNoRawData(eventData);

  const eventHash = computeEventHash(eventData);
  const nonce = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const tsHint = new Date().toISOString();

  const bodyObj = { type: proofType, eventData, policyRef, nonce, ts_hint: tsHint };
  if (agentId) bodyObj.agentId = agentId;
  if (agentKeyJwk) {
    const { privateKey, publicKeyHex } = loadAgentKey(agentKeyJwk);
    bodyObj.agentPublicKey = publicKeyHex;
    bodyObj.signature = signEventHash(privateKey, eventHash);
  }

  const res = await fetch(`${apiUrl}/v1/proofs`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(bodyObj),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }

  if (res.status === 201) {
    setOutput('proof-id', json.proofId ?? '');
    setOutput('vc', json.vc ?? '');
    setOutput('event-hash', json.eventHash ?? eventHash);
    setOutput('status', 'emitted');
    console.log(`Proof emitted: ${json.proofId ?? '(no id returned)'} against ${policyRef}`);
    console.log(`Event hash: ${json.eventHash ?? eventHash}`);
    return;
  }

  setOutput('status', 'failed');
  setOutput('event-hash', eventHash);
  const msg = `Proof rail returned ${res.status}: ${json.error ?? ''} ${json.message ?? ''}`.trim();
  if (failOnError) throw new Error(msg);
  console.log(`WARNING (non-fatal): ${msg}`);
}

const invokedDirectly = import.meta.url === pathToFileURL(process.argv[1] ?? '').href;
if (invokedDirectly) {
  main().catch((err) => {
    console.error(`::error::${err.message}`);
    process.exit(1);
  });
}
