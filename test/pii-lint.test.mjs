import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertNoRawData } from '../src/sign-and-emit.mjs';

/**
 * F4 / Threat 2: the SDK refuses to emit when the abstracted CI metadata carries raw sensitive
 * fields (proofs-not-data). Unlike the proof rail's top-level guard, the SDK scans every depth,
 * so nested and array-nested raw fields are caught before anything leaves the runner.
 */
const BANNED = ['amount', 'recipient', 'email', 'content', 'message', 'subject', 'body', 'password', 'secret', 'token', 'apikey', 'api_key'];

test('assertNoRawData throws on each banned top-level field', () => {
  for (const field of BANNED) {
    assert.throws(() => assertNoRawData({ repo: 'org/repo', [field]: 'raw' }), /Refusing to emit/, `field ${field}`);
  }
});

test('assertNoRawData throws on a nested banned field (deep scan)', () => {
  assert.throws(() => assertNoRawData({ repo: 'x', meta: { nested: { email: 'a@b.c' } } }), /Refusing to emit/);
  assert.throws(() => assertNoRawData({ items: [{ ok: 1 }, { password: 'p' }] }), /Refusing to emit/);
});

test('assertNoRawData is case-insensitive on field names', () => {
  assert.throws(() => assertNoRawData({ Amount: 1 }), /Refusing to emit/);
  assert.throws(() => assertNoRawData({ API_KEY: 'k' }), /Refusing to emit/);
});

test('assertNoRawData passes clean abstracted metadata', () => {
  assert.doesNotThrow(() =>
    assertNoRawData({ ci: 'github-actions', repo: 'org/repo', sha: 'abc123', run_id: '42', tags: ['a', 'b'] }),
  );
});
