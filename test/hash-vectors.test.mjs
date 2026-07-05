import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { computeEventHash } from '../src/sign-and-emit.mjs';

// Shared oracle committed to both this repo and the proof rail. These vectors are the contract:
// if the action's canonicalization drifts from the rail's, a signed proof would be rejected
// server-side with INVALID_SIGNATURE. This suite catches that at build time instead.
const here = dirname(fileURLToPath(import.meta.url));
const doc = JSON.parse(readFileSync(join(here, 'hash-vectors.json'), 'utf8'));

test('SDK reproduces every shared event-hash vector (parity with the proof rail)', () => {
  assert.ok(doc.vectors.length >= 10, 'expected at least 10 vectors');
  for (const v of doc.vectors) {
    assert.equal(computeEventHash(v.input), v.expected_eventHash, `vector ${v.id}`);
  }
});
