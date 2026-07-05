# Trustility Repo-Safe Proof

A GitHub Action that emits a Trustility proof for a step in your workflow.

It sends only a canonical hash of a small, abstracted description of the action — the
repository, the ref, the commit sha, the workflow name, the event. It never sends your
source code, diffs, logs, or secrets. The action refuses to run if the metadata contains
fields that look like raw content.

## What it does

1. Builds a compact metadata object from the GitHub context.
2. Canonicalizes it with RFC 8785 (JCS) and hashes it with SHA-256.
3. Optionally signs that hash with your Ed25519 agent key.
4. Posts the proof to your Trustility proof rail (`POST /v1/proofs`).

The proof rail returns a VC-JWT credential that anyone can verify statelessly against the
published keys.

## Usage

```yaml
- name: Emit Trustility proof
  uses: Trustility/repo-safe-action@v0
  with:
    api-url: https://api.trustility.io
    policy-ref: pol:baseline@1
    proof-type: Integrity
    # optional: sign the proof with an Ed25519 agent key stored as a secret
    agent-key: ${{ secrets.TRUSTILITY_AGENT_KEY }}
```

### Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `api-url` | yes | — | Base URL of your Trustility proof rail. |
| `policy-ref` | yes | — | Policy reference to prove against, e.g. `pol:baseline@1`. |
| `proof-type` | no | `Integrity` | `Integrity`, `Reliability`, or `Oversight`. |
| `agent-id` | no | `''` | Stable identifier for the emitting workflow or agent. |
| `agent-key` | no | `''` | Ed25519 private key as a JWK JSON string (use a secret). |
| `event-data` | no | `{}` | Extra abstracted metadata as JSON. No raw sensitive fields. |
| `fail-on-error` | no | `true` | Fail the step when the proof is not accepted. |

### Outputs

| Output | Description |
| --- | --- |
| `proof-id` | The emitted proof identifier. |
| `vc` | The VC-JWT credential. |
| `event-hash` | The canonical hash that was proven (`sha256:...`). |
| `status` | `emitted` or `failed`. |

## Generating an agent key

The optional signing key is a standard Ed25519 key in JWK form. You can generate one with
Node:

```js
const { generateKeyPairSync } = require('node:crypto');
const { privateKey } = generateKeyPairSync('ed25519');
console.log(JSON.stringify(privateKey.export({ format: 'jwk' })));
```

Store the printed JSON as a repository secret (for example `TRUSTILITY_AGENT_KEY`) and pass
it to the `agent-key` input. Keep the private key secret; only the public half is published
with each proof.

## What stays on your runner

Your code, file contents, diffs, environment variables, and secrets never leave the runner.
The action sends a hash and a short list of build-context fields. If you add `event-data`,
it is validated to reject fields such as `amount`, `recipient`, `email`, `content`,
`message`, `subject`, and `body`.

## Requirements

- A reachable Trustility proof rail (`api-url`).
- Node is provided by the GitHub-hosted runner; the action has no npm dependencies.

## License

Apache License 2.0. See [LICENSE](./LICENSE).
