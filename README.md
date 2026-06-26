# Atlas Transaction Decoder

Atlas Transaction Decoder is a small HTTP service that decodes Arkiv
entity-registry transactions back into human-readable operations
(create / update / extend / transfer / delete / expire).

The Arkiv SDK encodes entity mutations as a call to the registry precompile at
`0x4400000000000000000000000000000000000044`:

```solidity
function execute((
  uint8 operationType,
  bytes32 entityKey,
  bytes payload,
  (bytes32[4] data) contentType,                                  // Mime128
  (bytes32 name, uint8 valueType, bytes32[4] value)[] attributes,
  uint32 expiresAt,                                               // block-denominated
  address newOwner
)[] ops) external;
```

This service reverses that encoding. It accepts either bare `execute()` calldata
or a signed (EIP-2718) serialized transaction whose input is an `execute()`
call, and returns the decoded operations as JSON.

## What changed: payload references

Under the current API, create and update operations no longer carry the entity
bytes inline. Instead the SDK uploads the payload to an
[`atlas-payload-provider`](../atlas-payload-provider), receives a signed
receipt, and embeds a **payload reference** in the operation:

- `contentType` is exactly `application/vnd.atlas.payload-reference+json`.
- `payload` is the UTF-8 JSON of a v1 `PayloadReference` — content-address
  (`id`), `namespace`, `checksum`, `sizeBytes`, a one-time `nonce`, a `payment`
  amount, and the provider's EIP-191 receipt `signature`.

The decoder detects these operations, parses the reference, and verifies the
receipt **offline** — exactly as the on-chain precompile does
(`atlas-reth/crates/arkiv-node/src/precompile.rs`): it rebuilds the canonical
receipt, recovers the EIP-191 signer, and checks it against the trusted
payload-provider allowlist for the chain. No network calls are made; the
decoder does not fetch the original payload body.

## Quick start

```bash
cargo run
```

The default HTTP endpoint is:

```text
http://127.0.0.1:28884
```

Open the browser UI at `http://127.0.0.1:28884/`, or call the API directly.

## Configuration

Configuration is read from environment variables.

| Variable | Default | Description |
| --- | --- | --- |
| `LISTEN_HOST` | `0.0.0.0` | HTTP bind host. |
| `LISTEN_PORT` | `28884` | HTTP bind port. |
| `WEB_WORKERS` | `4` | Tokio worker thread count. |
| `HTML_TITLE` | `Atlas Transaction Decoder` | Browser UI title. |
| `MAX_INPUT_BYTES` | `2097152` | Maximum accepted input size. |
| `DEFAULT_CHAIN_ID` | `1337` | Chain id used when a request omits `chainId`. |
| `TRUSTED_PROVIDER_SIGNERS` | unset | Comma-separated 0x addresses added to the trusted signer allowlist. |

### Trusted signers

Reference verification trusts the live Atlas payload-provider signer
`0xbdd23fd1bab3f4075edef4738d1d78a6bc5c236c` on every chain, plus the
deterministic local dev signer `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf`
only on chain `1337`. `TRUSTED_PROVIDER_SIGNERS` adds more. `chainId` (per
request or `DEFAULT_CHAIN_ID`) selects whether the dev signer is trusted; it
does not affect verification of the production signer.

## API

### `GET /healthz`

```json
{ "ok": true }
```

### `GET /status`

Service configuration, the Arkiv registry address, the reference content type,
and the trusted-signer allowlist.

### `POST /decode`

Body: `{"data": "0x...", "chainId"?: 1337}` (JSON), or the raw hex string as
`text/plain`. Also available as `GET /decode?data=0x...&chainId=1337`.

```bash
curl -sS http://127.0.0.1:28884/decode \
  -H 'content-type: application/json' \
  -d '{"data": "0x<execute-calldata-or-signed-tx>"}'
```

Response (inline payload — legacy / non-reference operation):

```json
{
  "ok": true,
  "chainId": 1337,
  "functionName": "execute",
  "operationCount": 1,
  "operations": [
    {
      "index": 0,
      "operationType": 1,
      "operation": "create",
      "entityKey": "0x1111…",
      "contentType": "text/plain",
      "payload": { "hex": "0x48656c6c6f", "size": 5, "isReference": false, "text": "Hello" },
      "attributes": [
        { "key": "category", "valueType": 2, "valueTypeName": "string", "value": "greeting" },
        { "key": "version", "valueType": 1, "valueTypeName": "uint", "value": "42" }
      ],
      "expiresAtBlocks": 1800,
      "approxExpiresInSeconds": 3600
    }
  ]
}
```

Response (payload reference — current create / update operation):

```json
{
  "ok": true,
  "chainId": 1337,
  "functionName": "execute",
  "operationCount": 1,
  "operations": [
    {
      "index": 0,
      "operationType": 1,
      "operation": "create",
      "entityKey": "0x0000…",
      "contentType": "application/vnd.atlas.payload-reference+json",
      "payload": { "hex": "0x7b22…", "size": 700, "isReference": true },
      "payloadReference": {
        "kind": "atlas.payloadReference",
        "version": 1,
        "provider": "atlas-payload-provider",
        "id": "a806b74c…",
        "namespace": "atlas.test",
        "contentType": "text/plain",
        "checksum": "sha256:86a4700d…",
        "sizeBytes": 42,
        "submittedAt": "2026-06-24T15:24:30Z",
        "nonce": "0x0000…0001",
        "payment": 100000,
        "signature": { "scheme": "eip191", "signer": "0x7e5f…", "receipt": { "…": "…" }, "v": 27 }
      },
      "referenceVerification": {
        "valid": true,
        "signerTrusted": true,
        "chainId": 1337,
        "claimedSigner": "0x7e5f…",
        "recoveredSigner": "0x7e5F…",
        "messageHash": "0xc26441…"
      },
      "attributes": [],
      "expiresAtBlocks": 10,
      "approxExpiresInSeconds": 20
    }
  ]
}
```

Notes:

- `payload.text` is present only for non-reference payloads that are valid UTF-8.
- When `contentType` is the reference type but the payload does not parse, the
  operation includes `referenceError` instead of `payloadReference`.
- `approxExpiresInSeconds` assumes the 2-second Arkiv block time; the on-chain
  value is `expiresAtBlocks`.
- For a serialized transaction the response also includes `to`, plus a
  `warning` when the target is not the Arkiv registry address.
- Decoding and bad-request errors return `400` with
  `{ "ok": false, "error": { "message": "…" } }`.

## Packaging

```bash
scripts/package.sh
```

Builds with `cargo build --locked --profile release`, stages the binary with
the README and deployment docs, and writes
`dist/atlas-transaction-decoder-<version>-<target>.tar.gz` plus a `.sha256`.

## Docker

```bash
docker compose up --build
```

The GitHub Actions package workflow publishes Docker images to GitHub Packages:

```bash
docker pull ghcr.io/atlas-chain/atlas-transaction-decoder:main
```

See `instructions.md` for operator notes.
