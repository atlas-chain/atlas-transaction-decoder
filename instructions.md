# Atlas Transaction Decoder Integration

Run `atlas-transaction-decoder` as a small HTTP service next to Atlas tooling
that needs to inspect Arkiv transactions. It decodes `execute(Operation[])`
calldata (or a signed transaction wrapping it) into readable operations and, for
reference-mode create/update operations, parses and verifies the embedded
payload reference offline.

The default local endpoint is:

```text
http://<host>:28884
```

## Required Runtime Configuration

```env
LISTEN_HOST=0.0.0.0
LISTEN_PORT=28884
HTML_TITLE="Atlas Transaction Decoder"
MAX_INPUT_BYTES=2097152
DEFAULT_CHAIN_ID=1337
TRUSTED_PROVIDER_SIGNERS=
```

`DEFAULT_CHAIN_ID` is the chain id used when a request omits `chainId`. It only
affects whether the dev-chain provider signer
(`0x7e5f4552091a69125d5dfcb7b8c2659029395bdf`) is trusted; the production signer
(`0xbdd23fd1bab3f4075edef4738d1d78a6bc5c236c`) is trusted on every chain. Set
`DEFAULT_CHAIN_ID=42069` for the public Atlas chain, or leave it at `1337` for
local dev chains. Add operator-controlled signers with
`TRUSTED_PROVIDER_SIGNERS` (comma-separated 0x addresses).

## API Shape

Decode `execute()` calldata or a signed transaction:

```bash
curl -X POST http://localhost:28884/decode \
  -H 'content-type: application/json' \
  -d '{"data": "0x<hex>", "chainId": 1337}'
```

Raw hex also works as `text/plain`, and `GET /decode?data=0x...&chainId=1337`
mirrors the POST. Health and configuration:

```text
GET /healthz
GET /status
```

## How reference verification works

For create/update operations whose `contentType` is
`application/vnd.atlas.payload-reference+json`, the `payload` is a v1 payload
reference JSON. The decoder:

1. Parses the reference (`id`, `namespace`, `checksum`, `sizeBytes`,
   `submittedAt`, `nonce`, `payment`, `signature`).
2. Rebuilds the canonical provider receipt from the reference metadata.
3. Computes the EIP-191 message hash, recovers the secp256k1 signer, and checks
   the recovered signer against the trusted allowlist for the chain.

The verdict (`referenceVerification.valid` / `signerTrusted`) mirrors what the
on-chain Arkiv precompile would accept. The decoder performs no network calls
and does not resolve the original payload body from the payload provider;
fetching and checksum-verifying the body against
`GET <provider>/payloads/<id>/raw` is left to the caller.

## Docker Compose Example

```yaml
services:
  transaction-decoder:
    image: ghcr.io/atlas-chain/atlas-transaction-decoder:main
    ports:
      - "28884:28884"
    environment:
      LISTEN_HOST: "0.0.0.0"
      LISTEN_PORT: "28884"
      HTML_TITLE: "Atlas Transaction Decoder"
      MAX_INPUT_BYTES: "2097152"
      DEFAULT_CHAIN_ID: "1337"
      TRUSTED_PROVIDER_SIGNERS: ""
    restart: unless-stopped
```

## Operating Notes

- The service is stateless — no storage, no persistence. Scale horizontally.
- Use `/healthz` for liveness checks and `/status` to confirm the active chain
  id and trusted-signer configuration.
- Increase `MAX_INPUT_BYTES` only when callers legitimately submit larger
  serialized transactions.
- The ABI mirror and reference rules track
  `atlas-reth/crates/arkiv-node/src/precompile.rs` and the Arkiv SDK. Keep them
  in sync if the on-chain operation shape or reference format changes.
