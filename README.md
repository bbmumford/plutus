# plutus

plutus is a commerce protocol for peer-to-peer payments: a wallet, signed
per-chain currency adapters (EVM USDC and Bitcoin), non-custodial on-chain
escrow, deterministic settlement, and a witness protocol through which nodes
that cannot reach a chain verify its state. Every escrow pays a maintainer fee
fixed on-chain by the Protocol Registry Contract.

```sh
go get github.com/bbmumford/plutus
```

## API Docs

Generated API reference (pkgsite) for each tagged release is published to GitHub Pages:

- Latest: https://bbmumford.github.io/plutus/github.com/bbmumford/plutus/
- Published by `.github/workflows/docs.yml` on every `v*` tag.

## What Plutus Provides

| Capability | Description |
|---|---|
| **Wallet** | BIP39 seed, deterministic key hierarchy, encrypted storage, protocol-enforced signing |
| **Currency Adapters** | Maintainer-signed per-chain adapters (EVM USDC, BTC) |
| **Chain Witness Protocol** | Mesh-native blockchain verification via quorum attestations |
| **Escrow** | Non-custodial on-chain escrow with mandatory fee enforcement |
| **Settlement** | Deterministic fee calculation, multi-party payout orchestration |
| **WASM** | Full protocol stack runs in browser via WebAssembly |

## Architecture

```
Applications (a marketplace, any app)
    │
    ▼
Plutus (wallet, adapters, witnesses, escrow, settlement)
    │
    ├── whisper (witness gossip)
    ├── ledger (attestation records, the cache, on-chain storage proofs)
    └── diststore (blob fetch)
    │
    ▼
Blockchain (EVM, Bitcoin — via witness attestations)
```

## Fee Enforcement

Every escrow settlement extracts the maintainer fee at the smart contract level, at the rate the chain's PRC fixes:

1. **PRC** (Protocol Registry Contract) — immutable on-chain, stores fee BPS + maintainer pubkey
2. **Escrow contracts** — read fee from PRC at construction, extract before releasing
3. **Signed adapters** — wallets verify adapter signatures against PRC
4. **Witness attestation** — settlements are attested and auditable

One PRC per chain. All apps using Plutus share the same PRC. Universal fee collection.

## Protocol Registry Contract

`contracts/evm/ProtocolRegistry.sol` is the root of fee enforcement: one deployment per chain, shared by every escrow and app on that chain, with every parameter fixed at construction.

| Field | Meaning |
|---|---|
| `PROTOCOL_ID` | `"plutus-v1"` |
| `maintainerPayout` | the address every protocol fee is paid to; the zero address is refused |
| `maintainerFeeBPS` | the maintainer fee in basis points, at most 500 (5%) |
| `witnessBPS` | the witness attestation fee in basis points, at most 100 (1%) |
| `maintainerPubKeyHash` | SHA-256 of the maintainer's Ed25519 public key |
| `manifestHash` | the hash of the deployment manifest |

- The approved adapter hashes are set at construction (`isApprovedAdapter`); a new adapter set is a new PRC, authorised from the old one by a rotation certificate.
- `registerApp` records an app for analytics only; an unregistered app works the same.
- `distributeWindow` lands one fee-distribution window per chain and window id, first writer wins, and stores the Merkle root of the attestation log that earned it. `disputeDistribution` proves with a Merkle proof against that root that an attestation belongs to a landed window; it emits `DistributionDisputed` and settles nothing on-chain yet.

`PlutusEscrow` reads the payout address and both fees from the PRC when it is constructed. The buyer's `release` and an arbitrator's `settle` pay the maintainer fee before the seller's proceeds; the buyer can `refund` after the timeout. `maintainer/` and `cmd/plutus-ceremony` deploy and certify a PRC.

## Chain Witness Protocol

A node that cannot reach a chain's RPC (a browser running the WASM build, for one) verifies chain state through witnesses: nodes that query the chain and sign attestations, exchanged over Whisper on topics whose names carry the protocol fingerprint (`WitnessTopic` for registrations, `AttestRequestTopic` and `AttestResponseTopic`, `BroadcastTopic` and `BroadcastResponseTopic` for transaction broadcast, `ArbitratorTopic`). How many witnesses must answer and agree scales with the value at stake (`witness.PolicyForValue`):

| Tier | Value (USD) | Witnesses | Must agree | Timeout | Merkle proof |
|---|---|---|---|---|---|
| Quick | under 10 | 1 | 1 | 2 s | no |
| Standard | 10 to 100 | 3 | 2 | 5 s | no |
| High | 100 to 1,000 | 5 | 4 | 10 s | required |
| Maximum | 1,000 and over | 7 | 6 | 15 s | required |

Balance reads use `witness.BalancePolicy` (3 witnesses, 2 must agree, 5 s) unless the caller sets its own. `witness.CollusionDetector` tracks how often each pair of witnesses agrees and flags pairs whose agreement is suspiciously high.

## Packages

| package | what it holds |
|---|---|
| `plutus` | the SDK entry and the witness and arbitrator topic names |
| `wallet`, `evmsign`, `canonical`, `receipt` | the wallet (BIP39 seed, key hierarchy, encrypted storage, protocol-enforced signing), EIP-155 transaction signing, the hard-coded PRC addresses and trust-chain anchors, and signed receipts with their nonces and bundles |
| `adapter`, `adapter/evm`, `adapter/btc` | the currency adapter interface and the EVM and Bitcoin adapters (Bitcoin through neutrino) |
| `escrow`, `settle`, `arbitrator` | escrow lifecycles, fee calculation and payout, arbitrator registry and selection |
| `witness`, `reputation` | the chain witness protocol and witness reputation |
| `maintainer`, `cmd/plutus-ceremony` | deploying and certifying a PRC |
| `blob` | the storage-escrow client and the blob transport over diststore |
| `observability`, `observability/exporters` | tracing and metrics, and their OpenTelemetry exporters |
| `wasm`, `wasmratelimit` | the browser build and its rate limiter |
| `contracts/evm`, `contracts/btc` | the Solidity contracts (`ProtocolRegistry.sol`, `PlutusEscrow.sol`, `PlutusStorageEscrow.sol`, Foundry project) and the Bitcoin escrow script |
| `proto/plutus`, `internal/gossipstate` | the protobuf messages and the gossip state store |

## Dependencies

- `github.com/bbmumford/whisper`: the witness and arbitrator gossip.
- `github.com/bbmumford/ledger` (with `cache`): records and the directory cache.
- `github.com/bbmumford/diststore` (`fetch`, `onchain`): blob fetches, and the
  proof-of-storage and pinning surface the storage escrow client implements.
- `github.com/btcsuite/btcd` (with `btcutil`), `github.com/btcsuite/btcwallet/walletdb`,
  `github.com/lightninglabs/neutrino` and
  `github.com/decred/dcrd/dcrec/secp256k1/v4` for Bitcoin and secp256k1;
  OpenTelemetry (`go.opentelemetry.io/otel` and its exporters) and
  `github.com/prometheus/client_golang` for observability.
- `go.mod` replaces aether, whisper, ledger and diststore with the sibling
  checkouts `../aether`, `../whisper`, `../ledger` and `../diststore`.

## Used by

Importers in the ORBTR estate:

- `github.com/bbmumford/mercury` (its root package, `order`, `arbitration`,
  `reputation`, `runtime/mesh`, `cmd/mercury` and `cmd/mercury-node`, over
  `adapter`, `adapter/btc`, `adapter/evm`, `escrow`, `settle`, `wallet`,
  `witness`, `arbitrator`, `blob`, `reputation`, `observability`,
  `observability/exporters` and `wasmratelimit`): the marketplace pays and
  settles through plutus.

## Platforms and build

Pure Go, no cgo. `adapter/btc` and `observability/exporters` build everywhere
but js; `wasm` builds only for js/wasm. The Solidity contracts build and test
with Foundry (`contracts/evm/foundry.toml`). The module's `go` directive is
1.25.0. Releases are cut by release-please from conventional commits, and each
tag publishes the API reference to the repository's GitHub Pages site.

## Licence

MIT. Copyright (c) 2026 Brandon Miller-Mumford. The full text is in
[LICENSE](LICENSE).

## Contributing

[AGENTS.md](AGENTS.md) holds the repository's two rules, for people and coding
agents alike: no temporary documents in the repository, and conventional commit
messages that stand on their own. [CLAUDE.md](CLAUDE.md) imports it for Claude
Code; [CONTRIBUTING.md](CONTRIBUTING.md) has the commit and release
conventions.
