# Plutus — Universal Commerce Protocol

> `github.com/bbmumford/plutus`

Plutus is a universal commerce protocol for peer-to-peer payments, non-custodial escrow, and chain-agnostic settlement. Any application can integrate Plutus for commerce with automatic, immutable maintainer fee extraction.

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
Applications (Mercury, freelance, subscription, any app)
    │
    ▼
Plutus (wallet, adapters, witnesses, escrow, settlement)
    │
    ├── Aether (transport)
    ├── Whisper (witness gossip)
    └── Ledger (attestation storage)
    │
    ▼
Blockchain (EVM, Bitcoin — via witness attestations)
```

## Fee Enforcement

Every escrow settlement extracts a 1% maintainer fee at the smart contract level:

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

## Depends On

- **Aether** (`github.com/ORBTR/aether`) — wire protocol, transport
- **Whisper** (`github.com/bbmumford/whisper`) — gossip engine for witness attestations
- **Ledger** (`github.com/bbmumford/ledger`) — witness registry, attestation storage

## Consumed By

- **Mercury** (`github.com/bbmumford/mercury`) — decentralised marketplace
- Any Minerva app needing commerce
- Any web/native app needing P2P payments
