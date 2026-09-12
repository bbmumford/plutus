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

## Depends On

- **Aether** (`github.com/ORBTR/aether`) — wire protocol, transport
- **Whisper** (`github.com/bbmumford/whisper`) — gossip engine for witness attestations
- **Ledger** (`github.com/bbmumford/ledger`) — witness registry, attestation storage

## Consumed By

- **Mercury** (`github.com/bbmumford/mercury`) — decentralised marketplace
- Any Minerva app needing commerce
- Any web/native app needing P2P payments
