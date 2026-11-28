# Changelog

## [0.1.0](https://github.com/bbmumford/plutus/compare/v0.0.1...v0.1.0) (2026-11-28)


### ⚠ BREAKING CHANGES

* Plutus.createWallet answers a JSON object {"handle", "mnemonic"} instead of the bare handle.
* Limiter.SetNowFunc is removed, and Allow refuses an undeclared method instead of limiting it at the read default.
* CurrencyAdapter.CalculateFees returns (FeeBreakdown, error).

### Features

* reputation.DisputeRecord builds the record a dispute's arbitrator signs about each party ([43fc94f](https://github.com/bbmumford/plutus/commit/43fc94f616b8dd88dea5512352aa0cc1cef9ce0d))
* the browser bridge hands a wallet's mnemonic to the page once and gives it back only through exportIdentity under the page's passphrase ([fa97122](https://github.com/bbmumford/plutus/commit/fa9712244f152c04b1f5bd5a7e150b32012f1f35))
* the witness earning log and distribution store keep their records in one SQLite file stamped as a billing witness journal, read earnings through a settledAt index, and take in the JSON-lines journals already on disk ([253963f](https://github.com/bbmumford/plutus/commit/253963fb63bf1dbe05f976c12ba656916ff913e9))
* wasmratelimit's limits are ratelimit.Keyed buckets, and a method the bridge never declared is refused ([604bd75](https://github.com/bbmumford/plutus/commit/604bd75316043ef4270a9420054fd1178bd1bb1f))


### Bug Fixes

* a negative or unreadable value gets the strictest witness policy, never the one-witness tier ([1e98555](https://github.com/bbmumford/plutus/commit/1e98555b82abd454dde66834d7898c761e9359e8))
* a receipt's nonce and content hash must each have their fixed size, so no two field splits share a signed digest ([c8bb8ea](https://github.com/bbmumford/plutus/commit/c8bb8ea7ef1aac9080622342a6cd7299f3dad20d))
* bring the module under version control ([8d61250](https://github.com/bbmumford/plutus/commit/8d61250cd290d6bb8e9c7ccfe2d4e08cb92bdb76))
* BTC amounts are read as exact decimals into whole satoshis ([5072d40](https://github.com/bbmumford/plutus/commit/5072d408d3002f9940bd93d6a0a4e170dd89158b))
* chain adapters compute fees through settle.FeeCalculator ([932a63d](https://github.com/bbmumford/plutus/commit/932a63db2a239290ea32f4dee6e11ede213ee120))
* dependencies move past their reported vulnerabilities: OpenTelemetry v1.47.0, golang.org/x/net v0.63.0, gRPC v1.83.2 ([26fc7cc](https://github.com/bbmumford/plutus/commit/26fc7cc2633236f4b683aa62ca9b52221d20626d))
* field and reserved names are lowerCamelCase, and receipt.pb.go is generated from receipt.proto again ([3a83218](https://github.com/bbmumford/plutus/commit/3a83218506393e86165394aa00fc7e9658966e5b))
* go.mod requires ledger v0.1.0, whisper v0.0.20 and diststore v0.1.1, and Go 1.27.4 ([d6b121b](https://github.com/bbmumford/plutus/commit/d6b121b0cf4645cee1863e5e943f0a7e1ac9d936))
* go.mod requires the released ledger and diststore and keeps no replace of a sibling directory, so a checkout of this repository alone builds ([e65d60e](https://github.com/bbmumford/plutus/commit/e65d60e1489a91de7a0d9d03589625c3dda364e5))
* go.mod requires whisper v0.0.19, so the module builds read-only ([3c74741](https://github.com/bbmumford/plutus/commit/3c747410269c5362226e620ca1bd66c4f3b32efb))
* SplitWitnessFee counts a repeated attester once ([5e13f10](https://github.com/bbmumford/plutus/commit/5e13f107480fba0b8414d59f854c505198ba86ee))
* state sync admits a witness, arbitrator or reputation record only under the rule gossip applies ([29b38b8](https://github.com/bbmumford/plutus/commit/29b38b890919fc57a550135460d37d0926b3df4b))
* the arbitrator, reputation and witness state stores answer whisper's StateStore as the required whisper names it, with a fingerprint derived from the records ([44afba9](https://github.com/bbmumford/plutus/commit/44afba9283d0666338ab4310aa229f70f6ec2975))
* the settlement fee-total histogram records the fees paid, not the escrow amount ([4da7cdd](https://github.com/bbmumford/plutus/commit/4da7cddb365bd6dc14b46f9494dbbbd8fec1fe61))
* the witness fee remainder goes to the attester whose name sorts first, so every node computes the same split ([e8bf468](https://github.com/bbmumford/plutus/commit/e8bf4681ab2face35525953a5444a3d5d376aae9))
