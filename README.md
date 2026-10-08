# Inkan 印鑑

**Build, sign, and submit Cardano transactions from Elixir.**

An *inkan* is the registered seal that makes a document official in Japan.
This library is that seal for the Cardano blockchain: a small, carefully
verified Elixir core for putting payments and metadata on chain — no Node
sidecar, no wallet backend, no WASM.

Built and maintained by [Inkwright, Inc.](https://inkwright.inc), which runs
its document-proof service on it in production.

## Scope — a promise, not a roadmap

Inkan deliberately does a few things and aims to do them flawlessly:

- **Keys & addresses** — BIP-39 mnemonics, CIP-1852 / BIP32-Ed25519 key
  derivation, Shelley base & enterprise addresses.
- **Transactions** — build, balance, and fee a payment transaction in the
  current era; attach transaction metadata (CIP-20 and friends); sign and
  serialize to CBOR.
- **Providers** — a behaviour for chain access with a Blockfrost
  implementation: protocol parameters, UTxOs, submission, confirmation.

Explicitly **out of scope** (today, and honestly maybe forever): Plutus
scripts, minting, staking/governance certificates, chain indexing. A narrow
library that is correct and maintained beats a sprawling one that is
neither. If the scope grows, it grows because something in production needs
it.

## Correctness

Every cryptographic and serialization component is verified against
reference implementations and published test vectors, and the test suite
replays real on-chain transactions byte for byte. See `test/` — the vectors
ship with the library.

## Status

Pre-release. The Phase 0 correctness spike (CBOR round-trips of real
transactions, CIP-1852 derivation vectors) lives in the test suite; the
public API is not yet stable.

## Installation

```elixir
def deps do
  [
    {:inkan, "~> 0.1"}
  ]
end
```

## License

MIT © Inkwright, Inc.
