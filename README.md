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

Pre-release; the full scope above is implemented and verified (see
Correctness), through to the one-call flow:

```elixir
{:ok, wallet} = Inkan.Wallet.from_mnemonic(mnemonic, :mainnet)
config = Inkan.Provider.Blockfrost.config(blockfrost_project_id, :mainnet)

{:ok, tx_id} =
  Inkan.anchor(Inkan.Provider.Blockfrost, config, wallet, 7368, %{
    "doc_sha256" => sha256_hex
  })
```

Remaining before 0.1.0 on hex: a live preprod rehearsal and API-stability
review. The public API may still shift until then.

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
