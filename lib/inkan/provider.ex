defmodule Inkan.Provider do
  @moduledoc """
  Chain access, as a behaviour — building and signing are pure, and
  everything that touches the network funnels through these four calls, so
  swapping Blockfrost for Koios, Maestro, or a stub is one module.

  Implementations receive their own config term (API key, base URL,
  whatever they need) as the first argument of every callback.
  """

  @typedoc "Implementation-specific configuration, e.g. a Blockfrost project id."
  @type config :: term()

  @typedoc """
  The protocol facts building needs. `slot` is the current tip slot (for
  TTLs); fee parameters feed `Inkan.Transaction.build/2`.
  """
  @type protocol_params :: %{
          min_fee_a: non_neg_integer(),
          min_fee_b: non_neg_integer(),
          slot: non_neg_integer()
        }

  @typedoc "A spendable ADA-only UTxO at an address."
  @type utxo :: %{tx_id: String.t(), index: non_neg_integer(), lovelace: non_neg_integer()}

  @callback protocol_params(config()) :: {:ok, protocol_params()} | {:error, term()}

  @doc """
  The ADA-only UTxOs at an address. Implementations must *exclude* UTxOs
  carrying native assets or datums — spending those with an ADA-only
  change output would burn the assets, and that must be structurally
  impossible from this library.
  """
  @callback utxos(config(), address :: String.t()) :: {:ok, [utxo()]} | {:error, term()}

  @callback submit(config(), tx_cbor :: binary()) ::
              {:ok, tx_id :: String.t()} | {:error, term()}

  @doc "Confirmation status: block facts once the transaction is in a block."
  @callback tx_status(config(), tx_id :: String.t()) ::
              {:confirmed, %{block_height: non_neg_integer(), block_time: DateTime.t()}}
              | :pending
              | {:error, term()}
end
