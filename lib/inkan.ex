defmodule Inkan do
  @moduledoc """
  印鑑 — build, sign, and submit Cardano transactions from Elixir.

  The low-level pieces are their own modules (`Inkan.Wallet`,
  `Inkan.Transaction`, `Inkan.Metadata`, `Inkan.Provider`); this module
  offers the highest-level story in one call: anchoring metadata on chain
  from a wallet, the way a proof-of-existence or audit-log service uses
  Cardano.

      {:ok, wallet} = Inkan.Wallet.from_mnemonic(mnemonic, :preprod_or_mainnet_network_tag)
      config = Inkan.Provider.Blockfrost.config(project_id, :preprod)

      {:ok, tx_id} =
        Inkan.anchor(Inkan.Provider.Blockfrost, config, wallet, 7368, %{
          "doc_sha256" => sha256_hex,
          "v" => 1
        })

  The transaction is a minimal self-payment: the wallet pays itself,
  change returns to it, and only the fee (~0.2 ADA) is spent. Confirmation
  is the caller's affair — poll `provider.tx_status/2` on its own
  schedule (OTP retry machinery stays out of this library by design).
  """

  alias Inkan.{Transaction, Wallet}

  # A self-anchor needs change above the dust floor plus fee headroom.
  @min_input_lovelace 2_500_000

  # One hour of leeway for submission and block inclusion.
  @ttl_slots 3600

  @doc """
  Anchors `{label, metadata}` on chain from `wallet`, via `provider`.

  Selects the largest spendable UTxOs until ~#{@min_input_lovelace} lovelace
  is covered, builds a self-payment carrying the metadata, signs with the
  wallet's payment key, and submits. Returns the transaction id, which is
  known from the body hash — so it is stable whether or not submission's
  response ever arrives.
  """
  def anchor(provider, config, %Wallet{} = wallet, label, metadata, opts \\ []) do
    address = Wallet.address(wallet)

    with {:ok, params} <- provider.protocol_params(config),
         {:ok, utxos} <- provider.utxos(config, address),
         {:ok, inputs} <- select_inputs(utxos),
         {:ok, tx} <-
           Transaction.build(
             %{
               inputs: inputs,
               payments: [],
               change_address: address,
               metadata: {label, metadata},
               ttl: params.slot + Keyword.get(opts, :ttl_slots, @ttl_slots)
             },
             params
           ) do
      signed = Transaction.sign(tx, [wallet.payment])

      with {:ok, submitted_id} <- provider.submit(config, signed.cbor) do
        # Trust our own hash; a disagreeing provider is a serious bug.
        if submitted_id != signed.tx_id do
          {:error, {:tx_id_mismatch, ours: signed.tx_id, provider: submitted_id}}
        else
          {:ok, signed.tx_id}
        end
      end
    end
  end

  @doc false
  def select_inputs(utxos) do
    sorted = Enum.sort_by(utxos, & &1.lovelace, :desc)

    {selected, total} =
      Enum.reduce_while(sorted, {[], 0}, fn utxo, {acc, sum} ->
        if sum >= @min_input_lovelace do
          {:halt, {acc, sum}}
        else
          {:cont, {[utxo | acc], sum + utxo.lovelace}}
        end
      end)

    if total >= @min_input_lovelace do
      {:ok, Enum.reverse(selected)}
    else
      {:error, {:wallet_balance_too_low, total}}
    end
  end
end
