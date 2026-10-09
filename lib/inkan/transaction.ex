defmodule Inkan.Transaction do
  @moduledoc """
  Building, balancing, and signing a Cardano payment transaction.

  The shape built here is the plainest the ledger accepts — ADA-only
  inputs/outputs, optional metadata, a TTL — which is exactly Inkan's scope.
  A body is a CBOR map with integer keys (0 inputs, 1 outputs, 2 fee,
  3 ttl, 7 auxiliary-data hash); the full transaction is
  `[body, witness_set, is_valid, auxiliary_data]`; the transaction id is
  the BLAKE2b-256 of the body's serialization, and that id is what each
  witness signs.

  ## Balancing

  `build/2` computes the fee from the protocol parameters' linear formula
  (`a·size + b`) and returns the change to the change address. Fee and
  change amounts feed back into the serialized size, so the build iterates
  until the fee is stable — in practice two passes. Change smaller than
  `small_change_floor` lovelace is folded into the fee instead of creating
  a dust output the ledger would reject.

  ## Example

      {:ok, wallet} = Inkan.Wallet.from_mnemonic(mnemonic, :testnet)

      {:ok, tx} =
        Inkan.Transaction.build(
          %{
            inputs: [%{tx_id: utxo_id_hex, index: 0, lovelace: 10_000_000}],
            payments: [],
            change_address: Inkan.Wallet.address(wallet),
            metadata: {7368, %{"doc_sha256" => hash_hex}},
            ttl: tip_slot + 3600
          },
          protocol_params
        )

      signed = Inkan.Transaction.sign(tx, [wallet.payment])
      # => %{cbor: <<...>>, tx_id: "..."} ready for Provider.submit/2
  """

  alias Inkan.{Address, CBOR, Crypto, Ed25519, Metadata}

  @enforce_keys [:body_term, :tx_id, :fee, :auxiliary_data]
  defstruct [:body_term, :tx_id, :fee, :auxiliary_data]

  @type protocol_params :: %{
          required(:min_fee_a) => non_neg_integer(),
          required(:min_fee_b) => non_neg_integer(),
          optional(:small_change_floor) => non_neg_integer()
        }

  @type t :: %__MODULE__{}

  # Below this, change is dust: folded into the fee rather than output.
  # ~1 ADA covers the ledger's min-UTxO for a plain output with headroom.
  @default_small_change_floor 1_200_000

  # Signed-size headroom: a vkey witness is a fixed 102 bytes of CBOR
  # (array + 32-byte key + 64-byte signature + framing); fees must be
  # computed over the *signed* size.
  @witness_bytes 102

  @doc """
  Builds and balances an unsigned transaction. See the module doc for the
  parameter shape; `payments` is a list of `%{address: bech32, lovelace: n}`
  for third-party outputs (empty for a self-anchor), and all input values
  must be supplied (the provider's UTxO listing has them).
  """
  def build(params, protocol_params) do
    %{inputs: inputs, change_address: change_address} = params
    payments = Map.get(params, :payments, [])
    ttl = Map.get(params, :ttl)

    with {:ok, aux} <- build_aux(Map.get(params, :metadata)),
         {:ok, change_addr_bytes} <- Address.decode(change_address),
         {:ok, payment_outputs} <- payment_outputs(payments) do
      total_in = Enum.sum(Enum.map(inputs, & &1.lovelace))
      total_paid = Enum.sum(Enum.map(payments, & &1.lovelace))
      floor = Map.get(protocol_params, :small_change_floor, @default_small_change_floor)

      balance_loop(
        %{
          inputs: inputs,
          payment_outputs: payment_outputs,
          change_addr_bytes: change_addr_bytes,
          available: total_in - total_paid,
          ttl: ttl,
          aux: aux,
          floor: floor
        },
        protocol_params,
        # Fee seed: anything stable-ish; the loop converges regardless.
        170_000,
        5
      )
    end
  end

  defp balance_loop(_ctx, _pp, _fee, 0), do: {:error, :fee_did_not_converge}

  defp balance_loop(ctx, protocol_params, fee_guess, attempts) do
    with {:ok, body_term} <- body_term(ctx, fee_guess) do
      size = byte_size(CBOR.encode(body_term)) + @witness_bytes + aux_size(ctx.aux) + 4
      fee = protocol_params.min_fee_a * size + protocol_params.min_fee_b

      cond do
        ctx.available - fee < 0 ->
          {:error, :insufficient_funds}

        fee == fee_guess ->
          body_bytes = CBOR.encode(body_term)

          {:ok,
           %__MODULE__{
             body_term: body_term,
             tx_id: Crypto.blake2b_256(body_bytes),
             fee: actual_fee(ctx, fee),
             auxiliary_data: ctx.aux
           }}

        true ->
          balance_loop(ctx, protocol_params, fee, attempts - 1)
      end
    end
  end

  # When change is dust it is burned into the fee, so the declared fee must
  # absorb it for the transaction to balance exactly.
  defp actual_fee(ctx, fee) do
    change = ctx.available - fee
    if change >= ctx.floor, do: fee, else: fee + change
  end

  defp body_term(ctx, fee) do
    change = ctx.available - fee

    if change < 0 do
      {:error, :insufficient_funds}
    else
      outputs =
        if change >= ctx.floor do
          ctx.payment_outputs ++ [[ctx.change_addr_bytes, change]]
        else
          ctx.payment_outputs
        end

      if outputs == [] do
        {:error, :no_outputs}
      else
        declared_fee = if change >= ctx.floor, do: fee, else: fee + change

        body =
          [
            {0, Enum.map(ctx.inputs, &[Base.decode16!(&1.tx_id, case: :mixed), &1.index])},
            {1, outputs},
            {2, declared_fee}
          ] ++
            if(ctx.ttl, do: [{3, ctx.ttl}], else: []) ++
            if ctx.aux do
              [{7, Metadata.hash(ctx.aux)}]
            else
              []
            end

        {:ok, {:map, body}}
      end
    end
  end

  defp build_aux(nil), do: {:ok, nil}

  defp build_aux({label, term}), do: Metadata.build(label, term)

  defp aux_size(nil), do: 0
  defp aux_size(aux), do: byte_size(Metadata.serialize(aux))

  defp payment_outputs(payments) do
    Enum.reduce_while(payments, {:ok, []}, fn %{address: address, lovelace: lovelace},
                                              {:ok, acc} ->
      case Address.decode(address) do
        {:ok, bytes} -> {:cont, {:ok, [[bytes, lovelace] | acc]}}
        {:error, reason} -> {:halt, {:error, {:bad_address, address, reason}}}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end
  end

  @doc """
  Signs a built transaction with one or more extended private keys
  (typically just the wallet's payment key) and serializes the full
  transaction, ready for submission.

  Returns `%{cbor: binary, tx_id: hex}` — the id is fixed by the body, so
  it is known before submission and can be stored ahead of confirmation.
  """
  def sign(%__MODULE__{} = tx, keys) when is_list(keys) and keys != [] do
    witnesses =
      Enum.map(keys, fn {kl, kr, _cc} = _xprv ->
        public = Ed25519.public_key_from_scalar(kl)
        [public, Ed25519.sign_extended(tx.tx_id, kl, kr)]
      end)

    full = [tx.body_term, {:map, [{0, witnesses}]}, true, tx.auxiliary_data]

    %{cbor: CBOR.encode(full), tx_id: Base.encode16(tx.tx_id, case: :lower)}
  end
end
