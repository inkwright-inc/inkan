defmodule Inkan.TransactionTest do
  use ExUnit.Case, async: true

  alias Inkan.{CBOR, Crypto, Metadata, Transaction, Wallet}

  # Any valid wallet works; this one is the first Phase-0 cross-checked vector.
  @mnemonic "luggage fitness dance distance stumble quiz ship destroy verify inform runway near cereal mixture play credit gaze evoke oil deputy pool quarter situate rural"

  # Mainnet's long-standing fee parameters.
  @protocol_params %{min_fee_a: 44, min_fee_b: 155_381}

  @input %{tx_id: String.duplicate("ab", 32), index: 1, lovelace: 10_000_000}

  defp wallet do
    {:ok, wallet} = Wallet.from_mnemonic(@mnemonic, :testnet)
    wallet
  end

  defp build(overrides \\ %{}) do
    params =
      Map.merge(
        %{
          inputs: [@input],
          change_address: Wallet.address(wallet()),
          metadata: {7368, %{"doc_sha256" => String.duplicate("c", 64), "v" => 1}},
          ttl: 155_000_000
        },
        overrides
      )

    Transaction.build(params, @protocol_params)
  end

  test "builds a balanced body whose fee matches the linear formula" do
    {:ok, tx} = build()

    {:map, body} = tx.body_term
    assert [[_tx_id_bytes, 1]] = :proplists.get_value(0, body)
    outputs = :proplists.get_value(1, body)
    fee = :proplists.get_value(2, body)
    assert :proplists.get_value(3, body) == 155_000_000

    # Balanced to the lovelace: inputs = outputs + fee.
    assert Enum.sum(Enum.map(outputs, fn [_addr, coin] -> coin end)) + fee == 10_000_000
    assert fee == tx.fee

    # The declared fee covers the signed size by exactly the formula.
    signed = Transaction.sign(tx, [wallet().payment])
    assert fee >= @protocol_params.min_fee_a * byte_size(signed.cbor) + @protocol_params.min_fee_b
  end

  test "records the auxiliary-data hash and ships the metadata" do
    {:ok, tx} = build()
    {:map, body} = tx.body_term

    {:ok, expected_aux} =
      Metadata.build(7368, %{"doc_sha256" => String.duplicate("c", 64), "v" => 1})

    assert :proplists.get_value(7, body) == Metadata.hash(expected_aux)

    signed = Transaction.sign(tx, [wallet().payment])
    assert [_body, _witnesses, true, aux] = CBOR.decode!(signed.cbor)
    assert aux == expected_aux
  end

  test "a metadata-free transaction has no aux hash and a null aux slot" do
    {:ok, tx} = build(%{metadata: nil})
    {:map, body} = tx.body_term

    refute :proplists.is_defined(7, body)

    signed = Transaction.sign(tx, [wallet().payment])
    assert [_body, _witnesses, true, nil] = CBOR.decode!(signed.cbor)
  end

  test "the witness signature verifies against the tx id with :crypto" do
    {:ok, tx} = build()
    signed = Transaction.sign(tx, [wallet().payment])

    assert [body_term, {:map, [{0, [[public, signature]]}]}, true, _aux] =
             CBOR.decode!(signed.cbor)

    # The id is the body hash, and the signature covers exactly that id.
    assert Crypto.blake2b_256(CBOR.encode(body_term)) == tx.tx_id
    assert signed.tx_id == Base.encode16(tx.tx_id, case: :lower)
    assert :crypto.verify(:eddsa, :none, tx.tx_id, signature, [public, :ed25519])
  end

  test "dust change is folded into the fee instead of becoming an output" do
    payment = %{address: Wallet.address(wallet()), lovelace: 5_000_000}

    # Leftover after the payment and fee is ~400k lovelace — under the dust
    # floor — so it must be burned into the fee, not output.
    {:ok, tx} =
      build(%{inputs: [%{@input | lovelace: 5_600_000}], payments: [payment]})

    {:map, body} = tx.body_term
    outputs = :proplists.get_value(1, body)
    fee = :proplists.get_value(2, body)

    assert length(outputs) == 1
    assert Enum.sum(Enum.map(outputs, fn [_a, c] -> c end)) + fee == 5_600_000
  end

  test "refuses a transaction that would end up with no outputs at all" do
    assert {:error, :no_outputs} =
             build(%{inputs: [%{@input | lovelace: 600_000}], metadata: nil, ttl: nil})
  end

  test "errors are explicit" do
    assert {:error, :insufficient_funds} = build(%{inputs: [%{@input | lovelace: 100_000}]})

    assert {:error, {:bad_address, "addr1garbage", _}} =
             build(%{payments: [%{address: "addr1garbage", lovelace: 1_000_000}]})
  end
end
