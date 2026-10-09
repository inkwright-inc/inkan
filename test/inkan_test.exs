defmodule InkanTest do
  use ExUnit.Case, async: true

  alias Inkan.{CBOR, Crypto, Metadata, Provider.Blockfrost, Wallet}

  @mnemonic "luggage fitness dance distance stumble quiz ship destroy verify inform runway near cereal mixture play credit gaze evoke oil deputy pool quarter situate rural"

  # End-to-end through the public API: Blockfrost stubbed at the HTTP
  # layer, everything else real. The submitted bytes are decoded and
  # checked — this is the exact round a production anchor makes.
  test "anchor/6 builds, signs, and submits a metadata self-payment" do
    {:ok, wallet} = Wallet.from_mnemonic(@mnemonic, :testnet)
    address = Wallet.address(wallet)
    test_pid = self()

    Req.Test.stub(__MODULE__, fn conn ->
      case conn.request_path do
        "/api/v0/epochs/latest/parameters" ->
          Req.Test.json(conn, %{"min_fee_a" => 44, "min_fee_b" => 155_381})

        "/api/v0/blocks/latest" ->
          Req.Test.json(conn, %{"slot" => 100_000_000})

        "/api/v0/addresses/" <> rest ->
          assert rest == address <> "/utxos"

          Req.Test.json(conn, [
            %{
              "tx_hash" => String.duplicate("ab", 32),
              "output_index" => 0,
              "amount" => [%{"unit" => "lovelace", "quantity" => "5000000"}],
              "inline_datum" => nil,
              "reference_script_hash" => nil
            }
          ])

        "/api/v0/tx/submit" ->
          {:ok, body, conn} = Plug.Conn.read_body(conn)
          send(test_pid, {:submitted, body})

          tx_id =
            body
            |> CBOR.decode!()
            |> hd()
            |> CBOR.encode()
            |> Crypto.blake2b_256()
            |> Base.encode16(case: :lower)

          Plug.Conn.send_resp(conn, 200, ~s("#{tx_id}"))
      end
    end)

    config = Blockfrost.config("key", :preprod, plug: {Req.Test, __MODULE__})

    assert {:ok, tx_id} =
             Inkan.anchor(Blockfrost, config, wallet, 7368, %{
               "doc_sha256" => String.duplicate("e", 64),
               "v" => 1
             })

    assert_received {:submitted, submitted_cbor}

    # The submitted transaction is exactly what we claim: body hashing to
    # the returned id, our metadata aboard, TTL an hour past the tip.
    assert [body_term, _witnesses, true, aux] = CBOR.decode!(submitted_cbor)
    assert Crypto.blake2b_256(CBOR.encode(body_term)) == Base.decode16!(tx_id, case: :lower)

    {:ok, expected_aux} =
      Metadata.build(7368, %{"doc_sha256" => String.duplicate("e", 64), "v" => 1})

    assert aux == expected_aux

    {:map, body} = body_term
    assert :proplists.get_value(3, body) == 100_000_000 + 3600
    assert :proplists.get_value(7, body) == Metadata.hash(expected_aux)
  end

  test "anchor/6 refuses when the wallet can't cover a safe anchor" do
    {:ok, wallet} = Wallet.from_mnemonic(@mnemonic, :testnet)

    Req.Test.stub(__MODULE__, fn conn ->
      case conn.request_path do
        "/api/v0/epochs/latest/parameters" ->
          Req.Test.json(conn, %{"min_fee_a" => 44, "min_fee_b" => 155_381})

        "/api/v0/blocks/latest" ->
          Req.Test.json(conn, %{"slot" => 100_000_000})

        "/api/v0/addresses/" <> _rest ->
          Req.Test.json(conn, [])
      end
    end)

    config = Blockfrost.config("key", :preprod, plug: {Req.Test, __MODULE__})

    assert {:error, {:wallet_balance_too_low, 0}} =
             Inkan.anchor(Blockfrost, config, wallet, 1, %{"x" => 1})
  end

  test "select_inputs picks largest-first until covered" do
    utxos = [
      %{tx_id: "aa", index: 0, lovelace: 1_000_000},
      %{tx_id: "bb", index: 0, lovelace: 2_000_000},
      %{tx_id: "cc", index: 0, lovelace: 1_500_000}
    ]

    assert {:ok, [%{tx_id: "bb"}, %{tx_id: "cc"}]} = Inkan.select_inputs(utxos)
  end
end
