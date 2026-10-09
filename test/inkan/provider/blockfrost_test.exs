defmodule Inkan.Provider.BlockfrostTest do
  use ExUnit.Case, async: true

  alias Inkan.Provider.Blockfrost

  defp config do
    Blockfrost.config("preprod_test_key", :preprod, plug: {Req.Test, __MODULE__})
  end

  test "protocol_params merges fee parameters with the tip slot" do
    Req.Test.stub(__MODULE__, fn conn ->
      case conn.request_path do
        "/api/v0/epochs/latest/parameters" ->
          Req.Test.json(conn, %{"min_fee_a" => 44, "min_fee_b" => 155_381})

        "/api/v0/blocks/latest" ->
          Req.Test.json(conn, %{"slot" => 123_456_789})
      end
    end)

    assert {:ok, %{min_fee_a: 44, min_fee_b: 155_381, slot: 123_456_789}} =
             Blockfrost.protocol_params(config())
  end

  test "utxos keeps only plain ADA outputs" do
    Req.Test.stub(__MODULE__, fn conn ->
      assert conn.request_path =~ "/addresses/addr_test1xyz/utxos"
      assert Plug.Conn.get_req_header(conn, "project_id") == ["preprod_test_key"]

      Req.Test.json(conn, [
        %{
          "tx_hash" => "aa" <> String.duplicate("0", 62),
          "output_index" => 0,
          "amount" => [%{"unit" => "lovelace", "quantity" => "42000000"}],
          "inline_datum" => nil,
          "reference_script_hash" => nil
        },
        # Carries a native asset — must be excluded.
        %{
          "tx_hash" => "bb" <> String.duplicate("0", 62),
          "output_index" => 1,
          "amount" => [
            %{"unit" => "lovelace", "quantity" => "2000000"},
            %{"unit" => "deadbeef.token", "quantity" => "7"}
          ],
          "inline_datum" => nil,
          "reference_script_hash" => nil
        },
        # Carries an inline datum — must be excluded.
        %{
          "tx_hash" => "cc" <> String.duplicate("0", 62),
          "output_index" => 2,
          "amount" => [%{"unit" => "lovelace", "quantity" => "3000000"}],
          "inline_datum" => "d87980",
          "reference_script_hash" => nil
        }
      ])
    end)

    assert {:ok, [utxo]} = Blockfrost.utxos(config(), "addr_test1xyz")
    assert utxo.lovelace == 42_000_000
    assert utxo.index == 0
  end

  test "submit posts CBOR and returns the transaction id" do
    Req.Test.stub(__MODULE__, fn conn ->
      assert conn.request_path == "/api/v0/tx/submit"
      assert Plug.Conn.get_req_header(conn, "content-type") == ["application/cbor"]
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert body == <<0x84, 1, 2, 3>>

      Plug.Conn.send_resp(conn, 200, ~s("abc123"))
    end)

    assert {:ok, "abc123"} = Blockfrost.submit(config(), <<0x84, 1, 2, 3>>)
  end

  test "submit surfaces Blockfrost rejections" do
    Req.Test.stub(__MODULE__, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(400, ~s({"message": "transaction read error"}))
    end)

    assert {:error, {:blockfrost, 400, _body}} = Blockfrost.submit(config(), <<0x84>>)
  end

  test "tx_status maps 404 to :pending and 200 to block facts" do
    Req.Test.stub(__MODULE__, fn conn ->
      if conn.request_path =~ "pending" do
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(404, ~s({"status_code": 404}))
      else
        Req.Test.json(conn, %{"block_height" => 3_200_000, "block_time" => 1_760_000_000})
      end
    end)

    assert :pending = Blockfrost.tx_status(config(), "pending_tx")

    assert {:confirmed, %{block_height: 3_200_000, block_time: %DateTime{}}} =
             Blockfrost.tx_status(config(), "confirmed_tx")
  end

  test "transport errors surface as error tuples" do
    Req.Test.stub(__MODULE__, fn conn ->
      Req.Test.transport_error(conn, :econnrefused)
    end)

    assert {:error, %Req.TransportError{reason: :econnrefused}} =
             Blockfrost.protocol_params(config())

    assert {:error, %Req.TransportError{}} = Blockfrost.submit(config(), <<0x84>>)
    assert {:error, %Req.TransportError{}} = Blockfrost.tx_status(config(), "tx")
  end

  test "non-404 API errors from tx_status are surfaced, not treated as pending" do
    Req.Test.stub(__MODULE__, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(429, ~s({"message": "rate limited"}))
    end)

    assert {:error, {:blockfrost, 429, _}} = Blockfrost.tx_status(config(), "tx")
  end

  test "config/3 rejects unknown networks at construction time" do
    assert_raise FunctionClauseError, fn -> Blockfrost.config("key", :devnet) end
  end
end
