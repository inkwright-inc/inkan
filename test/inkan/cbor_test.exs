defmodule Inkan.CBORTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Inkan.CBOR
  alias Inkan.Crypto

  # Real Conway-era mainnet transactions, fetched from the chain via Koios
  # (block 14,043,242; see test/fixtures/mainnet_txs.json for provenance
  # fields). These are the ground truth for serialization: the network
  # accepted these exact bytes, and each tx id is the BLAKE2b-256 of the
  # body's exact serialization.
  @fixtures "test/fixtures/mainnet_txs.json"
            |> File.read!()
            |> :json.decode()

  test "re-encodes real on-chain transactions byte for byte" do
    for %{"tx_hash" => hash, "cbor" => cbor_hex} <- @fixtures do
      original = Base.decode16!(cbor_hex, case: :mixed)

      assert {:ok, decoded, <<>>} = CBOR.decode(original)
      assert CBOR.reencode(decoded) == original, "re-encode mismatch for tx #{hash}"
    end
  end

  test "recomputes each transaction id from the decoded body" do
    for %{"tx_hash" => hash, "cbor" => cbor_hex} <- @fixtures do
      original = Base.decode16!(cbor_hex, case: :mixed)

      # A transaction is [body, witness_set, is_valid, auxiliary_data];
      # the id is the hash of the body's serialization alone.
      {:ok, [body | _rest], <<>>} = CBOR.decode(original)

      computed = body |> CBOR.reencode() |> Crypto.blake2b_256() |> Base.encode16(case: :lower)

      assert computed == hash
    end
  end

  property "round-trips arbitrary nested terms" do
    term_gen =
      StreamData.tree(
        StreamData.one_of([
          StreamData.integer(-1_000_000_000_000..1_000_000_000_000),
          StreamData.binary(max_length: 40),
          StreamData.map(StreamData.string(:utf8, max_length: 20), &{:text, &1}),
          StreamData.boolean(),
          StreamData.constant(nil)
        ]),
        fn leaf ->
          StreamData.one_of([
            StreamData.list_of(leaf, max_length: 5),
            StreamData.map(
              StreamData.list_of(StreamData.tuple({leaf, leaf}), max_length: 5),
              &{:map, &1}
            ),
            StreamData.map(
              StreamData.tuple({StreamData.integer(0..1000), leaf}),
              fn {tag, value} -> {:tag, tag, value} end
            )
          ])
        end
      )

    check all(term <- term_gen, max_runs: 200) do
      encoded = CBOR.encode(term)
      assert {:ok, decoded, <<>>} = CBOR.decode(encoded)
      assert decoded == term
      assert CBOR.reencode(decoded) == encoded
    end
  end

  test "encodes canonical shortest-form heads" do
    assert CBOR.encode(0) == <<0x00>>
    assert CBOR.encode(23) == <<0x17>>
    assert CBOR.encode(24) == <<0x18, 24>>
    assert CBOR.encode(255) == <<0x18, 255>>
    assert CBOR.encode(256) == <<0x19, 1, 0>>
    assert CBOR.encode(-1) == <<0x20>>
    assert CBOR.encode(1_000_000) == <<0x1A, 0x00, 0x0F, 0x42, 0x40>>
  end
end
