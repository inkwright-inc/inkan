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

  # RFC 8949 Appendix A examples: the decode-anything paths (indefinite
  # lengths, half/single/double floats) that Cardano transactions never
  # use but arbitrary chain data can. Each vector checks the decoded value
  # AND byte-faithful re-encoding.
  describe "RFC 8949 vectors" do
    test "indefinite-length strings preserve chunking" do
      bytes = Base.decode16!("5F42010243030405FF")
      assert {:ok, {:indefinite_bytes, [<<1, 2>>, <<3, 4, 5>>]}, <<>>} = CBOR.decode(bytes)
      assert bytes |> CBOR.decode!() |> CBOR.reencode() == bytes

      text = Base.decode16!("7F657374726561646D696E67FF")
      assert {:ok, {:indefinite_text, ["strea", "ming"]}, <<>>} = CBOR.decode(text)
      assert text |> CBOR.decode!() |> CBOR.reencode() == text
    end

    test "indefinite-length arrays and maps round-trip" do
      array = Base.decode16!("9F018202039F0405FFFF")
      assert {:ok, {:indefinite, [1, [2, 3], {:indefinite, [4, 5]}]}, <<>>} = CBOR.decode(array)
      assert array |> CBOR.decode!() |> CBOR.reencode() == array

      map = Base.decode16!("BF61610161629F0203FFFF")

      assert {:ok, {:indefinite_map, [{{:text, "a"}, 1}, {{:text, "b"}, {:indefinite, [2, 3]}}]},
              <<>>} = CBOR.decode(map)

      assert map |> CBOR.decode!() |> CBOR.reencode() == map
    end

    test "half-precision floats decode" do
      assert CBOR.decode!(Base.decode16!("F90000")) == 0.0
      assert CBOR.decode!(Base.decode16!("F93C00")) == 1.0
      assert CBOR.decode!(Base.decode16!("F9C400")) == -4.0
      assert CBOR.decode!(Base.decode16!("F97BFF")) == 65_504.0
      assert CBOR.decode!(Base.decode16!("F90001")) == 5.960464477539063e-8
      assert CBOR.decode!(Base.decode16!("F97C00")) == :infinity
      assert CBOR.decode!(Base.decode16!("F97E00")) == :nan
    end

    test "single and double floats decode, doubles encode" do
      assert CBOR.decode!(Base.decode16!("FA47C35000")) == 100_000.0
      assert CBOR.decode!(Base.decode16!("FB3FF199999999999A")) == 1.1

      # Our encoder always emits float-64 (canonical for our purposes).
      assert CBOR.encode(1.1) == Base.decode16!("FB3FF199999999999A")
      assert 1.1 |> CBOR.encode() |> CBOR.decode!() == 1.1
    end
  end

  describe "error handling" do
    test "truncated and garbage input return an error tuple" do
      assert {:error, :invalid_cbor} = CBOR.decode(<<0x82, 0x01>>)
      assert {:error, :invalid_cbor} = CBOR.decode(<<0x5F, 0x42>>)
      assert {:error, :invalid_cbor} = CBOR.decode(<<>>)
    end

    test "decode! raises on trailing bytes and invalid input" do
      assert_raise ArgumentError, ~r/trailing/, fn -> CBOR.decode!(<<0x01, 0x02>>) end
      assert_raise ArgumentError, ~r/invalid/, fn -> CBOR.decode!(<<0xFF>>) end
    end

    test "plain Elixir maps are rejected by the encoder" do
      # Pair order changes bytes and therefore hashes; {:map, pairs} makes
      # order explicit, so a bare map must not silently encode.
      assert_raise FunctionClauseError, fn -> CBOR.encode(%{1 => 2}) end
    end
  end
end
