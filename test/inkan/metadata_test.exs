defmodule Inkan.MetadataTest do
  use ExUnit.Case, async: true

  alias Inkan.{CBOR, Metadata}

  test "builds a labeled metadata map from friendly terms" do
    {:ok, metadata} =
      Metadata.build(7368, %{
        "v" => 1,
        "doc_sha256" => String.duplicate("a", 64),
        "raw" => {:bytes, <<1, 2, 3>>},
        "list" => [1, "two"]
      })

    assert {:map, [{7368, {:map, pairs}}]} = metadata

    # Deterministic key order (sorted), values normalized.
    assert [
             {{:text, "doc_sha256"}, {:text, _hash}},
             {{:text, "list"}, [1, {:text, "two"}]},
             {{:text, "raw"}, <<1, 2, 3>>},
             {{:text, "v"}, 1}
           ] = pairs
  end

  test "the same term always hashes identically" do
    {:ok, a} = Metadata.build(1, %{"b" => 2, "a" => 1})
    {:ok, b} = Metadata.build(1, %{"a" => 1, "b" => 2})

    assert Metadata.hash(a) == Metadata.hash(b)
  end

  test "enforces the ledger's limits" do
    assert {:error, {:too_long, _}} = Metadata.build(1, String.duplicate("a", 65))
    assert {:error, {:too_long, _}} = Metadata.build(1, {:bytes, :binary.copy(<<0>>, 65)})
    assert {:error, {:int_out_of_range, _}} = Metadata.build(1, 2 ** 64)
    assert {:error, {:unsupported, _}} = Metadata.build(1, :atom)

    # 64 bytes exactly is legal — it's how a sha256 hex string travels.
    assert {:ok, _} = Metadata.build(1, String.duplicate("f", 64))
  end

  test "serializes to the Shelley auxiliary-data shape" do
    {:ok, metadata} = Metadata.build(674, %{"msg" => ["hello"]})

    decoded = metadata |> Metadata.serialize() |> CBOR.decode!()
    assert {:map, [{674, {:map, [{{:text, "msg"}, [{:text, "hello"}]}]}}]} = decoded
  end
end
