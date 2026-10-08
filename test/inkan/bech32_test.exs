defmodule Inkan.Bech32Test do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Inkan.Bech32

  # Valid test strings from BIP-173 itself.
  @valid_bip173 [
    "A12UEL5L",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
  ]

  test "decodes the BIP-173 valid vectors and re-encodes them unchanged" do
    for bech <- @valid_bip173 do
      assert {:ok, hrp, bytes} = Bech32.decode(bech)
      assert Bech32.encode(hrp, bytes) == String.downcase(bech)
    end
  end

  test "rejects tampering, mixed case, and missing separators" do
    assert {:error, :bad_checksum} =
             Bech32.decode("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3x")

    assert {:error, :mixed_case} = Bech32.decode("A12uEL5L")
    assert {:error, :no_separator} = Bech32.decode("pzry9x0s3jn54khce6mua7l")
  end

  # Cardano addresses blow past BIP-173's 90-character cap; the whole reason
  # this module exists is that encoding must survive that.
  property "round-trips arbitrary payloads, including address-sized and longer" do
    check all(
            hrp <- StreamData.member_of(["addr", "addr_test", "stake", "a1b"]),
            bytes <- StreamData.binary(min_length: 1, max_length: 200),
            max_runs: 100
          ) do
      encoded = Bech32.encode(hrp, bytes)
      assert {:ok, ^hrp, ^bytes} = Bech32.decode(encoded)
    end
  end
end
