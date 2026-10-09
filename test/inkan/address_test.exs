defmodule Inkan.AddressTest do
  use ExUnit.Case, async: true

  alias Inkan.{Address, KeyDerivation, Mnemonic}

  defp keys do
    {:ok, entropy} =
      Mnemonic.to_entropy(
        "luggage fitness dance distance stumble quiz ship destroy verify inform runway near cereal mixture play credit gaze evoke oil deputy pool quarter situate rural"
      )

    master = KeyDerivation.master_from_entropy(entropy)
    KeyDerivation.public_key(master)
  end

  test "enterprise addresses carry type 6 and only the payment credential" do
    public = keys()

    mainnet = Address.enterprise(public, :mainnet)
    testnet = Address.enterprise(public, :testnet)

    assert String.starts_with?(mainnet, "addr1")
    assert String.starts_with?(testnet, "addr_test1")

    assert {:ok, <<header, payload::binary>>} = Address.decode(mainnet)
    assert header == 0b0110_0001
    assert byte_size(payload) == 28

    assert {:ok, <<header_t, _::binary>>} = Address.decode(testnet)
    assert header_t == 0b0110_0000
  end

  test "decode rejects non-address bech32 and garbage" do
    stake_like = Inkan.Bech32.encode("stake", <<0xE1, 0::224>>)
    assert {:error, :not_an_address} = Address.decode(stake_like)
    assert {:error, :bad_checksum} = Address.decode("addr1qqqqqqqqqqqqqqqp")
    assert {:error, :no_separator} = Address.decode("notbech32")
  end
end
