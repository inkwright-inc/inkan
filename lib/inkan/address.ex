defmodule Inkan.Address do
  @moduledoc """
  Shelley addresses (CIP-19), the two kinds a payment wallet needs.

  A *base* address carries two credentials — a payment key hash (who can
  spend) and a stake key hash (who earns rewards) — behind one header byte:
  address type in the high nibble, network tag in the low. An *enterprise*
  address carries the payment credential alone.
  """

  import Bitwise

  alias Inkan.Crypto

  @type network :: :mainnet | :testnet

  @doc """
  Base address (type 0: payment key + stake key) from the two public keys.
  """
  @spec base(binary(), binary(), network()) :: String.t()
  def base(payment_pub, stake_pub, network) do
    header = <<0b0000 <<< 4 ||| network_tag(network)>>

    encode(
      header <> Crypto.blake2b_224(payment_pub) <> Crypto.blake2b_224(stake_pub),
      network
    )
  end

  @doc """
  Enterprise address (type 6: payment key only, no staking rights).
  """
  @spec enterprise(binary(), network()) :: String.t()
  def enterprise(payment_pub, network) do
    header = <<0b0110 <<< 4 ||| network_tag(network)>>
    encode(header <> Crypto.blake2b_224(payment_pub), network)
  end

  @doc "Decodes a bech32 address into `{:ok, bytes}` (header byte included)."
  def decode(address) do
    case Inkan.Bech32.decode(address) do
      {:ok, hrp, bytes} when hrp in ["addr", "addr_test"] -> {:ok, bytes}
      {:ok, _hrp, _bytes} -> {:error, :not_an_address}
      {:error, reason} -> {:error, reason}
    end
  end

  defp network_tag(:mainnet), do: 1
  defp network_tag(:testnet), do: 0

  defp encode(bytes, :mainnet), do: Inkan.Bech32.encode("addr", bytes)
  defp encode(bytes, :testnet), do: Inkan.Bech32.encode("addr_test", bytes)
end
