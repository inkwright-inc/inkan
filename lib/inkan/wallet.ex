defmodule Inkan.Wallet do
  @moduledoc """
  A single-account CIP-1852 payment wallet: mnemonic in, keys and address
  out. Account 0, external chain, address index 0 — the layout every
  mainstream Cardano wallet produces by default, so a wallet created in
  Eternl/Daedalus/etc. and one created here agree on the address.
  """

  alias Inkan.{Address, KeyDerivation, Mnemonic}

  import Inkan.KeyDerivation, only: [harden: 1]

  @enforce_keys [:payment, :stake, :network]
  defstruct [:payment, :stake, :network]

  @type t :: %__MODULE__{
          payment: KeyDerivation.xprv(),
          stake: KeyDerivation.xprv(),
          network: Address.network()
        }

  @doc """
  Builds the wallet for a BIP-39 phrase at path `m/1852'/1815'/0'`, with
  the payment key at `/0/0` and the stake key at `/2/0`.
  """
  @spec from_mnemonic(String.t(), Address.network()) :: {:ok, t()} | {:error, term()}
  def from_mnemonic(phrase, network) when network in [:mainnet, :testnet] do
    with {:ok, entropy} <- Mnemonic.to_entropy(phrase) do
      account =
        entropy
        |> KeyDerivation.master_from_entropy()
        |> KeyDerivation.derive_path([harden(1852), harden(1815), harden(0)])

      {:ok,
       %__MODULE__{
         payment: KeyDerivation.derive_path(account, [0, 0]),
         stake: KeyDerivation.derive_path(account, [2, 0]),
         network: network
       }}
    end
  end

  @doc "The wallet's base address (payment + stake credentials)."
  @spec address(t()) :: String.t()
  def address(%__MODULE__{} = wallet) do
    Address.base(
      KeyDerivation.public_key(wallet.payment),
      KeyDerivation.public_key(wallet.stake),
      wallet.network
    )
  end
end
