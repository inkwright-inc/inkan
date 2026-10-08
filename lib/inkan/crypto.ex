defmodule Inkan.Crypto do
  @moduledoc """
  The hash and MAC primitives Cardano is built on, in one place.

  Cardano uses BLAKE2b for everything content-addressed: 224-bit digests for
  key and script hashes (inside addresses), 256-bit digests for transaction
  ids and auxiliary-data hashes. SHA-512 appears only inside key derivation
  (PBKDF2/HMAC) and Ed25519 itself.
  """

  @doc "BLAKE2b-224 — key hashes, as found inside addresses."
  def blake2b_224(data) when is_binary(data), do: Blake2.hash2b(data, 28)

  @doc "BLAKE2b-256 — transaction ids and auxiliary-data hashes."
  def blake2b_256(data) when is_binary(data), do: Blake2.hash2b(data, 32)

  @doc "HMAC-SHA512, as used by BIP32-Ed25519 child key derivation."
  def hmac_sha512(key, data), do: :crypto.mac(:hmac, :sha512, key, data)

  @doc """
  PBKDF2-HMAC-SHA512 — the Icarus master-key stretch (CIP-3) and BIP-39
  seed derivation both use it.
  """
  def pbkdf2_sha512(password, salt, iterations, length) do
    :crypto.pbkdf2_hmac(:sha512, password, salt, iterations, length)
  end
end
