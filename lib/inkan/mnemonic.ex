defmodule Inkan.Mnemonic do
  @moduledoc """
  BIP-39 mnemonics: recovering entropy from a seed phrase.

  Only the English wordlist ships (vendored from the BIP-39 reference
  repository; its SHA-256 is pinned in the test suite). Note Cardano's
  Icarus scheme consumes the *entropy*, not BIP-39's PBKDF2 seed — so this
  module stops at entropy and `Inkan.KeyDerivation` takes over.
  """

  @wordlist :inkan
            |> :code.priv_dir()
            |> Path.join("bip39_english.txt")
            |> File.read!()
            |> String.split("\n", trim: true)

  @word_index @wordlist |> Enum.with_index() |> Map.new()

  @doc """
  Converts a phrase of 12/15/18/21/24 words into `{:ok, entropy}`,
  validating both the words and the embedded checksum.
  """
  def to_entropy(phrase) when is_binary(phrase) do
    words = phrase |> String.downcase() |> String.split()

    with :ok <- check_length(words),
         {:ok, indices} <- lookup(words) do
      total_bits = length(words) * 11
      checksum_bits = div(total_bits, 33)
      entropy_bits = total_bits - checksum_bits

      all = for i <- indices, into: <<>>, do: <<i::11>>
      <<entropy::bits-size(^entropy_bits), checksum::bits-size(^checksum_bits)>> = all

      entropy = pad_to_bytes(entropy)
      <<expected::bits-size(^checksum_bits), _::bits>> = :crypto.hash(:sha256, entropy)

      if checksum == expected do
        {:ok, entropy}
      else
        {:error, :bad_checksum}
      end
    end
  end

  defp check_length(words) when length(words) in [12, 15, 18, 21, 24], do: :ok
  defp check_length(_words), do: {:error, :bad_word_count}

  defp lookup(words) do
    indices = Enum.map(words, &Map.get(@word_index, &1))

    if Enum.any?(indices, &is_nil/1), do: {:error, :unknown_word}, else: {:ok, indices}
  end

  # Entropy bit counts are all multiples of 8, so this is a cast, not a pad —
  # but bitstring syntax needs the hop back to a binary.
  defp pad_to_bytes(bits) when rem(bit_size(bits), 8) == 0 do
    for <<byte::8 <- bits>>, into: <<>>, do: <<byte>>
  end

  @doc "The full English wordlist, mostly for generating test phrases."
  def wordlist, do: @wordlist

  @doc """
  Builds a valid mnemonic from raw entropy (16/20/24/28/32 bytes) —
  the inverse of `to_entropy/1`, used for wallet generation and tests.
  """
  def from_entropy(entropy) when byte_size(entropy) in [16, 20, 24, 28, 32] do
    checksum_bits = div(byte_size(entropy) * 8, 32)
    <<checksum::bits-size(^checksum_bits), _::bits>> = :crypto.hash(:sha256, entropy)
    all = <<entropy::binary, checksum::bits>>

    for <<index::11 <- all>> do
      Enum.at(@wordlist, index)
    end
    |> Enum.join(" ")
  end
end
