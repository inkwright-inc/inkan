defmodule Inkan.Metadata do
  @moduledoc """
  Transaction metadata: converting friendly Elixir terms into the constrained
  shape the ledger accepts, and the auxiliary-data serialization that gets
  hashed into the transaction body.

  The ledger's rules, enforced here so a bad value fails at build time
  rather than at submission:

  * integers must fit in 64 bits (signed or unsigned),
  * byte strings and text strings are limited to **64 bytes each**,
  * structure is maps and lists of the above, keyed by an unsigned
    integer label at the top level.

  Elixir maps are accepted as input and their pairs are encoded in the
  deterministic order `Enum.sort/1` gives, so the same term always produces
  the same bytes (and therefore the same auxiliary-data hash). Binaries map
  to CBOR text when valid UTF-8 — the overwhelmingly common case for
  metadata — and `{:bytes, binary}` forces a byte string.
  """

  import Bitwise, only: [<<<: 2]

  alias Inkan.{CBOR, Crypto}

  @max_string_bytes 64
  @max_int (1 <<< 63) - 1
  @min_int -(1 <<< 63)

  @doc """
  Validates and normalizes `{label, term}` metadata into the CBOR term for
  the transaction's auxiliary data (Shelley format: `{label => value}`).
  """
  def build(label, term) when is_integer(label) and label >= 0 do
    with {:ok, value} <- normalize(term) do
      {:ok, {:map, [{label, value}]}}
    end
  end

  @doc "Serializes built metadata; the body carries this serialization's hash."
  def serialize(metadata_term), do: CBOR.encode(metadata_term)

  @doc "The auxiliary-data hash recorded in the transaction body (key 7)."
  def hash(metadata_term), do: metadata_term |> serialize() |> Crypto.blake2b_256()

  defp normalize(int) when is_integer(int) and int >= @min_int and int <= @max_int,
    do: {:ok, int}

  defp normalize(int) when is_integer(int), do: {:error, {:int_out_of_range, int}}

  defp normalize({:bytes, bytes}) when is_binary(bytes) do
    if byte_size(bytes) <= @max_string_bytes do
      {:ok, bytes}
    else
      {:error, {:too_long, bytes}}
    end
  end

  defp normalize(string) when is_binary(string) do
    cond do
      byte_size(string) > @max_string_bytes -> {:error, {:too_long, string}}
      String.valid?(string) -> {:ok, {:text, string}}
      true -> {:ok, string}
    end
  end

  defp normalize(list) when is_list(list) do
    map_all(list, &normalize/1)
  end

  defp normalize(map) when is_map(map) do
    with {:ok, pairs} <-
           map_all(Enum.sort(map), fn {k, v} ->
             with {:ok, key} <- normalize(k),
                  {:ok, value} <- normalize(v) do
               {:ok, {key, value}}
             end
           end) do
      {:ok, {:map, pairs}}
    end
  end

  defp normalize(other), do: {:error, {:unsupported, other}}

  defp map_all(enum, fun) do
    Enum.reduce_while(enum, {:ok, []}, fn item, {:ok, acc} ->
      case fun.(item) do
        {:ok, value} -> {:cont, {:ok, [value | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end
  end
end
