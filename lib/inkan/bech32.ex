defmodule Inkan.Bech32 do
  @moduledoc """
  Bech32 encoding (BIP-173) as Cardano uses it.

  Implemented here rather than depended on because Cardano departs from
  Bitcoin's profile in one load-bearing way: addresses routinely exceed
  BIP-173's 90-character cap (a mainnet base address is ~103 characters), so
  Bitcoin-faithful libraries reject valid Cardano addresses. This module
  applies no length limit and always uses the original bech32 checksum
  constant (Cardano does not use bech32m).
  """

  import Bitwise

  @charset ~c"qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  @generator [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

  @doc """
  Encodes `data` (raw bytes) under the human-readable prefix `hrp`,
  e.g. `encode("addr", address_bytes)`.
  """
  def encode(hrp, data) when is_binary(hrp) and is_binary(data) do
    five_bit = convert_bits(data, 8, 5, true)
    checksum = checksum(hrp, five_bit)
    hrp <> "1" <> for(d <- five_bit ++ checksum, into: "", do: <<Enum.at(@charset, d)>>)
  end

  @doc """
  Decodes a bech32 string into `{:ok, hrp, bytes}`, verifying the checksum.
  Mixed-case strings are rejected per the spec; case is otherwise ignored.
  """
  def decode(bech) when is_binary(bech) do
    with :ok <- check_case(bech),
         bech = String.downcase(bech),
         {:ok, hrp, data_part} <- split(bech),
         {:ok, values} <- to_values(data_part),
         :ok <- verify_checksum(hrp, values) do
      payload = Enum.drop(values, -6)

      case convert_bits_strict(payload, 5, 8) do
        {:ok, bytes} -> {:ok, hrp, bytes}
        :error -> {:error, :invalid_padding}
      end
    end
  end

  defp check_case(bech) do
    down = String.downcase(bech)
    up = String.upcase(bech)

    if bech == down or bech == up, do: :ok, else: {:error, :mixed_case}
  end

  defp split(bech) do
    # The separator is the LAST "1" — the hrp itself may contain "1".
    case :binary.matches(bech, "1") do
      [] ->
        {:error, :no_separator}

      matches ->
        {pos, 1} = List.last(matches)
        hrp = binary_part(bech, 0, pos)
        data = binary_part(bech, pos + 1, byte_size(bech) - pos - 1)

        if hrp == "" or byte_size(data) < 6 do
          {:error, :invalid_format}
        else
          {:ok, hrp, data}
        end
    end
  end

  defp to_values(data_part) do
    values =
      for <<c <- data_part>> do
        Enum.find_index(@charset, &(&1 == c))
      end

    if Enum.any?(values, &is_nil/1), do: {:error, :invalid_character}, else: {:ok, values}
  end

  defp checksum(hrp, data) do
    values = hrp_expand(hrp) ++ data ++ [0, 0, 0, 0, 0, 0]
    polymod = bxor(polymod(values), 1)

    for i <- 0..5, do: polymod >>> (5 * (5 - i)) &&& 31
  end

  defp verify_checksum(hrp, values) do
    if polymod(hrp_expand(hrp) ++ values) == 1, do: :ok, else: {:error, :bad_checksum}
  end

  defp hrp_expand(hrp) do
    chars = String.to_charlist(hrp)
    Enum.map(chars, &(&1 >>> 5)) ++ [0] ++ Enum.map(chars, &(&1 &&& 31))
  end

  defp polymod(values) do
    Enum.reduce(values, 1, fn value, chk ->
      top = chk >>> 25
      chk = bxor((chk &&& 0x1FFFFFF) <<< 5, value)

      Enum.reduce(0..4, chk, fn i, chk ->
        if (top >>> i &&& 1) == 1, do: bxor(chk, Enum.at(@generator, i)), else: chk
      end)
    end)
  end

  # 8→5 bit regrouping with final-group padding (encode direction).
  defp convert_bits(data, from, to, _pad) do
    {acc, bits, out} =
      for <<value <- data>>, reduce: {0, 0, []} do
        {acc, bits, out} ->
          acc = (acc <<< from ||| value) &&& 0xFFFFFFFF
          bits = bits + from
          {out, bits} = drain(acc, bits, to, out)
          {acc, bits, out}
      end

    out = if bits > 0, do: [acc <<< (to - bits) &&& (1 <<< to) - 1 | out], else: out
    Enum.reverse(out)
  end

  # 5→8 bit regrouping, strict (decode direction): leftover bits must be
  # zero padding only, per BIP-173.
  defp convert_bits_strict(values, from, to) do
    {acc, bits, out} =
      Enum.reduce(values, {0, 0, []}, fn value, {acc, bits, out} ->
        acc = acc <<< from ||| value
        bits = bits + from
        {out, bits} = drain(acc, bits, to, out)
        {acc, bits, out}
      end)

    if bits >= from or (acc <<< (to - bits) &&& (1 <<< to) - 1) != 0 do
      :error
    else
      {:ok, out |> Enum.reverse() |> :erlang.list_to_binary()}
    end
  end

  defp drain(acc, bits, to, out) when bits >= to do
    drain(acc, bits - to, to, [acc >>> (bits - to) &&& (1 <<< to) - 1 | out])
  end

  defp drain(_acc, bits, _to, out), do: {out, bits}
end
