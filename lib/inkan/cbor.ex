defmodule Inkan.CBOR do
  @moduledoc """
  CBOR (RFC 8949), the subset Cardano transactions live in.

  Implemented in-library because transaction *bytes* are load-bearing: the
  transaction id is the BLAKE2b-256 of the body's exact serialization, and
  signatures cover that hash, so the encoder must reproduce the reference
  implementations byte for byte. Owning the codec keeps that guarantee ours
  to make — the test suite proves it by re-encoding real on-chain
  transactions and comparing hashes.

  Encoding is always definite-length with shortest-form heads (what the
  Cardano reference stack emits). Decoding additionally understands
  indefinite-length containers and all tags, so anything the chain serves
  can be read.

  Terms map as: integers, binaries (byte strings), `{:text, string}` for
  text strings, lists, maps (`%{}` — key order preserved via sorted
  re-encode? no: see `encode/1` — maps encode in the key order of the
  supplied `{:map, pairs}` form, and plain maps are rejected to keep byte
  layout explicit), `{:tag, n, value}`, booleans, `nil`, and floats.
  """

  @doc """
  Encodes a term to CBOR bytes.

  Maps must be given as `{:map, [{key, value}, ...]}` so pair order — which
  changes the bytes and therefore the hash — is always explicit and
  faithful. Plain Elixir maps are deliberately not accepted.
  """
  def encode(term)

  def encode(int) when is_integer(int) and int >= 0, do: head(0, int)
  def encode(int) when is_integer(int), do: head(1, -int - 1)
  def encode(bytes) when is_binary(bytes), do: head(2, byte_size(bytes)) <> bytes

  def encode({:text, text}) when is_binary(text), do: head(3, byte_size(text)) <> text

  def encode(list) when is_list(list) do
    Enum.reduce(list, head(4, length(list)), fn item, acc -> acc <> encode(item) end)
  end

  def encode({:map, pairs}) when is_list(pairs) do
    Enum.reduce(pairs, head(5, length(pairs)), fn {k, v}, acc ->
      acc <> encode(k) <> encode(v)
    end)
  end

  def encode({:tag, tag, value}) when is_integer(tag) and tag >= 0 do
    head(6, tag) <> encode(value)
  end

  def encode(false), do: <<0xF4>>
  def encode(true), do: <<0xF5>>
  def encode(nil), do: <<0xF6>>

  def encode(float) when is_float(float), do: <<0xFB, float::float-64>>

  # Shortest-form argument encoding, as canonical CBOR requires.
  defp head(major, value) when value < 24, do: <<major::3, value::5>>
  defp head(major, value) when value < 0x100, do: <<major::3, 24::5, value::8>>
  defp head(major, value) when value < 0x10000, do: <<major::3, 25::5, value::16>>
  defp head(major, value) when value < 0x100000000, do: <<major::3, 26::5, value::32>>
  defp head(major, value), do: <<major::3, 27::5, value::64>>

  @doc "Decodes one CBOR item, returning `{:ok, term, rest}`."
  def decode(bytes) when is_binary(bytes) do
    {:ok, term, rest} = do_decode(bytes)
    {:ok, term, rest}
  rescue
    _e -> {:error, :invalid_cbor}
  end

  @doc "Decodes exactly one CBOR item; errors if bytes remain."
  def decode!(bytes) do
    case decode(bytes) do
      {:ok, term, <<>>} -> term
      {:ok, _term, _rest} -> raise ArgumentError, "trailing bytes after CBOR item"
      {:error, reason} -> raise ArgumentError, "invalid CBOR: #{inspect(reason)}"
    end
  end

  defp do_decode(<<major::3, info::5, rest::binary>>) do
    case {major, info} do
      {0, _} ->
        {value, rest} = argument(info, rest)
        {:ok, value, rest}

      {1, _} ->
        {value, rest} = argument(info, rest)
        {:ok, -value - 1, rest}

      {2, 31} ->
        decode_indefinite_string(rest, 2, [])

      {2, _} ->
        {len, rest} = argument(info, rest)
        <<bytes::binary-size(^len), rest::binary>> = rest
        {:ok, bytes, rest}

      {3, 31} ->
        decode_indefinite_string(rest, 3, [])

      {3, _} ->
        {len, rest} = argument(info, rest)
        <<text::binary-size(^len), rest::binary>> = rest
        {:ok, {:text, text}, rest}

      {4, 31} ->
        decode_indefinite_list(rest, [])

      {4, _} ->
        {len, rest} = argument(info, rest)
        decode_list(rest, len, [])

      {5, 31} ->
        decode_indefinite_map(rest, [])

      {5, _} ->
        {len, rest} = argument(info, rest)
        decode_map(rest, len, [])

      {6, _} ->
        {tag, rest} = argument(info, rest)
        {:ok, value, rest} = do_decode(rest)
        {:ok, {:tag, tag, value}, rest}

      {7, 20} ->
        {:ok, false, rest}

      {7, 21} ->
        {:ok, true, rest}

      {7, 22} ->
        {:ok, nil, rest}

      {7, 25} ->
        <<half::16, rest::binary>> = rest
        {:ok, decode_half(half), rest}

      {7, 26} ->
        <<float::float-32, rest::binary>> = rest
        {:ok, float, rest}

      {7, 27} ->
        <<float::float-64, rest::binary>> = rest
        {:ok, float, rest}
    end
  end

  defp argument(info, rest) when info < 24, do: {info, rest}
  defp argument(24, <<value::8, rest::binary>>), do: {value, rest}
  defp argument(25, <<value::16, rest::binary>>), do: {value, rest}
  defp argument(26, <<value::32, rest::binary>>), do: {value, rest}
  defp argument(27, <<value::64, rest::binary>>), do: {value, rest}

  defp decode_list(rest, 0, acc), do: {:ok, Enum.reverse(acc), rest}

  defp decode_list(rest, n, acc) do
    {:ok, item, rest} = do_decode(rest)
    decode_list(rest, n - 1, [item | acc])
  end

  defp decode_map(rest, 0, acc), do: {:ok, {:map, Enum.reverse(acc)}, rest}

  defp decode_map(rest, n, acc) do
    {:ok, key, rest} = do_decode(rest)
    {:ok, value, rest} = do_decode(rest)
    decode_map(rest, n - 1, [{key, value} | acc])
  end

  defp decode_indefinite_list(<<0xFF, rest::binary>>, acc),
    do: {:ok, {:indefinite, Enum.reverse(acc)}, rest}

  defp decode_indefinite_list(rest, acc) do
    {:ok, item, rest} = do_decode(rest)
    decode_indefinite_list(rest, [item | acc])
  end

  defp decode_indefinite_map(<<0xFF, rest::binary>>, acc),
    do: {:ok, {:indefinite_map, Enum.reverse(acc)}, rest}

  defp decode_indefinite_map(rest, acc) do
    {:ok, key, rest} = do_decode(rest)
    {:ok, value, rest} = do_decode(rest)
    decode_indefinite_map(rest, [{key, value} | acc])
  end

  # Chunks are kept as a list (not joined) so re-encoding preserves the
  # original chunking byte for byte.
  defp decode_indefinite_string(<<0xFF, rest::binary>>, major, chunks) do
    kind = if major == 2, do: :indefinite_bytes, else: :indefinite_text
    {:ok, {kind, Enum.reverse(chunks)}, rest}
  end

  defp decode_indefinite_string(bytes, major, chunks) do
    {:ok, chunk, rest} = do_decode(bytes)

    chunk =
      case chunk do
        {:text, text} -> text
        bin when is_binary(bin) -> bin
      end

    decode_indefinite_string(rest, major, [chunk | chunks])
  end

  # RFC 8949 half-precision decoding; txs never carry floats, but the
  # decoder shouldn't choke on arbitrary chain data.
  defp decode_half(half) do
    <<sign::1, exp::5, frac::10>> = <<half::16>>

    value =
      cond do
        exp == 0 -> :math.pow(2, -14) * (frac / 1024)
        exp == 31 -> if frac == 0, do: :infinity, else: :nan
        true -> :math.pow(2, exp - 15) * (1 + frac / 1024)
      end

    case {value, sign} do
      {v, 0} when is_float(v) -> v
      {v, 1} when is_float(v) -> -v
      {special, _} -> special
    end
  end

  @doc """
  Re-encodes a decoded term, reproducing indefinite-length framing — so
  `decoded |> reencode()` round-trips chain bytes exactly.
  """
  def reencode({:indefinite, items}) do
    Enum.reduce(items, <<0x9F>>, fn item, acc -> acc <> reencode(item) end) <> <<0xFF>>
  end

  def reencode({:indefinite_map, pairs}) do
    Enum.reduce(pairs, <<0xBF>>, fn {k, v}, acc -> acc <> reencode(k) <> reencode(v) end) <>
      <<0xFF>>
  end

  def reencode({:map, pairs}) do
    Enum.reduce(pairs, head(5, length(pairs)), fn {k, v}, acc ->
      acc <> reencode(k) <> reencode(v)
    end)
  end

  def reencode({:tag, tag, value}), do: head(6, tag) <> reencode(value)

  def reencode({:indefinite_bytes, chunks}) do
    Enum.reduce(chunks, <<0x5F>>, fn chunk, acc -> acc <> encode(chunk) end) <> <<0xFF>>
  end

  def reencode({:indefinite_text, chunks}) do
    Enum.reduce(chunks, <<0x7F>>, fn chunk, acc -> acc <> encode({:text, chunk}) end) <> <<0xFF>>
  end

  def reencode(list) when is_list(list) do
    Enum.reduce(list, head(4, length(list)), fn item, acc -> acc <> reencode(item) end)
  end

  def reencode(other), do: encode(other)
end
