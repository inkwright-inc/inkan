defmodule Inkan.Ed25519 do
  @moduledoc """
  Ed25519 group arithmetic (RFC 8032) in pure Elixir.

  OTP's `:crypto` signs and verifies Ed25519, but its API only accepts
  *seeds* — it derives the scalar internally by hashing. Cardano's
  BIP32-Ed25519 keys don't work that way: child derivation produces the
  scalar directly, so computing a public key (and later a signature)
  requires raw scalar-times-basepoint multiplication, which is what this
  module provides. Arithmetic uses Erlang bignums with extended twisted
  Edwards coordinates; at a handful of multiplications per transaction,
  clarity beats constant-time tricks we couldn't guarantee on the BEAM
  anyway — treat the host as trusted, as with any hot wallet.

  Verified in the test suite against `:crypto`'s own Ed25519 for randomly
  generated keys, making OTP the reference implementation.
  """

  import Bitwise

  @p (1 <<< 255) - 19
  @d 37_095_705_934_669_439_343_138_083_508_754_565_189_542_113_879_843_219_016_388_785_533_085_940_283_555

  # The standard base point B, in extended coordinates (x, y, 1, x*y).
  @bx 15_112_221_349_535_400_772_501_151_409_588_531_511_454_012_693_041_857_206_046_113_283_949_847_762_202
  @by 46_316_835_694_926_478_169_428_394_003_475_163_141_307_993_866_256_225_615_783_033_603_165_251_855_960

  @doc """
  The public key for a raw little-endian 32-byte scalar: `encode(scalar·B)`.
  """
  def public_key_from_scalar(<<scalar::little-unsigned-256>>) do
    base = {@bx, @by, 1, mulmod(@bx, @by)}

    base
    |> scalar_mult(scalar)
    |> compress()
  end

  @doc """
  The public key for a standard Ed25519 *seed*, per RFC 8032: SHA-512 the
  seed, clamp the lower half, multiply. Exists mainly so the tests can
  check this whole module against `:crypto.generate_key/3`.
  """
  def public_key_from_seed(seed) when byte_size(seed) == 32 do
    <<lower::binary-size(32), _upper::binary-size(32)>> = :crypto.hash(:sha512, seed)
    public_key_from_scalar(clamp(lower))
  end

  @doc "RFC 8032 scalar clamping of a little-endian 32-byte string."
  def clamp(<<first, middle::binary-size(30), last>>) do
    <<first &&& 248, middle::binary, (last &&& 127) ||| 64>>
  end

  # ── Group operations (extended twisted Edwards coordinates) ──

  defp scalar_mult(_point, 0), do: {0, 1, 1, 0}

  defp scalar_mult(point, k) do
    half = scalar_mult(point, k >>> 1)
    doubled = point_add(half, half)
    if (k &&& 1) == 1, do: point_add(doubled, point), else: doubled
  end

  # Unified addition, complete for the twisted Edwards curve a = -1.
  defp point_add({x1, y1, z1, t1}, {x2, y2, z2, t2}) do
    a = mulmod(submod(y1, x1), submod(y2, x2))
    b = mulmod(addmod(y1, x1), addmod(y2, x2))
    c = t1 |> mulmod(t2) |> mulmod(2) |> mulmod(@d)
    d = z1 |> mulmod(z2) |> mulmod(2)
    e = submod(b, a)
    f = submod(d, c)
    g = addmod(d, c)
    h = addmod(b, a)

    {mulmod(e, f), mulmod(g, h), mulmod(f, g), mulmod(e, h)}
  end

  # Point compression: 32-byte little-endian y, top bit carrying x's parity.
  defp compress({x, y, z, _t}) do
    zinv = invmod(z)
    x = mulmod(x, zinv)
    y = mulmod(y, zinv)
    <<y ||| (x &&& 1) <<< 255::little-unsigned-256>>
  end

  # ── Field arithmetic mod p = 2^255 - 19 ─────────────────────

  defp addmod(a, b), do: Integer.mod(a + b, @p)
  defp submod(a, b), do: Integer.mod(a - b, @p)
  defp mulmod(a, b), do: Integer.mod(a * b, @p)

  # Fermat: a^(p-2) mod p.
  defp invmod(a), do: powmod(a, @p - 2)

  defp powmod(a, e) do
    :crypto.mod_pow(a, e, @p) |> :binary.decode_unsigned()
  end
end
