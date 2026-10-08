defmodule Inkan.KeyDerivation do
  @moduledoc """
  Cardano HD key derivation: the Icarus master key (CIP-3) and
  BIP32-Ed25519 "V2" child derivation (CIP-1852 paths).

  A derived private key is `{kL, kR, chain_code}` — three 32-byte strings.
  `kL` is a raw Ed25519 scalar (the nonstandard part: unlike RFC 8032 keys
  it is used directly, never re-hashed from a seed), `kR` feeds signature
  nonces, and the chain code drives child derivation.

  The exact bit-fiddling below (the 28-byte truncation, the ×8, the
  prefix bytes 0x00–0x03) comes from the BIP32-Ed25519 paper as adopted by
  Cardano. None of it is guessable from first principles, which is why the
  test suite's cross-check — full-path derivation must produce the same
  addresses as the JavaScript reference stack — is the module's real spec.
  """

  import Bitwise

  alias Inkan.Crypto
  alias Inkan.Ed25519

  @hardened 0x8000_0000

  @typedoc "An extended private key: `{kL, kR, chain_code}`, 32 bytes each."
  @type xprv :: {binary(), binary(), binary()}

  @doc "Hardened-index marker; `harden(1852)` is the `1852'` in a path."
  def harden(index), do: index + @hardened

  @doc """
  The Icarus master key (CIP-3): PBKDF2-HMAC-SHA512 stretches the BIP-39
  *entropy* (salt) under the spending passphrase (password, usually empty),
  and the scalar half is clamped per BIP32-Ed25519.
  """
  @spec master_from_entropy(binary(), binary()) :: xprv()
  def master_from_entropy(entropy, passphrase \\ "") do
    <<kl::binary-size(32), kr::binary-size(32), cc::binary-size(32)>> =
      Crypto.pbkdf2_sha512(passphrase, entropy, 4096, 96)

    {clamp_v2(kl), kr, cc}
  end

  # RFC 8032 clamping plus BIP32-Ed25519's extra demand: the third-highest
  # bit must be clear, so child-key scalar additions can never overflow
  # into the forbidden range.
  defp clamp_v2(<<first, middle::binary-size(30), last>>) do
    <<first &&& 0b1111_1000, middle::binary, (last &&& 0b0001_1111) ||| 0b0100_0000>>
  end

  @doc "Derives one child key (hardened when `index >= 2^31`)."
  @spec derive_child(xprv(), non_neg_integer()) :: xprv()
  def derive_child({kl, kr, cc}, index) when index >= @hardened do
    serialized = <<kl::binary, kr::binary, index::little-32>>

    z = Crypto.hmac_sha512(cc, <<0x00, serialized::binary>>)

    <<_::binary-size(32), cc_child::binary-size(32)>> =
      Crypto.hmac_sha512(cc, <<0x01, serialized::binary>>)

    child_from_z(z, kl, kr, cc_child)
  end

  def derive_child({kl, kr, cc}, index) do
    public = Ed25519.public_key_from_scalar(kl)
    serialized = <<public::binary, index::little-32>>

    z = Crypto.hmac_sha512(cc, <<0x02, serialized::binary>>)

    <<_::binary-size(32), cc_child::binary-size(32)>> =
      Crypto.hmac_sha512(cc, <<0x03, serialized::binary>>)

    child_from_z(z, kl, kr, cc_child)
  end

  defp child_from_z(<<zl28::binary-size(28), _::binary-size(4), zr::binary-size(32)>>, kl, kr, cc) do
    <<zl_int::little-unsigned-224>> = zl28
    <<kl_int::little-unsigned-256>> = kl
    <<kr_int::little-unsigned-256>> = kr
    <<zr_int::little-unsigned-256>> = zr

    kl_child = zl_int * 8 + kl_int
    kr_child = rem(zr_int + kr_int, 1 <<< 256)

    {<<kl_child::little-unsigned-256>>, <<kr_child::little-unsigned-256>>, cc}
  end

  @doc "Folds `derive_child/2` over a full path, e.g. `[harden(1852), harden(1815), harden(0), 0, 0]`."
  @spec derive_path(xprv(), [non_neg_integer()]) :: xprv()
  def derive_path(xprv, path), do: Enum.reduce(path, xprv, &derive_child(&2, &1))

  @doc "The 32-byte Ed25519 public key for an extended private key."
  def public_key({kl, _kr, _cc}), do: Ed25519.public_key_from_scalar(kl)
end
