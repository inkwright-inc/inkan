defmodule Inkan.Ed25519Test do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias Inkan.Ed25519

  # OTP's :crypto is the reference implementation: for any seed, our pure
  # Elixir pipeline (SHA-512, clamp, scalar·B, compress) must produce the
  # byte-identical public key. One agreement would already be meaningful;
  # a hundred random ones pin the group arithmetic down hard.
  property "public_key_from_seed agrees with :crypto for random seeds" do
    check all(seed <- StreamData.binary(length: 32), max_runs: 100) do
      {expected_pub, _priv} = :crypto.generate_key(:eddsa, :ed25519, seed)

      assert Ed25519.public_key_from_seed(seed) == expected_pub
    end
  end

  test "clamping clears and sets the RFC 8032 bits" do
    clamped = Ed25519.clamp(:binary.copy(<<0xFF>>, 32))
    <<first, _::binary-size(30), last>> = clamped

    assert (first &&& 0b111) == 0
    assert (last &&& 0b10000000) == 0
    assert (last &&& 0b01000000) == 0b01000000
  end

  # Extended-key signatures are plain Ed25519 signatures; OTP's verifier is
  # the oracle. Keys come from real CIP-1852 derivation so the scalars have
  # the exact shape (clamped master, arithmetic-derived children) Cardano
  # produces.
  property "sign_extended produces signatures :crypto accepts" do
    check all(
            entropy <- StreamData.binary(length: 32),
            message <- StreamData.binary(min_length: 1, max_length: 200),
            max_runs: 50
          ) do
      {kl, kr, _cc} =
        entropy
        |> Inkan.KeyDerivation.master_from_entropy()
        |> Inkan.KeyDerivation.derive_path([
          Inkan.KeyDerivation.harden(1852),
          Inkan.KeyDerivation.harden(1815),
          Inkan.KeyDerivation.harden(0),
          0,
          0
        ])

      public = Ed25519.public_key_from_scalar(kl)
      signature = Ed25519.sign_extended(message, kl, kr)

      assert :crypto.verify(:eddsa, :none, message, signature, [public, :ed25519])

      refute :crypto.verify(:eddsa, :none, message <> "x", signature, [public, :ed25519])
    end
  end
end
