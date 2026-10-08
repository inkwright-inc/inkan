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
end
