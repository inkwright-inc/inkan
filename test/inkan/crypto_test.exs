defmodule Inkan.CryptoTest do
  use ExUnit.Case, async: true

  alias Inkan.Crypto

  # Vectors generated with Python's hashlib.blake2b (an independent
  # implementation of the same RFC 7693 function).
  test "blake2b_224 matches reference digests" do
    assert hex(Crypto.blake2b_224("")) ==
             "836cc68931c2e4e3e838602eca1902591d216837bafddfe6f0c8cb07"

    assert hex(Crypto.blake2b_224("abc")) ==
             "9bd237b02a29e43bdd6738afa5b53ff0eee178d6210b618e4511aec8"

    assert hex(Crypto.blake2b_224("cardano")) ==
             "dc48bf6844bb9458793babb6f78abc483c4876c641d972928c5851b8"
  end

  test "blake2b_256 matches reference digests" do
    assert hex(Crypto.blake2b_256("")) ==
             "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"

    assert hex(Crypto.blake2b_256("abc")) ==
             "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"

    assert hex(Crypto.blake2b_256("cardano")) ==
             "27456857d960d4862e6b449534cdca82c19a3bebc4bf7c29a13d773388593c84"
  end

  defp hex(bytes), do: Base.encode16(bytes, case: :lower)
end
