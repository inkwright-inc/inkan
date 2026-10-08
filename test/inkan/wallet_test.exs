defmodule Inkan.WalletTest do
  use ExUnit.Case, async: true

  alias Inkan.{Mnemonic, Wallet}

  # Cross-implementation oracle: these vectors were generated with
  # lucid-cardano (which wraps Emurgo's cardano-serialization-lib, the
  # reference JavaScript stack). Agreement on the final bech32 address
  # exercises every layer at once — BIP-39 entropy recovery, the Icarus
  # master key, CIP-1852/BIP32-Ed25519 derivation for both the payment and
  # stake paths, Ed25519 scalar→point math, BLAKE2b-224 credential hashing,
  # CIP-19 header assembly, and bech32 encoding. A single wrong bit
  # anywhere avalanches into a completely different address.
  @vectors [
    %{
      mnemonic:
        "luggage fitness dance distance stumble quiz ship destroy verify inform runway near cereal mixture play credit gaze evoke oil deputy pool quarter situate rural",
      mainnet:
        "addr1q9lzhuexmemhnzs405usnqu4ywjh6s0q80tsm6dpm0w87njghs8qpj94c2t3qay7treamw98wpc4pn5n9mvyq894xfcsq9lczy",
      testnet:
        "addr_test1qplzhuexmemhnzs405usnqu4ywjh6s0q80tsm6dpm0w87njghs8qpj94c2t3qay7treamw98wpc4pn5n9mvyq894xfcsrnzcwm"
    },
    %{
      mnemonic:
        "foam enjoy race mixed boost gesture leg step unknown cotton slide warm diagram unhappy fresh near urban excite fringe glory rotate addict silk thunder",
      mainnet:
        "addr1qyltshpft7np639znvqrfdy73gk5f84f4rzrflvfrfy2f7zhkal5ff6n8gtlx2l4xdl88hr43saha644egr7jfzc82eqe948g9",
      testnet:
        "addr_test1qqltshpft7np639znvqrfdy73gk5f84f4rzrflvfrfy2f7zhkal5ff6n8gtlx2l4xdl88hr43saha644egr7jfzc82eq6ng8y6"
    },
    %{
      mnemonic:
        "spot cereal museum cream copper suffer burst adjust bid timber happy deputy reduce cement state praise topple fun time joke resource flush lady front",
      mainnet:
        "addr1q9379ge6z56ufc4jtp0hqew5zxc5q45ny99klutypcjnky0ssflc7wzf7da65l9f9k7kkv7sp3vsgqg0cfxjfch7ajhqxlgzaj",
      testnet:
        "addr_test1qp379ge6z56ufc4jtp0hqew5zxc5q45ny99klutypcjnky0ssflc7wzf7da65l9f9k7kkv7sp3vsgqg0cfxjfch7ajhq9f4z3d"
    },
    %{
      mnemonic:
        "indicate hawk brand shaft noodle consider rotate depth muffin green where mass property stadium dial awake cream wisdom feed ecology test stand city best",
      mainnet:
        "addr1q8u7sacucn5t9q6e287mq0nlx0u3cwuudscjt5l9e67qk76x6slklkgk7etpplkhc5p5uvxp56qtjxs5c687vrwwhmuq6nrd85",
      testnet:
        "addr_test1qru7sacucn5t9q6e287mq0nlx0u3cwuudscjt5l9e67qk76x6slklkgk7etpplkhc5p5uvxp56qtjxs5c687vrwwhmuqe97dtt"
    },
    %{
      mnemonic:
        "wish mountain denial scan husband amazing jar vintage return ridge myself enjoy turn tail youth champion crazy tag venue finger olive stable sunset manual",
      mainnet:
        "addr1q8wrjlyvf4cldumtahl0dqwtvrhm6f4ndshyynmfjqjy7azy6yzwg0n6glyygrnxuy36y03q40pazy0354tsw3m35mkqqy3gxg",
      testnet:
        "addr_test1qrwrjlyvf4cldumtahl0dqwtvrhm6f4ndshyynmfjqjy7azy6yzwg0n6glyygrnxuy36y03q40pazy0354tsw3m35mkqrjvg2h"
    }
  ]

  test "derives the same addresses as the JavaScript reference stack" do
    for %{mnemonic: mnemonic, mainnet: mainnet, testnet: testnet} <- @vectors do
      {:ok, mainnet_wallet} = Wallet.from_mnemonic(mnemonic, :mainnet)
      {:ok, testnet_wallet} = Wallet.from_mnemonic(mnemonic, :testnet)

      assert Wallet.address(mainnet_wallet) == mainnet
      assert Wallet.address(testnet_wallet) == testnet
    end
  end

  test "rejects invalid phrases" do
    assert {:error, :unknown_word} =
             Wallet.from_mnemonic("definitely not actual words x y z a b c d e", :mainnet)

    assert {:error, :bad_word_count} = Wallet.from_mnemonic("abandon ability", :mainnet)

    [first | rest] = String.split(hd(@vectors).mnemonic)
    swapped = Enum.join(["ability" | rest], " ")
    assert first != "ability"
    assert {:error, :bad_checksum} = Wallet.from_mnemonic(swapped, :mainnet)
  end

  test "mnemonic round-trips through entropy" do
    phrase = hd(@vectors).mnemonic
    {:ok, entropy} = Mnemonic.to_entropy(phrase)
    assert Mnemonic.from_entropy(entropy) == phrase
  end
end
