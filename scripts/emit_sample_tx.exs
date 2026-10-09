# Emits a deterministic signed sample transaction (id + hex) for
# scripts/csl_check.mjs. Run with: mix run scripts/emit_sample_tx.exs
mnemonic =
  "luggage fitness dance distance stumble quiz ship destroy verify inform runway near cereal mixture play credit gaze evoke oil deputy pool quarter situate rural"

{:ok, wallet} = Inkan.Wallet.from_mnemonic(mnemonic, :testnet)

{:ok, tx} =
  Inkan.Transaction.build(
    %{
      inputs: [%{tx_id: String.duplicate("ab", 32), index: 1, lovelace: 10_000_000}],
      change_address: Inkan.Wallet.address(wallet),
      metadata: {7368, %{"doc_sha256" => String.duplicate("c", 64), "v" => 1}},
      ttl: 155_000_000
    },
    %{min_fee_a: 44, min_fee_b: 155_381}
  )

signed = Inkan.Transaction.sign(tx, [wallet.payment])
IO.puts("#{signed.tx_id} #{Base.encode16(signed.cbor, case: :lower)}")
