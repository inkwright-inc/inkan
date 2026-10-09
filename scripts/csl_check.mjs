// Oracle check against the reference JavaScript stack: parse an
// Inkan-built transaction with CML (bundled inside lucid-cardano),
// recompute its hash, and re-serialize it byte-for-byte.
//
// Not part of the test suite (needs node + lucid-cardano in node_modules
// next to this script); run it when the builder changes or a new era
// lands:
//
//   mix run scripts/emit_sample_tx.exs      # prints <tx_id> <tx_hex>
//   node scripts/csl_check.mjs <tx_id> <tx_hex>
//
// Expected output: three lines, all affirmative.

import { C } from "lucid-cardano";

const [txId, txHex] = process.argv.slice(2);
const tx = C.Transaction.from_bytes(Buffer.from(txHex, "hex"));

const reserialized = Buffer.from(tx.to_bytes()).toString("hex");
console.log("parses:       yes");
console.log("roundtrip_ok:", reserialized === txHex);

const hash = C.hash_transaction(tx.body()).to_hex();
console.log("hash_ok:     ", hash === txId, `(cml=${hash})`);
