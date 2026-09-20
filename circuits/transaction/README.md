# transaction circuit (1-in / 1-out)

Spend one note, create one note. Proves: ownership, Merkle membership, correct nullifier, output
well-formedness + `value < 2^64`, and value conservation `in_value + public_amount == out_value`.
The public external-data hash is constrained to a private witness copy so it cannot be replaced
after proving. The Merkle path's fixed-width bit decomposition constrains `leaf_index < 2^20`.

## Note / key shapes (finalized by this circuit)
```
mpk        = Poseidon(Poseidon(spending_key), Poseidon(viewing_key))
npk        = Poseidon(mpk, random)
commitment = Poseidon(npk, asset_id, value)
nullifier  = Poseidon(Poseidon(viewing_key), leaf_index)
```

## Public-input layout (the contract slices this)
Sunspot public witness = 12-byte gnark header + 5 × 32-byte big-endian fields, in declaration order.
Total 172 bytes. Verified against a real proof:
| offset | field |
|---|---|
| 12..44 | `root` |
| 44..76 | `nullifier` |
| 76..108 | `out_commitment` |
| 108..140 | `public_amount` (signed, field-wrapped for withdrawals) |
| 140..172 | `ext_data_hash` |

## Build
```bash
nargo test                 # circuit invariant and boundary matrix
nargo compile && nargo execute witness
SP=~/tools/sunspot/sunspot ; export GNARK_VERIFIER_BIN=~/tools/sunspot/gnark-solana/crates/verifier-bin
cd target
$SP compile transaction.json && $SP setup transaction.ccs
$SP prove transaction.json witness.gz transaction.ccs transaction.pk
$SP verify transaction.vk transaction.proof transaction.pw     # off-chain sanity
$SP deploy transaction.vk                                       # -> transaction.so (verifier program)
```
Verified: off-chain proof verifies; `transaction.pw` is 172 bytes with the layout above.
