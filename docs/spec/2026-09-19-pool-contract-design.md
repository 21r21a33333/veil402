# Veil402 pool contract — design (W3), reviewed against Tornado Nova + RAILGUN

The most important component. Designed up-front from the reference contracts + Solana constraints so
we don't patch later. Implements the 1-in/1-out `transact` (spec §7.1/§10) and `shield`, reusing the
Phase-1 mixer's proven pieces (incremental tree, nullifier PDA, verify-by-CPI, SPL vault).

## Reference takeaways
- **Canonical `transact` (Nova `_transact`, RAILGUN `validateTransaction`+`accumulateAndNullify`):**
  known-root → nullifiers unspent → bind ext/bound-params hash into a public input → verify → mark
  spent → move tokens → insert output commitment(s) → emit (commitment+ciphertext, nullifier).
- **Tree:** incremental (`filledSubtrees` + `zeros`), root history. Nova = 100-root **ring buffer**,
  batch-insert; RAILGUN = depth-16 + **rollover**, all-roots **mapping** (never expires), batched
  level-by-level insert.
- **Verify cost** ≈ 125K CU, scales with # public inputs (we have 5 → cheap).

## Key decisions (adopted now) + rationale
| Area | Decision | Why |
|---|---|---|
| **Verifier** | **Sunspot verifier via CPI**, but the **program assembles the public-witness itself** from `(root, nullifier, out_commitment, public_amount, ext_data_hash)` (prepend the constant 12-byte gnark header `00000005 00000000 00000005`) — never trusts a client blob | Reuses the Phase-1-proven path; contract feeds values it *already checked*, eliminating pw-blob-parsing bugs; no VK-format conversion risk (groth16-solana inline deferred) |
| **Merkle tree** | **On-chain incremental tree** (depth 20), recompute root via `sol_poseidon` on insert; a generic `insert_leaves(&[Field])` (handles 1 now, 2 later) | Proven in Phase-1; syscall Poseidon == circuit (proven). Light-style "only-root-on-chain + in-circuit insertion" (rent-zero) is a documented future optimization (needs a heavier circuit) |
| **Root history** | **Ring buffer (64 roots)** in the pool account | Bounded, fixed account size (RAILGUN's never-expire mapping = per-root storage, costly on Solana). Proofs build against a recent root; rebuild if aged out (client concern, already covered) |
| **Account storage** | **`#[account(zero_copy)]` + `AccountLoader`** for the Pool/tree account | ~4KB account; avoids the deserialize-onto-stack blowup we Boxed around in Phase-1 — the proper Solana fix for a large, hot account |
| **Nullifiers** | **PDA per nullifier** (`seeds=[b"nullifier", pool, nullifier]`, `init`) | Idiomatic; `init` = atomic double-spend guard. Rent (~0.0009 SOL) paid by the tx payer; reclaim/optimize later. Light's nullifier-queue is over-engineering for MVP |
| **extData hash** | `keccak256(borsh(extData)) % p` (Solana `keccak` syscall) | Matches Nova; binds `{recipient, relayer, fee, public_amount sign, asset_mint, encrypted_note}`; client feeds the same value to the circuit |
| **Assets** | `register_asset(mint) -> asset_id` (u32 index) + a per-asset **vault PDA (ATA owned by pool)** | Small in-field `asset_id`; one shared pool, many SPL mints |
| **shield** | **No proof.** `shield(npk, asset_id, amount)`: pull `amount` SPL, `commitment = Poseidon(npk, asset_id, amount)` (on-chain, syscall), insert, emit | Deposit amount is public anyway (transparent transfer in); binding it on-chain to the commitment is safe and needs no SNARK |
| **Tree rollover** | **Single depth-20 tree (1M leaves)** for MVP; no rollover | 1M is plenty; `treeNumber` rollover (RAILGUN) is a documented later addition |
| **Events** | `emit!` NewCommitment{commitment, leaf_index, encrypted_note}, NewNullifier{nullifier} | Indexer scans these; ciphertext carried for recipient discovery (RAILGUN/Nova pattern) |

## Accounts
- **Pool (zero_copy):** `authority, verifier_program, denomination?/n/a, next_leaf_index, current_root_index, filled_subtrees[20], zeros[20], roots[64], asset_count`. (~ 8+32+32+8+8+ 20*32*2 + 64*32 + ... ≈ 3.4 KB.)
- **AssetRegistry (or in Pool):** `asset_id -> mint`; **Vault:** PDA `[b"vault", pool, asset_id]`, an ATA owned by a pool-signer PDA, holding shielded SPL.
- **NullifierRecord:** PDA `[b"nullifier", pool, nullifier]`, `init` on spend.

## Instructions
1. **init_pool(verifier_program)** — create the zero_copy Pool; compute `zeros`, seed `filled_subtrees`, `roots[0] = empty_root` (on-chain syscall).
2. **register_asset(mint) -> asset_id** — assign an index, create the vault ATA.
3. **shield(npk, asset_id, amount)** — pull `amount` SPL to the vault; `commitment = Poseidon(npk, asset_id, amount)`; `insert_leaves(&[commitment])`; emit.
4. **transact(proof, root, nullifier, out_commitment, public_amount, ext_data)** —
   a. `require(is_known_root(root))`
   b. nullifier PDA `init` (unspent guard)
   c. `require(ext_data_hash(ext_data) == expected)` and `require(public_amount == extAmount − fee)` (field-signed)
   d. **assemble public witness** from (root, nullifier, out_commitment, public_amount, ext_data_hash) → CPI Sunspot verifier (reverts if invalid)
   e. move SPL: `public_amount>0` pull from payer; `<0` pay `ext_data.recipient` (and relayer `fee`)
   f. `insert_leaves(&[out_commitment])`; emit NewCommitment(+ciphertext) & NewNullifier

## Budgets
- transact CU: verify ~125K + insert (≤20 syscall hashes) + state writes → set `ComputeUnitLimit` ~400K.
- tx size (1232 B): proof (~256 B) + 5×32 public values in ix data + accounts; ciphertext emitted via a separate log/ix if it pressures size. Fine for 1-in/1-out.

## Explicitly deferred (documented, not patched-in)
inline `groth16-solana` verify · tree rollover (`treeNumber`) · all-roots mapping · Light-style
only-root-on-chain + in-circuit insertion (rent-zero) · nullifier-rent reclaim · FMD note discovery.

## Reuse map (from Phase-1 mixer, green)
incremental tree + `zeros`/`filled_subtrees` insert · nullifier PDA (`init` guard) · verify-by-CPI ·
SPL vault. **New:** zero_copy Pool, value-carrying note, `public_amount` conservation binding,
contract-assembled public witness, `shield`, asset registry, extData/keccak binding.
