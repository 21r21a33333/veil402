# Security test matrix plan

## Goal

Prove the transaction circuit, pool program, SDK encoding, and real Sunspot
verifier agree at every security boundary. Keep the normal gate small; keep
load tests explicit and repeatable.

## Locked decisions

- Reject non-canonical BN254 encodings for `npk`, `root`, `nullifier`, and
  `out_commitment` before hashing, proof verification, or state persistence.
- Reject the zero nullifier.
- Keep Noir's existing `to_le_bits::<20>()` range constraint and reject
  `leaf_index >= 2^20` early in the SDK.
- Keep one asset per deployed pool. Test the current transitive asset binding;
  do not add an unused public `asset_id` until multi-asset pools exist.
- Reject `recipient_ata == vault`; spending a note without paying the recipient
  is not a useful supported operation.
- The current encrypted-note limit is 128 bytes, not 512.
- Fee cases T4-T6 are obsolete because fees were removed. Do not preserve dead
  behavior with tests.
- The ciphertext is now included in `ext_data_hash`; mutation must fail.

## Harness

Use three layers and one shared Rust fixture:

1. **Noir** — table-driven constraint tests in the circuit package.
2. **Pool program** — the existing local validator plus a tiny SBF mock verifier
   whose first proof byte selects success or failure. Put validator, account,
   transaction, and state-assertion helpers under `onchain/tests/e2e/src/`.
3. **Real verifier** — reuse one generated proof and mutate each public input to
   detect field order, gnark-header, and SDK/contract encoding drift.

The mock must only replace proof verification. Tests still exercise the real
deployed pool, SPL Token, PDA creation, Light tree, account constraints, and
transaction rollback.

## Progress

- Task 1 committed as `e875711`.
- Task 2 committed as `1fad017`.
- Task 3 implemented and verified; pending review.
- Task 4 not started.

## Task 1 — Close field and circuit invariants

Implementation:

- Add one canonical-field predicate in the pool and reuse it at every raw field
  boundary.
- Add SDK leaf-index validation, zero-nullifier rejection, and self-transfer
  rejection. Do not duplicate Noir's `to_le_bits::<20>()` range constraint.
- Version the exact compiled ACIR. Reuse the proving and verification keys only
  when Sunspot confirms the constraint system is byte-identical; otherwise run
  a new setup and regenerate the verifier program.

Minimal tests:

- **C1-C5:** conservation both directions; values at `2^64 - 1`, `2^64`, and
  near the field modulus. Demonstrate that a synthetic huge input can satisfy
  the circuit, then prove the program cannot create its matching leaf; document
  that shield plus range-checked outputs provide the induction invariant.
- **C6-C7:** reject index `2^20`; accept and independently check roots for
  `0`, `1`, `2^19`, and `2^20 - 1`.
- **C8-C9:** wrong spend key and wrong view key.
- **C10:** show that one `asset_id` is used for both commitments and prove the
  pool cannot supply a root for another asset; do not add an artificial
  `out_asset_id` parameter.
- **C11-C12:** real versus zero sibling paths and an intentional zero-value
  output.
- **N4-N5:** reject `n + P` bytes and zero before PDA creation.

## Task 2 — Program matrix with the mock verifier

Group related rows into scenario tests sharing one fixture; do not create one
validator process per table row.

- **Initialization I1-I6:** happy state, re-init rejection, non-executable
  verifier rejection, and SDK/on-chain asset-ID parity. For I4, the System
  Program may be stored because it is executable, but its verifier CPI must
  fail; the deliberately configured mock verifier succeeds and makes this
  trust assumption explicit. I5 is tested as
  `TREE_BYTES == size_in_account(...)`; callers cannot choose Anchor's init
  allocation size.
- **Shield S1-S11:** amounts `1`, `0`, and `u64::MAX`; ciphertext lengths `0`,
  `128`, and `129`; canonical/zero/non-canonical `npk`; wrong mint, insufficient
  funds with rollback, substituted vault, and duplicate commitments at distinct
  indices.
- **Public leg T1-T3, T7:** positive amount rejection, `i64::MIN` without panic,
  zero-flow transfer without token movement, and ciphertext `128/129`.
- **Roots R1-R7:** zero/unseen/current roots and exact 63/64/65-append window
  boundaries. Adapt cross-pool isolation to the current one-pool-per-program
  model by substituting a foreign tree account; prove non-canonical roots are
  rejected before lookup.
- **Verifier V1-V4:** wrong program, controlled verifier error, configured
  always-success verifier, and exact proof-length boundaries
  `0/387/388/389` with rollback checks.
- **Nullifiers N1-N3, N6-N8:** first spend, replay, same nullifier with changed
  output, deployment-scoped PDA derivation, and two distinct sequential spends.
  N6 is an address/isolation test because the current program intentionally
  supports only one pool per program deployment. N7/N8 cannot be represented
  as one Solana transaction: two instructions carrying 388-byte proofs exceed
  the 1,232-byte packet limit, so replay rollback is tested per transaction.
- **Withdrawals W1-W8:** exact payout, insufficient vault rollback, wrong owner,
  wrong mint, frozen account rollback, vault self-transfer rejection, inert
  zero-flow recipient, and exact vault drain.

Every rejection asserts all relevant state, not only the error: vault balances,
tree root/index, nullifier-account absence, and recipient balance.

## Task 3 — Real-proof compatibility matrix

Keep the existing real-validator happy path, then reuse its valid instruction
to mutate exactly one element at a time:

- `root`, `nullifier`, `out_commitment`, `public_amount`, and `ext_data_hash`;
- recipient, encrypted-note byte, encrypted-note length, domain, pool, mint, and
  program binding inputs;
- proof byte, proof truncation, and replay.

This covers **R3, N1-N2, W1, W9** and one real-verifier rejection for every
public input. Assert the successful serialized transaction remains within the
Solana packet limit.

## Task 4 — State and load regressions

- **Root churn:** submit proofs around the 63/64/65 append boundary and report
  the expiry behavior.
- **Changelog:** perform 1,000 appends and compare every final root with an
  independent reference built from `light-hasher` primitives.
- **Tree exhaustion / S12:** initialize a direct tree fixture at the last valid
  index; the next append must return `TreeError`, never wrap.
- **Compute:** record real-verifier compute units for the 128-byte withdrawal
  path and set the regression ceiling from the measured baseline plus explicit
  headroom. Do not use the obsolete 200k estimate.
- **Account size:** keep the exact Light `size_in_account(20, 8, 64, 0)` check in
  the normal gate.
- **Concurrency:** submit 20 unique spends concurrently; successful events must
  have distinct indices and the final root must match the reference tree.

The 1,000-append and 20-client cases live in a separate stress test target and
are invoked explicitly; correctness boundary tests remain in the normal gate.

## Verification commands

```sh
/tmp/veil402-noir.*/nargo test
cargo test --workspace --all-features
cd onchain && NO_DNA=1 cargo test -p pool --lib
cd onchain && NO_DNA=1 cargo test -p pool-e2e --test program
cd onchain && NO_DNA=1 cargo test -p pool-e2e --test real_verifier
cd onchain && NO_DNA=1 cargo test -p pool-e2e --test stress -- --ignored --nocapture
```

Before review, also run formatting, clippy with warnings denied, Go test/vet,
the SBF build, and `git diff --check`. Stop uncommitted for review.
