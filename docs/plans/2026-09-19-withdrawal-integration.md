# Withdrawal integration implementation plan

## Task 1: Lock the shared boundary

- Add the versioned Keccak binding in the SDK and contract with identical byte
  ordering and BN254 reduction.
- Store `domain` in `Pool`, remove the unfinished fee field, enforce proof/note
  limits, and require an executable configured verifier.
- Pin Light Protocol dependencies to their resolved Git revision.

## Task 2: Add the client-shaped SDK API

- Add a focused `solana` module containing `Pool`, `Withdrawal`, and `Prepared`.
- Implement PDA/ATA derivation, asset derivation, and Anchor-compatible
  `transact` instruction encoding using standard Solana and Borsh crates.
- Implement `Veil::withdraw` as validate -> bind -> prove -> build.

## Task 3: Rebuild the integration harness

- Recreate `onchain/tests/e2e` cleanly and load the pool and generated verifier
  into `solana-test-validator`.
- In one scenario, shield a real note, derive the actual Light-tree witness,
  generate a real proof through the SDK, reject a mutated recipient, execute the
  valid withdrawal, and reject its replay.

## Task 4: Verify and hand off

- Run formatting, clippy, Rust tests, Go tests/vet, the local-validator test,
  and `git diff --check` with `NO_DNA=1` for Solana commands.
- Review the final diff and stop with all changes uncommitted for user review.
