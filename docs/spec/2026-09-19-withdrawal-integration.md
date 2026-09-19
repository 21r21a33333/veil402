# Withdrawal integration

W4 makes a withdrawal one SDK operation and proves that operation against the
real Solana programs.

## Client API

- `Pool` holds the program, verifier, mint, and deployment domain and derives
  every PDA plus the circuit asset identifier.
- `Withdrawal` validates the recipient, amount, and encrypted-note size.
- `Veil::withdraw(...) -> Prepared` derives the public amount and bound hash,
  generates the proof, and returns the exact `transact` instruction.
- `Prepared` exposes the proof and instruction. Account creation and transaction
  submission stay with the caller.

The existing low-level `Veil::prove(Transaction)` remains available for private
transfers and advanced callers.

## Canonical binding

The circuit public hash is the BN254 field reduction of:

```text
keccak256(
  "veil402:transact:v1" || domain || program || pool || mint || recipient ||
  ext_amount_be_i64 || encrypted_note_len_be_u32 || encrypted_note
)
```

`domain` is a deployment identifier chosen at pool initialization (normally the
cluster genesis hash). Including the program, pool, mint, and signed amount
prevents cross-deployment, cross-pool, cross-asset, and amount replay.

W4 intentionally has no relayer fee. A fee requires a bound relayer and payout
path, so it will be introduced as a new binding version rather than silently
remaining in the vault.

## Contract boundary

- `init_pool(domain)` stores the immutable deployment domain.
- `transact` recomputes the canonical binding, assembles the public witness,
  verifies it by CPI, transfers the withdrawal, records the nullifier, and
  inserts the output commitment atomically.
- The verifier account must be executable and match the configured verifier.
- Proof and encrypted-note lengths are bounded before CPI.

## Acceptance

One local-validator scenario uses the bundled prover and real verifier to cover
shield, tampered-recipient rejection, successful withdrawal, and replay
rejection. A successful serialized transaction also guards the Solana packet
size boundary.
