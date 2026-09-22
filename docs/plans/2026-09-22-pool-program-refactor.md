# Pool Program Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Do not dispatch subagents unless the user explicitly requests them.

**Goal:** Turn the v4 pool into a production-shaped Anchor program with trusted singleton initialization, focused modules, explicit asset state, checked token transfers, and isolated external wire encoders.

**Architecture:** Keep `lib.rs` as the stable Anchor entrypoint and delegate to one module per instruction. Preserve the fixed 2-in/2-out protocol and all shield/transact wire contracts while moving hashing, verifier serialization, and the Light tree behind narrow concrete modules.

**Tech Stack:** Rust 2021, Anchor 0.32, classic SPL Token, Light Protocol concurrent Merkle tree, Solana Poseidon/Keccak syscalls, Sunspot/gnark Groth16 verifier CPI.

**Spec:** `docs/spec/2026-09-22-pool-program-refactor.md`

## Global Constraints

- Keep one immutable classic-SPL-token pool per program deployment.
- Do not add dependencies, traits, service layers, a shared protocol crate, Token-2022 support, or multi-asset behavior.
- Preserve `shield` and `transact` instruction names, argument encoding, account ordering, events, errors, PDA seeds, proof binding, and atomic rollback behavior.
- The pool account and `init_pool` account list may change because v4 has no deployed state requiring migration.
- Comments explain protocol invariants or external wire formats, never implementation chronology.
- Add only the unauthorized-initializer regression; reuse the existing matrix for all other behavior.
- Do not use TDD for this phase. Implement each complete task, run its narrow gate, and leave every task uncommitted until the final user review.

## File map

| File | Responsibility |
| --- | --- |
| `onchain/programs/pool/src/lib.rs` | Program ID, public re-exports, thin Anchor entrypoints |
| `onchain/programs/pool/src/instructions/mod.rs` | Instruction module exports |
| `onchain/programs/pool/src/instructions/initialize.rs` | Trusted initialization accounts and handler |
| `onchain/programs/pool/src/instructions/shield.rs` | Deposit accounts and handler |
| `onchain/programs/pool/src/instructions/transact.rs` | Spend/withdraw accounts, `ExtData`, and handler |
| `onchain/programs/pool/src/state.rs` | `Pool`, `Asset`, `MerkleTree`, `NullifierRecord` |
| `onchain/programs/pool/src/utils.rs` | Canonical field encoding and protocol hashes |
| `onchain/programs/pool/src/verifier.rs` | Typed public inputs, gnark encoding, verifier CPI |
| `onchain/programs/pool/src/tree.rs` | Light tree sizing, initialization, root lookup, append |
| `onchain/programs/pool/src/events.rs` | Stable commitment and nullifier events |
| `onchain/programs/pool/src/error.rs` | Stable pool errors; new variants append at the end |
| `onchain/tests/e2e/src/harness.rs` | Upgradeable pool deployment for initialization tests |
| `onchain/tests/e2e/src/scenario.rs` | Updated `init_pool` instruction builder |
| `onchain/tests/e2e/tests/program.rs` | Typed state assertions and initializer authorization regression |
| `README.md` | Current 2-in/2-out public-input and initialization description |

---

### Task 1: Mechanical module split

**Files:**
- Modify: `onchain/programs/pool/src/lib.rs`
- Create: `onchain/programs/pool/src/instructions/mod.rs`
- Create: `onchain/programs/pool/src/instructions/initialize.rs`
- Create: `onchain/programs/pool/src/instructions/shield.rs`
- Create: `onchain/programs/pool/src/instructions/transact.rs`
- Create: `onchain/programs/pool/src/utils.rs`
- Create: `onchain/programs/pool/src/verifier.rs`
- Create: `onchain/programs/pool/src/tree.rs`
- Create: `onchain/programs/pool/src/events.rs`
- Create: `onchain/programs/pool/src/error.rs`
- Modify: `onchain/programs/pool/src/state.rs`
- Delete: `onchain/programs/pool/src/util.rs`

**Interfaces:**
- Consumes: The current `InitPool`, `Shield`, `Transact`, `ExtData`, `Pool`, `MerkleTree`, `NullifierRecord`, events, errors, and helper functions without semantic changes.
- Produces: `instructions::{InitPool, Shield, Transact, ExtData}`, `state::{Pool, MerkleTree, NullifierRecord}`, `tree::{initialize, append, contains_root}`, `utils::*`, and `verifier::verify` for the later hardening tasks.

- [ ] **Step 1: Create the module boundaries and move existing definitions without changing behavior**

`lib.rs` becomes a façade and keeps the existing entrypoint signatures:

```rust
mod error;
mod events;
mod instructions;
mod state;
mod tree;
mod utils;
mod verifier;

pub use instructions::{ExtData, InitPool, Shield, Transact};
pub use state::{MerkleTree, NullifierRecord, Pool};

#[program]
pub mod pool {
    use super::*;

    pub fn init_pool(ctx: Context<InitPool>, domain: [u8; 32]) -> Result<()> {
        instructions::initialize::handle(ctx, domain)
    }

    pub fn shield(
        ctx: Context<Shield>,
        npk: [u8; 32],
        amount: u64,
        encrypted_note: Vec<u8>,
    ) -> Result<()> {
        instructions::shield::handle(ctx, npk, amount, encrypted_note)
    }

    pub fn transact(
        ctx: Context<Transact>,
        proof: Vec<u8>,
        root: [u8; 32],
        nullifiers: [[u8; 32]; 2],
        out_commitments: [[u8; 32]; 2],
        ext_amount: i64,
        ext_data: ExtData,
    ) -> Result<()> {
        instructions::transact::handle(
            ctx,
            proof,
            root,
            nullifiers,
            out_commitments,
            ext_amount,
            ext_data,
        )
    }
}
```

Keep `PoolError` variant order, event names and fields, account type names, all account constraints, and all handler statement ordering unchanged during this task. In particular, retain `MerkleTree` so its Anchor account discriminator does not change during a mechanical move.

- [ ] **Step 2: Keep external types visible to Anchor-generated clients**

Use direct public re-exports from the crate root:

```rust
pub use error::PoolError;
pub use events::{NewCommitment, NewNullifier};
pub use instructions::{ExtData, InitPool, Shield, Transact};
pub use state::{MerkleTree, NullifierRecord, Pool};
```

Do not re-export internal hash, verifier, or tree helpers.

- [ ] **Step 3: Run the narrow behavior-preservation gate**

Run:

```sh
cd onchain
cargo fmt --all -- --check
NO_DNA=1 cargo clippy -p pool --lib --all-targets -- -D warnings
NO_DNA=1 cargo test -p pool --lib
```

Expected: formatting and clippy succeed; all existing pool unit tests pass without test changes.

- [ ] **Step 4: Inspect the diff before continuing**

Run:

```sh
git diff --check
git diff --stat -- onchain/programs/pool
```

Expected: only the module move is present; no instruction account order, serialized argument, event, or error change.

---

### Task 2: Secure initialization and model the configured asset

**Files:**
- Modify: `onchain/programs/pool/src/instructions/initialize.rs`
- Modify: `onchain/programs/pool/src/instructions/shield.rs`
- Modify: `onchain/programs/pool/src/instructions/transact.rs`
- Modify: `onchain/programs/pool/src/state.rs`
- Modify: `onchain/programs/pool/src/error.rs`
- Modify: `onchain/tests/e2e/src/harness.rs`
- Modify: `onchain/tests/e2e/src/scenario.rs`
- Modify: `onchain/tests/e2e/tests/program.rs`
- Modify: `onchain/tests/e2e/tests/verifier.rs`

**Interfaces:**
- Consumes: `utils::asset_id(&Pubkey) -> Result<[u8; 32]>`, the existing versioned pool PDA, and Anchor's `ProgramData` account type.
- Produces: `Asset { mint, id }`, `Pool { verifier, asset, domain, bump }`, and an `InitPool` context that accepts only the current upgrade authority.

- [ ] **Step 1: Replace the flat asset fields and dead authority**

Use one stored value object while retaining identical mint and asset-ID bytes:

```rust
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, InitSpace)]
pub struct Asset {
    pub mint: Pubkey,
    pub id: [u8; 32],
}

#[account]
#[derive(InitSpace)]
pub struct Pool {
    pub verifier: Pubkey,
    pub asset: Asset,
    pub domain: [u8; 32],
    pub bump: u8,
}
```

Construct `Asset` only inside initialization from the supplied typed `Mint` account. Replace later `pool.mint` and `pool.asset_id` reads with `pool.asset.mint` and `pool.asset.id`.

- [ ] **Step 2: Bind initialization to the upgrade authority**

Add the executing program and canonical `ProgramData` account to `InitPool`:

```rust
pub pool_program: Program<'info, crate::program::Pool>,

#[account(
    constraint = pool_program.programdata_address()? == Some(program_data.key())
        @ PoolError::UnauthorizedInitializer,
    constraint = program_data.upgrade_authority_address == Some(authority.key())
        @ PoolError::UnauthorizedInitializer,
)]
pub program_data: Account<'info, ProgramData>,
```

Append `UnauthorizedInitializer` to `PoolError`; do not reorder existing variants. Do not retain the initializer in pool state.

- [ ] **Step 3: Move immutable relationships into Anchor constraints**

Use the nested asset mint and stored verifier directly in account validation:

```rust
#[account(address = pool.asset.mint)]
pub mint: Account<'info, Mint>,

#[account(address = pool.verifier @ PoolError::WrongVerifier, executable)]
pub verifier_program: UncheckedAccount<'info>,
```

Delete the now-duplicated runtime verifier equality check. Keep recipient ownership conditional on an actual withdrawal in the handler.

- [ ] **Step 4: Make the E2E pool deployment upgradeable**

Change the validator constructor to receive the initializer before it starts:

```rust
pub fn start(
    repository: &Path,
    pool_authority: Pubkey,
    programs: &[(Pubkey, &Path)],
) -> Result<Self>
```

Load the pool with:

```text
--upgradeable-program <pool id> <pool.so> <pool authority>
```

Create each fixture payer before `Validator::start`, pass its public key as the upgrade authority, and add `pool_program` plus the loader-derived program-data address to `init_instruction`.

- [ ] **Step 5: Add the one new regression and replace raw layout assertions**

Use a purpose-built validator segment inside `initialization_enforces_configuration_and_layout`:

1. Create the real initializer before starting the validator and load the pool as upgradeable with
   that public key.
2. Create and fund an attacker signer, then attempt initialization signed only by the attacker.
3. Assert rejection and absence of pool, tree, and vault accounts.
4. Initialize with the real upgrade authority and continue the existing initialization matrix.

Deserialize `Pool` with `AccountDeserialize` and assert:

```rust
assert_eq!(pool.verifier, MOCK_VERIFIER);
assert_eq!(pool.asset.mint, fixture.mint);
assert_eq!(pool.asset.id, fixture.config.asset().to_bytes());
assert_eq!(pool.domain, DOMAIN);
```

Do not add separate tests for the struct shape or Anchor constraints already covered by the scenario.

- [ ] **Step 6: Run initialization and program tests**

Run:

```sh
cd onchain
NO_DNA=1 cargo test -p pool --lib
PATH=/tmp/agave-v4.2.1/bin:$PATH NO_DNA=1 \
  cargo test --manifest-path tests/e2e/Cargo.toml --test program \
  initialization_enforces_configuration_and_layout -- --exact --nocapture
PATH=/tmp/agave-v4.2.1/bin:$PATH NO_DNA=1 \
  cargo test --manifest-path tests/e2e/Cargo.toml --test program -- --nocapture
```

Expected: the unauthorized attempt fails atomically; authorized initialization and all five program scenarios pass.

---

### Task 3: Replace patchy protocol adapters with typed library-backed code

**Files:**
- Modify: `onchain/programs/pool/src/instructions/shield.rs`
- Modify: `onchain/programs/pool/src/instructions/transact.rs`
- Modify: `onchain/programs/pool/src/utils.rs`
- Modify: `onchain/programs/pool/src/verifier.rs`
- Modify: `onchain/programs/pool/src/tree.rs`
- Modify: `onchain/programs/pool/src/state.rs`
- Modify: `onchain/programs/pool/src/lib.rs`

**Interfaces:**
- Consumes: `Asset`, `ExtData`, Light's `ConcurrentMerkleTree::size_in_account`, gnark's documented `[nbPublic | nbSecret | vectorLength | fields]` witness format, and Anchor SPL `transfer_checked`.
- Produces: `PublicInputs::new(...).verify(verifier, proof)`, library-derived tree space, stable commitment insertion, and checked classic SPL token movements.

- [ ] **Step 1: Replace both token transfers with `transfer_checked`**

Use the existing classic SPL types and configured mint:

```rust
use anchor_spl::token::{self, TransferChecked};

token::transfer_checked(
    CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        TransferChecked {
            from: ctx.accounts.depositor_ata.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
            authority: ctx.accounts.depositor.to_account_info(),
        },
    ),
    amount,
    ctx.accounts.mint.decimals,
)?;
```

Use the same account type with `new_with_signer` for withdrawals. Do not switch to `token_interface` or accept Token-2022.

- [ ] **Step 2: Make tree sizing and access one Light adapter**

Define production constants and calculate space from Light:

```rust
pub const HEIGHT: usize = 20;
const CANOPY: usize = 0;
const CHANGELOG: usize = 8;
const ROOTS: usize = 64;
const ANCHOR_DISCRIMINATOR: usize = 8;

pub fn account_space() -> usize {
    ANCHOR_DISCRIMINATOR
        + ConcurrentMerkleTree::<Poseidon, HEIGHT>::size_in_account(
            HEIGHT,
            CHANGELOG,
            ROOTS,
            CANOPY,
        )
}
```

Use `space = tree::account_space()` in `InitPool`. Keep all slicing past the discriminator private to `tree.rs`.

Replace the unit test's raw `next_index` byte mutation with a generic internal append helper exercised using a small test-only tree that reaches capacity through the public Light API.

- [ ] **Step 3: Encode gnark public inputs through a named type**

Use fixed constants and a single ordered field array:

```rust
const FIELD_BYTES: usize = 32;
const PUBLIC_INPUTS: usize = 7;
const WITNESS_HEADER_BYTES: usize = 12;
const WITNESS_BYTES: usize = WITNESS_HEADER_BYTES + PUBLIC_INPUTS * FIELD_BYTES;

pub struct PublicInputs {
    root: [u8; 32],
    nullifiers: [[u8; 32]; 2],
    commitments: [[u8; 32]; 2],
    amount: [u8; 32],
    external: [u8; 32],
}
```

`encode` writes `7u32`, `0u32`, and `7u32` in big-endian order, then copies the seven fields by iterating over one ordered array. `verify` builds the exact proof-plus-witness buffer and performs the existing no-account CPI.

Do not add a serialization dependency; the gnark header is twelve bytes and its format is already pinned by the real-verifier compatibility test.

- [ ] **Step 4: Centralize commitment insertion without hiding token or proof rules**

Expose one helper used by both instruction handlers:

```rust
pub fn insert(
    account: &AccountInfo,
    commitment: [u8; 32],
    encrypted_note: Vec<u8>,
) -> Result<()> {
    let leaf_index = append(account, &commitment)?;
    emit!(NewCommitment {
        commitment,
        leaf_index,
        encrypted_note,
    });
    Ok(())
}
```

Keep proof validation order, nullifier writes, withdrawal, and two-output loop visible in `transact::handle`. Remove numbered narration comments; retain only comments explaining atomicity, fixed arity, or external formats.

- [ ] **Step 5: Run the adapter and real-proof gates**

Run:

```sh
cd onchain
cargo fmt --all -- --check
NO_DNA=1 cargo clippy -p pool --lib --all-targets -- -D warnings
NO_DNA=1 cargo test -p pool --lib
PATH=/tmp/agave-v4.2.1/bin:$PATH NO_DNA=1 \
  cargo test --manifest-path tests/e2e/Cargo.toml --test verifier -- --nocapture
```

Expected: unit tests pass; the real proof remains 1,385 bytes, stays below 650,000 compute units, and rejects every mutated public input.

---

### Task 4: Documentation, consistency audit, and complete verification

**Files:**
- Modify: `README.md`
- Review: `onchain/programs/pool/src/lib.rs`
- Review: `onchain/programs/pool/src/instructions/initialize.rs`
- Review: `onchain/programs/pool/src/instructions/shield.rs`
- Review: `onchain/programs/pool/src/instructions/transact.rs`
- Review: `onchain/programs/pool/src/state.rs`
- Review: `onchain/programs/pool/src/utils.rs`
- Review: `onchain/programs/pool/src/verifier.rs`
- Review: `onchain/programs/pool/src/tree.rs`
- Review: `onchain/programs/pool/src/events.rs`
- Review: `onchain/programs/pool/src/error.rs`
- Review: `onchain/tests/e2e/src/harness.rs`
- Review: `onchain/tests/e2e/src/scenario.rs`
- Review: `onchain/tests/e2e/tests/program.rs`
- Review: `onchain/tests/e2e/tests/verifier.rs`

**Interfaces:**
- Consumes: The complete refactored pool and unchanged SDK/circuit protocol.
- Produces: A review-ready, uncommitted diff with current documentation and full verification evidence.

- [ ] **Step 1: Update current documentation, not historical records**

Update the README's stale 1-in/1-out public-input description to:

```text
[root, nullifier_0, nullifier_1, out_commitment_0, out_commitment_1,
 public_amount, ext_data_hash]
```

Document that the current upgrade authority initializes the singleton pool before the program is
made immutable. Do not rewrite historical W3/W4 plans or research notes.

- [ ] **Step 2: Perform the final DRY and security review**

Inspect the diff for:

- duplicated validation or commitment insertion;
- production `unwrap`, `expect`, panic, unchecked arithmetic, or lossy casts;
- `UncheckedAccount` values without explicit address/executable validation;
- account relationship checks left in handlers when an Anchor constraint expresses them exactly;
- changes to instruction account ordering, Borsh field ordering, event schemas, or existing error numbers;
- public helpers or abstractions with only speculative consumers;
- comments that narrate steps rather than explain invariants.

Keep the nullifier PDA design, verifier CPI, and classic SPL Token boundary unchanged.

- [ ] **Step 3: Run all repository gates**

Run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features

cd circuits/transaction
$HOME/.nargo/bin/nargo test

cd ../../prover/veil402-gnark
go test ./...
go vet ./...

cd ../../onchain
cargo fmt --all -- --check
NO_DNA=1 cargo build-sbf
NO_DNA=1 cargo clippy -p pool --lib --all-targets -- -D warnings
NO_DNA=1 cargo test -p pool --lib
NO_DNA=1 cargo clippy --manifest-path tests/e2e/Cargo.toml --all-targets -- -D warnings
PATH=/tmp/agave-v4.2.1/bin:$PATH NO_DNA=1 \
  cargo test --manifest-path tests/e2e/Cargo.toml --tests -- --nocapture
PATH=/tmp/agave-v4.2.1/bin:$PATH NO_DNA=1 \
  cargo test --manifest-path tests/e2e/Cargo.toml --test stress -- --ignored --nocapture \
  --test-threads=1

cd ..
git diff --check
git status --short
```

Expected: every command succeeds; the normal E2E suite reports five program scenarios and one real-verifier scenario; both explicit stress scenarios pass.

- [ ] **Step 4: Stop for user review**

Report the file-by-file changes, exact test results, real transaction size and compute units, and any deliberate compatibility changes. Leave the refactor and both planning documents uncommitted. Do not push.
