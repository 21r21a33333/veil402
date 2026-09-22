# Pool program refactor

## Goal

Reshape the v4 Anchor program into a small entrypoint plus focused instruction and protocol
modules, close the singleton-initialization vulnerability, and remove avoidable hand-written
encoding and layout code without changing the shield or transact wire format.

The program remains one immutable SPL Token pool per deployment. Multi-asset pools, Token-2022,
new transaction features, and changes to the circuit are outside this refactor.

## Security decisions

### Singleton initialization

`init_pool` currently lets the first signer choose the singleton pool's mint, verifier, and
deployment domain. Initialization must instead require the current program upgrade authority:

- the executing pool program is a typed `Program` account;
- its `ProgramData` account must be the program's canonical program-data address; and
- `ProgramData.upgrade_authority_address` must equal the initializing signer.

Deployment order is therefore deploy, initialize, then optionally transfer or remove the upgrade
authority. An immutable program that has not been initialized cannot create the pool.

The local validator must load the pool with `--upgradeable-program` and the fixture payer as its
upgrade authority. The mock and real verifier programs remain ordinary immutable test programs.

### Asset and verifier configuration

The account stores one value object:

```rust
pub struct Asset {
    pub mint: Pubkey,
    pub id: [u8; 32],
}
```

`Asset::derive(mint)` computes the circuit asset identifier once during initialization. `Pool`
stores `verifier`, `asset`, `domain`, and `bump`. The existing `authority` field is removed because
the initialized configuration has no administrative operations.

Every later instruction validates the mint against `pool.asset.mint`. `transact` validates the
executable verifier address in its Anchor account constraints rather than in the handler.

This changes the v4 pool account layout and the `init_pool` account list. It assumes there is no
deployed v4 state requiring migration. Pool, tree, vault, and nullifier PDA derivations remain
unchanged.

### Token boundary

The program continues to support only the classic SPL Token program. Both deposits and
withdrawals use `transfer_checked` with the configured mint and its decimals. Token-2022 is not
accepted through a generic token interface because transfer fees, hooks, permanent delegates, and
mint lifecycle rules require a separate protocol design.

### Existing invariants

The refactor preserves:

- the fixed two-input/two-output circuit and seven public inputs;
- canonical BN254 field checks and zero/distinct nullifier checks;
- one pool-scoped PDA per nullifier as the atomic double-spend guard;
- the Light Protocol depth-20 concurrent Merkle tree and 64-root window;
- proof, ciphertext, withdrawal, and vault-balance checks;
- external-data binding and public-input ordering;
- current events, instruction names, instruction arguments, error messages, and rollback behavior.

## Code structure

```text
onchain/programs/pool/src/
├── lib.rs
├── instructions/
│   ├── mod.rs
│   ├── initialize.rs
│   ├── shield.rs
│   └── transact.rs
├── state.rs
├── hash.rs
├── verifier.rs
├── tree.rs
├── events.rs
└── error.rs
```

- `lib.rs` declares the program ID, exposes stable public types, and delegates each Anchor
  entrypoint to its instruction handler.
- Each instruction file owns its `Accounts` context and handler. Account validation stays beside
  the operation it protects.
- `state.rs` contains only `Pool`, `Asset`, the commitment-tree marker, and the nullifier record.
- `hash.rs` owns BN254 field encoding plus the asset, note, and external-data hashes.
- `verifier.rs` owns the seven checked public inputs, gnark witness serialization, and verifier
  CPI.
- `tree.rs` is the only adapter over `light-concurrent-merkle-tree`.
- `events.rs` and `error.rs` keep public events and stable error ordering visible and independent
  from account storage.

Modules remain concrete. No traits, service layers, new protocol crate, or speculative extension
points are introduced.

## Removing hand-written code

### Tree allocation

The account allocation calls `ConcurrentMerkleTree::size_in_account` with the production tree
constants. The literal `8224` is removed from production code. The adapter continues to account
for Anchor's eight-byte discriminator in one place.

The exhaustion regression uses the same generic adapter with a tiny test-only tree rather than
editing Light's private zero-copy header offsets.

### Verifier witness

There is no maintained Rust encoder for gnark's witness wire format. The required local encoder is
kept, but it is represented as a `PublicInputs` value with named constants for the public count,
field width, header width, and total size. It writes the documented gnark header from integers and
copies the seven fields in canonical order without repeated numeric offsets.

The verifier CPI accepts `PublicInputs`, performs the encoding internally, allocates exactly the
proof-plus-witness capacity, and maps verifier failure to `InvalidProof`.

### Shared commitment insertion

Appending a commitment and emitting `NewCommitment` is one domain operation reused by `shield`
and `transact`. Token transfer setup remains inside each handler because deposit and PDA-signed
withdrawal have materially different authorities.

## Compatibility

Unchanged:

- `shield` and `transact` discriminators and serialized argument bytes;
- `ExtData` field order and encoding;
- all non-initialization account lists;
- SDK proof binding and PDA derivation;
- event names and field order.

Changed intentionally:

- the pool account layout removes `authority` and nests mint plus asset identifier under `Asset`;
- `init_pool` additionally requires the pool program and its canonical `ProgramData` account;
- initialization by anyone other than the upgrade authority fails;
- SPL transfers use the checked instruction.

## Verification

Only one new behavior test is required: an unauthorized signer cannot initialize the singleton
pool and all attempted account creations roll back. The existing initialization test will decode
the typed `Pool` account instead of asserting raw byte offsets.

All existing circuit, SDK, program, real-verifier, and stress scenarios remain unchanged in
meaning. Before review, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features

cd onchain
cargo fmt --all -- --check
NO_DNA=1 cargo clippy -p pool --lib --all-targets -- -D warnings
NO_DNA=1 cargo test -p pool --lib
NO_DNA=1 cargo clippy --manifest-path tests/e2e/Cargo.toml --all-targets -- -D warnings
PATH=/tmp/agave-v4.2.1/bin:$PATH NO_DNA=1 \
  cargo test --manifest-path tests/e2e/Cargo.toml --tests -- --nocapture
PATH=/tmp/agave-v4.2.1/bin:$PATH NO_DNA=1 \
  cargo test --manifest-path tests/e2e/Cargo.toml --test stress -- --ignored --nocapture \
  --test-threads=1
```

The refactor remains uncommitted for review and is not pushed.
