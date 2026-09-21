# Proof-capable Rust SDK — implementation plan

**Goal:** Ship one canonical Rust SDK that accepts a typed transaction request and returns a locally generated, locally verified Groth16 proof. The user never invokes `nargo` or `sunspot`.

**Phase boundary:** Implement against the existing 1-in/1-out `transaction` circuit and its five public inputs. Do not change the circuit, Anchor program, wallet persistence, note encryption, or restored on-chain tests. The later 2-in/2-out circuit replaces the internal request mapping without changing the SDK façade.

## Minimal LLD

```text
Veil::prove(Transaction)
  -> validate + derive protocol values
  -> execute ACIR in-process (Rust)
  -> send witness bytes to private local worker
  -> Groth16 prove + verify (Go/gnark)
  -> validate returned public witness
  -> Proof
```

Public surface:

```rust
pub struct Veil;
pub struct Transaction { input: Spend, send: Output, public: Public }
pub struct Spend { note: Note, owner: Owner, merkle: MerklePath }
pub struct Proof { bytes: Vec<u8>, public: PublicInputs, artifact: String }

impl Veil {
    pub fn open(config: Config) -> Result<Self, Error>;
    pub async fn prove(&self, transaction: Transaction) -> Result<Proof, Error>;
}
```

`Field` owns canonical 32-byte big-endian encoding; secret types redact `Debug` and zeroize on drop. All errors pass through one public `Error` and never include witness/key material.

## Task 1 — Public model and protocol primitives

**Files:** root `Cargo.toml`; `crates/veil402-sdk/Cargo.toml`; `src/lib.rs`; `src/client/{mod,error}.rs`; `src/protocol/{mod,field,encoding,note,transaction}.rs`.

- Add the workspace and the single public crate.
- Implement canonical field parsing/encoding, signed public-amount conversion, key/note/nullifier/commitment derivation, Merkle request types, and public-input ordering.
- Reuse `solana-poseidon = 2`, `ark-bn254/ark-ff = 0.5`, `thiserror`, and `zeroize`; hand-write only Veil402-specific packing and formulas.
- Keep constructors validating so an invalid field, amount, path length, or inconsistent asset cannot reach the prover.
- Gate: `cargo fmt --all --check && cargo check --workspace --all-targets`.

## Task 2 — In-process Noir witness generation

**Files:** `crates/veil402-sdk/src/proving/{mod,artifacts,witness}.rs` plus dependency pins.

- Pin Noir crates (`nargo`, `noirc_abi`, `noirc_artifacts`, `acvm`, `bn254_blackbox_solver`) to commit `c57152f91260ecdb9faad4efc20abb14b6d2ece7`, matching Nargo `1.0.0-beta.22`.
- Reuse `serde/serde_json` for the artifact ABI, `sha2` for the manifest, and Noir's own `WitnessStack::serialize`; do not create a second artifact or witness codec.
- Load the compiled `transaction.json`, verify its version/hash manifest, and map `Transaction` through `Abi::encode`—never build raw witness indexes manually.
- Execute with `nargo::ops::execute_program` and serialize the returned `WitnessStack` directly in memory. No CLI subprocess and no witness file.
- Gate: `cargo check -p veil402-sdk --all-targets`.

## Task 3 — Private Go/gnark worker

**Files:** `prover/veil402-gnark/{go.mod,main.go,protocol.go,prover.go}` and `artifacts/transaction-v1/{manifest.json,transaction.json,transaction.ccs,transaction.pk,transaction.vk}`.

- Pin Sunspot to `github.com/reilabs/sunspot/go v0.0.0-20260826142849-43891c5de8a2`; reuse its ACIR/witness conversion and gnark `v0.14.0` rather than porting the prover.
- Start one long-lived worker, validate SHA-256 for every versioned public artifact, and load ACIR/CCS/PK/VK once.
- Use a small NDJSON stdin/stdout protocol with base64 witness/proof bytes and request IDs. Feed witness bytes through an anonymous pipe to Sunspot's file-path API; never persist witness/proof material.
- Generate the proof, derive the public witness, verify with the loaded VK, then return bytes. Logs contain request IDs/error codes only.
- Gate: `cd prover/veil402-gnark && gofmt -w . && go test ./... && go vet ./...`.

## Task 4 — Orchestration, minimal tests, and review handoff

**Files:** `crates/veil402-sdk/src/proving/worker.rs`; `crates/veil402-sdk/tests/proving.rs`; short crate/worker READMEs.

- Implement `Veil::open` and `prove` with `tokio`: worker lifecycle, bounded request/response size, timeout, cancellation/child cleanup, response-ID check, and exact public-witness equality before returning `Proof`.
- Package/configure the worker and artifact directory behind `Config`; expose no worker protocol or Noir/Sunspot types publicly.
- Add exactly three regression tests:
  1. one protocol vector covering Poseidon derivations, canonical encoding, signed amount, and five-field ordering;
  2. one corrupted-artifact manifest rejection test;
  3. one real end-to-end test: Rust witness -> worker proof -> local verification -> expected public inputs.
- Do not add tests for serde, getters, config plumbing, dependency behavior, or trivial round trips.
- Final gate: `cargo fmt --all --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`; `cd prover/veil402-gnark && go test ./... && go vet ./...`.

## Review and delivery gate

Implementation remains uncommitted. Present the diff, artifact-size impact (about 8.3 MB), test results, and any deviations for user review. Only after explicit approval: create one phase commit, then ask separately before pushing.
