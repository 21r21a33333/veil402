# Local prover worker implementation plan

**Goal:** replace the ad-hoc JSON worker protocol with a bounded, versioned,
production-style persistent worker while preserving the public SDK API.

## Task 1: Canonical wire protocol

- Add one protobuf schema for readiness, proof requests, proof responses, and
  stable failure codes.
- Check generated Rust and Go code into the repository.
- Implement four-byte bounded framing with `tokio-util` and Go's standard
  library; remove JSON and base64 from the transport.

## Task 2: Worker lifecycle

- Split Rust worker code into protocol and process concerns.
- Use `process-wrap` for process-group ownership.
- Harden launch configuration, enforce the startup handshake, and explicitly
  kill/reap invalid workers.
- Keep cancellation fail-closed: dropping an in-flight worker terminates it;
  the next request starts cleanly.

## Task 3: Go server

- Load and verify artifacts before sending readiness.
- Read frames on a dedicated loop so stdin EOF terminates the worker even while
  proving.
- Preserve local Groth16 verification and clear witness buffers after use.

## Task 4: Verification

- Keep the existing three integration tests; the end-to-end proof test covers
  handshake, framing, proving, local verification, and public-input binding.
- Run formatting, Rust clippy/tests, Go tests/vet, and `git diff --check`.
- Stop for review before committing or pushing.
