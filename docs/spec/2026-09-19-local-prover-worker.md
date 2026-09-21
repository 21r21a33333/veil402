# Local prover worker

## Decision

Veil generates proofs in one long-lived native worker connected by inherited
stdin/stdout pipes. Requests are singleplex: at most one proof is active in a
worker. This keeps proving-key setup amortized while avoiding the endpoint,
authentication, and lifecycle surface of a local RPC server.

The worker is trusted release code, isolated from the Rust client for fault
containment. It is not a sandbox for hostile executables. Release packaging is
responsible for platform code signing and protecting the installed binary.

## Protocol

`internal/protocol/worker.proto` is the canonical schema. Generated Rust and Go
sources are checked in; consumers do not need `protoc`.

Every message is a protobuf body prefixed by a four-byte big-endian length.
Both peers reject frames above their configured limit before allocating the
body.

After loading and verifying its artifacts, the worker sends exactly one
`Ready` message containing the protocol version and artifact identity. The
client fails closed unless both values match. It then exchanges `Request` and
`Response` messages with monotonically increasing request IDs. Failures expose
only stable error codes, never internal prover errors or witness data.

## Lifecycle

The client starts the executable directly without a shell, clears its inherited
environment, and gives it only piped stdin/stdout. The worker treats stdin EOF
as parent death. A malformed frame, protocol mismatch, unexpected response,
timeout, cancellation, or process exit invalidates that worker.

Invalid workers are killed as a process group, reaped, and never reused. A
later proof starts a fresh worker. Proof requests are not automatically retried.
The worker verifies every generated proof before returning it; the Rust client
also checks that the returned public witness exactly matches the transaction.

## Deferred hardening

OS sandboxing is packaging-specific. A macOS application should sign the nested
worker and use App Sandbox inheritance. A Linux package may add fail-closed
Landlock restrictions after Sunspot accepts witness bytes without the current
`/dev/fd` bridge. Wasmtime remains a separate compatibility and performance
spike, not part of this transport refactor.
