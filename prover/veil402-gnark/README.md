# veil402-gnark

Private local proving worker used by `veil402-sdk`. It loads and verifies one versioned
ACIR/CCS/PK/VK bundle, accepts in-memory Noir witness stacks over stdin, and returns Groth16 proof
and public-witness bytes over stdout after local verification.

It is an implementation detail, not a user-facing CLI. Stdout is reserved for its versioned,
length-delimited protobuf protocol; dependency logging is disabled and witness data is never
written to disk.

The worker sends its protocol and artifact identity after initialization, handles one proof at a
time, and exits when its parent closes stdin. Protocol sources live in `internal/protocol`; generated
Rust and Go bindings are checked in so application builds do not require `protoc`.

The anonymous file-descriptor bridge currently targets macOS and Linux. Windows packaging is
deferred until Sunspot exposes an `io.Reader` witness API.

## Regenerating the protocol

From this directory, regenerate the Go binding with:

```sh
protoc --go_out=. --go_opt=paths=source_relative internal/protocol/worker.proto
```

Generate the Prost binding with `protoc-gen-prost`, then replace
`../../crates/veil402-sdk/src/proving/worker/generated.rs`. Generated bindings are committed and
must change in the same commit as `worker.proto`.
