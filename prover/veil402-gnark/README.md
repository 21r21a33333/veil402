# veil402-gnark

Private local proving worker used by `veil402-sdk`. It loads and verifies one versioned
ACIR/CCS/PK/VK bundle, accepts in-memory Noir witness stacks over stdin, and returns Groth16 proof
and public-witness bytes over stdout after local verification.

It is an implementation detail, not a user-facing CLI. Stdout is reserved for its bounded NDJSON
protocol; dependency logging is disabled and witness data is never written to disk.

The anonymous file-descriptor bridge currently targets macOS and Linux. Windows packaging is
deferred until Sunspot exposes an `io.Reader` witness API.
