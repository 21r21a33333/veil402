# veil402-sdk

The canonical Veil client library. `Veil::withdraw` validates and binds public data, generates a
locally verified Groth16 proof, and returns the exact Solana instruction that consumes it.

```rust
let veil = Veil::open(Config::new(worker, artifacts))?;
let prepared = veil
    .withdraw(&pool, input, output, withdrawal, payer)
    .await?;
```

The public API does not expose Noir, Sunspot, worker-protocol, or temporary-file concerns. The
current `transaction-v2` artifact implements the bound 1-in/1-out transaction circuit. Advanced
callers can still use `Veil::prove` directly.
