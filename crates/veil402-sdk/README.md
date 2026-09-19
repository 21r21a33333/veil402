# veil402-sdk

The canonical Veil client library. `Veil::prove` validates a typed transaction, generates its Noir
witness in-process, and asks the bundled local worker for a locally verified Groth16 proof.

```rust
let veil = Veil::open(Config::new(worker, artifacts))?;
let proof = veil.prove(transaction).await?;
```

The public API does not expose Noir, Sunspot, worker-protocol, or temporary-file concerns. The
current artifact implements the 1-in/1-out transaction circuit.
