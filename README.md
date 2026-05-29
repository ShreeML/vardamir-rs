# vardamir-rs

A cryptographically verifiable, offline-capable decision ledger
for autonomous systems operating in denied-network environments.

## The Problem

Autonomous systems — UAVs, robots, AI-driven vehicles — make 
hundreds of consequential decisions during offline operation. 
When they return, there is no way to prove what was decided, 
why, or whether the log was tampered with afterward. Existing 
logging solutions offer no cryptographic guarantees. Vardamir 
fills that gap.

## How It Works

- Every decision is recorded with a SHA3-256 hash linking it 
  to the previous record. Modifying any entry breaks the chain.
- Records are written to a binary `.vdmr` file with CRC32 
  integrity checks and crash-safe append-only semantics.
- Power-loss recovery detects and truncates incomplete tail 
  entries on restart, leaving the chain in a valid state.
- Hardware-bound attestation signatures (in progress) will 
  make the log unforgeable without the physical device.

## Crates

- `vardamir-rs-core` — `DecisionRecord`, `DecisionChain`, 
  SHA3-256 hashing, serde serialization. Phase 1 done.
- `vardamir-rs-log` — Binary `.vdmr` file format, `LogWriter`,
  `LogReader`, crash recovery. Phase 1 done.
- `vardamir-rs-attest` — Hardware-bound key derivation and 
  entry signing. Planned.
- `vardamir-rs-cli` — Command-line verifier and recorder. 
  Planned.

## Status

Phase 1 — core data types and log engine — is built and tested.
Phase 2 (attestation layer) is in progress.

Known limitation: tampering with the final record in a chain
is not detectable by hash chaining alone. This is addressed
in the attestation layer via independent entry signing.

## Building

    git clone https://github.com/ShreeML/vardamir-rs
    cd vardamir-rs
    cargo build --workspace
    cargo test --workspace

## Security Model

Vardamir provides tamper detection via SHA3-256 hash chaining 
and CRC32 corruption detection. It does not currently provide 
encryption or hardware attestation.

## License

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
