# vardamir-rs

A cryptographically verifiable decision ledger for offline autonomous systems.

## The Problem

Autonomous systems like UAVs, robots, and AI vehicles often operate in environments with no network access. During these missions they make hundreds of critical decisions. When the system returns, there needs to be strong proof of what decisions were made and in what order — and that the log has not been tampered with later. Regular logging doesn't provide cryptographic guarantees. Vardamir aims to solve this.

## How It Works

- Records are linked using SHA3-256 hash chaining. Any modification breaks the entire chain.
- Decisions are stored in a binary `.vdmr` file format containing length prefix, CRC32 checksum, and a signature.
- The log supports crash-safe appends and includes recovery logic that truncates incomplete entries after power loss.
- Per-record attestation signatures (using HMAC-SHA3-256) allow proving which model on which hardware produced each decision.
- Reopening an existing log rebuilds its internal state from disk rather than trusting a fresh start. If corruption is detected during that rescan, the damaged file is left untouched for forensic inspection and a new file is opened alongside it.

## Architecture

The project is split into several crates:

- **vardamir-rs-core**: Core data structures (`DecisionRecord`, `DecisionChain`) and hash chaining logic.
- **vardamir-rs-log**: Binary log writer, reader, and recovery implementation.
- **vardamir-rs-attest**: Attestation layer with `DeviceIdentity`, `ModelCommitment`, and `AttestationKey` derivation + signing.
- **vardamir-rs-cli**: Command-line interface (planned).

The long-term goal is to make the core run in `no_std` environments for bare-metal embedded systems.

## Status

Phase 1 (core logic and log engine) is complete.  
The attestation layer with per-record signatures has now been integrated.  
All tests are passing.
Ported the core, log and attest crates to `no_std` + `alloc` where applicable

**Next steps:**
- Implement the CLI tool
- Improve attestation key management and add hardware binding

## Known Limitations & Vulnerabilities

- Key management is currently quite manual. The user must supply the correct list of `AttestationKey`s in exact order when writing or reading logs. This is fragile and will need improvement.
- Attestation is still software-only. Real deployments will need proper hardware binding (TPM or secure element).
- Recovery is best-effort. While it handles common crash scenarios, very messy corruption can still cause problems.
- Test device identities are predictable. Production code must use strong hardware-derived identities.
- The last record in the chain relies heavily on its signature for protection (hash chaining alone is not enough for the tail).
- A mission's full history might now be split across multiple files (mission.vdmr, mission.vdmr.recovered1, etc.) if corruption occurred mid-session, and nothing currently stitches them back together into one continuous audit trail.

These limitations are acceptable during the core development phase, but they will be addressed before using this in real autonomous systems.

## Building & Testing

```bash
cargo build --workspace
cargo test --workspace
```

## License

Licensed under the Apache License, Version 2.0.
See LICENSE for details.
