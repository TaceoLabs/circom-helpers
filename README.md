# Various Crates to work with Circom (and Groth16) proofs from Rust

This repository contains a collection of crates that make working with [Circom ZK circuits](https://docs.circom.io/) and the associated artifacts easier.

## Crates

Crates are released with a `taceo-` prefix on crates.io, since crate namespaces are not yet supported.

* `ark-serde-compat`: This crate implements a compatibility layer that allows for the serialization of Circom types. When used with human-readable adapters, it uses string de/serialization, with additional checks that the strings are in canonical form.
* `circom-types`: This crate implements Rust types and associated parsing functions for Circom artifacts, including R1CS files, Groth 16 proving keys (ZKeys), Groth16 verification keys, Groth16 proofs, Plonk proving and verification keys, and Plonk proofs as well as support for loading public input files. Supported curves are `BN254` and `BLS-12-381`.
* `groth16`: A minor fork of the arkworks `groth16` [prover](https://docs.rs/ark-groth16/latest/ark_groth16/), which improves the parallelization of some of the internal operations.
* `groth16-material`: A crate with wrapper functionality, encapsulating the loading of proving keys as well as witness generation graphs using [`circom-witness-rs`](https://docs.rs/circom-witness-rs/latest/circom_witness_rs/) for Groth16 proofs.
* `groth16-sol`: A crate that takes a Groth16 verification key and outputs a Solidity verifier contract. The contract template is based on the audited contract template in [gnark](https://github.com/Consensys/gnark) and produces byte-for-byte identical Solidity code to the gnark one.
