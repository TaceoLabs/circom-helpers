# Groth16

An implementation of the [Groth16](https://eprint.iacr.org/2016/260) zkSNARK proof system.

To run tests, use:
```
cargo test --all-features
```

To run benchmarks, use:
```
cargo bench
```

This library provides two different R1CS to QAP reductions:

* `LibSnarkReduction` — Implements the witness map used by libsnark, based on <https://github.com/arkworks-rs/groth16/>.
* `CircomReduction` — Implements the witness map used by snarkjs (compatible with Circom), based on <https://github.com/arkworks-rs/circom-compat/>.
