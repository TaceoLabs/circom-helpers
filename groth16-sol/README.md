# groth16-sol

A crate for generating Solidity verifier contracts for BN254 Groth16 proofs.
This crate uses the `askama` templating engine to render Solidity code based on
the provided verifying key and configuration options.

The solidity contract is based on the [Groth16 verifier implementation from gnark](https://github.com/Consensys/gnark/blob/9c9cf0deb462ea302af36872669457c36da0f160/backend/groth16/bn254/solidity.go),
with minor modifications to be compatible with the [askama](docs.rs/askama) crate.

See <https://2π.com/23/bn254-compression> for further explanation of the internal compression approaches.
