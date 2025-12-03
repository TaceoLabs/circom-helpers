# Groth16 Solidity generator

A crate for generating Solidity verifier contracts for BN254 Groth16 proofs.
This crate uses the `askama` templating engine to render Solidity code based on
the provided verifying key and configuration options.

The solidity contract is based on the [Groth16 verifier implementation from
gnark](https://github.com/Consensys/gnark/blob/9c9cf0deb462ea302af36872669457c36da0f160/backend/groth16/bn254/solidity.go),
with minor modifications to be compatible with the [askama](docs.rs/askama) crate.

## Example usage
Generation of the Solidity verifier contract can be done as follows and requires the `template` feature to be enabled, which it is by default.
If the features is enabled, the crate also re-exports `askama` for convenience.
```rust,no_run
#[cfg(feature = "template")]
{
    let config = SolidityVerifierConfig::default();
    let vk : ark_groth16::VerifyingKey<ark_bn254::Bn254> = load_verification_key();
    let contract = SolidityVerifierContext {
        vk,
        config,
    };
    let rendered = contract.render().unwrap();
    println!("{}", rendered);
    // You can also write the rendered contract to a file, see askama documentation for details
    let mut file = std::fs::File::create("Verifier.sol").unwrap();
    contract.write_into(&mut file).unwrap();
}
```
## Preparing proofs
The crate also provides utility functions to prepare Groth16 proofs for verification in the generated contract.
The proofs can be prepared in either compressed or uncompressed format, depending on the specific deployment of the verifier contract.
See <https://2π.com/23/bn254-compression> for explanation of the point compression scheme used and explanation of the gas tradeoffs.
```rust,no_run
let proof: ark_groth16::Proof<ark_bn254::Bn254> = load_proof();
let compressed_proof = taceo_groth16_sol::prepare_compressed_proof(&proof);
let uncompressed_proof = taceo_groth16_sol::prepare_uncompressed_proof(&proof);
```

## Binary
We provide an accompanying CLI that packages the functionality of this library crate.

The CLI enables you to:

- **Extract a Solidity verifier contract** from a Circom verification key.
- **Generate Solidity-compatible calldata** for `verifyProof` and `verifyCompressedProof` methods, using a proof and corresponding public inputs.

### Usage

Use the CLI by invoking its subcommands:

#### ExtractVerifier

Generates a Solidity verifier contract from a Circom verification key.

```sh
groth16-sol-utils extract-verifier --vk <VERIFICATION_KEY_FILE> [--output <OUTPUT_SOL_FILE>] [--pragma-version <VERSION>]
```
- `--vk`         Path to the Circom verification key JSON file.
- `--output`     Path to save the generated Solidity verifier. If omitted, writes to stdout.
- `--pragma-version`   Specify the pragma version (`^0.8.0` by default).

#### GenerateCall

Produces calldata for verifying proofs with the generated Solidity contract.

```sh
groth16-sol-utils generate-call --proof <PROOF_FILE> --public <PUBLIC_FILE> [--output <OUTPUT_FILE>] [--uncompressed]
```
- `--proof`      Path to the Circom proof file.
- `--public`     Path to the Circom public inputs file.
- `--output`     Path to save calldata. If omitted, writes to stdout.
- `--uncompressed`  If set, uses uncompressed elliptic curve points (default is compressed; use uncompressed for compatibility where required).

#### Example commands

Extract a verifier with the default pragma version and output to `Verifier.sol`:
```sh
groth16-sol-utils extract-verifier --vk verification_key.json --output Verifier.sol
```

Generate calldata for `verifyProof` using compressed points:
```sh
groth16-sol-utils generate-call --proof proof.json --public public.json
```

Generate calldata for `verifyProof` using uncompressed points:
```sh
groth16-sol-utils generate-call --proof proof.json --public public.json --uncompressed
```
