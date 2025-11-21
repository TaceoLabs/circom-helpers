//! Provides utilities for loading Circom Groth16 proving keys and circuits, computing witnesses,
//! and generating/verifying Groth16 proofs using the `arkworks` ecosystem. Only the `bn254` curve is supported.

use ark_bn254::Bn254;
use ark_ff::AdditiveGroup as _;
use ark_ff::Field as _;
use ark_ff::LegendreSymbol;
use ark_ff::UniformRand as _;
use ark_serialize::CanonicalDeserialize;
use circom_witness_rs::Graph;
use groth16::CircomReduction;
use groth16::Groth16;
use rand::{CryptoRng, Rng};
use ruint::aliases::U256;
use sha2::Digest as _;
use std::ops::Shr;
use std::sync::Arc;
use std::{collections::HashMap, path::Path};

use crate::Groth16Error;

pub use ark_groth16::Proof;
pub use ark_serialize::Compress;
pub use ark_serialize::Validate;
pub use circom_types::groth16::ArkZkey;
pub use circom_witness_rs::BlackBoxFunction;

/// Trait for preparing proof inputs for zk-SNARK circuits.
///
/// The `prepare_input` method converts the implementing type into a
/// `HashMap<String, Vec<U256>>`, which is the expected format for proof inputs for Circom.
pub trait ProofInput {
    /// Prepares the input for zk-SNARK proof generation.
    ///
    /// Returns a `HashMap<String, Vec<U256>>` representing the input.
    ///
    /// # Example
    /// ```rust
    /// # use std::collections::HashMap;
    /// # use ruint::aliases::U256;
    /// # use taceo_groth16_material::circom::ProofInput;
    ///
    /// struct MyInput {
    ///    a: U256,
    ///    b: U256,
    /// }
    ///
    /// impl ProofInput for MyInput {
    ///     fn prepare_input(&self) -> HashMap<String, Vec<U256>> {
    ///         let mut input = HashMap::new();
    ///         input.insert("a".to_string(), vec![self.a]);
    ///         input.insert("b".to_string(), vec![self.b]);
    ///         input
    ///     }
    /// }
    /// ```
    fn prepare_input(&self) -> HashMap<String, Vec<U256>>;
}

impl ProofInput for HashMap<String, Vec<U256>> {
    fn prepare_input(&self) -> HashMap<String, Vec<U256>> {
        self.to_owned()
    }
}

/// Errors that can occur while loading or parsing a `.zkey` or graph file.
#[derive(Debug, thiserror::Error)]
pub enum ZkeyError {
    /// The SHA-256 fingerprint of the `.zkey` did not match the expected value.
    #[error("invalid zkey - wrong sha256 fingerprint: {0}")]
    ZkeyFingerprintMismatch(String),
    /// The SHA-256 fingerprint of the witness graph did not match the expected value.
    #[error("invalid graph - wrong sha256 fingerprint: {0}")]
    GraphFingerprintMismatch(String),
    /// Could not parse the `.zkey` file.
    #[error("Could not parse zkey - see wrapped error")]
    ZkeyInvalid(#[source] eyre::Report),
    /// Could not parse the graph file.
    #[error(transparent)]
    GraphInvalid(#[from] eyre::Report),
    /// Any I/O error encountered while reading the `.zkey` or graph file
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[cfg(any(feature = "reqwest", feature = "reqwest-blocking"))]
impl From<reqwest::Error> for ZkeyError {
    fn from(value: reqwest::Error) -> Self {
        Self::IoError(std::io::Error::new(std::io::ErrorKind::InvalidData, value))
    }
}

impl From<circom_types::ZkeyParserError> for ZkeyError {
    fn from(value: circom_types::ZkeyParserError) -> Self {
        Self::ZkeyInvalid(eyre::eyre!(value))
    }
}

impl From<ark_serialize::SerializationError> for ZkeyError {
    fn from(value: ark_serialize::SerializationError) -> Self {
        Self::ZkeyInvalid(eyre::eyre!(value))
    }
}

/// Core material for generating groth-16 zero-knowledge proofs based on Circom. Currently we only support `bn254` material, because the underlying witness extension library only support `bn254`.
///
/// Holds the proving keys, constraint matrices and graphs for the witness extension.
/// Provides methods to:
/// - Generate proofs from structured inputs
/// - Verify proofs internally immediately after generation
#[derive(Clone)]
pub struct CircomGroth16Material {
    zkey: ArkZkey<Bn254>,
    /// The graph for witness extension
    graph: Graph,
    /// The black-box functions needed for witness extension
    bbfs: HashMap<String, BlackBoxFunction>,
}

/// Builder for `CircomGroth16Material`.
/// Allows configuring options like compression, validation, fingerprints, and black-box functions.
///
/// # Example
///
/// ```rust,no_run
/// # use taceo_groth16_material::circom::{CircomGroth16MaterialBuilder, Compress, Validate};
/// # use std::collections::HashMap;
///
/// let material = CircomGroth16MaterialBuilder::new()
///                  .compress(Compress::No)
///                  .validate(Validate::Yes)
///                  .fingerprint_zkey("d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1".to_owned())
///                  .build_from_paths("./circuit.zkey", "./circuit.graph");
/// ```
pub struct CircomGroth16MaterialBuilder {
    compress: Compress,
    validate: Validate,
    fingerprint_zkey: Option<String>,
    fingerprint_graph: Option<String>,
    bbfs: HashMap<String, BlackBoxFunction>,
}

impl Default for CircomGroth16MaterialBuilder {
    fn default() -> Self {
        Self {
            compress: Compress::No,
            validate: Validate::Yes,
            fingerprint_zkey: None,
            fingerprint_graph: None,
            bbfs: HashMap::default(),
        }
    }
}

impl CircomGroth16MaterialBuilder {
    /// Creates a new `CircomGroth16MaterialBuilder` with default settings.
    ///
    /// Defaults:
    /// - `compress`: `Compress::No`
    /// - `validate`: `Validate::Yes`
    /// - `fingerprint_zkey`: No fingerprint verification of the Zkey.
    /// - `fingerprint_graph`: No fingerprint verification of the graph.
    /// - `bbfs`: No black-box functions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the compression mode for deserializing the `.zkey` file. See [ark_serialize::Compress] for details.
    pub fn compress(mut self, compress: Compress) -> Self {
        self.compress = compress;
        self
    }

    /// Sets the validation mode for deserializing the `.zkey` file. See [ark_serialize::Validate] for details.
    pub fn validate(mut self, validate: Validate) -> Self {
        self.validate = validate;
        self
    }

    /// Sets the expected SHA-256 fingerprint for the `.zkey` file. If provided, the fingerprint will be verified during loading.
    pub fn fingerprint_zkey(mut self, fingerprint_zkey: String) -> Self {
        self.fingerprint_zkey = Some(fingerprint_zkey);
        self
    }

    /// Sets the expected SHA-256 fingerprint for the graph file. If provided, the fingerprint will be verified during loading.
    pub fn fingerprint_graph(mut self, fingerprint_graph: String) -> Self {
        self.fingerprint_graph = Some(fingerprint_graph);
        self
    }

    /// Adds custom black-box functions for witness extension. See [circom_witness_rs::BlackBoxFunction] for details.
    pub fn add_bbfs(mut self, bbfs: HashMap<String, BlackBoxFunction>) -> Self {
        self.bbfs.extend(bbfs);
        self
    }

    /// Adds the standard black-box function `bbf_inv` for field inversion.
    ///
    /// The function implements the following Circom logic:
    /// ```text
    /// function bbf_inv(in) {
    ///     return in!=0 ? 1/in : 0;
    /// }
    /// ```
    pub fn bbf_inv(mut self) -> Self {
        self.bbfs.insert(
            "bbf_inv".to_string(),
            Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
                // function bbf_inv(in) {
                //     return in!=0 ? 1/in : 0;
                // }
                args[0].inverse().unwrap_or(ark_bn254::Fr::ZERO)
            }),
        );

        self
    }

    /// Adds a black-box function `bbf_legendre` for computing the legendre symbol.
    ///
    /// The function implements the following Circom logic:
    /// ```text
    /// function bbf_legendre(in) {
    ///     return in!=0 ? 1/in : 0;
    /// }
    /// ```
    pub fn bbf_legendre(mut self) -> Self {
        self.bbfs.insert(
            "bbf_legendre".to_string(),
            Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
                match args[0].legendre() {
                    LegendreSymbol::Zero => ark_bn254::Fr::from(0u64),
                    LegendreSymbol::QuadraticResidue => ark_bn254::Fr::from(1u64),
                    LegendreSymbol::QuadraticNonResidue => -ark_bn254::Fr::from(1u64),
                }
            }),
        );

        self
    }

    /// Adds a black-box function `bbf_sqrt_unchecked` for computing the square root of a field element.
    pub fn bbf_sqrt_unchecked(mut self) -> Self {
        self.bbfs.insert(
            "bbf_sqrt_unchecked".to_string(),
            Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
                args[0].sqrt().unwrap_or(ark_bn254::Fr::ZERO)
            }),
        );
        self
    }

    /// Adds a black-box function `bbf_sqrt_input` for selecting between two field elements based on a condition.
    ///
    /// The function implements the following Circom logic:
    /// ```text
    /// function bbf_sqrt_input(l, a, na) {
    ///   if (l != -1) {
    ///     return a;
    ///   } else {
    ///     return na;
    ///   }
    /// }
    /// ```
    pub fn bbf_sqrt_input(mut self) -> Self {
        self.bbfs.insert(
            "bbf_sqrt_input".to_string(),
            Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
                // function bbf_sqrt_input(l, a, na) {
                //     if (l != -1) {
                //         return a;
                //     } else {
                //         return na;
                //     }
                // }
                if args[0] != -ark_bn254::Fr::ONE {
                    args[1]
                } else {
                    args[2]
                }
            }),
        );
        self
    }

    /// Adds a black-box function `bbf_num_2_bits_helper`.
    ///
    /// The function implements the following Circom logic:
    /// ```text
    /// function bbf_num_2_bits_helper(in, i) {
    ///     return (in >> i) & 1;
    /// }
    /// ```
    pub fn bbf_num_2_bits_helper(mut self) -> Self {
        self.bbfs.insert(
            "bbf_num_2_bits_helper".to_string(),
            Arc::new(move |args: &[ark_bn254::Fr]| -> ark_bn254::Fr {
                // function bbf_num_2_bits_helper(in, i) {
                //     return (in >> i) & 1;
                // }
                let a: U256 = args[0].into();
                let b: U256 = args[1].into();
                let ls_limb = b.as_limbs()[0];
                ark_bn254::Fr::new((a.shr(ls_limb as usize) & U256::from(1)).into())
            }),
        );
        self
    }

    /// Loads the Groth16 material from `.zkey` and graph files and verifies their fingerprints if provided.
    pub fn build_from_paths(
        self,
        zkey_path: impl AsRef<Path>,
        graph_path: impl AsRef<Path>,
    ) -> Result<CircomGroth16Material, ZkeyError> {
        let zkey_bytes = std::fs::read(zkey_path)?;
        let graph_bytes = std::fs::read(graph_path)?;
        self.build_from_bytes(&zkey_bytes, &graph_bytes)
    }

    /// Builds Groth16 material directly from `.zkey` and graph readers.
    pub fn build_from_reader(
        self,
        mut zkey_reader: impl std::io::Read,
        mut graph_reader: impl std::io::Read,
    ) -> Result<CircomGroth16Material, ZkeyError> {
        let mut zkey_bytes = Vec::new();
        zkey_reader.read_to_end(&mut zkey_bytes)?;
        let mut graph_bytes = Vec::new();
        graph_reader.read_to_end(&mut graph_bytes)?;
        self.build_from_bytes(&zkey_bytes, &graph_bytes)
    }

    /// Builds Groth16 material directly from in-memory `.zkey` and graph bytes.
    pub fn build_from_bytes(
        self,
        zkey_bytes: &[u8],
        graph_bytes: &[u8],
    ) -> Result<CircomGroth16Material, ZkeyError> {
        let validate = if let Some(should_fingerprint) = self.fingerprint_zkey {
            let is_fingerprint = hex::encode(sha2::Sha256::digest(zkey_bytes));
            if is_fingerprint != should_fingerprint {
                return Err(ZkeyError::ZkeyFingerprintMismatch(is_fingerprint));
            }
            Validate::No
        } else {
            self.validate
        };

        let zkey = circom_types::groth16::ArkZkey::deserialize_with_mode(
            zkey_bytes,
            self.compress,
            validate,
        )?;
        if let Some(should_fingerprint) = self.fingerprint_graph {
            let is_fingerprint = hex::encode(sha2::Sha256::digest(graph_bytes));
            if is_fingerprint != should_fingerprint {
                return Err(ZkeyError::GraphFingerprintMismatch(is_fingerprint));
            }
        }
        let graph = circom_witness_rs::init_graph(graph_bytes).map_err(ZkeyError::GraphInvalid)?;
        Ok(CircomGroth16Material {
            zkey,
            graph,
            bbfs: self.bbfs,
        })
    }

    /// Downloads `.zkey` and graph files from the provided URLs and builds the Groth16 material.
    #[cfg(feature = "reqwest")]
    pub async fn build_from_urls(
        self,
        zkey_url: impl reqwest::IntoUrl,
        graph_url: impl reqwest::IntoUrl,
    ) -> Result<CircomGroth16Material, ZkeyError> {
        let zkey_bytes = reqwest::get(zkey_url).await?.bytes().await?;
        let graph_bytes = reqwest::get(graph_url).await?.bytes().await?;
        self.build_from_bytes(&zkey_bytes, &graph_bytes)
    }

    /// Downloads `.zkey` and graph files from the provided URLs and builds the Groth16 material. Uses the blocking reqwest client.
    #[cfg(feature = "reqwest-blocking")]
    pub fn build_from_urls_blocking(
        self,
        zkey_url: impl reqwest::IntoUrl,
        graph_url: impl reqwest::IntoUrl,
    ) -> Result<CircomGroth16Material, ZkeyError> {
        let zkey_bytes = reqwest::blocking::get(zkey_url)?.bytes()?;
        let graph_bytes = reqwest::blocking::get(graph_url)?.bytes()?;
        self.build_from_bytes(&zkey_bytes, &graph_bytes)
    }
}

impl CircomGroth16Material {
    /// Returns a reference to the underlying [ArkZkey].
    pub fn zkey(&self) -> &ArkZkey<Bn254> {
        &self.zkey
    }

    /// Computes a witness vector from a circuit graph and inputs.
    pub fn generate_witness(
        &self,
        inputs: &impl ProofInput,
    ) -> Result<Vec<ark_bn254::Fr>, Groth16Error> {
        let witness = circom_witness_rs::calculate_witness(
            inputs.prepare_input(),
            &self.graph,
            Some(&self.bbfs),
        )
        .map_err(Groth16Error::WitnessGeneration)?
        .into_iter()
        .map(|v| ark_bn254::Fr::from(ark_ff::BigInt(v.into_limbs())))
        .collect::<Vec<_>>();
        Ok(witness)
    }

    /// Generates a Groth16 proof from a witness and verifies it.
    ///
    /// Doesn't verify the proof internally.
    pub fn generate_proof_from_witness<R: Rng + CryptoRng>(
        &self,
        witness: &[ark_bn254::Fr],
        rng: &mut R,
    ) -> Result<(Proof<Bn254>, Vec<ark_bn254::Fr>), Groth16Error> {
        let r = ark_bn254::Fr::rand(rng);
        let s = ark_bn254::Fr::rand(rng);

        let (matrices, pk) = self.zkey.as_inner();
        let proof = Groth16::prove::<CircomReduction>(pk, r, s, matrices, witness)
            .map_err(Groth16Error::ProofGeneration)?;

        let inputs = witness[1..matrices.num_instance_variables].to_vec();
        Ok((proof, inputs))
    }

    /// Generates a Groth16 proof from structured inputs.
    ///
    /// This internally computes the witness using the provided inputs and then generates the proof.
    pub fn generate_proof<R: Rng + CryptoRng>(
        &self,
        inputs: &impl ProofInput,
        rng: &mut R,
    ) -> Result<(Proof<Bn254>, Vec<ark_bn254::Fr>), Groth16Error> {
        let witness = self.generate_witness(inputs)?;
        self.generate_proof_from_witness(&witness, rng)
    }

    /// Verifies a Groth16 proof and accompanying public inputs using the verification key.
    pub fn verify_proof(
        &self,
        proof: &Proof<Bn254>,
        public_inputs: &[ark_bn254::Fr],
    ) -> Result<(), Groth16Error> {
        Groth16::verify(&self.zkey.pk.vk, proof, public_inputs)
            .map_err(|_| Groth16Error::InvalidProof)
    }
}
