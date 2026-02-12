//! # Groth16 Solidity generator
//!
//! A crate for generating Solidity verifier contracts for BN254 Groth16 proofs.
//! This crate uses the `askama` templating engine to render Solidity code based on
//! the provided verifying key and configuration options.
//!
//! The solidity contract is based on the [Groth16 verifier implementation from
//! gnark](https://github.com/Consensys/gnark/blob/9c9cf0deb462ea302af36872669457c36da0f160/backend/groth16/bn254/solidity.go),
//! with minor modifications to be compatible with the [askama](docs.rs/askama) crate.
//!
//! ## Example usage
//! Generation of the Solidity verifier contract can be done as follows and requires the `template` feature to be enabled, which it is by default.
//! If the features is enabled, the crate also re-exports `askama` for convenience.
//! ```rust,no_run
//! # #[cfg(feature = "template")]
//! # {
//! # fn load_verification_key() -> ark_groth16::VerifyingKey<ark_bn254::Bn254> { todo!() }
//! use taceo_groth16_sol::{SolidityVerifierConfig, SolidityVerifierContext};
//! use taceo_groth16_sol::askama::Template;
//! let config = SolidityVerifierConfig::default();
//! let vk : ark_groth16::VerifyingKey<ark_bn254::Bn254> = load_verification_key();
//! let contract = SolidityVerifierContext {
//!     vk,
//!     config,
//! };
//! let rendered = contract.render().unwrap();
//! println!("{}", rendered);
//! // You can also write the rendered contract to a file, see askama documentation for details
//! let mut file = std::fs::File::create("Verifier.sol").unwrap();
//! contract.write_into(&mut file).unwrap();
//! # }
//! ```
//! ## Preparing proofs
//! The crate also provides utility functions to prepare Groth16 proofs for verification in the generated contract.
//! The proofs can be prepared in either compressed or uncompressed format, depending on the specific deployment of the verifier contract.
//! See <https://2π.com/23/bn254-compression> for explanation of the point compression scheme used and explanation of the gas tradeoffs.
//! ```rust,no_run
//! # fn load_proof() -> ark_groth16::Proof<ark_bn254::Bn254> { todo!() }
//! let proof: ark_groth16::Proof<ark_bn254::Bn254> = load_proof();
//! let compressed_proof = taceo_groth16_sol::prepare_compressed_proof(&proof);
//! let uncompressed_proof = taceo_groth16_sol::prepare_uncompressed_proof(&proof);
//! ```
#![deny(missing_docs)]

use alloy_primitives::U256;
use ark_bn254::{Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_groth16::Proof;

/// Re-export askama for users of this crate
#[cfg(feature = "template")]
pub use askama;
#[cfg(feature = "template")]
pub use template::{SolidityVerifierConfig, SolidityVerifierContext};

#[cfg(feature = "template")]
mod template {
    use ark_ec::AffineRepr;
    use ark_groth16::VerifyingKey;
    use askama::Template;

    /// Context for generating a Solidity verifier contract for BN254 Groth16 proofs.
    /// The context is passed to `askama` for template rendering.
    /// Parameters:
    /// - `vk`: The [verifying key](ark_groth16::VerifyingKey) for the BN254 curve.
    /// - `config`: Configuration options for the Solidity verifier contract generation.
    #[derive(Debug, Clone, Template)]
    #[template(path = "../templates/bn254_verifier.sol", escape = "none")]
    pub struct SolidityVerifierContext {
        /// The Groth16 verifying key
        pub vk: VerifyingKey<ark_bn254::Bn254>,
        /// Configuration options for the Solidity verifier contract generation
        pub config: SolidityVerifierConfig,
    }

    /// Configuration for the Solidity verifier contract generation.
    ///
    /// Parameters:
    /// - `pragma_version`: The Solidity pragma version to use in the generated contract. Default is "^0.8.0".
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct SolidityVerifierConfig {
        /// The Solidity pragma version to use in the generated contract. Default is "^0.8.0".
        pub pragma_version: String,
    }

    impl Default for SolidityVerifierConfig {
        fn default() -> Self {
            Self {
                pragma_version: "^0.8.0".to_string(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use askama::Template;
        use circom_types::groth16::VerificationKey;

        const TEST_VK_BN254: &str = include_str!("../data/test_verification_key.json");
        const TEST_GNARK_OUTPUT: &str = include_str!("../data/gnark_output.txt");

        #[test]
        fn test() {
            let config = super::SolidityVerifierConfig::default();
            let vk =
                serde_json::from_str::<VerificationKey<ark_bn254::Bn254>>(TEST_VK_BN254).unwrap();
            let contract = super::SolidityVerifierContext {
                vk: vk.into(),
                config,
            };

            let rendered = contract.render().unwrap();
            // Askama supresses trailing newlines, so we add one for comparison
            let rendered = format!("{}\n", rendered);
            assert_eq!(rendered, TEST_GNARK_OUTPUT);
        }
    }
}

/// Compress a G1 point into a single U256, using the method described in the contract.
/// See <https://2π.com/23/bn254-compression> for further explanation.
fn compress_g1_point(point: &G1Affine) -> U256 {
    match point.xy() {
        Some((x, y)) => {
            let x_comp: U256 = x.into();
            let y_sqr = x.pow([3]) + ark_bn254::Fq::from(3);
            let y_computed = y_sqr
                .sqrt()
                .expect("Point is not on curve, this should not happen");
            if y == y_computed {
                x_comp << 1
            } else {
                assert_eq!(y, -y_computed);
                (x_comp << 1) | U256::ONE
            }
        }
        None => U256::ZERO, // Infinity represented as 0
    }
}

/// Compress a G2 point into two U256s, using the method described in the contract.
/// See <https://2π.com/23/bn254-compression> for further explanation.
fn compress_g2_point(point: &G2Affine) -> [U256; 2] {
    match point.xy() {
        Some((x, y)) => {
            let n3ab = x.c0 * x.c1 * Fq::from(-3);
            let a_3 = x.c0.pow([3]);
            let b_3 = x.c1.pow([3]);

            let frac_27_82 = Fq::from(27) * Fq::from(82).inverse().unwrap();
            let frac_3_82 = Fq::from(3) * Fq::from(82).inverse().unwrap();
            let y0_pos = (n3ab * x.c1) + a_3 + frac_27_82;
            let y1_pos = -((n3ab * x.c0) + b_3 + frac_3_82);

            let half = Fq::from(2).inverse().unwrap();
            let d = ((y0_pos * y0_pos) + (y1_pos * y1_pos))
                .sqrt()
                .expect("x is not on curve, this should not happen");
            let hint = ((y0_pos + d) * half).sqrt().is_none();

            let y2 = ark_bn254::Fq2::new(y0_pos, y1_pos);
            let y_computed = y2
                .sqrt()
                .expect("Point is on curve, this should not happen");
            if y_computed == y {
                let b0_comp: U256 = x.c0.into();
                let b1_comp: U256 = x.c1.into();
                if hint {
                    [b0_comp << 2 | U256::ONE << 1, b1_comp]
                } else {
                    [b0_comp << 2, b1_comp]
                }
            } else {
                assert_eq!(y, -y_computed);
                let b0_comp: U256 = x.c0.into();
                let b1_comp: U256 = x.c1.into();
                if hint {
                    [b0_comp << 2 | (U256::ONE << 1) | U256::ONE, b1_comp]
                } else {
                    [b0_comp << 2 | U256::ONE, b1_comp]
                }
            }
        }
        None => [U256::ZERO, U256::ZERO], // Infinity represented as (0, 0)
    }
}

/// Compress a Groth16 proofs by compressing the individual curve points.
/// This method uses the point compression scheme described in the contract.
/// See <https://2π.com/23/bn254-compression> for further explanation.
///
/// # Panics
///
/// This function will panic if the proof contains points that are not on the respective curves.
pub fn prepare_compressed_proof(proof: &Proof<ark_bn254::Bn254>) -> [U256; 4] {
    let a_compressed = compress_g1_point(&proof.a);
    let [b0_compressed, b1_compressed] = compress_g2_point(&proof.b);
    let c_compressed = compress_g1_point(&proof.c);

    [a_compressed, b1_compressed, b0_compressed, c_compressed]
}

/// Prepare an uncompressed Groth16 proof for verification in the generated contract.
/// The proof is represented as an array of 8 U256 values, corresponding to the
/// x and y coordinates of the points A, B, and C in the proof.
pub fn prepare_uncompressed_proof(proof: &Proof<ark_bn254::Bn254>) -> [U256; 8] {
    // Infinity is represented as (0, 0)
    let (ax, ay) = proof.a.xy().unwrap_or_default();
    // Infinity is represented as (0, 0, 0, 0)
    let (bx, by) = proof.b.xy().unwrap_or_default();
    // Infinity is represented as (0, 0)
    let (cx, cy) = proof.c.xy().unwrap_or_default();

    [
        ax.into(),
        ay.into(),
        bx.c1.into(),
        bx.c0.into(),
        by.c1.into(),
        by.c0.into(),
        cx.into(),
        cy.into(),
    ]
}

/// An error type representing an invalid compressed point during decompression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InvalidCompressedPoint;

impl core::error::Error for InvalidCompressedPoint {}

impl core::fmt::Display for InvalidCompressedPoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Encountered an invalid point during decompression")
    }
}

fn decompress_g1_point(compressed: U256) -> Result<G1Affine, InvalidCompressedPoint> {
    if compressed.is_zero() {
        // Infinity point
        return Ok(G1Affine::identity());
    }
    let x: U256 = compressed >> 1;
    // Checks that x is a valid field element < p
    let x = Fq::try_from(x).map_err(|_| InvalidCompressedPoint)?;
    let y_sqr = x.pow([3]) + Fq::from(3);
    let y = y_sqr.sqrt().ok_or(InvalidCompressedPoint)?;
    let y = if compressed.bit(0) {
        // y is the negative square root
        -y
    } else {
        // y is the positive square root
        y
    };
    let res = G1Affine::new_unchecked(x, y);
    if res.is_on_curve() && res.is_in_correct_subgroup_assuming_on_curve() {
        Ok(res)
    } else {
        Err(InvalidCompressedPoint)
    }
}

/// Decompress a G2 point from its compressed representation.
/// The input array is [c0, c1], with c0 being the low degree term of the quadratic extension field..
fn decompress_g2_point(compressed: [U256; 2]) -> Result<G2Affine, InvalidCompressedPoint> {
    let c0 = compressed[0];
    let c1 = compressed[1];
    if c0.is_zero() && c1.is_zero() {
        // Infinity point
        return Ok(G2Affine::identity());
    }
    let negate_point = c0.bit(0);
    let hint = c0.bit(1);
    let x0: U256 = c0 >> 2;
    let x1 = c1;
    // Checks that x0 is a valid field element < p
    let x0 = Fq::try_from(x0).map_err(|_| InvalidCompressedPoint)?;
    // Checks that x1 is a valid field element < p
    let x1 = Fq::try_from(x1).map_err(|_| InvalidCompressedPoint)?;

    let n3ab = x0 * x1 * Fq::from(-3);
    let a_3 = x0.pow([3]);
    let b_3 = x1.pow([3]);

    let frac_27_82 = Fq::from(27) * Fq::from(82).inverse().unwrap();
    let frac_3_82 = Fq::from(3) * Fq::from(82).inverse().unwrap();
    let y0_pos = (n3ab * x1) + a_3 + frac_27_82;
    let y1_pos = -((n3ab * x0) + b_3 + frac_3_82);

    let y2 = ark_bn254::Fq2::new(y0_pos, y1_pos);
    let y = y2.sqrt().ok_or(InvalidCompressedPoint)?;
    let y = if negate_point { -y } else { y };
    // recompute the hint and check it against the compressed value to ensure the point is valid
    let half = Fq::from(2).inverse().unwrap();
    let d = ((y0_pos * y0_pos) + (y1_pos * y1_pos))
        .sqrt()
        .ok_or(InvalidCompressedPoint)?;
    let hint_recomputed = ((y0_pos + d) * half).sqrt().is_none();
    if hint != hint_recomputed {
        return Err(InvalidCompressedPoint);
    }
    let res = G2Affine::new_unchecked(ark_bn254::Fq2::new(x0, x1), y);
    if res.is_on_curve() && res.is_in_correct_subgroup_assuming_on_curve() {
        Ok(res)
    } else {
        Err(InvalidCompressedPoint)
    }
}

/// Decompress a Groth16 proof from its compressed representation.
///
/// The input is an array of 4 U256 values, corresponding to the compressed points A, B, and C in the proof.
/// The output is a `Proof<ark_bn254::Bn254>` that can be used for verification with arkworks.
///
/// # Errors
/// This function will return an error if any of the compressed points are invalid.
pub fn decompress_proof(
    compressed_proof: &[U256; 4],
) -> Result<Proof<ark_bn254::Bn254>, InvalidCompressedPoint> {
    let a_compressed = compressed_proof[0];
    let b1_compressed = compressed_proof[1];
    let b0_compressed = compressed_proof[2];
    let c_compressed = compressed_proof[3];

    let a = decompress_g1_point(a_compressed)?;
    let b = decompress_g2_point([b0_compressed, b1_compressed])?;
    let c = decompress_g1_point(c_compressed)?;

    Ok(Proof { a, b, c })
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;

    #[test]
    fn test_roundtrip_compression() {
        use ark_bn254::{G1Affine, G2Affine};
        use rand::thread_rng;

        let mut rng = thread_rng();

        // Test G1 point compression and decompression
        for _ in 0..100 {
            let point = G1Affine::rand(&mut rng);
            let compressed = super::compress_g1_point(&point);
            let decompressed = super::decompress_g1_point(compressed).unwrap();
            assert_eq!(point, decompressed);
        }
        {
            let point = G1Affine::identity();
            let compressed = super::compress_g1_point(&point);
            let decompressed = super::decompress_g1_point(compressed).unwrap();
            assert_eq!(point, decompressed);
        }

        // Test G2 point compression and decompression
        for _ in 0..100 {
            let point = G2Affine::rand(&mut rng);
            let compressed = super::compress_g2_point(&point);
            let decompressed = super::decompress_g2_point(compressed).unwrap();
            assert_eq!(point, decompressed);
        }
        {
            let point = G2Affine::identity();
            let compressed = super::compress_g2_point(&point);
            let decompressed = super::decompress_g2_point(compressed).unwrap();
            assert_eq!(point, decompressed);
        }
    }
}
