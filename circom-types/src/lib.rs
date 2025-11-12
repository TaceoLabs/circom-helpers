#![warn(missing_docs)]
//! # circom-types
//!
//! Types and utilities for reading circom-generated files into arkworks representations.
//!
//! This crate provides deserialization support for circom's binary and JSON formats,
//! including proofs, verification keys, witnesses, R1CS constraint systems, and zkeys
//! for both Groth16 and PLONK proof systems.
#[cfg(feature = "zkey")]
mod binfile;
#[cfg(feature = "groth16")]
pub mod groth16;
pub mod plonk;

#[cfg(feature = "r1cs")]
mod r1cs;
pub mod traits;

#[cfg(feature = "witness")]
mod witness;

#[cfg(feature = "r1cs")]
pub use r1cs::R1CS;
#[cfg(feature = "r1cs")]
pub use r1cs::R1CSParserError;

#[cfg(feature = "witness")]
pub use witness::Witness;
#[cfg(feature = "witness")]
pub use witness::WitnessParserError;

#[cfg(feature = "zkey")]
pub use binfile::ZKeyParserError;

pub use taceo_ark_serde_compat::CheckElement;

//mod bn254;

#[cfg(any(feature = "r1cs", feature = "witness"))]
pub(crate) mod reader_utils {
    use ark_ff::PrimeField;
    use ark_serialize::Read;
    use std::{io, str::Utf8Error};
    use thiserror::Error;

    /// Error type describing errors during reading circom file headers
    #[derive(Debug, Error)]
    pub enum InvalidHeaderError {
        /// Error during IO operations (reading/opening file, etc.)
        #[error(transparent)]
        IoError(#[from] std::io::Error),
        /// File header is not valid UTF-8
        #[error(transparent)]
        Utf8Error(#[from] Utf8Error),
        /// File header does not match the expected header
        #[error("Wrong header. Expected {0} but got {1}")]
        WrongHeader(String, String),
    }

    pub(crate) fn read_header<R: Read>(
        mut reader: R,
        should_header: &str,
    ) -> Result<(), InvalidHeaderError> {
        let mut buf = [0_u8; 4];
        reader.read_exact(&mut buf)?;
        let is_header = std::str::from_utf8(&buf[..])?;
        if is_header == should_header {
            Ok(())
        } else {
            Err(InvalidHeaderError::WrongHeader(
                should_header.to_owned(),
                is_header.to_owned(),
            ))
        }
    }

    pub(crate) fn prime_field_from_reader<F: PrimeField>(
        mut reader: impl Read,
        size: usize,
    ) -> io::Result<F> {
        let mut buf = vec![0u8; size];
        reader.read_exact(&mut buf[..])?;
        Ok(F::from_le_bytes_mod_order(&buf))
    }

    // pub(crate) fn from_reader_for_groth16_zkey(reader: impl Read) -> SerResult<Self> {
    //     Ok(Self::new_unchecked(
    //         Self::montgomery_bigint_from_reader(reader)?.into_bigint(),
    //     ))
    // }
}

#[cfg(test)]
pub(crate) mod tests {
    // allow the tests folder to be unused in case we turn off the features
    #![allow(unused)]
    use std::path::PathBuf;

    #[cfg(feature = "bn254")]
    pub(crate) fn groth16_bn254_kats() -> PathBuf {
        let cargo_manifest = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        cargo_manifest.join("kats/groth16/bn254")
    }

    #[cfg(feature = "bn254")]
    pub(crate) fn plonk_bn254_kats() -> PathBuf {
        let cargo_manifest = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        cargo_manifest.join("kats/plonk/bn254")
    }

    #[cfg(feature = "bls12-381")]
    pub(crate) fn groth16_bls12_381_kats() -> PathBuf {
        let cargo_manifest = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        cargo_manifest.join("kats/groth16/bls12_381")
    }

    #[cfg(feature = "bls12-381")]
    pub(crate) fn plonk_bls12_381_kats() -> PathBuf {
        let cargo_manifest = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        cargo_manifest.join("kats/plonk/bls12_381")
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    #![allow(unused)]
    #[cfg(feature = "bls12-381")]
    macro_rules! to_g1_bls12_381 {
        ($x: expr, $y: expr) => {{
            use ark_ec::pairing::Pairing;
            use std::str::FromStr;
            <ark_bls12_381::Bls12_381 as Pairing>::G1Affine::new(
                ark_bls12_381::Fq::from_str($x).unwrap(),
                ark_bls12_381::Fq::from_str($y).unwrap(),
            )
        }};
    }
    #[cfg(feature = "bls12-381")]
    macro_rules! to_g2_bls12_381 {
        ({$x1: expr, $x2: expr}, {$y1: expr, $y2: expr}) => {{
            use ark_ec::pairing::Pairing;
            use std::str::FromStr;
            <ark_bls12_381::Bls12_381 as Pairing>::G2Affine::new(
                ark_bls12_381::Fq2::new(
                    ark_bls12_381::Fq::from_str($x1).unwrap(),
                    ark_bls12_381::Fq::from_str($x2).unwrap(),
                ),
                ark_bls12_381::Fq2::new(
                    ark_bls12_381::Fq::from_str($y1).unwrap(),
                    ark_bls12_381::Fq::from_str($y2).unwrap(),
                ),
            )
        }};
    }

    #[cfg(feature = "bn254")]
    macro_rules! to_g1_bn254 {
        ($x: expr, $y: expr) => {{
            use ark_ec::pairing::Pairing;
            use std::str::FromStr;
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        }};
    }

    #[cfg(feature = "bn254")]
    macro_rules! to_g2_bn254 {
        ({$x1: expr, $x2: expr}, {$y1: expr, $y2: expr}) => {{
            use ark_ec::pairing::Pairing;
            use std::str::FromStr;
            <ark_bn254::Bn254 as Pairing>::G2Affine::new(
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($x1).unwrap(),
                    ark_bn254::Fq::from_str($x2).unwrap(),
                ),
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($y1).unwrap(),
                    ark_bn254::Fq::from_str($y2).unwrap(),
                ),
            )
        }};
    }
    #[cfg(feature = "bls12-381")]
    pub(crate) use to_g1_bls12_381;
    #[cfg(feature = "bn254")]
    pub(crate) use to_g1_bn254;
    #[cfg(feature = "bls12-381")]
    pub(crate) use to_g2_bls12_381;
    #[cfg(feature = "bn254")]
    pub(crate) use to_g2_bn254;
}
