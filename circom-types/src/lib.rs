#![warn(missing_docs)]
//! This crate defines types used in circom and utilities to read these types from files.
mod binfile;
pub mod groth16;
pub mod plonk;
mod r1cs;
pub mod traits;
mod witness;

pub use r1cs::R1CS;
pub use r1cs::R1CSParserError;

pub use witness::Witness;
pub use witness::WitnessParserError;

pub use binfile::ZKeyParserError;

pub(crate) mod reader_utils {

    use ark_serialize::Read;
    use std::str::Utf8Error;
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
}

#[cfg(test)]
pub(crate) mod tests {
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
